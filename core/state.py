"""Deterministic core of the framework.

Every consequential decision (severity, overall risk, findings
consolidation, orchestrator progression) lives here, never in an agent nor
in a language model's response. See PROJECT.md, guiding principle.
"""
from __future__ import annotations

import ipaddress
import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


PHASE_ORDER: list[str] = ["recon", "enum", "exploit", "postexploit", "report"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact(text: str, secret: Optional[str]) -> str:
    """Strip any literal occurrence of a secret (e.g. the session cookie)

    from free text before storage. Defense in depth: nuclei already
    redacts its own curl-command field itself (verified in its source
    code), but sqlmap/dalfox/commix/nikto offer no equivalent guarantee on
    their raw output - nothing structurally prevents a verbose mode/error
    from one of these tools echoing the sent cookie into text that ends up
    in evidence/description (see docs/HISTORY.md, section 20). Doesn't
    replace the discipline of never passing the raw cookie through the
    API/report (already the case elsewhere), adds to it.
    """
    if not secret or not text:
        return text
    return text.replace(secret, "***")


def _dedup_key_text(value: str) -> str:
    """Normalize for duplicate comparison: whitespace, case, trailing

    slash (e.g. "/admin/" and "/admin" must count as the same path).
    """
    return value.strip().lower().rstrip("/")


def cap_severity(severity: Severity, exploited: bool) -> Severity:
    """Without proof of exploitation, a mere discovery never exceeds MEDIUM.

    HIGH/CRITICAL requires exploited=True. See docs/HISTORY.md, incident
    #10: a hallucinated CRITICAL made it through the whole pipeline for
    lack of systematically applied capping. This function is the sole
    source of truth; it must never be reimplemented locally in an agent.
    """
    if not exploited and severity in (Severity.HIGH, Severity.CRITICAL):
        return Severity.MEDIUM
    return severity


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    affected_component: str
    evidence: str
    discovered_by: str
    remediation: str = ""
    cve: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    exploited: bool = False
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=_now)

    def __post_init__(self) -> None:
        # Structural guardrail: even if an agent forgets to call
        # cap_severity before constructing this Finding, the severity can
        # never exceed MEDIUM without exploited=True. Defense in depth
        # beyond the discipline expected of agents (incident #10: an agent
        # not covered by capping let a hallucinated CRITICAL through to
        # the final report).
        requested_severity = self.severity
        self.severity = cap_severity(self.severity, self.exploited)
        if self.severity != requested_severity:
            # A note visible in the report rather than a silent cap: a
            # reader must be able to see that a higher severity was
            # proposed (by a tool or the LLM) and brought back down here
            # for lack of confirmed exploitation proof, rather than having
            # to guess it.
            self.description = (
                f"{self.description}\n\n"
                f"[Note automatique : severite proposee {requested_severity.name}, "
                f"plafonnee a {self.severity.name} faute de preuve d'exploitation "
                "confirmee - a verifier manuellement.]"
            ).strip()
        if self.cve and not self.exploited:
            self.cve = None


@dataclass
class Lead:
    """Speculative lead. No severity field: a lead isn't scored."""

    title: str
    rationale: str
    source: str
    confidence: float
    tags: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=_now)


@dataclass
class Target:
    host: str
    ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    os_guess: Optional[str] = None
    os_confidence: Optional[float] = None
    # Session cookie supplied by the operator (e.g. "PHPSESSID=...;
    # security=low" for DVWA), obtained manually via a browser. Lets the
    # web tools (gobuster, ffuf, nikto, sqlmap) reach pages protected by
    # authentication. Never shown in the clear in the report (see
    # report_agent.py); never guessed or automated by the framework -
    # every application handles its own login flow differently.
    session_cookie: Optional[str] = None


@dataclass
class MissionState:
    mission_id: str
    mission_name: str
    operator: str
    authorization_ref: Optional[str]
    target: Target

    status: str = "pending"
    current_agent: Optional[str] = None
    last_decision: Optional[str] = None
    completed_phases: list[str] = field(default_factory=list)
    orchestration_cycles: int = 0

    findings: list[Finding] = field(default_factory=list)
    leads: list[Lead] = field(default_factory=list)

    attack_chain: list[dict] = field(default_factory=list)
    tool_results: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    # Work context shared between phases, keyed by agent name (e.g.
    # scratch["enum"] = {"candidate_urls": [...]}). Purely informational: a
    # downstream agent may read it to avoid re-deriving what a previous
    # phase already established, but no critical decision (severity, risk)
    # must ever be based on it - only findings/leads count.
    scratch: dict[str, dict] = field(default_factory=dict)

    report_path: Optional[str] = None

    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def add_finding(self, finding: Finding) -> None:
        # Append-only: a confirmed finding is never removed or modified
        # afterward, only consolidated at creation time. Deduplicated on
        # normalized (title, affected component, severity): the same tool
        # (nikto, gobuster, ...) may re-report the same thing twice in a
        # mission, which would otherwise produce literally duplicated
        # findings in the report.
        cookie = self.target.session_cookie
        finding.evidence = _redact(finding.evidence, cookie)
        finding.description = _redact(finding.description, cookie)
        finding.affected_component = _redact(finding.affected_component, cookie)

        key = (_dedup_key_text(finding.title), _dedup_key_text(finding.affected_component), finding.severity)
        for existing in self.findings:
            existing_key = (
                _dedup_key_text(existing.title),
                _dedup_key_text(existing.affected_component),
                existing.severity,
            )
            if existing_key == key:
                return
        self.findings.append(finding)
        self.updated_at = _now()

    def add_lead(self, lead: Lead) -> None:
        lead.rationale = _redact(lead.rationale, self.target.session_cookie)

        # Same deduplication logic as add_finding, on (title, source).
        key = (_dedup_key_text(lead.title), lead.source)
        for existing in self.leads:
            if (_dedup_key_text(existing.title), existing.source) == key:
                return
        self.leads.append(lead)
        self.updated_at = _now()


def compute_overall_risk(findings: list[Finding]) -> Severity:
    """Never asked of the LLM. Maximum severity among confirmed findings.

    Leads never enter this calculation (see PROJECT.md).
    """
    if not findings:
        return Severity.INFO
    return max(f.severity for f in findings)


def consolidate_denied_paths(candidate_paths: list[dict], discovered_by: str) -> Optional[Finding]:
    """Groups every 401/403 path into a single LOW finding.

    Avoids a scan with, say, 22 protected paths producing 22 nearly
    identical findings (noise in the report, perceived false positives).
    """
    denied = [p for p in candidate_paths if p.get("status_code") in (401, 403)]
    if not denied:
        return None
    paths_list = ", ".join(sorted(p["path"] for p in denied))
    return Finding(
        title="Chemins proteges detectes (acces refuse)",
        severity=Severity.LOW,
        description=(
            f"{len(denied)} chemin(s) decouvert(s) retournent un code d'acces "
            "refuse (401/403). Protection en place, mais surface "
            "d'enumeration notable a documenter."
        ),
        affected_component="application web",
        evidence=paths_list,
        discovered_by=discovered_by,
        exploited=False,
        remediation=(
            "Confirmer que chaque chemin protege est volontairement restreint. "
            "Si un chemin n'a pas vocation a etre expose publiquement, envisager "
            "de le retirer de la surface accessible plutot que de compter sur le "
            "controle d'acces seul."
        ),
        tags=["consolidated", "access-denied"],
    )


def enforce_progression(state: MissionState, proposed_next_phase: str, max_cycles: int = 10) -> str:
    """Orchestrator anti-loop guardrail.

    - increments orchestration_cycles on every decision
    - past max_cycles: forces "report" (once) then "end"
    - a phase already completed (other than "report") is redirected to the
      first incomplete phase in the linear order
    - any attempt to finish without going through "report" forces "report"
    - a suggestion (MissionState.last_decision) can never skip an
      incomplete intermediate phase: only the real next phase, or a direct
      skip to "report" (early completion), is honored. A skipped
      intermediate phase (e.g. exploit before enum) deprives a downstream
      phase of data it genuinely depends on (exploit_agent relies on the
      URLs enum discovered via MissionState.scratch) - see
      docs/HISTORY.md for the incident that motivated this rule.
    """
    state.orchestration_cycles += 1

    def first_incomplete_phase() -> str:
        for phase in PHASE_ORDER:
            if phase not in state.completed_phases:
                return phase
        return "report"

    if state.orchestration_cycles > max_cycles:
        if "report" not in state.completed_phases:
            return "report"
        return "end"

    if proposed_next_phase == "end":
        if "report" not in state.completed_phases:
            return "report"
        return "end"

    if proposed_next_phase not in PHASE_ORDER:
        return first_incomplete_phase()

    if proposed_next_phase != "report" and proposed_next_phase in state.completed_phases:
        return first_incomplete_phase()

    if proposed_next_phase != "report" and proposed_next_phase != first_incomplete_phase():
        return first_incomplete_phase()

    return proposed_next_phase


def is_target_in_allowed_ranges(host: str, allowed_ranges: list[str]) -> bool:
    """Optional perimeter guardrail (disabled if allowed_ranges is empty).

    Disabled by default: the MVP must work against any external target
    (see PROJECT.md), so restricting to private ranges by default would
    contradict that goal. An operator can enable it via
    ALLOWED_TARGET_RANGES to lock their own missions to a known lab. Fails
    closed (returns False) if DNS resolution of a hostname fails while the
    restriction is active: never guess the scope of a target that can't be
    resolved.
    """
    if not allowed_ranges:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except (OSError, ValueError):
            return False
    for cidr in allowed_ranges:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False
