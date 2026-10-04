"""Reconnaissance: nmap discovery/ports/vuln.

Never explicitly caps a severity here: Finding.__post_init__
(core/state.py) is the sole point where cap_severity applies, so the
transparency note correctly compares the severity the agent actually
intended against the final one (incident #10: this is precisely the agent
that got forgotten in v1 when capping depended on each agent's discipline
rather than a structural guarantee).
"""
from __future__ import annotations

import asyncio
import ipaddress

import dns.resolver
import dns.reversename

from core.state import Finding, Lead, MissionState, Severity
from tools.nmap_tool import NmapTool

from .base_agent import BaseAgent

# nmap's own NSE vuln-category scripts don't all share one output
# convention, any more than gobuster/ffuf/nuclei/dalfox share one archive
# layout (CLAUDE.md, section 2) - so a script simply appearing in
# --script=vuln output is not itself a positive signal (docs/HISTORY.md,
# section 22). Incidents 22-24 fixed this one negative phrasing at a time
# (a blocklist), each catching the next shape the previous pass hadn't
# seen; section 25 replaces that with CLAUDE.md's sqlmap rule applied
# here instead - "a single unambiguous positive signal, checked line by
# line" - for the subset of scripts that give one: nselib/vulns.lua
# always prints a "State: <value>" conclusion line (78277 bytes as of
# 2026-10-04, line 1834: string_format("  State: %s",
# STATE_MSG[vuln_table.state])), so for those scripts the State: line
# itself is ground truth, not an enumerated list of known-bad phrasings.
_NMAP_VULN_STATE_MARKER = "state:"
# Deliberately matches "State: VULNERABLE", "State: VULNERABLE (DoS)" and
# "State: VULNERABLE (Exploitable)" (all three start with this exact
# substring, per vulns.lua's STATE_MSG table, docs/HISTORY.md section 24)
# while excluding "State: LIKELY VULNERABLE" and "State: NOT VULNERABLE"
# (a different word immediately follows "State: " in both).
_NMAP_VULN_STATE_POSITIVE = "state: vulnerable"
_NMAP_VULN_STATE_LIKELY = "state: likely vulnerable"
# "State: UNKNOWN (unable to test)" falls through both checks above and
# is silently not a Finding - inconclusive, not confirmed either way.

_NMAP_VULN_ERROR_MARKER = "error: script execution failed"
# Scripts with no "State:" line at all don't use vulns.lua (http-enum's
# plain directory listing, http-vuln-cve2010-0738's bare
# "/jmx-console/: Authentication was not required") and have no single
# shared positive/negative convention across them - this allowlist only
# closes the vulns.lua category, not this one. "couldn't find" is the one
# negative phrasing actually observed in real captured output for this
# remaining category; this is still the blocklist pattern section 25
# moves away from for vulns.lua scripts, kept here for lack of a better
# generalizable alternative (docs/HISTORY.md, section 25).
_NMAP_VULN_NEGATIVE_MARKER = "couldn't find"

# A -O guess below this confidence threshold must never appear as a fact
# in the report (see CLAUDE.md, section 2 and docs/HISTORY.md, section 3:
# nmap -O produced absurd results at high displayed confidence on
# single-port targets).
OS_CONFIDENCE_THRESHOLD = 0.85


def _dns_recon(host: str) -> list[str]:
    """Best-effort DNS enumeration: reverse (PTR) if the target is an IP,

    otherwise A/MX/NS if it's a hostname. Always purely informational
    (never a Finding, never a severity/risk factor) and never blocking: a
    missing or failed DNS resolution on the target must never fail the
    mission.
    """
    records: list[str] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    try:
        if is_ip:
            rev_name = dns.reversename.from_address(host)
            for rdata in resolver.resolve(rev_name, "PTR"):
                records.append(f"PTR: {rdata.target}")
        else:
            for record_type in ("A", "MX", "NS"):
                try:
                    for rdata in resolver.resolve(host, record_type):
                        records.append(f"{record_type}: {rdata}")
                except Exception:  # noqa: BLE001 - a missing record type isn't an error
                    continue
    except Exception:  # noqa: BLE001 - DNS recon must never interrupt the mission
        pass
    return records


class ReconAgent(BaseAgent):
    name = "recon"

    def __init__(self) -> None:
        super().__init__()
        self.nmap = NmapTool()

    async def run(self, state: MissionState) -> MissionState:
        state.current_agent = self.name
        host = state.target.host

        # dnspython is synchronous/blocking: never called directly in a
        # coroutine, or it freezes the entire asyncio loop (and therefore
        # the whole API/dashboard) for the duration of the resolution.
        dns_records = await asyncio.to_thread(_dns_recon, host)
        if dns_records:
            state.add_lead(
                Lead(
                    title="Enregistrements DNS decouverts",
                    rationale="\n".join(dns_records),
                    source=self.name,
                    confidence=0.5,
                    tags=["dns"],
                )
            )

        discovery = await self.nmap.run(target=host, mode="discovery")
        state.tool_results.append({"agent": self.name, "tool": "nmap-discovery", "result": discovery.parsed})

        ports_result = await self.nmap.run(target=host, mode="ports")
        state.tool_results.append({"agent": self.name, "tool": "nmap-ports", "result": ports_result.parsed})
        open_ports = ports_result.parsed.get("open_ports", [])
        state.target.ports = [p["port"] for p in open_ports]
        state.target.services = {p["port"]: p["service"] for p in open_ports}

        os_guess = ports_result.parsed.get("os_guess") or discovery.parsed.get("os_guess")
        os_confidence = ports_result.parsed.get("os_confidence")
        if os_confidence is None:
            os_confidence = discovery.parsed.get("os_confidence")

        if os_guess is not None and os_confidence is not None:
            if os_confidence >= OS_CONFIDENCE_THRESHOLD:
                state.target.os_guess = os_guess
                state.target.os_confidence = os_confidence
            else:
                state.add_lead(
                    Lead(
                        title=f"OS possible : {os_guess}",
                        rationale=f"Detection nmap -O a confiance {os_confidence:.0%}, trop faible pour etre affirmee comme un fait.",
                        source=self.name,
                        confidence=os_confidence,
                        tags=["os-guess"],
                    )
                )

        def _make_vuln_finding(script_id: str, port_num: int, service: str, output: str) -> Finding:
            return Finding(
                title=f"Script nmap {script_id} positif sur le port {port_num}",
                severity=Severity.MEDIUM,
                description=output[:500],
                affected_component=f"{host}:{port_num} ({service})",
                evidence=output,
                discovered_by=self.name,
                exploited=False,
                remediation=(
                    f"Examiner le resultat du script nmap {script_id} et appliquer le "
                    "correctif ou le durcissement de configuration recommande par l'editeur "
                    "du service concerne. Desactiver ce service s'il n'est pas necessaire."
                ),
                tags=["nmap-vuln"],
            )

        vuln_result = await self.nmap.run(target=host, mode="vuln")
        state.tool_results.append({"agent": self.name, "tool": "nmap-vuln", "result": vuln_result.parsed})
        for port in vuln_result.parsed.get("open_ports", []):
            for script in port.get("scripts", []):
                script_id = script["id"]
                port_num = port["port"]
                service = port.get("service", "unknown")
                output = script.get("output") or ""
                output_lower = output.lower()

                if _NMAP_VULN_ERROR_MARKER in output_lower:
                    self.log_error(
                        state,
                        f"Script nmap {script_id} sur le port {port_num} a echoue a l'execution "
                        "(pas une constatation, pas de preuve collectee).",
                    )
                    continue

                if _NMAP_VULN_STATE_MARKER in output_lower:
                    # vulns.lua-based script: the State: line is ground
                    # truth. NOT VULNERABLE / UNKNOWN fall through both
                    # checks below and are silently not a Finding.
                    if _NMAP_VULN_STATE_LIKELY in output_lower:
                        state.add_lead(
                            Lead(
                                title=f"Script nmap {script_id} possiblement positif sur le port {port_num}",
                                rationale=(
                                    "nmap rapporte un etat LIKELY VULNERABLE (heuristique, non confirme) "
                                    f"pour {script_id} : {output[:300]}"
                                ),
                                source=self.name,
                                confidence=0.5,
                                tags=["nmap-vuln-likely"],
                            )
                        )
                    elif _NMAP_VULN_STATE_POSITIVE in output_lower:
                        state.add_finding(_make_vuln_finding(script_id, port_num, service, output))
                    continue

                # No "State:" line: not a vulns.lua script - fall back to
                # the one negative phrasing observed for this category.
                if _NMAP_VULN_NEGATIVE_MARKER in output_lower:
                    continue
                state.add_finding(_make_vuln_finding(script_id, port_num, service, output))

        llm_summary = await self.ask_llm(
            system_prompt=(
                "Tu es un assistant de reconnaissance reseau en test d'intrusion autorise. "
                "Tu resumes les resultats bruts d'outils, tu ne decides jamais d'une severite. "
                "La prochaine phase normale est enum : tu n'as pas besoin de le repeter. "
                "Tu peux seulement suggerer de clore la mission plus tot en repondant "
                "next_phase_suggestion: report, si et seulement si tu juges qu'aucune suite "
                "n'apportera rien (l'orchestrateur reste seul juge final et peut l'ignorer). "
                'Reponds uniquement en JSON: {"summary": str, "suggested_leads": [str, ...], '
                '"next_phase_suggestion": str}.'
            ),
            user_prompt=f"Ports ouverts: {open_ports}. OS detecte: {os_guess} (confiance {os_confidence}).",
        )
        for suggestion in llm_summary.get("suggested_leads") or []:
            state.add_lead(
                Lead(
                    title=str(suggestion)[:200],
                    rationale="Suggestion du LLM a partir des resultats de reconnaissance.",
                    source=self.name,
                    confidence=0.3,
                    tags=["llm-suggestion"],
                )
            )
        state.last_decision = llm_summary.get("next_phase_suggestion")

        summary = llm_summary.get("summary") or (
            f"{len(open_ports)} port(s) ouvert(s) detecte(s)." if open_ports
            else "Aucun port ouvert detecte."
        )

        state.completed_phases.append(self.name)
        state.attack_chain.append({"phase": self.name, "summary": summary})
        return state
