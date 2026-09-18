"""Coeur deterministe du framework.

Toute decision engageante (severite, risque global, consolidation des
findings, progression de l'orchestrateur) vit ici, jamais dans un agent ni
dans une reponse de modele de langage. Voir PROJECT.md, principe directeur.
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


def cap_severity(severity: Severity, exploited: bool) -> Severity:
    """Sans preuve d'exploitation, une decouverte ne depasse jamais MEDIUM.

    HIGH/CRITICAL exige exploited=True. Voir docs/HISTORY.md, incident #10 :
    un CRITICAL hallucine a traverse tout le pipeline faute d'un plafonnement
    applique systematiquement. Cette fonction est la seule source de verite ;
    elle ne doit jamais etre reimplementee localement dans un agent.
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
        # Garde-fou structurel : meme si un agent oublie d'appeler
        # cap_severity avant de construire ce Finding, la severite ne peut
        # jamais depasser MEDIUM sans exploited=True. Defense en profondeur
        # au-dela de la discipline attendue des agents (incident #10 : un
        # agent non couvert par le plafonnement a laisse passer un CRITICAL
        # hallucine jusqu'au rapport final).
        requested_severity = self.severity
        self.severity = cap_severity(self.severity, self.exploited)
        if self.severity != requested_severity:
            # Note visible dans le rapport plutot qu'un plafonnement silencieux :
            # un lecteur doit pouvoir voir qu'une severite plus haute a ete
            # proposee (par un outil ou le LLM) et ramenee ici faute de preuve
            # d'exploitation, plutot que de le deviner.
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
    """Piste speculative. Pas de champ severity : une piste n'est pas notee."""

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

    # Contexte de travail partage entre phases, cle par nom d'agent (ex.
    # scratch["enum"] = {"candidate_urls": [...]}). Purement informatif : un
    # agent en aval peut le lire pour eviter de re-deriver ce qu'une phase
    # precedente a deja etabli, mais aucune decision critique (severite,
    # risque) ne doit jamais se fonder dessus - seuls findings/leads comptent.
    scratch: dict[str, dict] = field(default_factory=dict)

    report_path: Optional[str] = None

    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def add_finding(self, finding: Finding) -> None:
        # Append-only : un finding confirme n'est jamais retire ni modifie
        # apres coup, seulement consolide au moment de sa creation.
        self.findings.append(finding)
        self.updated_at = _now()

    def add_lead(self, lead: Lead) -> None:
        self.leads.append(lead)
        self.updated_at = _now()


def compute_overall_risk(findings: list[Finding]) -> Severity:
    """Jamais demande au LLM. Severite maximale parmi les findings confirmes.

    Les leads n'entrent jamais dans ce calcul (voir PROJECT.md).
    """
    if not findings:
        return Severity.INFO
    return max(f.severity for f in findings)


def consolidate_denied_paths(candidate_paths: list[dict], discovered_by: str) -> Optional[Finding]:
    """Regroupe tous les chemins en 401/403 en un seul finding LOW.

    Evite qu'un scan avec, par exemple, 22 chemins proteges ne produise 22
    findings quasi identiques (bruit dans le rapport, faux positifs percus).
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
        tags=["consolidated", "access-denied"],
    )


def enforce_progression(state: MissionState, proposed_next_phase: str, max_cycles: int = 10) -> str:
    """Garde-fou anti-boucle de l'orchestrateur.

    - incremente orchestration_cycles a chaque decision
    - au-dela de max_cycles : force "report" (une seule fois) puis "end"
    - une phase deja terminee (hors "report") est redirigee vers la premiere
      phase non terminee de l'ordre lineaire
    - toute tentative de terminer sans etre passe par "report" force "report"
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

    return proposed_next_phase


def is_target_in_allowed_ranges(host: str, allowed_ranges: list[str]) -> bool:
    """Garde-fou de perimetre optionnel (desactive si allowed_ranges est vide).

    Desactive par defaut : le MVP doit fonctionner contre une cible externe
    quelconque (voir PROJECT.md), donc restreindre par defaut a des plages
    privees contredirait cet objectif. Un operateur peut l'activer via
    ALLOWED_TARGET_RANGES pour verrouiller ses propres missions a un
    laboratoire connu. Ferme (retourne False) si la resolution DNS d'un nom
    d'hote echoue alors que la restriction est active : on ne devine jamais
    la portee d'une cible qu'on ne sait pas resoudre.
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
