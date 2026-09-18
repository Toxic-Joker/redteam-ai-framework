"""Reconnaissance : nmap decouverte/ports/vuln.

Ne plafonne jamais explicitement une severite ici : Finding.__post_init__
(core/state.py) est l'unique point d'application de cap_severity, pour que
la note de transparence compare bien la severite reellement voulue par
l'agent a la severite finale (incident #10 : c'est precisement l'agent qui
avait ete oublie dans la v1 quand le plafonnement dependait de la
discipline de chaque agent plutot que d'une garantie structurelle).
"""
from __future__ import annotations

import asyncio
import ipaddress

import dns.resolver
import dns.reversename

from core.state import Finding, Lead, MissionState, Severity
from tools.nmap_tool import NmapTool

from .base_agent import BaseAgent

# Un guess -O en dessous de ce seuil de confiance ne doit jamais apparaitre
# comme un fait dans le rapport (voir CLAUDE.md, section 2 et docs/HISTORY.md,
# section 3 : nmap -O a produit des resultats absurdes a haute confiance
# affichee sur des cibles a port unique).
OS_CONFIDENCE_THRESHOLD = 0.85


def _dns_recon(host: str) -> list[str]:
    """Enumeration DNS best-effort : reverse (PTR) si la cible est une IP,

    sinon A/MX/NS si c'est un nom d'hote. Toujours purement informatif
    (jamais un Finding, jamais un facteur de severite/risque) et jamais
    bloquant : une resolution DNS absente ou en echec sur la cible ne doit
    jamais faire echouer la mission.
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
                except Exception:  # noqa: BLE001 - un type d'enregistrement absent n'est pas une erreur
                    continue
    except Exception:  # noqa: BLE001 - la recon DNS ne doit jamais interrompre la mission
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

        # dnspython est synchrone/bloquant : jamais appele directement dans
        # une coroutine sous peine de geler toute la boucle asyncio (et donc
        # l'API/le dashboard entiers) pendant le delai de resolution.
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

        vuln_result = await self.nmap.run(target=host, mode="vuln")
        state.tool_results.append({"agent": self.name, "tool": "nmap-vuln", "result": vuln_result.parsed})
        for port in vuln_result.parsed.get("open_ports", []):
            for script in port.get("scripts", []):
                state.add_finding(
                    Finding(
                        title=f"Script nmap {script['id']} positif sur le port {port['port']}",
                        severity=Severity.MEDIUM,
                        description=(script.get("output") or "")[:500],
                        affected_component=f"{host}:{port['port']} ({port.get('service', 'unknown')})",
                        evidence=script.get("output", ""),
                        discovered_by=self.name,
                        exploited=False,
                        remediation=(
                            f"Examiner le resultat du script nmap {script['id']} et appliquer le "
                            "correctif ou le durcissement de configuration recommande par l'editeur "
                            "du service concerne. Desactiver ce service s'il n'est pas necessaire."
                        ),
                        tags=["nmap-vuln"],
                    )
                )

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
