"""Reconnaissance : nmap decouverte/ports/vuln. Applique cap_severity sur

chaque finding, sans exception (incident #10 : c'est precisement l'agent qui
avait ete oublie dans la v1).
"""
from __future__ import annotations

from core.state import Finding, Lead, MissionState, Severity, cap_severity
from tools.nmap_tool import NmapTool

from .base_agent import BaseAgent

# Un guess -O en dessous de ce seuil de confiance ne doit jamais apparaitre
# comme un fait dans le rapport (voir CLAUDE.md, section 2 et docs/HISTORY.md,
# section 3 : nmap -O a produit des resultats absurdes a haute confiance
# affichee sur des cibles a port unique).
OS_CONFIDENCE_THRESHOLD = 0.85


class ReconAgent(BaseAgent):
    name = "recon"

    def __init__(self) -> None:
        super().__init__()
        self.nmap = NmapTool()

    async def run(self, state: MissionState) -> MissionState:
        state.current_agent = self.name
        host = state.target.host

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
                severity = cap_severity(Severity.MEDIUM, exploited=False)
                state.add_finding(
                    Finding(
                        title=f"Script nmap {script['id']} positif sur le port {port['port']}",
                        severity=severity,
                        description=(script.get("output") or "")[:500],
                        affected_component=f"{host}:{port['port']} ({port.get('service', 'unknown')})",
                        evidence=script.get("output", ""),
                        discovered_by=self.name,
                        exploited=False,
                        tags=["nmap-vuln"],
                    )
                )

        llm_summary = await self.ask_llm(
            system_prompt=(
                "Tu es un assistant de reconnaissance reseau en test d'intrusion autorise. "
                "Tu resumes les resultats bruts d'outils, tu ne decides jamais d'une severite. "
                'Reponds uniquement en JSON: {"summary": str, "suggested_leads": [str, ...]}.'
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

        state.completed_phases.append(self.name)
        state.attack_chain.append({"phase": self.name, "summary": llm_summary.get("summary", "")})
        return state
