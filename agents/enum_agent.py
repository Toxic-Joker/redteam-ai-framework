"""Enumeration web : gobuster + ffuf + nikto + nuclei sur les ports HTTP(S)

trouves, plus un crawler pour les pages avec parametres. Consolide
systematiquement les 401/403 (critere de validation MVP : 22 chemins en
401/403 produisent un seul finding LOW, jamais 22).
"""
from __future__ import annotations

from core.state import Finding, Lead, MissionState, Severity, consolidate_denied_paths
from tools.crawler_tool import CrawlerTool
from tools.ffuf_tool import FfufTool
from tools.gobuster_tool import GobusterTool
from tools.nikto_tool import NiktoTool
from tools.nuclei_tool import NucleiTool

from .base_agent import BaseAgent

HTTP_SERVICE_HINTS = ("http", "www", "ssl/http")

# nuclei detecte des motifs, il ne confirme jamais une exploitation : meme un
# match "critical" est plafonne a MEDIUM par Finding.__post_init__
# (core/state.py), seul point d'application de cap_severity - jamais un
# appel explicite ici, pour que la note de transparence compare la severite
# reellement rapportee par nuclei a la severite finale.
NUCLEI_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class EnumAgent(BaseAgent):
    name = "enum"

    def __init__(self) -> None:
        super().__init__()
        self.gobuster = GobusterTool()
        self.nikto = NiktoTool()
        self.ffuf = FfufTool()
        self.crawler = CrawlerTool()
        self.nuclei = NucleiTool()

    def _http_ports(self, state: MissionState) -> list[tuple[int, bool]]:
        ports = []
        for port, service in state.target.services.items():
            svc = (service or "").lower()
            if any(hint in svc for hint in HTTP_SERVICE_HINTS):
                ports.append((port, "ssl" in svc or port == 443))
        return ports

    async def run(self, state: MissionState) -> MissionState:
        state.current_agent = self.name
        host = state.target.host

        # Chemins accessibles decouverts cette phase, partages via
        # state.scratch pour que l'agent d'exploitation n'ait pas besoin de
        # re-deriver cette information depuis la liste plate tool_results.
        candidate_urls: list[str] = []
        post_forms: list[dict] = []
        base_urls: list[str] = []
        cookie = state.target.session_cookie

        for port, is_ssl in self._http_ports(state):
            scheme = "https" if is_ssl else "http"
            base_url = f"{scheme}://{host}:{port}"
            base_urls.append(base_url)

            gob_result = await self.gobuster.run(target=base_url, cookie=cookie)
            state.tool_results.append({"agent": self.name, "tool": "gobuster", "result": gob_result.parsed})

            ffuf_result = await self.ffuf.run(target=base_url, cookie=cookie)
            state.tool_results.append({"agent": self.name, "tool": "ffuf", "result": ffuf_result.parsed})

            all_paths = gob_result.parsed.get("paths", []) + ffuf_result.parsed.get("paths", [])

            denied_finding = consolidate_denied_paths(all_paths, discovered_by=self.name)
            if denied_finding:
                state.add_finding(denied_finding)

            accessible = [p for p in all_paths if p.get("status_code") == 200]
            candidate_urls.extend(f"{base_url}{p['path']}" for p in accessible)
            if accessible:
                state.add_finding(
                    Finding(
                        title=f"Chemins accessibles decouverts sur {base_url}",
                        severity=Severity.LOW,
                        description=f"{len(accessible)} chemin(s) accessibles (200) decouverts par enumeration.",
                        affected_component=base_url,
                        evidence=", ".join(sorted(p["path"] for p in accessible)),
                        discovered_by=self.name,
                        remediation=(
                            "Verifier que chaque chemin expose est intentionnel. Retirer ou "
                            "restreindre l'acces aux ressources qui ne sont pas destinees a etre "
                            "publiques (interfaces d'administration, fichiers de configuration, "
                            "sauvegardes)."
                        ),
                        tags=["enumeration"],
                    )
                )

            nikto_result = await self.nikto.run(target=host, port=port, ssl=is_ssl, cookie=cookie)
            state.tool_results.append({"agent": self.name, "tool": "nikto", "result": nikto_result.parsed})
            items = nikto_result.parsed.get("items", [])
            if items:
                state.add_finding(
                    Finding(
                        title=f"Constatations Nikto sur {base_url}",
                        severity=Severity.MEDIUM,
                        description="Nikto a signale des elements de configuration ou d'exposition a verifier.",
                        affected_component=base_url,
                        evidence="\n".join(items[:50]),
                        discovered_by=self.name,
                        remediation=(
                            "Examiner individuellement chaque element signale par Nikto (bannieres "
                            "de version, fichiers exposes, en-tetes manquants) et appliquer les "
                            "correctifs ou durcissements recommandes par l'editeur du service "
                            "concerne."
                        ),
                        tags=["nikto"],
                    )
                )

            # Un crawler trouve de vraies pages avec parametres (ex.
            # /vulnerabilities/sqli/?id=1 apres connexion) qu'aucune
            # wordlist ne devinera jamais - gobuster/ffuf ne connaissent que
            # des segments de chemin, jamais les parametres qu'une page
            # attend reellement. Les formulaires GET sont synthetises en
            # URL avec parametres (reutilisent le meme pipeline) ; les
            # formulaires POST sont gardes a part pour sqlmap --data.
            crawl_result = await self.crawler.crawl(base_url, cookie=cookie)
            state.tool_results.append(
                {
                    "agent": self.name,
                    "tool": "crawler",
                    "result": {
                        "pages_visited": len(crawl_result.visited),
                        "urls_with_params": crawl_result.urls_with_params,
                        "post_forms": crawl_result.post_forms,
                    },
                }
            )
            candidate_urls.extend(crawl_result.urls_with_params)
            post_forms.extend(crawl_result.post_forms)

            # Couverture large de motifs connus (identifiants par defaut,
            # panels exposes, CVE courantes) via des templates communautaires
            # - complement aux outils cibles, pas un remplacement de sqlmap.
            nuclei_result = await self.nuclei.run(target=base_url, cookie=cookie)
            state.tool_results.append({"agent": self.name, "tool": "nuclei", "result": nuclei_result.parsed})
            for match in nuclei_result.parsed.get("matches", []):
                severity = NUCLEI_SEVERITY_MAP.get(match.get("severity", "info"), Severity.INFO)
                state.add_finding(
                    Finding(
                        title=match.get("name") or match.get("template_id") or "Correspondance nuclei",
                        severity=severity,
                        description=match.get("description") or "Correspondance de template nuclei.",
                        affected_component=match.get("matched_at") or base_url,
                        evidence=match.get("curl_command", ""),
                        discovered_by=self.name,
                        remediation=(
                            f"Consulter la documentation du template nuclei "
                            f"'{match.get('template_id')}' et appliquer le correctif ou "
                            "durcissement recommande."
                        ),
                        tags=["nuclei", match.get("template_id") or ""],
                    )
                )

        llm_summary = await self.ask_llm(
            system_prompt=(
                "Tu es un assistant d'enumeration web en test d'intrusion autorise. "
                "Tu proposes des pistes a explorer, tu ne decides jamais d'une severite. "
                "La prochaine phase normale est exploit : tu n'as pas besoin de le repeter. "
                "Tu peux seulement suggerer de clore la mission plus tot en repondant "
                "next_phase_suggestion: report, si et seulement si tu juges qu'aucune suite "
                "n'apportera rien (l'orchestrateur reste seul juge final et peut l'ignorer). "
                'Reponds uniquement en JSON: {"summary": str, "suggested_leads": [str, ...], '
                '"next_phase_suggestion": str}.'
            ),
            user_prompt=f"Findings collectes cette phase: {[f.title for f in state.findings]}",
        )
        for suggestion in llm_summary.get("suggested_leads") or []:
            state.add_lead(
                Lead(
                    title=str(suggestion)[:200],
                    rationale="Suggestion du LLM a partir de l'enumeration.",
                    source=self.name,
                    confidence=0.3,
                    tags=["llm-suggestion"],
                )
            )
        state.last_decision = llm_summary.get("next_phase_suggestion")

        state.scratch["enum"] = {"candidate_urls": candidate_urls, "base_urls": base_urls, "post_forms": post_forms}

        state.completed_phases.append(self.name)
        state.attack_chain.append({"phase": self.name, "summary": llm_summary.get("summary", "")})
        return state
