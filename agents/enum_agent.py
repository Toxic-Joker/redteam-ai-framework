"""Web enumeration: gobuster + ffuf + nikto + nuclei on the HTTP(S) ports

found, plus a crawler for pages with parameters. Systematically
consolidates 401/403s (MVP validation criterion: 22 paths returning
401/403 produce a single LOW finding, never 22).
"""
from __future__ import annotations

import asyncio

from core.state import Finding, Lead, MissionState, Severity, consolidate_denied_paths
from tools.crawler_tool import CrawlerTool
from tools.ffuf_tool import FfufTool
from tools.gobuster_tool import GobusterTool
from tools.nikto_tool import NiktoTool
from tools.nuclei_tool import NucleiTool

from .base_agent import BaseAgent

HTTP_SERVICE_HINTS = ("http", "www", "ssl/http")

# nuclei detects patterns, it never confirms exploitation: even a
# "critical" match is capped to MEDIUM by Finding.__post_init__
# (core/state.py), the sole point where cap_severity applies - never an
# explicit call here, so the transparency note correctly compares the
# severity nuclei actually reported against the final one.
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

        # Accessible paths discovered this phase, shared via state.scratch
        # so the exploit agent doesn't need to re-derive this information
        # from the flat tool_results list.
        candidate_urls: list[str] = []
        post_forms: list[dict] = []
        base_urls: list[str] = []
        cookie = state.target.session_cookie

        for port, is_ssl in self._http_ports(state):
            scheme = "https" if is_ssl else "http"
            base_url = f"{scheme}://{host}:{port}"
            base_urls.append(base_url)

            # The 5 tools in this phase are independent of one another
            # (none consumes another's output): running them concurrently
            # rather than sequentially is the main mission-time reduction
            # possible without losing coverage (see docs/HISTORY.md,
            # section 18). asyncio.gather() preserves result order based
            # on the awaitables' order, not completion order - the
            # processing below stays deterministic.
            gob_result, ffuf_result, nikto_result, crawl_result, nuclei_result = await asyncio.gather(
                self.gobuster.run(target=base_url, cookie=cookie),
                self.ffuf.run(target=base_url, cookie=cookie),
                self.nikto.run(target=host, port=port, ssl=is_ssl, cookie=cookie),
                self.crawler.crawl(base_url, cookie=cookie),
                self.nuclei.run(target=base_url, cookie=cookie),
            )
            state.tool_results.append({"agent": self.name, "tool": "gobuster", "result": gob_result.parsed})
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

            # A crawler finds real pages with parameters (e.g.
            # /vulnerabilities/sqli/?id=1 after login) that no wordlist
            # will ever guess - gobuster/ffuf only know path segments,
            # never the parameters a page actually expects. GET forms are
            # synthesized into a URL with parameters (reusing the same
            # pipeline); POST forms are kept separately for sqlmap --data.
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

            # Broad coverage of known patterns (default credentials,
            # exposed panels, common CVEs) via community templates - a
            # complement to the targeted tools, not a replacement for
            # sqlmap.
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

        phase_findings = [f for f in state.findings if f.discovered_by == self.name]
        summary = llm_summary.get("summary") or (
            f"{len(phase_findings)} finding(s) collecte(s) lors de l'enumeration." if phase_findings
            else "Aucun finding notable collecte lors de l'enumeration."
        )

        state.completed_phases.append(self.name)
        state.attack_chain.append({"phase": self.name, "summary": summary})
        return state
