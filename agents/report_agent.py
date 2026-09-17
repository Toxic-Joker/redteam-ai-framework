"""Rapport final : le risque global est calcule, jamais demande au LLM.

Le LLM ne redige que le resume executif ; le badge de risque, la liste des
findings et leurs severites viennent exclusivement du coeur deterministe.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.config import get_settings
from core.state import MissionState, compute_overall_risk

from .base_agent import BaseAgent

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")


class ReportAgent(BaseAgent):
    name = "report"

    def __init__(self) -> None:
        super().__init__()
        self._env = Environment(
            loader=FileSystemLoader(TEMPLATES_DIR),
            autoescape=select_autoescape(["html"]),
        )

    async def run(self, state: MissionState) -> MissionState:
        state.current_agent = self.name
        settings = get_settings()

        overall_risk = compute_overall_risk(state.findings)  # jamais demande au LLM

        llm_summary = await self.ask_llm(
            system_prompt=(
                "Tu es un assistant de redaction de rapport de test d'intrusion autorise. "
                "Tu rediges un resume executif en francais a partir des findings fournis. "
                "Tu ne mentionnes jamais une severite differente de celle fournie. "
                'Reponds uniquement en JSON: {"executive_summary": str}.'
            ),
            user_prompt=(
                f"Risque global (calcule, non modifiable): {overall_risk.name}. "
                f"Findings: {[(f.title, f.severity.name) for f in state.findings]}. "
                f"Pistes non confirmees: {[l.title for l in state.leads]}."
            ),
        )
        executive_summary = llm_summary.get(
            "executive_summary",
            "Resume executif indisponible (le modele local n'a pas produit de reponse exploitable).",
        )

        os.makedirs(settings.reports_dir, exist_ok=True)
        template = self._env.get_template("report.html")
        html_content = template.render(
            mission=state,
            overall_risk=overall_risk.name,
            executive_summary=executive_summary,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

        html_path = os.path.join(settings.reports_dir, f"{state.mission_id}.html")
        pdf_path = os.path.join(settings.reports_dir, f"{state.mission_id}.pdf")
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)

        try:
            # Import differe : WeasyPrint exige des bibliotheques natives
            # (Pango/Cairo/GObject) presentes dans l'image Docker mais pas
            # forcement sur toute machine de developpement. Un echec ici ne
            # doit jamais empecher la construction du graphe d'orchestration
            # ni degrader le reste de la mission : le rapport HTML suffit.
            from weasyprint import HTML

            HTML(string=html_content, base_url=settings.reports_dir).write_pdf(pdf_path)
            state.report_path = pdf_path
        except Exception as exc:  # noqa: BLE001 - le rapport HTML reste disponible meme si le PDF echoue
            self.log_error(state, f"Echec generation PDF: {exc}")
            state.report_path = html_path

        state.completed_phases.append(self.name)
        state.attack_chain.append({"phase": self.name, "summary": "Rapport genere."})
        state.status = "completed"
        return state
