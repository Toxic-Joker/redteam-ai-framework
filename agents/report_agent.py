"""Rapport final : le risque global est calcule, jamais demande au LLM.

Le LLM ne redige que le resume executif, les "risques principaux" et les
"actions immediates" (trois champs de texte libre) ; le badge de risque, le
regroupement des findings par severite et la liste des recommandations par
finding (state.remediation) viennent exclusivement du coeur deterministe,
avec un repli deterministe si le LLM ne repond rien d'exploitable.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.config import get_settings
from core.state import Finding, MissionState, Severity, compute_overall_risk

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
        findings_by_severity = self._group_by_severity(state.findings)

        llm_summary = await self.ask_llm(
            system_prompt=(
                "Tu es un assistant de redaction de rapport de test d'intrusion autorise, "
                "pour un public RSSI/direction technique. Tu rediges en francais un resume "
                "executif (3 a 5 phrases), une liste courte de risques principaux (titres), "
                "et une liste d'actions immediates prioritaires. Tu ne mentionnes jamais une "
                "severite differente de celle fournie : ce sont des faits deja etablis, pas "
                "des hypotheses a reformuler. "
                'Reponds uniquement en JSON: {"executive_summary": str, "key_risks": '
                '[str, ...], "immediate_actions": [str, ...]}.'
            ),
            user_prompt=(
                f"Risque global (calcule, non modifiable): {overall_risk.name}. "
                f"Findings: {[(f.title, f.severity.name, f.remediation) for f in state.findings]}. "
                f"Pistes non confirmees: {[l.title for l in state.leads]}."
            ),
        )
        executive_summary = llm_summary.get("executive_summary") or self._fallback_executive_summary(
            state, overall_risk
        )
        key_risks = llm_summary.get("key_risks") or [
            f.title for f in state.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ][:5]
        immediate_actions = llm_summary.get("immediate_actions") or self._fallback_immediate_actions(state.findings)

        created_at = datetime.fromisoformat(state.created_at)
        updated_at = datetime.fromisoformat(state.updated_at)
        duration_seconds = max(0.0, (updated_at - created_at).total_seconds())
        duration = f"{int(duration_seconds // 60)}m {int(duration_seconds % 60)}s"

        os.makedirs(settings.reports_dir, exist_ok=True)
        template = self._env.get_template("report.html")
        html_content = template.render(
            mission=state,
            overall_risk=overall_risk.name,
            findings_by_severity=findings_by_severity,
            executive_summary=executive_summary,
            key_risks=key_risks,
            immediate_actions=immediate_actions,
            created_at_display=created_at.strftime("%d/%m/%Y %H:%M UTC"),
            duration=duration,
            generated_at=datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC"),
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

    @staticmethod
    def _group_by_severity(findings: list[Finding]) -> dict[str, list[Finding]]:
        groups: dict[str, list[Finding]] = {s.name.lower(): [] for s in Severity}
        for finding in findings:
            groups[finding.severity.name.lower()].append(finding)
        return groups

    @staticmethod
    def _fallback_immediate_actions(findings: list[Finding]) -> list[str]:
        # Repli deterministe : les recommandations de la severite confirmee
        # la plus haute presente, jamais une opinion du LLM.
        for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            texts = [f.remediation for f in findings if f.severity == severity and f.remediation]
            if texts:
                return texts[:5]
        return []

    @staticmethod
    def _fallback_executive_summary(state: MissionState, overall_risk: Severity) -> str:
        counts = {s.name: 0 for s in Severity}
        for finding in state.findings:
            counts[finding.severity.name] += 1
        return (
            f"Le test d'intrusion mene sur {state.target.host} a identifie {len(state.findings)} "
            f"constatation(s) confirmee(s), pour un risque global {overall_risk.name}. "
            f"Repartition : {counts['CRITICAL']} CRITICAL, {counts['HIGH']} HIGH, "
            f"{counts['MEDIUM']} MEDIUM, {counts['LOW']} LOW, {counts['INFO']} INFO. "
            "(Resume genere automatiquement : le modele local n'a pas produit de texte exploitable.)"
        )
