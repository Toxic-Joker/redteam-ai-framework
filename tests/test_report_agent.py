"""Priorite : le rendu Jinja du rapport doit reussir de bout en bout - une

erreur de template (typo, cle manquante) ne se voit qu'a l'execution, jamais
a la lecture du fichier.
"""
from types import SimpleNamespace

import pytest

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agents.report_agent import TEMPLATES_DIR, ReportAgent
from core.state import Finding, Lead, MissionState, Severity, Target


def _make_report_agent() -> ReportAgent:
    agent = ReportAgent.__new__(ReportAgent)  # bypass __init__ : pas de connexion LLM reelle
    agent.name = "report"
    agent._env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=select_autoescape(["html"]))
    return agent


def test_group_by_severity_buckets_every_severity_including_empty():
    findings = [
        Finding("a", Severity.LOW, "", "c", "e", "enum"),
        Finding("b", Severity.LOW, "", "c2", "e", "enum"),
    ]
    groups = ReportAgent._group_by_severity(findings)
    assert set(groups.keys()) == {"critical", "high", "medium", "low", "info"}
    assert len(groups["low"]) == 2
    assert groups["critical"] == []


def test_fallback_immediate_actions_prefers_highest_populated_severity():
    findings = [
        Finding("a", Severity.MEDIUM, "", "c", "e", "enum", remediation="fix medium"),
        Finding(
            "b", Severity.CRITICAL, "", "c", "e", "exploit", exploited=True, remediation="fix critical"
        ),
    ]
    actions = ReportAgent._fallback_immediate_actions(findings)
    assert actions == ["fix critical"]


def test_fallback_immediate_actions_empty_when_nothing_has_remediation():
    findings = [Finding("a", Severity.LOW, "", "c", "e", "enum")]
    assert ReportAgent._fallback_immediate_actions(findings) == []


def test_fallback_executive_summary_mentions_host_and_risk():
    mission = MissionState(
        mission_id="m1", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )
    mission.add_finding(Finding("a", Severity.LOW, "", "c", "e", "enum"))
    summary = ReportAgent._fallback_executive_summary(mission, Severity.LOW)
    assert "10.0.0.1" in summary
    assert "LOW" in summary


@pytest.mark.asyncio
async def test_report_renders_without_template_errors(tmp_path, monkeypatch):
    agent = _make_report_agent()

    async def fake_ask_llm(*args, **kwargs):
        return {}  # force le chemin de repli deterministe

    agent.ask_llm = fake_ask_llm
    agent.log_error = lambda state, message: state.errors.append({"agent": "report", "message": message})

    monkeypatch.setattr("agents.report_agent.get_settings", lambda: SimpleNamespace(reports_dir=str(tmp_path)))

    mission = MissionState(
        mission_id="m2", mission_name="Rapport de test", operator="op", authorization_ref="AUTH-1",
        target=Target(host="10.0.0.1"),
    )
    mission.target.ports = [80]
    mission.target.os_guess = "Linux 5.x"
    mission.add_finding(
        Finding(
            "Injection SQL confirmee", Severity.CRITICAL, "desc", "http://10.0.0.1/?id=1", "evidence",
            "exploit", exploited=True, remediation="Utiliser des requetes parametrees.", tags=["sqli"],
        )
    )
    mission.add_lead(Lead(title="Verifier X", rationale="raison", source="recon", confidence=0.4))
    mission.attack_chain.append({"phase": "recon", "summary": "ok"})
    mission.attack_chain.append({"phase": "exploit", "action": "sqlmap", "target": "http://10.0.0.1/?id=1", "result": "exploited"})
    mission.completed_phases = ["recon", "enum", "exploit", "postexploit"]

    result = await agent.run(mission)

    assert result.status == "completed"
    assert result.report_path is not None
    assert (tmp_path / f"{mission.mission_id}.html").exists()
    html = (tmp_path / f"{mission.mission_id}.html").read_text(encoding="utf-8")
    assert "Rapport de test" in html
    assert "CRITICAL" in html
    assert "Utiliser des requetes parametrees" in html
