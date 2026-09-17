"""Regression directe de l'incident lie a nmap -O (docs/HISTORY.md, section 3) :

un guess d'OS a faible confiance ne doit jamais apparaitre comme un fait sur
Target, seulement comme une Lead. L'agent est teste sans connexion LLM ni
outil reel (BaseAgent.__init__ est court-circuite).
"""
import pytest

from agents.recon_agent import ReconAgent
from core.state import MissionState, Target
from tools.base import ToolResult


class _StubNmapTool:
    def __init__(self, responses: dict[str, ToolResult]) -> None:
        self._responses = responses

    async def run(self, target: str, mode: str, **kwargs) -> ToolResult:
        return self._responses[mode]


def _make_recon_agent(nmap_responses: dict[str, ToolResult]) -> ReconAgent:
    agent = ReconAgent.__new__(ReconAgent)  # bypass __init__ : pas de connexion LLM reelle
    agent.name = "recon"

    async def fake_ask_llm(*args, **kwargs):
        return {"summary": "", "suggested_leads": []}

    agent.ask_llm = fake_ask_llm
    agent.nmap = _StubNmapTool(nmap_responses)
    return agent


def _empty_nmap_result() -> ToolResult:
    return ToolResult(
        tool="nmap",
        command=[],
        returncode=0,
        stdout="",
        stderr="",
        success=True,
        parsed={"open_ports": [], "os_guess": None, "os_confidence": None, "host_up": True},
    )


@pytest.mark.asyncio
async def test_low_confidence_os_guess_becomes_a_lead_not_a_fact():
    ports = _empty_nmap_result()
    ports.parsed["os_guess"] = "Linux 2.6"
    ports.parsed["os_confidence"] = 0.42

    agent = _make_recon_agent({"discovery": _empty_nmap_result(), "ports": ports, "vuln": _empty_nmap_result()})
    mission = MissionState(
        mission_id="m1", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )

    result = await agent.run(mission)

    assert result.target.os_guess is None
    assert any("os-guess" in lead.tags for lead in result.leads)


@pytest.mark.asyncio
async def test_high_confidence_os_guess_is_recorded_as_target_fact():
    ports = _empty_nmap_result()
    ports.parsed["os_guess"] = "Linux 5.x"
    ports.parsed["os_confidence"] = 0.95

    agent = _make_recon_agent({"discovery": _empty_nmap_result(), "ports": ports, "vuln": _empty_nmap_result()})
    mission = MissionState(
        mission_id="m2", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )

    result = await agent.run(mission)

    assert result.target.os_guess == "Linux 5.x"
    assert result.target.os_confidence == 0.95
    assert not any("os-guess" in lead.tags for lead in result.leads)
