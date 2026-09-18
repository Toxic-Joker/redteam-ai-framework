"""Regression directe de l'incident lie a nmap -O (docs/HISTORY.md, section 3) :

un guess d'OS a faible confiance ne doit jamais apparaitre comme un fait sur
Target, seulement comme une Lead. L'agent est teste sans connexion LLM ni
outil reel (BaseAgent.__init__ est court-circuite).
"""
import pytest

import agents.recon_agent as recon_agent_module
from agents.enum_agent import EnumAgent
from agents.exploit_agent import ExploitAgent
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
async def test_low_confidence_os_guess_becomes_a_lead_not_a_fact(monkeypatch):
    monkeypatch.setattr(recon_agent_module, "_dns_recon", lambda host: [])
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
async def test_high_confidence_os_guess_is_recorded_as_target_fact(monkeypatch):
    monkeypatch.setattr(recon_agent_module, "_dns_recon", lambda host: [])
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


@pytest.mark.asyncio
async def test_dns_records_become_a_lead_never_a_finding(monkeypatch):
    monkeypatch.setattr(recon_agent_module, "_dns_recon", lambda host: ["PTR: mail.example.com."])
    agent = _make_recon_agent(
        {"discovery": _empty_nmap_result(), "ports": _empty_nmap_result(), "vuln": _empty_nmap_result()}
    )
    mission = MissionState(
        mission_id="m3", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )

    result = await agent.run(mission)

    dns_leads = [lead for lead in result.leads if "dns" in lead.tags]
    assert len(dns_leads) == 1
    assert "mail.example.com" in dns_leads[0].rationale
    assert result.findings == []


class _StubEnumTool:
    def __init__(self, parsed: dict) -> None:
        self._parsed = parsed

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(tool="stub", command=[], returncode=0, stdout="", stderr="", success=True, parsed=self._parsed)


@pytest.mark.asyncio
async def test_enum_agent_populates_scratch_with_query_bearing_urls():
    agent = EnumAgent.__new__(EnumAgent)
    agent.name = "enum"

    async def fake_ask_llm(*args, **kwargs):
        return {"summary": "", "suggested_leads": []}

    agent.ask_llm = fake_ask_llm
    agent.gobuster = _StubEnumTool({"paths": [{"path": "/search?q=1", "status_code": 200}]})
    agent.ffuf = _StubEnumTool({"paths": []})
    agent.nikto = _StubEnumTool({"items": []})

    mission = MissionState(
        mission_id="m4", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )
    mission.target.services = {80: "http"}

    result = await agent.run(mission)

    assert result.scratch["enum"]["candidate_urls"] == ["http://10.0.0.1:80/search?q=1"]
    assert result.scratch["enum"]["base_urls"] == ["http://10.0.0.1:80"]


def test_exploit_agent_prefers_scratch_urls_over_tool_results():
    agent = ExploitAgent.__new__(ExploitAgent)
    mission = MissionState(
        mission_id="m5", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )
    mission.scratch["enum"] = {"candidate_urls": ["http://10.0.0.1:80/search?q=1"], "base_urls": []}
    mission.tool_results.append(
        {"agent": "enum", "tool": "gobuster", "result": {"paths": [{"path": "/other?x=1", "status_code": 200}]}}
    )

    urls = agent._candidate_urls(mission)

    assert urls == ["http://10.0.0.1:80/search?q=1"]


def test_exploit_agent_falls_back_to_tool_results_without_scratch():
    agent = ExploitAgent.__new__(ExploitAgent)
    mission = MissionState(
        mission_id="m6", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )
    mission.tool_results.append(
        {"agent": "enum", "tool": "gobuster", "result": {"paths": [{"path": "/other?x=1", "status_code": 200}]}}
    )

    urls = agent._candidate_urls(mission)

    assert urls == ["/other?x=1"]
