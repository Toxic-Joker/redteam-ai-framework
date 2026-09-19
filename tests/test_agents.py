"""Direct regression test for the nmap -O incident (docs/HISTORY.md, section 3):

a low-confidence OS guess must never appear as a fact on Target, only as a
Lead. The agent is tested with no real LLM connection or tool
(BaseAgent.__init__ is bypassed).
"""
from types import SimpleNamespace

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
    agent = ReconAgent.__new__(ReconAgent)  # bypass __init__: no real LLM connection
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


class _StubCrawler:
    def __init__(self, urls_with_params=None, post_forms=None) -> None:
        from tools.crawler_tool import CrawlResult

        self._result = CrawlResult(
            urls_with_params=urls_with_params or [], post_forms=post_forms or [], visited=["http://stub/"]
        )

    async def crawl(self, base_url, **kwargs):
        return self._result


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
    agent.crawler = _StubCrawler()
    agent.nuclei = _StubEnumTool({"matches": []})

    mission = MissionState(
        mission_id="m4", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )
    mission.target.services = {80: "http"}

    result = await agent.run(mission)

    assert result.scratch["enum"]["candidate_urls"] == ["http://10.0.0.1:80/search?q=1"]
    assert result.scratch["enum"]["base_urls"] == ["http://10.0.0.1:80"]
    assert result.scratch["enum"]["post_forms"] == []


@pytest.mark.asyncio
async def test_enum_agent_merges_crawler_urls_and_post_forms_into_scratch():
    agent = EnumAgent.__new__(EnumAgent)
    agent.name = "enum"

    async def fake_ask_llm(*args, **kwargs):
        return {"summary": "", "suggested_leads": []}

    agent.ask_llm = fake_ask_llm
    agent.gobuster = _StubEnumTool({"paths": []})
    agent.ffuf = _StubEnumTool({"paths": []})
    agent.nikto = _StubEnumTool({"items": []})
    agent.crawler = _StubCrawler(
        urls_with_params=["http://10.0.0.1:80/vulnerabilities/sqli/?id=1"],
        post_forms=[{"url": "http://10.0.0.1:80/login.php", "data": "username=1&password=1"}],
    )
    agent.nuclei = _StubEnumTool({"matches": []})

    mission = MissionState(
        mission_id="m4b", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )
    mission.target.services = {80: "http"}

    result = await agent.run(mission)

    assert "http://10.0.0.1:80/vulnerabilities/sqli/?id=1" in result.scratch["enum"]["candidate_urls"]
    assert result.scratch["enum"]["post_forms"] == [
        {"url": "http://10.0.0.1:80/login.php", "data": "username=1&password=1"}
    ]


@pytest.mark.asyncio
async def test_enum_agent_caps_nuclei_critical_match_without_exploitation_proof():
    """nuclei detects patterns, it never confirms exploitation:

    even a "critical" match must go through cap_severity like everything
    else and fall back to MEDIUM without proof of exploitation.
    """
    agent = EnumAgent.__new__(EnumAgent)
    agent.name = "enum"

    async def fake_ask_llm(*args, **kwargs):
        return {"summary": "", "suggested_leads": []}

    agent.ask_llm = fake_ask_llm
    agent.gobuster = _StubEnumTool({"paths": []})
    agent.ffuf = _StubEnumTool({"paths": []})
    agent.nikto = _StubEnumTool({"items": []})
    agent.crawler = _StubCrawler()
    agent.nuclei = _StubEnumTool(
        {
            "matches": [
                {
                    "template_id": "exposed-panel",
                    "name": "Exposed Admin Panel",
                    "severity": "critical",
                    "description": "desc",
                    "matched_at": "http://10.0.0.1:80/admin",
                    "curl_command": "curl http://10.0.0.1:80/admin",
                }
            ]
        }
    )

    mission = MissionState(
        mission_id="m4c", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )
    mission.target.services = {80: "http"}

    result = await agent.run(mission)

    assert len(result.findings) == 1
    assert result.findings[0].severity.name == "MEDIUM"
    assert "plafonnee" in result.findings[0].description


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


class _StubSqlmap:
    def __init__(self, vulnerable_urls: set[str] = frozenset()) -> None:
        self._vulnerable_urls = vulnerable_urls
        self.calls: list[dict] = []

    async def run(self, url, cookie=None, data=None, **kwargs) -> ToolResult:
        self.calls.append({"url": url, "cookie": cookie, "data": data})
        vulnerable = url in self._vulnerable_urls
        return ToolResult(
            tool="sqlmap", command=[], returncode=0, stdout="", stderr="", success=True,
            parsed={"vulnerable": vulnerable, "injection_points": ["Parameter: id (GET)"] if vulnerable else []},
        )


class _StubDalfox:
    def __init__(self, vulnerable_urls: set[str] = frozenset(), reflected_urls: set[str] = frozenset()) -> None:
        self._vulnerable_urls = vulnerable_urls
        self._reflected_urls = reflected_urls
        self.calls: list[dict] = []

    async def run(self, url, cookie=None, **kwargs) -> ToolResult:
        self.calls.append({"url": url, "cookie": cookie})
        vulnerable = url in self._vulnerable_urls
        findings = [{"param": "q", "payload": "<script>"}] if vulnerable else []
        reflected = [{"param": "q", "payload": "<script>"}] if url in self._reflected_urls else []
        return ToolResult(
            tool="dalfox", command=[], returncode=0, stdout="", stderr="", success=True,
            parsed={"vulnerable": vulnerable, "findings": findings, "reflected": reflected},
        )


class _StubCommix:
    def __init__(self, vulnerable_urls: set[str] = frozenset()) -> None:
        self._vulnerable_urls = vulnerable_urls
        self.calls: list[dict] = []

    async def run(self, url, cookie=None, data=None, **kwargs) -> ToolResult:
        self.calls.append({"url": url, "cookie": cookie, "data": data})
        vulnerable = url in self._vulnerable_urls
        return ToolResult(
            tool="commix", command=[], returncode=0, stdout="", stderr="", success=True,
            parsed={"vulnerable": vulnerable, "injection_points": ["'cmd' is vulnerable"] if vulnerable else []},
        )


@pytest.mark.asyncio
async def test_exploit_agent_tests_post_forms_discovered_by_crawler():
    agent = ExploitAgent.__new__(ExploitAgent)
    agent.name = "exploit"
    agent._settings = SimpleNamespace(exploit_max_concurrent_urls=5)

    async def fake_ask_llm(*args, **kwargs):
        return {"summary": "", "suggested_leads": []}

    agent.ask_llm = fake_ask_llm
    agent.sqlmap = _StubSqlmap(vulnerable_urls={"http://10.0.0.1:80/login.php"})
    agent.dalfox = _StubDalfox()
    agent.commix = _StubCommix()

    mission = MissionState(
        mission_id="m7", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )
    mission.target.services = {}  # no HTTP port to loop over: only the post_forms path is tested here
    mission.scratch["enum"] = {
        "candidate_urls": [],
        "base_urls": [],
        "post_forms": [{"url": "http://10.0.0.1:80/login.php", "data": "username=1&password=1"}],
    }

    result = await agent.run(mission)

    assert agent.sqlmap.calls == [
        {"url": "http://10.0.0.1:80/login.php", "cookie": None, "data": "username=1&password=1"}
    ]
    assert len(result.findings) == 1
    assert result.findings[0].exploited is True
    assert result.findings[0].severity.name == "CRITICAL"


@pytest.mark.asyncio
async def test_exploit_agent_tests_all_three_vectors_per_candidate_url():
    agent = ExploitAgent.__new__(ExploitAgent)
    agent.name = "exploit"
    agent._settings = SimpleNamespace(exploit_max_concurrent_urls=5)

    async def fake_ask_llm(*args, **kwargs):
        return {"summary": "", "suggested_leads": []}

    agent.ask_llm = fake_ask_llm
    url = "http://10.0.0.1:80/?q=1"
    agent.sqlmap = _StubSqlmap(vulnerable_urls={url})
    agent.dalfox = _StubDalfox(vulnerable_urls={url})
    agent.commix = _StubCommix(vulnerable_urls={url})

    mission = MissionState(
        mission_id="m8", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )
    mission.target.services = {80: "http"}
    mission.scratch["enum"] = {"candidate_urls": [url], "base_urls": [], "post_forms": []}

    result = await agent.run(mission)

    titles = {f.title for f in result.findings}
    assert f"Injection SQL confirmee sur {url}" in titles
    assert f"XSS confirmee sur {url}" in titles
    assert f"Injection de commandes confirmee sur {url}" in titles
    assert all(f.exploited and f.severity.name == "CRITICAL" for f in result.findings)


@pytest.mark.asyncio
async def test_exploit_agent_tests_absolute_candidate_url_once_with_multiple_http_ports():
    """Direct regression test: a real mission with two HTTP ports (8000, 8080)

    made every already-complete candidate URL get tested once per port
    instead of once in total (candidates are already absolute, so
    independent of the current port) - visible in the attack chain as two
    identical dalfox entries for the same exploited URL.
    """
    agent = ExploitAgent.__new__(ExploitAgent)
    agent.name = "exploit"
    agent._settings = SimpleNamespace(exploit_max_concurrent_urls=5)

    async def fake_ask_llm(*args, **kwargs):
        return {"summary": "", "suggested_leads": []}

    agent.ask_llm = fake_ask_llm
    url = "http://10.0.0.1:8080/vulnerabilities/xss_r/?name=1"
    agent.sqlmap = _StubSqlmap()
    agent.dalfox = _StubDalfox(vulnerable_urls={url})
    agent.commix = _StubCommix()

    mission = MissionState(
        mission_id="m10", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )
    mission.target.services = {8000: "http-alt", 8080: "http"}
    mission.scratch["enum"] = {"candidate_urls": [url], "base_urls": [], "post_forms": []}

    await agent.run(mission)

    assert agent.dalfox.calls == [{"url": url, "cookie": None}]


@pytest.mark.asyncio
async def test_exploit_agent_records_reflected_xss_as_lead_not_finding():
    """Direct regression test: dalfox "Reflected" (type R) is never

    proof of exploitation - only a lead to verify manually.
    """
    agent = ExploitAgent.__new__(ExploitAgent)
    agent.name = "exploit"
    agent._settings = SimpleNamespace(exploit_max_concurrent_urls=5)

    async def fake_ask_llm(*args, **kwargs):
        return {"summary": "", "suggested_leads": []}

    agent.ask_llm = fake_ask_llm
    url = "http://10.0.0.1:80/?q=1"
    agent.sqlmap = _StubSqlmap()
    agent.dalfox = _StubDalfox(reflected_urls={url})
    agent.commix = _StubCommix()

    mission = MissionState(
        mission_id="m9", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )
    mission.target.services = {80: "http"}
    mission.scratch["enum"] = {"candidate_urls": [url], "base_urls": [], "post_forms": []}

    result = await agent.run(mission)

    assert result.findings == []
    reflected_leads = [l for l in result.leads if "reflected" in l.tags]
    assert len(reflected_leads) == 1
