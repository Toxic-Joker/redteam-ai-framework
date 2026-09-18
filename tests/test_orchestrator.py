"""Priorite : les garde-fous anti-boucle doivent exister des la construction

du graphe, pas etre verifies uniquement en execution reelle (qui necessite
Ollama + les binaires d'outils, hors de portee des tests unitaires).
"""
import pytest

import core.orchestrator as orchestrator_module
from core.orchestrator import AGENT_MAP, build_graph, run_mission
from core.state import PHASE_ORDER, MissionState, Target


def test_agent_map_covers_every_phase_exactly_once():
    assert set(AGENT_MAP.keys()) == set(PHASE_ORDER)
    assert len(AGENT_MAP) == len(PHASE_ORDER)


def test_graph_compiles_without_error():
    graph = build_graph()
    assert graph is not None


def _make_stub_agent(phase_name: str, decision: str | None = None):
    class _Stub:
        name = phase_name

        async def run(self, state: MissionState) -> MissionState:
            state.current_agent = phase_name
            state.completed_phases.append(phase_name)
            state.last_decision = decision
            if phase_name == "report":
                state.status = "completed"
            return state

    return _Stub


@pytest.mark.asyncio
async def test_run_mission_calls_on_progress_once_per_phase(monkeypatch):
    monkeypatch.setattr(
        orchestrator_module, "AGENT_MAP", {phase: _make_stub_agent(phase) for phase in PHASE_ORDER}
    )

    seen_agents: list[str] = []

    async def on_progress(mission: MissionState) -> None:
        seen_agents.append(mission.current_agent)

    mission = MissionState(
        mission_id="m1", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )

    result = await run_mission(mission, on_progress=on_progress)

    assert result.status == "completed"
    assert seen_agents == list(PHASE_ORDER)


@pytest.mark.asyncio
async def test_run_mission_rejects_a_forward_skip_suggestion(monkeypatch):
    """Regression directe d'un incident reel : recon avait suggere de sauter

    directement a exploit, privant exploit_agent des URLs qu'enum aurait
    decouvertes via MissionState.scratch (moins de cibles testees). L'ordre
    lineaire doit rester intact meme si une suggestion tente de le rompre.
    """
    monkeypatch.setattr(
        orchestrator_module,
        "AGENT_MAP",
        {
            "recon": _make_stub_agent("recon", decision="exploit"),
            "enum": _make_stub_agent("enum"),
            "exploit": _make_stub_agent("exploit"),
            "postexploit": _make_stub_agent("postexploit"),
            "report": _make_stub_agent("report"),
        },
    )

    seen_agents: list[str] = []

    async def on_progress(mission: MissionState) -> None:
        seen_agents.append(mission.current_agent)

    mission = MissionState(
        mission_id="m3", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )

    result = await run_mission(mission, on_progress=on_progress)

    assert result.status == "completed"
    assert seen_agents == list(PHASE_ORDER)


@pytest.mark.asyncio
async def test_run_mission_honors_an_early_report_suggestion(monkeypatch):
    """Le seul saut qui reste autorise : enum suggere de conclure

    directement en "report", puisque rien en aval ne depend de son resultat.
    """
    monkeypatch.setattr(
        orchestrator_module,
        "AGENT_MAP",
        {
            "recon": _make_stub_agent("recon"),
            "enum": _make_stub_agent("enum", decision="report"),
            "exploit": _make_stub_agent("exploit"),
            "postexploit": _make_stub_agent("postexploit"),
            "report": _make_stub_agent("report"),
        },
    )

    seen_agents: list[str] = []

    async def on_progress(mission: MissionState) -> None:
        seen_agents.append(mission.current_agent)

    mission = MissionState(
        mission_id="m4", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )

    result = await run_mission(mission, on_progress=on_progress)

    assert result.status == "completed"
    assert seen_agents == ["recon", "enum", "report"]
