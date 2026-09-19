"""LangGraph orchestrator: anti-loop guardrails present from the graph's

very first commit (cycle limit, completed-phase tracking), not added after
observing an infinite loop in production.

The LLM can influence the next phase (MissionState.last_decision, read from
the same summary call each agent already makes at the end of its phase - no
extra inference call), but never has the final word:
enforce_progression() remains the sole final judge and can ignore, correct,
or cancel any suggestion (invalid phase, already completed, an attempt to
finish without going through "report", or a skip over an incomplete
intermediate phase). This last point isn't theoretical: a recon -> exploit
suggestion actually skipped "enum" during a real deployment, depriving
exploit of data it depends on (state.scratch["enum"]["candidate_urls"]) and
reducing the number of targets tested. So only two outcomes are possible:
the real next phase in the linear order, or a direct skip to "report"
(early completion, never problematic since nothing downstream depends on
it). Bounded by MAX_CYCLES in all cases. See docs/HISTORY.md.
"""
from __future__ import annotations

from typing import Awaitable, Callable, Optional, TypedDict

from langgraph.graph import END, StateGraph

from agents.enum_agent import EnumAgent
from agents.exploit_agent import ExploitAgent
from agents.postexploit_agent import PostexploitAgent
from agents.recon_agent import ReconAgent
from agents.report_agent import ReportAgent
from core.config import get_settings
from core.state import PHASE_ORDER, MissionState, enforce_progression

AGENT_MAP = {
    "recon": ReconAgent,
    "enum": EnumAgent,
    "exploit": ExploitAgent,
    "postexploit": PostexploitAgent,
    "report": ReportAgent,
}


class GraphState(TypedDict):
    mission: MissionState


def _make_node(phase: str):
    agent = AGENT_MAP[phase]()

    async def node(state: GraphState) -> GraphState:
        mission = state["mission"]
        try:
            mission = await agent.run(mission)
        except Exception as exc:  # noqa: BLE001 - a mission never stops on an agent exception
            mission.errors.append({"agent": phase, "message": str(exc)})
            if phase not in mission.completed_phases:
                mission.completed_phases.append(phase)
        return {"mission": mission}

    return node


def _route(state: GraphState) -> str:
    mission = state["mission"]
    settings = get_settings()

    if mission.status == "completed":
        return END

    remaining = [p for p in PHASE_ORDER if p not in mission.completed_phases]
    default_proposed = remaining[0] if remaining else "report"
    # The LLM's suggestion (if present and valid) takes priority over the
    # default linear order, but enforce_progression() remains the sole
    # final decision-maker - an invalid or absent suggestion simply falls
    # back to the previous deterministic behavior.
    proposed = mission.last_decision or default_proposed

    next_phase = enforce_progression(mission, proposed, max_cycles=settings.max_cycles)
    return END if next_phase == "end" else next_phase


def build_graph():
    graph = StateGraph(GraphState)
    for phase in PHASE_ORDER:
        graph.add_node(phase, _make_node(phase))

    graph.set_entry_point("recon")

    routing_table = {phase: phase for phase in PHASE_ORDER}
    routing_table[END] = END
    for phase in PHASE_ORDER:
        graph.add_conditional_edges(phase, _route, routing_table)

    return graph.compile()


async def run_mission(
    mission: MissionState,
    on_progress: Optional[Callable[[MissionState], Awaitable[None]]] = None,
) -> MissionState:
    """Runs the mission end to end.

    If on_progress is supplied, it's called with the current state after
    each phase (persistence + WebSocket broadcast on the caller's side),
    instead of waiting until the very end of the mission for the first
    update visible on the dashboard. core/ stays decoupled from api/: it's
    the caller that decides what to do with each intermediate state.
    """
    settings = get_settings()
    graph = build_graph()
    result: GraphState = {"mission": mission}
    is_first_yield = True
    # Explicit ceiling on top of the orchestration_cycles counter:
    # LangGraph has its own default recursion limit (undocumented, ~25),
    # better to never implicitly depend on it.
    config = {"recursion_limit": settings.max_cycles * 2 + 2}
    async for step in graph.astream({"mission": mission}, stream_mode="values", config=config):
        result = step
        if is_first_yield:
            # stream_mode="values" first emits the input state as-is,
            # before the first node runs: nothing to broadcast yet.
            is_first_yield = False
            continue
        if on_progress is not None:
            await on_progress(result["mission"])
    return result["mission"]
