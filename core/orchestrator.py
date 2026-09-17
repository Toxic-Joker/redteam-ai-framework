"""Orchestrateur LangGraph : garde-fous anti-boucle presents des le premier

commit du graphe (limite de cycles, suivi des phases terminees), pas ajoutes
apres avoir observe une boucle infinie en production.

La progression entre phases est elle-meme deterministe (pipeline lineaire
recon -> enum -> exploit -> postexploit -> report) : le LLM n'est jamais
consulte pour choisir la prochaine phase, seulement pour resumer/proposer des
pistes a l'interieur de chaque phase. enforce_progression() reste le filet de
securite si cette logique est etendue plus tard vers un routage moins rigide.
"""
from __future__ import annotations

from typing import TypedDict

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
        except Exception as exc:  # noqa: BLE001 - une mission ne s'arrete jamais sur une exception d'agent
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
    proposed = remaining[0] if remaining else "report"

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


async def run_mission(mission: MissionState) -> MissionState:
    graph = build_graph()
    result = await graph.ainvoke({"mission": mission})
    return result["mission"]
