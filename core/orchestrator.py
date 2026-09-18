"""Orchestrateur LangGraph : garde-fous anti-boucle presents des le premier

commit du graphe (limite de cycles, suivi des phases terminees), pas ajoutes
apres avoir observe une boucle infinie en production.

Le LLM peut influencer la prochaine phase (MissionState.last_decision, lu
depuis le meme appel de resume que chaque agent fait deja en fin de phase -
aucun appel d'inference supplementaire), mais n'a jamais le dernier mot :
enforce_progression() reste seul juge final et peut ignorer, corriger ou
annuler toute suggestion (phase invalide, deja terminee, ou tentative de finir
sans etre passe par "report"). Une suggestion peut faire sauter une phase
(ex. recon -> exploit directement) ; si la phase sautee n'est jamais
revalidee par un signal deterministe, le filet de securite finit par y
revenir de lui-meme des qu'aucune suggestion ne la contourne plus, borne par
MAX_CYCLES dans tous les cas.
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
    default_proposed = remaining[0] if remaining else "report"
    # La suggestion du LLM (si presente et valide) prime sur l'ordre lineaire
    # par defaut, mais enforce_progression() reste seul a decider en dernier
    # ressort - une suggestion invalide ou absente retombe simplement sur le
    # comportement deterministe precedent.
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
    """Execute la mission de bout en bout.

    Si on_progress est fourni, il est appele avec l'etat courant apres
    chaque phase (persistance + diffusion WebSocket cote appelant), au lieu
    d'attendre la toute fin de la mission pour la premiere mise a jour
    visible sur le dashboard. core/ reste decouple de api/ : c'est
    l'appelant qui decide quoi faire de chaque etat intermediaire.
    """
    graph = build_graph()
    result: GraphState = {"mission": mission}
    is_first_yield = True
    async for step in graph.astream({"mission": mission}, stream_mode="values"):
        result = step
        if is_first_yield:
            # stream_mode="values" emet d'abord l'etat d'entree tel quel,
            # avant l'execution du premier noeud : rien a diffuser encore.
            is_first_yield = False
            continue
        if on_progress is not None:
            await on_progress(result["mission"])
    return result["mission"]
