"""Priorite : les garde-fous anti-boucle doivent exister des la construction

du graphe, pas etre verifies uniquement en execution reelle (qui necessite
Ollama + les binaires d'outils, hors de portee des tests unitaires).
"""
from core.orchestrator import AGENT_MAP, build_graph
from core.state import PHASE_ORDER


def test_agent_map_covers_every_phase_exactly_once():
    assert set(AGENT_MAP.keys()) == set(PHASE_ORDER)
    assert len(AGENT_MAP) == len(PHASE_ORDER)


def test_graph_compiles_without_error():
    graph = build_graph()
    assert graph is not None
