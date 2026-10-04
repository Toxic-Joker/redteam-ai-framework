"""_extract_json must degrade to {} rather than raise an exception:

a mission never stops over a malformed LLM reply (CLAUDE.md section 11).
These tests cover the real imperfections of a small local model, not just
the perfectly well-formed JSON case.
"""
import logging
from types import SimpleNamespace

import pytest

from agents.base_agent import BaseAgent
from agents.recon_agent import ReconAgent


def _make_bare_agent(llm_content: str):
    agent = ReconAgent.__new__(ReconAgent)  # bypass __init__: no real LLM connection
    agent.name = "test"

    class _StubLLM:
        async def ainvoke(self, messages):
            return SimpleNamespace(content=llm_content)

    agent._llm = _StubLLM()
    return agent


@pytest.mark.asyncio
async def test_ask_llm_logs_a_warning_when_reply_has_no_usable_json(caplog):
    # Before this, nothing captured the raw LLM reply anywhere - "why did
    # the LLM contribute nothing to this report" was unanswerable from
    # logs (docs/HISTORY.md, section 25).
    agent = _make_bare_agent("")
    with caplog.at_level(logging.WARNING):
        result = await agent.ask_llm("system", "user")
    assert result == {}
    assert any("no usable JSON" in record.message for record in caplog.records)


@pytest.mark.asyncio
async def test_ask_llm_does_not_warn_on_a_valid_reply(caplog):
    agent = _make_bare_agent('{"summary": "ok"}')
    with caplog.at_level(logging.WARNING):
        result = await agent.ask_llm("system", "user")
    assert result == {"summary": "ok"}
    assert not any("no usable JSON" in record.message for record in caplog.records)


def test_llm_is_constrained_to_json_output():
    # Every agent's system_prompt says "Reponds uniquement en JSON" - none
    # mix prose with JSON - so constraining generation at the source via
    # Ollama's format=json is safe and reduces malformed replies before
    # they ever reach _extract_json. Doesn't replace the tolerant parsing
    # or any deterministic fallback: a model can still return syntactically
    # valid JSON with the wrong shape.
    agent = ReconAgent()
    assert agent._llm.format == "json"


def test_extract_json_parses_plain_valid_json():
    assert BaseAgent._extract_json('{"summary": "ok"}') == {"summary": "ok"}


def test_extract_json_strips_markdown_code_fence():
    content = '```json\n{"summary": "ok"}\n```'
    assert BaseAgent._extract_json(content) == {"summary": "ok"}


def test_extract_json_ignores_trailing_prose_after_object():
    content = '{"summary": "ok"} Merci, dites-moi si vous avez besoin d\'autre chose !'
    assert BaseAgent._extract_json(content) == {"summary": "ok"}


def test_extract_json_tolerates_trailing_comma():
    content = '{"summary": "ok", "suggested_leads": ["a", "b",],}'
    assert BaseAgent._extract_json(content) == {"summary": "ok", "suggested_leads": ["a", "b"]}


def test_extract_json_tolerates_literal_control_character_in_string():
    # A literal newline (not escaped as \n) inside a string value: rejected
    # by strict json.loads, tolerated by strict=False.
    content = '{"summary": "ligne un\nligne deux"}'
    result = BaseAgent._extract_json(content)
    assert "summary" in result


def test_extract_json_returns_empty_dict_when_no_json_present():
    assert BaseAgent._extract_json("desole, je ne peux pas repondre a cela.") == {}


def test_extract_json_returns_empty_dict_on_irrecoverable_garbage():
    assert BaseAgent._extract_json("{not json at all : : :") == {}
