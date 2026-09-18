"""_extract_json doit degrader vers {} plutot que de lever une exception :

une mission ne s'arrete jamais sur une reponse LLM malformee (section 11 de
CLAUDE.md). Ces tests couvrent les imperfections reelles d'un petit modele
local, pas seulement le cas JSON parfaitement forme.
"""
from agents.base_agent import BaseAgent


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
    # Un retour a la ligne litteral (non echappe en \n) dans une valeur de
    # chaine : rejete par json.loads strict, tolere par strict=False.
    content = '{"summary": "ligne un\nligne deux"}'
    result = BaseAgent._extract_json(content)
    assert "summary" in result


def test_extract_json_returns_empty_dict_when_no_json_present():
    assert BaseAgent._extract_json("desole, je ne peux pas repondre a cela.") == {}


def test_extract_json_returns_empty_dict_on_irrecoverable_garbage():
    assert BaseAgent._extract_json("{not json at all : : :") == {}
