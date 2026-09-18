"""mission_to_dict/mission_from_dict doivent faire un aller-retour fidele -

un champ oublie dans l'un des deux sens se perd silencieusement au premier
rechargement depuis la base (voir session_cookie, ajoute apres coup).
"""
from core.memory import mission_from_dict, mission_to_dict
from core.state import MissionState, Target


def test_session_cookie_round_trips_through_dict_conversion():
    mission = MissionState(
        mission_id="m1",
        mission_name="t",
        operator="op",
        authorization_ref="A",
        target=Target(host="10.0.0.1", session_cookie="PHPSESSID=abc; security=low"),
    )
    restored = mission_from_dict(mission_to_dict(mission))
    assert restored.target.session_cookie == "PHPSESSID=abc; security=low"


def test_session_cookie_defaults_to_none_when_absent():
    mission = MissionState(
        mission_id="m2", mission_name="t", operator="op", authorization_ref="A", target=Target(host="10.0.0.1")
    )
    restored = mission_from_dict(mission_to_dict(mission))
    assert restored.target.session_cookie is None
