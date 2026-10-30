"""The mission WebSocket must follow the same API_KEY guardrail as every

/api/* route (api/dependencies.py::require_api_key) - a router-level
`dependencies=` doesn't apply to a websocket route, so /ws/missions had no
auth at all until this fix: anyone reaching the port could harvest every
mission_id as missions ran, with API_KEY set or not (docs/HISTORY.md,
section 27).
"""
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from core.config import get_settings
from main import app


def test_ws_open_when_api_key_unset(monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "")
    with TestClient(app) as client:
        with client.websocket_connect("/ws/missions"):
            pass  # connects without being closed


def test_ws_rejects_missing_or_wrong_key_when_set(monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "s3cr3t")
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws/missions") as ws:
                ws.receive_text()

        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws/missions?api_key=wrong") as ws:
                ws.receive_text()


def test_ws_accepts_correct_query_param_key(monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "s3cr3t")
    with TestClient(app) as client:
        with client.websocket_connect("/ws/missions?api_key=s3cr3t"):
            pass  # connects without being closed
