from __future__ import annotations

import hmac
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from core.config import get_settings

router = APIRouter()

_connections: set[WebSocket] = set()


@router.websocket("/ws/missions")
async def missions_ws(websocket: WebSocket) -> None:
    # Same guardrail as every /api/* route (api/dependencies.py::require_api_key):
    # this router is included directly in main.py (a websocket route can't
    # take the router-level `dependencies=` the REST routers use), so the
    # check is done here instead (docs/HISTORY.md, section 27). A browser's
    # WebSocket API can't send a custom header, so the key arrives the same
    # way the report-download link's fallback already works: ?api_key=.
    settings = get_settings()
    await websocket.accept()
    if settings.api_key and not hmac.compare_digest(
        websocket.query_params.get("api_key", ""), settings.api_key
    ):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    _connections.add(websocket)
    try:
        while True:
            # The dashboard doesn't send anything useful; the connection is
            # kept open to receive mission progress broadcasts.
            await websocket.receive_text()
    except WebSocketDisconnect:
        _connections.discard(websocket)


async def broadcast(event: dict[str, Any]) -> None:
    stale = []
    for ws in _connections:
        try:
            await ws.send_json(event)
        except Exception:  # noqa: BLE001 - a dead connection must not interrupt the broadcast
            stale.append(ws)
    for ws in stale:
        _connections.discard(ws)
