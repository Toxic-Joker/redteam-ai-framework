from __future__ import annotations

from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

_connections: set[WebSocket] = set()


@router.websocket("/ws/missions")
async def missions_ws(websocket: WebSocket) -> None:
    await websocket.accept()
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
