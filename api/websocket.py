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
            # Le dashboard n'envoie rien d'utile ; on garde la connexion ouverte
            # pour recevoir les broadcasts de progression de mission.
            await websocket.receive_text()
    except WebSocketDisconnect:
        _connections.discard(websocket)


async def broadcast(event: dict[str, Any]) -> None:
    stale = []
    for ws in _connections:
        try:
            await ws.send_json(event)
        except Exception:  # noqa: BLE001 - une connexion morte ne doit pas interrompre le broadcast
            stale.append(ws)
    for ws in stale:
        _connections.discard(ws)
