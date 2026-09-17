from __future__ import annotations

from fastapi import APIRouter

from core.state import PHASE_ORDER

router = APIRouter()


@router.get("")
async def list_agents():
    return {"phases": PHASE_ORDER}
