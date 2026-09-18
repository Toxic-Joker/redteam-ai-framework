"""Routes REST des missions.

REQUIRE_AUTHORIZATION bloque toute mission sans authorization_ref (contrat de
MissionState, section 6 de CLAUDE.md). L'execution reelle tourne dans une
asyncio.Task suivie dans _running_tasks (pas BackgroundTasks, qui ne fournit
aucun moyen d'annuler une mission en cours - voir docs/HISTORY.md section 6).
Le statut/risque exposes viennent toujours du coeur deterministe, jamais
d'une reformulation par le LLM.
"""
from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from api.dependencies import get_store
from api.websocket import broadcast
from core.config import get_settings
from core.orchestrator import run_mission
from core.state import MissionState, Target, compute_overall_risk, is_target_in_allowed_ranges

router = APIRouter()

# Une mission en cours doit pouvoir etre annulee depuis l'API (POST .../abort).
# BackgroundTasks ne donne aucune prise sur la tache une fois lancee ; on
# garde donc le handle asyncio.Task ici, purge des qu'une mission se termine.
_running_tasks: dict[str, asyncio.Task] = {}


class MissionCreateRequest(BaseModel):
    mission_name: str
    operator: str
    target_host: str = Field(..., description="Cible externe, jamais embarquee dans le deploiement")
    authorization_ref: str | None = None


@router.post("")
async def create_mission(payload: MissionCreateRequest):
    settings = get_settings()
    if settings.require_authorization and not payload.authorization_ref:
        raise HTTPException(status_code=400, detail="authorization_ref est obligatoire (REQUIRE_AUTHORIZATION=true)")

    allowed_ranges = settings.allowed_target_ranges_list()
    if not is_target_in_allowed_ranges(payload.target_host, allowed_ranges):
        raise HTTPException(
            status_code=400,
            detail=f"Cible hors des plages autorisees par ALLOWED_TARGET_RANGES ({', '.join(allowed_ranges)})",
        )

    mission = MissionState(
        mission_id=str(uuid.uuid4()),
        mission_name=payload.mission_name,
        operator=payload.operator,
        authorization_ref=payload.authorization_ref,
        target=Target(host=payload.target_host),
    )
    mission.status = "running"

    store = get_store()
    await store.save(mission)

    task = asyncio.create_task(_execute_mission(mission.mission_id))
    _running_tasks[mission.mission_id] = task
    return {"mission_id": mission.mission_id, "status": mission.status}


async def _execute_mission(mission_id: str) -> None:
    store = get_store()
    mission = await store.get(mission_id)
    if mission is None:
        return

    async def on_progress(current: MissionState) -> None:
        current.updated_at = datetime.now(timezone.utc).isoformat()
        await store.save(current)
        await broadcast(
            {"mission_id": current.mission_id, "status": current.status, "current_agent": current.current_agent}
        )

    try:
        mission = await run_mission(mission, on_progress=on_progress)
    except asyncio.CancelledError:
        mission.status = "aborted"
        mission.errors.append({"agent": "orchestrator", "message": "Mission interrompue par l'operateur"})
    except Exception as exc:  # noqa: BLE001 - une mission ne doit jamais planter silencieusement l'API
        mission.errors.append({"agent": "orchestrator", "message": str(exc)})
        mission.status = "failed"
    finally:
        mission.updated_at = datetime.now(timezone.utc).isoformat()
        await store.save(mission)
        await broadcast(
            {"mission_id": mission.mission_id, "status": mission.status, "current_agent": mission.current_agent}
        )
        _running_tasks.pop(mission_id, None)


@router.post("/{mission_id}/abort")
async def abort_mission(mission_id: str):
    task = _running_tasks.get(mission_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Aucune mission en cours avec cet identifiant")
    task.cancel()
    return {"mission_id": mission_id, "status": "aborting"}


@router.delete("/{mission_id}")
async def delete_mission(mission_id: str):
    if mission_id in _running_tasks:
        raise HTTPException(status_code=409, detail="Mission en cours : l'interrompre d'abord avec /abort")

    store = get_store()
    mission = await store.get(mission_id)
    if mission is None:
        raise HTTPException(status_code=404, detail="Mission introuvable")

    for ext in (".html", ".pdf"):
        path = os.path.join(get_settings().reports_dir, f"{mission_id}{ext}")
        if os.path.exists(path):
            os.remove(path)

    await store.delete(mission_id)
    return {"mission_id": mission_id, "deleted": True}


@router.get("")
async def list_missions():
    store = get_store()
    missions = await store.list_all()
    return [
        {
            "mission_id": m.mission_id,
            "mission_name": m.mission_name,
            "status": m.status,
            "current_agent": m.current_agent,
            "target": m.target.host,
        }
        for m in missions
    ]


@router.get("/{mission_id}")
async def get_mission(mission_id: str):
    store = get_store()
    mission = await store.get(mission_id)
    if mission is None:
        raise HTTPException(status_code=404, detail="Mission introuvable")
    return _mission_summary(mission)


def _mission_summary(mission: MissionState) -> dict:
    return {
        "mission_id": mission.mission_id,
        "mission_name": mission.mission_name,
        "status": mission.status,
        "current_agent": mission.current_agent,
        "completed_phases": mission.completed_phases,
        "orchestration_cycles": mission.orchestration_cycles,
        "target": {"host": mission.target.host, "ports": mission.target.ports},
        "findings": [
            {"title": f.title, "severity": f.severity.name, "affected_component": f.affected_component}
            for f in mission.findings
        ],
        "leads": [{"title": l.title, "confidence": l.confidence} for l in mission.leads],
        "overall_risk": compute_overall_risk(mission.findings).name,
        "report_path": mission.report_path,
        "errors": mission.errors,
    }
