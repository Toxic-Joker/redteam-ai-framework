from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from api.dependencies import get_store

router = APIRouter()


@router.get("/{mission_id}/download")
async def download_report(mission_id: str):
    store = get_store()
    mission = await store.get(mission_id)
    if mission is None or not mission.report_path:
        raise HTTPException(status_code=404, detail="Rapport introuvable")
    if not os.path.exists(mission.report_path):
        raise HTTPException(status_code=404, detail="Fichier de rapport introuvable sur le disque")
    return FileResponse(mission.report_path, filename=os.path.basename(mission.report_path))
