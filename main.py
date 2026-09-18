"""Point d'entree de l'application FastAPI."""
from __future__ import annotations

import logging
import os

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from api.dependencies import get_store, render_template
from api.routes import agents as agents_routes
from api.routes import missions as missions_routes
from api.routes import reports as reports_routes
from api.websocket import router as websocket_router
from core.config import get_settings

settings = get_settings()
logging.basicConfig(level=settings.log_level)

app = FastAPI(title="RedTeam AI Framework", version="2.0.0")

app.include_router(missions_routes.router, prefix="/api/missions", tags=["missions"])
app.include_router(reports_routes.router, prefix="/api/reports", tags=["reports"])
app.include_router(agents_routes.router, prefix="/api/agents", tags=["agents"])
app.include_router(websocket_router)


@app.on_event("startup")
async def on_startup() -> None:
    os.makedirs(settings.reports_dir, exist_ok=True)
    os.makedirs(settings.db_dir, exist_ok=True)
    await get_store().init()
    try:
        app.mount("/reports_static", StaticFiles(directory=settings.reports_dir), name="reports_static")
    except Exception:  # noqa: BLE001 - le montage statique n'est pas critique au demarrage
        logging.getLogger(__name__).warning("Montage de /reports_static impossible", exc_info=True)


@app.get("/health")
async def health() -> dict:
    # Le LLM est consultatif, mais quand Ollama est injoignable, chaque
    # ask_llm degrade silencieusement en {} - un operateur n'a sinon aucun
    # signal visible d'un backend hors service. Voir docs/HISTORY.md.
    ollama_ok = False
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{settings.ollama_base_url}/api/tags")
            ollama_ok = response.status_code == 200
    except Exception:  # noqa: BLE001 - un Ollama injoignable n'est pas une erreur serveur
        ollama_ok = False
    return {"status": "ok" if ollama_ok else "degraded", "ollama": ollama_ok, "model": settings.ollama_model_main}


@app.get("/")
async def index() -> HTMLResponse:
    return HTMLResponse(render_template("dashboard.html", {}))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
