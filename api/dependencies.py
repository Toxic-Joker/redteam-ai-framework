from __future__ import annotations

import os
from functools import lru_cache

from fastapi import Header, HTTPException, Query
from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.config import get_settings
from core.memory import MissionStore

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")


@lru_cache
def get_store() -> MissionStore:
    settings = get_settings()
    os.makedirs(settings.db_dir, exist_ok=True)
    return MissionStore(os.path.join(settings.db_dir, "missions.sqlite3"))


@lru_cache
def get_jinja_env() -> Environment:
    return Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=select_autoescape(["html"]))


def render_template(name: str, context: dict) -> str:
    return get_jinja_env().get_template(name).render(**context)


def require_api_key(x_api_key: str = Header(default=""), api_key: str = Query(default="")) -> None:
    """API guardrail: open by default with no API_KEY set (see

    core/config.py) so it doesn't break an existing deployment on the
    first pull - an explicit choice documented in docs/HISTORY.md,
    section 20, not an oversight. Once API_KEY is set, every protected
    route requires the X-API-Key header (fetch()) or, failing that, the
    ?api_key= parameter (a fallback for the direct <a href> download
    link, which can't set a custom header on a plain navigation).
    """
    settings = get_settings()
    if not settings.api_key:
        return
    if x_api_key == settings.api_key or api_key == settings.api_key:
        return
    raise HTTPException(
        status_code=401, detail="Cle API invalide ou manquante (en-tete X-API-Key ou parametre ?api_key=)"
    )
