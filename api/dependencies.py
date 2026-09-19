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
    """Garde-fou de l'API : sans API_KEY definie, ouvert par defaut (voir

    core/config.py) pour ne pas casser un deploiement existant au premier
    pull - un choix explicite documente dans docs/HISTORY.md, section 20,
    pas un oubli. Des que API_KEY est definie, toute route protegee exige
    l'en-tete X-API-Key (fetch()) ou, a defaut, le parametre ?api_key=
    (repli pour le lien de telechargement direct <a href>, qui ne peut pas
    poser d'en-tete personnalise sur une navigation classique).
    """
    settings = get_settings()
    if not settings.api_key:
        return
    if x_api_key == settings.api_key or api_key == settings.api_key:
        return
    raise HTTPException(
        status_code=401, detail="Cle API invalide ou manquante (en-tete X-API-Key ou parametre ?api_key=)"
    )
