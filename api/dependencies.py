from __future__ import annotations

import os
from functools import lru_cache

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
