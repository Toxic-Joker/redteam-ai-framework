"""Source unique de verite pour toutes les variables d'environnement.

Chaque variable listee dans CLAUDE.md, section 9, est lue une seule fois ici
et propagee partout ailleurs par injection de Settings, jamais relue via
os.environ directement dans un agent, un outil ou une route.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    ollama_base_url: str = "http://ollama:11434"
    ollama_model_main: str = "qwen3.5:9b"
    ollama_embed_model: str = "nomic-embed-text"

    require_authorization: bool = True

    nmap_scan_mode: str = "syn"  # "syn" (-sS) ou "connect" (-sT)
    max_cycles: int = 10
    log_level: str = "INFO"

    reports_dir: str = "reports"
    db_dir: str = "db"


@lru_cache
def get_settings() -> Settings:
    return Settings()
