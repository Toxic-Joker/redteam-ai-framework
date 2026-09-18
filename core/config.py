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

    # CIDR separes par des virgules (ex. "10.0.0.0/8,192.168.0.0/16"). Vide
    # par defaut = aucune restriction (voir core/state.py::is_target_in_allowed_ranges
    # pour pourquoi ce n'est pas restreint aux plages privees par defaut).
    allowed_target_ranges: str = ""

    nmap_scan_mode: str = "syn"  # "syn" (-sS) ou "connect" (-sT)
    max_cycles: int = 10
    log_level: str = "INFO"

    reports_dir: str = "reports"
    db_dir: str = "db"

    def allowed_target_ranges_list(self) -> list[str]:
        return [r.strip() for r in self.allowed_target_ranges.split(",") if r.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
