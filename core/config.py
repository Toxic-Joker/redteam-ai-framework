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

    # Cle partagee protegeant l'API/dashboard (en-tete X-API-Key). Vide par
    # defaut pour ne pas casser un deploiement existant au premier pull, mais
    # laisse alors l'API entierement ouverte a quiconque atteint le port 8000
    # (voir docs/HISTORY.md, section 20) - a definir avant toute exposition
    # au-dela de la machine de l'operateur.
    api_key: str = ""

    # CIDR separes par des virgules (ex. "10.0.0.0/8,192.168.0.0/16"). Vide
    # par defaut = aucune restriction (voir core/state.py::is_target_in_allowed_ranges
    # pour pourquoi ce n'est pas restreint aux plages privees par defaut).
    allowed_target_ranges: str = ""

    nmap_scan_mode: str = "syn"  # "syn" (-sS) ou "connect" (-sT)
    max_cycles: int = 10
    log_level: str = "INFO"

    # Bornes de performance : aucune ne change ce qu'un outil trouve, seulement
    # combien de temps une mission met a le trouver (voir docs/HISTORY.md,
    # section 18, pour le detail de chaque decision).
    llm_num_predict: int = 512  # cap la longueur de generation, jamais la sortie attendue (JSON court)
    llm_timeout_seconds: int = 180  # borne un appel Ollama bloque, plutot qu'une attente indefinie
    nikto_max_time: str = "180s"  # -maxtime de nikto lui-meme ; pire cas borne, pas une moyenne
    exploit_max_concurrent_urls: int = 5  # parallelisme borne entre URLs candidates, pas de rafale illimitee

    reports_dir: str = "reports"
    db_dir: str = "db"

    def allowed_target_ranges_list(self) -> list[str]:
        return [r.strip() for r in self.allowed_target_ranges.split(",") if r.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
