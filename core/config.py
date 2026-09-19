"""Single source of truth for every environment variable.

Each variable listed in CLAUDE.md, section 9, is read once here and
propagated everywhere else via Settings injection, never re-read via
os.environ directly in an agent, a tool, or a route.
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

    # Shared key protecting the API/dashboard (X-API-Key header). Empty by
    # default so it doesn't break an existing deployment on the first pull,
    # but that leaves the API wide open to anyone reaching port 8000 (see
    # docs/HISTORY.md, section 20) - set before any exposure beyond the
    # operator's own machine.
    api_key: str = ""

    # Comma-separated CIDRs (e.g. "10.0.0.0/8,192.168.0.0/16"). Empty by
    # default = no restriction (see core/state.py::is_target_in_allowed_ranges
    # for why this isn't restricted to private ranges by default).
    allowed_target_ranges: str = ""

    nmap_scan_mode: str = "syn"  # "syn" (-sS) or "connect" (-sT)
    max_cycles: int = 10
    log_level: str = "INFO"

    # Performance bounds: none of these change what a tool finds, only how
    # long a mission takes to find it (see docs/HISTORY.md, section 18, for
    # the detail behind each decision).
    llm_num_predict: int = 512  # caps generation length, never the expected output (short JSON)
    llm_timeout_seconds: int = 180  # bounds a stuck Ollama call rather than an indefinite wait
    nikto_max_time: str = "180s"  # nikto's own -maxtime; a bounded worst case, not an average
    exploit_max_concurrent_urls: int = 5  # bounded concurrency across candidate URLs, no unbounded burst

    reports_dir: str = "reports"
    db_dir: str = "db"

    def allowed_target_ranges_list(self) -> list[str]:
        return [r.strip() for r in self.allowed_target_ranges.split(",") if r.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
