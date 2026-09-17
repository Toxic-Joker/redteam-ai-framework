"""Contrat commun a tous les agents. Le LLM y est strictement consultatif :

toute erreur de communication ou reponse JSON invalide degrade en dict vide
plutot que de faire echouer la mission (voir critere de validation MVP,
section 11 de CLAUDE.md : une mission se termine toujours).
"""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any

from langchain_ollama import ChatOllama

from core.config import get_settings
from core.state import MissionState


class BaseAgent(ABC):
    name: str = "base"

    def __init__(self) -> None:
        settings = get_settings()
        self._settings = settings
        self._llm = ChatOllama(
            base_url=settings.ollama_base_url,
            model=settings.ollama_model_main,
            temperature=0.1,
        )

    async def ask_llm(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        try:
            response = await self._llm.ainvoke(
                [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ]
            )
            content = response.content if isinstance(response.content, str) else str(response.content)
            return self._extract_json(content)
        except Exception as exc:  # noqa: BLE001 - la mission ne doit jamais s'arreter sur un souci LLM
            return {"_llm_error": str(exc)}

    @staticmethod
    def _extract_json(content: str) -> dict[str, Any]:
        match = re.search(r"\{.*\}", content, re.S)
        if not match:
            return {}
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return {}

    def log_error(self, state: MissionState, message: str) -> None:
        state.errors.append({"agent": self.name, "message": message})

    @abstractmethod
    async def run(self, state: MissionState) -> MissionState:
        ...
