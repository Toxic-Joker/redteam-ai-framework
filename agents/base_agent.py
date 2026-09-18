"""Contrat commun a tous les agents. Le LLM y est strictement consultatif :

toute erreur de communication ou reponse JSON invalide degrade en dict vide
plutot que de faire echouer la mission (voir critere de validation MVP,
section 11 de CLAUDE.md : une mission se termine toujours).
"""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any, Optional

from langchain_ollama import ChatOllama

from core.config import get_settings
from core.state import MissionState


def _try_json_object(text: str) -> Optional[dict[str, Any]]:
    try:
        result = json.loads(text, strict=False)
    except json.JSONDecodeError:
        return None
    return result if isinstance(result, dict) else None


class BaseAgent(ABC):
    name: str = "base"

    def __init__(self) -> None:
        settings = get_settings()
        self._settings = settings
        self._llm = ChatOllama(
            base_url=settings.ollama_base_url,
            model=settings.ollama_model_main,
            temperature=0.1,
            # Chaque prompt de ce fichier demande explicitement un JSON court
            # (quelques phrases, quelques listes courtes) : un plafond de
            # generation borne le pire cas sur un modele local CPU-only sans
            # jamais couper une reponse utile en pratique. client_kwargs est
            # transmis tel quel au client ollama (lui-meme base sur httpx),
            # qui accepte "timeout" - sans ca, un appel bloque peut geler une
            # phase entiere indefiniment (voir docs/HISTORY.md, section 18).
            num_predict=settings.llm_num_predict,
            client_kwargs={"timeout": settings.llm_timeout_seconds},
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
        """Extraction de JSON tolerante aux petites imperfections d'un modele

        local plus modeste (cloture de bloc markdown, caracteres de controle
        litteraux, texte parasite avant/apres le JSON, virgule trainante).
        Renvoie {} plutot que de lever une exception : voir le principe
        consultatif du LLM en tete de ce fichier.
        """
        text = content.strip()

        fence_match = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
        if fence_match:
            text = fence_match.group(1).strip()

        start = text.find("{")
        if start == -1:
            return {}

        # 1) Tentative directe, strict=False tolere les caracteres de
        #    controle litteraux (cause frequente d'echec sur un petit modele).
        parsed = _try_json_object(text[start:])
        if parsed is not None:
            return parsed

        # 2) Isolation par comptage d'accolades : le modele a pu ajouter du
        #    texte apres le JSON (ex. une phrase de politesse).
        depth = 0
        end = None
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        isolated = text[start:end] if end is not None else text[start:]
        if end is not None:
            parsed = _try_json_object(isolated)
            if parsed is not None:
                return parsed

        # 3) Nettoyage best-effort : virgules trainantes et caracteres de
        #    controle non echappes a l'interieur des chaines.
        cleaned = re.sub(r",\s*([\]}])", r"\1", isolated)
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", cleaned)
        parsed = _try_json_object(cleaned)
        return parsed if parsed is not None else {}

    def log_error(self, state: MissionState, message: str) -> None:
        state.errors.append({"agent": self.name, "message": message})

    @abstractmethod
    async def run(self, state: MissionState) -> MissionState:
        ...
