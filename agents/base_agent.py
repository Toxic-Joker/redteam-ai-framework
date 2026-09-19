"""Common contract for every agent. The LLM here is strictly consultative:

any communication error or invalid JSON reply degrades to an empty dict
instead of failing the mission (see the MVP validation criterion, CLAUDE.md
section 11: a mission always completes).
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
            # Every prompt in this file explicitly asks for short JSON (a
            # few sentences, a few short lists): a generation cap bounds
            # the worst case on a CPU-only local model without ever
            # cutting off a useful reply in practice. client_kwargs is
            # passed through as-is to the ollama client (itself based on
            # httpx), which accepts "timeout" - without it, a stuck call
            # could freeze an entire phase indefinitely (see
            # docs/HISTORY.md, section 18).
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
        except Exception as exc:  # noqa: BLE001 - the mission must never stop over an LLM issue
            return {"_llm_error": str(exc)}

    @staticmethod
    def _extract_json(content: str) -> dict[str, Any]:
        """JSON extraction tolerant of the small imperfections a more

        modest local model produces (markdown fences, literal control
        characters, stray text before/after the JSON, trailing commas).
        Returns {} rather than raising: see this file's consultative LLM
        principle at the top.
        """
        text = content.strip()

        fence_match = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
        if fence_match:
            text = fence_match.group(1).strip()

        start = text.find("{")
        if start == -1:
            return {}

        # 1) Direct attempt, strict=False tolerates literal control
        #    characters (a frequent failure cause on a small model).
        parsed = _try_json_object(text[start:])
        if parsed is not None:
            return parsed

        # 2) Brace-counting isolation: the model may have added text
        #    after the JSON (e.g. a polite closing sentence).
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

        # 3) Best-effort cleanup: trailing commas and unescaped control
        #    characters inside strings.
        cleaned = re.sub(r",\s*([\]}])", r"\1", isolated)
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", cleaned)
        parsed = _try_json_object(cleaned)
        return parsed if parsed is not None else {}

    def log_error(self, state: MissionState, message: str) -> None:
        state.errors.append({"agent": self.name, "message": message})

    @abstractmethod
    async def run(self, state: MissionState) -> MissionState:
        ...
