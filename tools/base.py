"""Contrat commun a tous les outils externes (nmap, gobuster, nikto, sqlmap, ffuf)."""
from __future__ import annotations

import abc
import asyncio
import os
import shutil
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    success: bool
    parsed: dict[str, Any] = field(default_factory=dict)


class BaseTool(abc.ABC):
    name: str = "base"
    binary: str = ""

    def binary_path(self) -> str:
        path = shutil.which(self.binary)
        if not path:
            raise FileNotFoundError(f"Binaire requis introuvable dans le PATH: {self.binary}")
        return path

    @staticmethod
    def is_root() -> bool:
        # sudo uniquement si le processus ne tourne pas deja en root
        # (le conteneur applicatif tourne en root ; incident #9).
        geteuid = getattr(os, "geteuid", None)
        if geteuid is None:
            return False
        return geteuid() == 0

    def is_success(self, returncode: int) -> bool:
        # Surchargeable : certains outils (sqlmap) utilisent un code de
        # sortie non nul pour un resultat propre mais negatif ("pas
        # vulnerable"), ce qui n'est pas un echec d'execution.
        return returncode == 0

    async def _run(self, args: list[str], timeout: int = 300) -> ToolResult:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return ToolResult(tool=self.name, command=args, returncode=-1, stdout="", stderr="timeout", success=False)
        except asyncio.CancelledError:
            # Mission interrompue par l'operateur (POST .../abort) : ne jamais
            # laisser un processus d'outil externe (nmap, gobuster, ...)
            # orphelin en arriere-plan une fois la tache annulee.
            proc.kill()
            try:
                await proc.communicate()
            except Exception:  # noqa: BLE001 - nettoyage best-effort, l'annulation prime
                pass
            raise
        stdout = stdout_b.decode(errors="replace")
        stderr = stderr_b.decode(errors="replace")
        return ToolResult(
            tool=self.name,
            command=args,
            returncode=proc.returncode or 0,
            stdout=stdout,
            stderr=stderr,
            success=self.is_success(proc.returncode or 0),
        )

    @abc.abstractmethod
    def build_command(self, **kwargs: Any) -> list[str]:
        ...

    @abc.abstractmethod
    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        ...

    async def run(self, **kwargs: Any) -> ToolResult:
        args = self.build_command(**kwargs)
        result = await self._run(args, timeout=kwargs.get("timeout", 300))
        result.parsed = self.parse_output(result)
        return result
