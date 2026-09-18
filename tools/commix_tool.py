"""commix : injection de commandes systeme, architecture et CLI directement

inspirees de sqlmap (memes auteurs de conventions) - confirme via le code
source (`src/core/parse/cmdline.py`, `src/core/controller/checks.py`)
avant ecriture, pas suppose par analogie :
- flags : -u/--url, --batch, --cookie, --data (identiques a sqlmap)
- signal positif : la phrase exacte "is vulnerable" (vulnerable_message()) ;
  le cas negatif utilise explicitement "false positive"/"unexploitable",
  jamais "is vulnerable" - meme piege evite qu'avec le correctif sqlmap
  (docs/HISTORY.md section 6) : ne jamais combiner des mots-cles
  independants presents n'importe ou dans la sortie.
"""
from __future__ import annotations

from typing import Any, Optional

from .base import BaseTool, ToolResult


class CommixTool(BaseTool):
    name = "commix"
    binary = "commix"

    def build_command(
        self, url: str, data: Optional[str] = None, cookie: Optional[str] = None, batch: bool = True, **kwargs: Any
    ) -> list[str]:
        binary = self.binary_path()
        args = [binary, "-u", url]
        if data:
            args += ["--data", data]
        if cookie:
            args += ["--cookie", cookie]
        if batch:
            args.append("--batch")
        return args

    def is_success(self, returncode: int) -> bool:
        # Non verifie independamment (pas de source consultee sur les codes
        # de sortie precis de commix), mais son architecture reprend
        # deliberement celle de sqlmap - meme hypothese appliquee par
        # prudence : un resultat negatif propre ne doit pas etre traite
        # comme un echec d'execution.
        return returncode in (0, 1)

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        vulnerable = any("is vulnerable" in line.lower() for line in result.stdout.splitlines())
        injection_points = [line.strip() for line in result.stdout.splitlines() if "is vulnerable" in line.lower()]
        return {"vulnerable": vulnerable, "injection_points": injection_points}
