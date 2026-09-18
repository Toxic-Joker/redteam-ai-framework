"""sqlmap : pas de paquet apt fiable (incident #3), wrapper shell sur clone GitHub."""
from __future__ import annotations

from typing import Any, Optional

from .base import BaseTool, ToolResult


class SqlmapTool(BaseTool):
    name = "sqlmap"
    binary = "sqlmap"

    def build_command(
        self,
        url: str,
        data: Optional[str] = None,
        batch: bool = True,
        level: int = 1,
        risk: int = 1,
        **kwargs: Any,
    ) -> list[str]:
        binary = self.binary_path()
        args = [binary, "-u", url, "--level", str(level), "--risk", str(risk)]
        if data:
            args += ["--data", data]
        if batch:
            args.append("--batch")
        args += ["--output-dir", "/tmp/sqlmap-output"]
        return args

    def is_success(self, returncode: int) -> bool:
        # sqlmap sort avec un code non nul (1) pour un resultat propre mais
        # negatif ("pas vulnerable") : ce n'est pas un echec d'execution.
        return returncode in (0, 1)

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        # Un seul signal positif, verifie ligne par ligne : la phrase exacte
        # que sqlmap imprime pour un resultat CONFIRME. Ne jamais combiner
        # des mots-cles independants (ex. "parameter" ET "injectable")
        # presents n'importe ou dans la sortie : sqlmap imprime aussi ces
        # deux mots dans ses messages NEGATIFS ("parameter 'id' is NOT
        # injectable"), ce qui a produit un faux CRITICAL confirme lors d'un
        # deploiement reel (voir docs/HISTORY.md, section 6).
        vulnerable = any("is vulnerable" in line.lower() for line in result.stdout.splitlines())
        injection_points = [line.strip() for line in result.stdout.splitlines() if "Parameter:" in line]
        return {"vulnerable": vulnerable, "injection_points": injection_points}
