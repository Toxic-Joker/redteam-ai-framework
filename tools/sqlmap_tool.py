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

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        stdout_lower = result.stdout.lower()
        vulnerable = "is vulnerable" in stdout_lower or ("parameter" in stdout_lower and "injectable" in stdout_lower)
        injection_points = [line.strip() for line in result.stdout.splitlines() if "Parameter:" in line]
        return {"vulnerable": vulnerable, "injection_points": injection_points}
