"""sqlmap: no reliable apt package (incident #3), shell wrapper on a GitHub clone."""
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
        cookie: Optional[str] = None,
        **kwargs: Any,
    ) -> list[str]:
        binary = self.binary_path()
        args = [binary, "-u", url, "--level", str(level), "--risk", str(risk)]
        if data:
            args += ["--data", data]
        if cookie:
            args += ["--cookie", cookie]
        if batch:
            args.append("--batch")
        args += ["--output-dir", "/tmp/sqlmap-output"]
        return args

    def is_success(self, returncode: int) -> bool:
        # sqlmap exits with a non-zero code (1) for a clean but negative
        # result ("not vulnerable"): this isn't an execution failure.
        return returncode in (0, 1)

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        # A single positive signal, checked line by line: the exact phrase
        # sqlmap prints for a CONFIRMED result. Never combine independent
        # keywords (e.g. "parameter" AND "injectable") present anywhere in
        # the output: sqlmap also prints both words in its NEGATIVE
        # messages ("parameter 'id' is NOT injectable"), which produced a
        # confirmed false CRITICAL in a real deployment (see
        # docs/HISTORY.md, section 6).
        vulnerable = any("is vulnerable" in line.lower() for line in result.stdout.splitlines())
        injection_points = [line.strip() for line in result.stdout.splitlines() if "Parameter:" in line]
        return {"vulnerable": vulnerable, "injection_points": injection_points}
