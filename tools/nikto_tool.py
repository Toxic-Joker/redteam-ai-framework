"""nikto : pas de paquet apt fiable (incident #2), wrapper shell sur clone GitHub."""
from __future__ import annotations

from typing import Any, Optional

from .base import BaseTool, ToolResult


class NiktoTool(BaseTool):
    name = "nikto"
    binary = "nikto"

    def build_command(
        self, target: str, port: int = 80, ssl: bool = False, cookie: Optional[str] = None, **kwargs: Any
    ) -> list[str]:
        binary = self.binary_path()
        args = [binary, "-h", target, "-p", str(port), "-Format", "txt", "-output", "-"]
        if ssl:
            args.append("-ssl")
        if cookie:
            args += ["-Header", f"Cookie: {cookie}"]
        return args

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        items: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("+ ") and "requested" not in line.lower():
                items.append(line[2:])
        return {"items": items}
