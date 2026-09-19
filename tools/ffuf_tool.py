"""ffuf: GitHub release binary, JSON output for reliable parsing."""
from __future__ import annotations

import json
from typing import Any, Optional

from .base import BaseTool, ToolResult
from .gobuster_tool import resolve_wordlist


class FfufTool(BaseTool):
    name = "ffuf"
    binary = "ffuf"

    def build_command(
        self, target: str, wordlist: Optional[str] = None, cookie: Optional[str] = None, **kwargs: Any
    ) -> list[str]:
        binary = self.binary_path()
        wl = resolve_wordlist(wordlist)
        url = target.rstrip("/") + "/FUZZ"
        # -t 80: same reasoning as gobuster (see gobuster_tool.py) - ffuf
        # runs concurrently with the other enumeration tools, not alone.
        args = [binary, "-u", url, "-w", wl, "-t", "80", "-of", "json", "-o", "-", "-s"]
        if cookie:
            args += ["-b", cookie]
        return args

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        paths: list[dict[str, Any]] = []
        try:
            data = json.loads(result.stdout)
            for r in data.get("results", []):
                paths.append(
                    {
                        "path": "/" + r.get("input", {}).get("FUZZ", ""),
                        "status_code": r.get("status"),
                        "length": r.get("length"),
                    }
                )
        except (json.JSONDecodeError, AttributeError):
            pass
        return {"paths": paths}
