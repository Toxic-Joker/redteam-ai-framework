"""nuclei: community templates for broad coverage of known issues

(default credentials, exposed panels, security headers, common CVEs), each
match carrying its own evidence (a reproduction curl command). A complement
to the targeted tools (sqlmap), not a replacement: nuclei detects patterns,
it never confirms exploitation - cap_severity therefore still applies
systematically on the agent side, like for any other tool.

Flags confirmed via the official documentation before writing (see
CLAUDE.md, section 2, on verifying a tool's real naming/CLI): -jsonl for
JSON Lines output on stdout, -H for a custom header (no dedicated cookie
flag, unlike gobuster/ffuf/sqlmap).
"""
from __future__ import annotations

import json
from typing import Any, Optional

from .base import BaseTool, ToolResult


class NucleiTool(BaseTool):
    name = "nuclei"
    binary = "nuclei"

    def build_command(
        self, target: str, cookie: Optional[str] = None, severity: Optional[str] = None, **kwargs: Any
    ) -> list[str]:
        binary = self.binary_path()
        args = [binary, "-u", target, "-jsonl", "-silent", "-no-color"]
        if cookie:
            args += ["-H", f"Cookie: {cookie}"]
        if severity:
            args += ["-severity", severity]
        return args

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        matches: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = data.get("info") or {}
            matches.append(
                {
                    "template_id": data.get("template-id", ""),
                    "name": info.get("name", ""),
                    "severity": (info.get("severity") or "info").lower(),
                    "description": info.get("description", ""),
                    "matched_at": data.get("matched-at", ""),
                    "curl_command": data.get("curl-command", ""),
                }
            )
        return {"matches": matches}
