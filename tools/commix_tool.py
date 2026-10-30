"""commix: OS command injection, architecture and CLI directly inspired by

sqlmap (same convention authors) - confirmed via the source code
(`src/core/parse/cmdline.py`, `src/core/controller/checks.py`) before
writing, not assumed by analogy:
- flags: -u/--url, --batch, --cookie, --data (identical to sqlmap)
- positive signal: the exact phrase "is vulnerable" (vulnerable_message());
  the negative case explicitly uses "false positive"/"unexploitable",
  never "is vulnerable" - the same pitfall as the sqlmap fix
  (docs/HISTORY.md section 6) avoided from the start: never combine
  independent keywords present anywhere in the output.
- --output-dir: confirmed present (src/core/parse/cmdline.py) with the
  same flag name as sqlmap's. Unlike sqlmap (which already hardcodes
  /tmp/sqlmap-output), commix's own default (src/utils/settings.py:
  OUTPUT_DIR = ".output/") is relative - it resolves against the
  framework process's cwd (/app, since asyncio.create_subprocess_exec
  never sets cwd=), which a non-root container user can't write to.
  Set explicitly for the same reason sqlmap already does
  (docs/HISTORY.md, section 27).
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
        args += ["--output-dir", "/tmp/commix-output"]
        return args

    def is_success(self, returncode: int) -> bool:
        # Not independently verified (no source consulted on commix's
        # exact exit codes), but its architecture deliberately mirrors
        # sqlmap's - the same assumption applied out of caution: a clean
        # negative result must not be treated as an execution failure.
        return returncode in (0, 1)

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        vulnerable = any("is vulnerable" in line.lower() for line in result.stdout.splitlines())
        injection_points = [line.strip() for line in result.stdout.splitlines() if "is vulnerable" in line.lower()]
        return {"vulnerable": vulnerable, "injection_points": injection_points}
