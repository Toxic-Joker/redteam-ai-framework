"""gobuster: a single binary name ('gobuster', never 'gobuster3', incident #6)."""
from __future__ import annotations

import os
import re
from typing import Any, Optional

from .base import BaseTool, ToolResult

KNOWN_WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/app/wordlists/common.txt",
]


def resolve_wordlist(explicit: Optional[str] = None) -> str:
    """Checks that the wordlist actually exists, falling back to a known path."""
    candidates = [explicit] if explicit else []
    candidates += KNOWN_WORDLIST_PATHS
    for path in candidates:
        if path and os.path.exists(path):
            return path
    raise FileNotFoundError(
        "Aucune wordlist gobuster trouvee. Chemins essayes: " + ", ".join(c for c in candidates if c)
    )


class GobusterTool(BaseTool):
    name = "gobuster"
    binary = "gobuster"

    def build_command(
        self,
        target: str,
        wordlist: Optional[str] = None,
        extensions: str = "",
        cookie: Optional[str] = None,
        **kwargs: Any,
    ) -> list[str]:
        binary = self.binary_path()
        wl = resolve_wordlist(wordlist)
        # -t 50: gobuster now runs concurrently with the 4 other
        # enumeration tools (see enum_agent.py), the conservative default
        # of 10 threads no longer needs to dominate the phase's total time.
        args = [binary, "dir", "-u", target, "-w", wl, "-t", "50", "-q", "-n", "-o", "-"]
        if extensions:
            args += ["-x", extensions]
        if cookie:
            args += ["-c", cookie]
        return args

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        paths: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            m = re.match(r"^(/\S*)\s+\(Status:\s*(\d+)\)", line.strip())
            if m:
                paths.append({"path": m.group(1), "status_code": int(m.group(2))})
        return {"paths": paths}
