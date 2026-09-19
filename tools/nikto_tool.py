"""nikto: no reliable apt package (incident #2), shell wrapper on a GitHub clone."""
from __future__ import annotations

from typing import Any, Optional

from core.config import get_settings

from .base import BaseTool, ToolResult


class NiktoTool(BaseTool):
    name = "nikto"
    binary = "nikto"

    def build_command(
        self, target: str, port: int = 80, ssl: bool = False, cookie: Optional[str] = None, **kwargs: Any
    ) -> list[str]:
        binary = self.binary_path()
        settings = get_settings()
        # -maxtime is a real nikto flag (GetOptions: "maxtime=s"), designed
        # for exactly this case: bounds the worst case on a slow/verbose
        # site without changing what nikto finds on a normal target (see
        # docs/HISTORY.md, section 18).
        args = [
            binary, "-h", target, "-p", str(port), "-Format", "txt", "-output", "-",
            "-maxtime", settings.nikto_max_time,
        ]
        if ssl:
            args.append("-ssl")
        if cookie:
            # nikto 2.5.0 has no -Header option (verified in the real
            # GetOptions of program/plugins/nikto_core.plugin - absent
            # from the list). The only documented mechanism to inject a
            # cookie is the STATIC-COOKIE config key (nikto.conf.default),
            # passed via -Option, which only splits on the first "=";
            # each name=value pair must be quoted, separated by ";".
            # An invalid -Header makes GetOptions fail -> usage() -> an
            # undefined exit (numified to 0, so perceived as a success):
            # nikto then never scans anything, and the displayed help text
            # gets mistaken for a real finding.
            pairs = [p.strip() for p in cookie.split(";") if p.strip()]
            static_cookie = ";".join(f'"{p}"' for p in pairs)
            args += ["-Option", f"STATIC-COOKIE={static_cookie}"]
        return args

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        # "+ requires a value" is the last line of nikto's help screen (the
        # legend for the "+" suffix used throughout the option list), never
        # a real finding: a safety net in case a future invalid option
        # makes nikto fall into usage() again (see build_command).
        items: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line == "+ requires a value":
                continue
            if line.startswith("+ ") and "requested" not in line.lower():
                items.append(line[2:])
        return {"items": items}
