"""dalfox: dedicated XSS scanner.

A real bug fixed here (see docs/HISTORY.md): this file's first version
assumed "any parsed JSON line = confirmed vulnerability", based on outdated
generic documentation. dalfox has been entirely rewritten in Rust (the repo
is "Rust", not Go) and its JSON "type" field is a four-value enum,
confirmed by reading the source code (`src/scanning/result/mod.rs`) rather
than assumed:
  - "V" (Verified)     : the only value representing a confirmed,
                          exploitable vulnerability.
  - "R" (Reflected)     : a payload reflected in the response, position not
                          confirmed exploitable - explicitly documented as
                          "not a vulnerability assertion".
  - "A" (AstDetected)   : DOM XSS detection via static JS analysis, a
                          method label, not a confirmation.
  - "I" (Informational) : a non-exploitable observation (e.g. an outdated
                          library), not an XSS finding.
Treating "R"/"A"/"I" as confirmed would have produced exactly the same kind
of false positive as the old sqlmap bug (docs/HISTORY.md, section 6) - and
actually did produce one in a real deployment before this fix.

Dedicated cookie flag confirmed via the repo's CLI reference: `--cookies`,
not `--headers "Cookie: ..."` (which belonged to the old, outdated Go CLI).
"""
from __future__ import annotations

import json
from typing import Any, Optional

from .base import BaseTool, ToolResult

VERIFIED_TYPE = "V"
REFLECTED_TYPE = "R"


class DalfoxTool(BaseTool):
    name = "dalfox"
    binary = "dalfox"

    def build_command(self, url: str, cookie: Optional[str] = None, **kwargs: Any) -> list[str]:
        binary = self.binary_path()
        args = [binary, "scan", url, "-f", "jsonl"]
        if cookie:
            args += ["--cookies", cookie]
        return args

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        verified: list[dict[str, Any]] = []
        reflected: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            entry = {
                "param": data.get("param", ""),
                "payload": data.get("payload", ""),
                "evidence": data.get("evidence", ""),
                "severity": (data.get("severity") or "medium").lower(),
                "cwe": data.get("cwe", ""),
            }
            finding_type = data.get("type")
            if finding_type == VERIFIED_TYPE:
                verified.append(entry)
            elif finding_type == REFLECTED_TYPE:
                reflected.append(entry)
            # "A" and "I": neither a confirmation nor an actionable
            # reflection signal for this project - ignored.
        return {"vulnerable": bool(verified), "findings": verified, "reflected": reflected}
