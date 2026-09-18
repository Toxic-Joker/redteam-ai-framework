"""nuclei : templates communautaires pour une couverture large de problemes

connus (identifiants par defaut, panels exposes, en-tetes de securite,
CVE courantes), chaque correspondance portant sa propre preuve
(commande curl de reproduction). Complement aux outils cibles (sqlmap),
pas un remplacement : nuclei detecte des motifs, il ne confirme jamais une
exploitation - cap_severity s'applique donc systematiquement cote agent,
comme pour tout autre outil.

Flags confirmes via la documentation officielle avant ecriture (voir
CLAUDE.md, section 2, sur la verification du nommage/CLI reel des outils) :
-jsonl pour la sortie JSON Lines sur stdout, -H pour un en-tete personnalise
(pas de flag cookie dedie, contrairement a gobuster/ffuf/sqlmap).
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
