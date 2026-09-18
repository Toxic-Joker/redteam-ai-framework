"""dalfox : scanner XSS dedie (reflechi), meme logique de preuve que sqlmap -

dalfox n'emet une entree JSON que pour une vulnerabilite reellement
confirmee, jamais pour un diagnostic negatif, donc "au moins une entree
parsee" est un signal positif fiable ici (contrairement a sqlmap/commix, qui
impriment du texte de diagnostic quel que soit le resultat et exigent un
mot-cle positif explicite).

Flags confirmes via la documentation officielle avant ecriture : sous-
commande `scan`, `-f jsonl` pour la sortie JSON Lines, `--headers` pour un
en-tete personnalise (pas de flag cookie dedie, comme nuclei).
"""
from __future__ import annotations

import json
from typing import Any, Optional

from .base import BaseTool, ToolResult


class DalfoxTool(BaseTool):
    name = "dalfox"
    binary = "dalfox"

    def build_command(self, url: str, cookie: Optional[str] = None, **kwargs: Any) -> list[str]:
        binary = self.binary_path()
        args = [binary, "scan", url, "-f", "jsonl", "--silence"]
        if cookie:
            args += ["--headers", f"Cookie: {cookie}"]
        return args

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append(
                {
                    "type": data.get("type", ""),
                    "param": data.get("param", ""),
                    "payload": data.get("payload", ""),
                    "evidence": data.get("evidence", ""),
                    "severity": (data.get("severity") or "medium").lower(),
                    "cwe": data.get("cwe", ""),
                }
            )
        return {"vulnerable": bool(findings), "findings": findings}
