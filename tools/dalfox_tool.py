"""dalfox : scanner XSS dedie.

Bug reel corrige ici (voir docs/HISTORY.md) : la premiere version de ce
fichier supposait que "toute ligne JSON parsee = vulnerabilite confirmee",
base sur une documentation generique perimee. dalfox a ete entierement
reecrit en Rust (le depot est "Rust", pas Go) et son champ JSON "type" est
un enum a quatre valeurs, confirme en lisant le code source
(`src/scanning/result/mod.rs`) plutot que suppose :
  - "V" (Verified)      : seule valeur representant une vulnerabilite
                           confirmee exploitable.
  - "R" (Reflected)      : payload reflete dans la reponse, position non
                           confirmee exploitable - documente explicitement
                           comme "not a vulnerability assertion".
  - "A" (AstDetected)    : detection XSS DOM par analyse statique JS, une
                           etiquette de methode, pas une confirmation.
  - "I" (Informational)  : observation non-exploitable (ex. bibliotheque
                           obsolete), pas un finding XSS.
Traiter "R"/"A"/"I" comme confirmes aurait produit exactement le meme genre
de faux positif que l'ancien bug sqlmap (docs/HISTORY.md, section 6) - et
l'a effectivement produit lors d'un deploiement reel avant ce correctif.

Flag cookie dedie confirme via la reference CLI du depot : `--cookies`, pas
`--headers "Cookie: ..."` (qui appartenait a l'ancienne CLI Go, perimee).
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
            # "A" et "I" : ni une confirmation ni un signal de reflexion
            # exploitable pour ce projet - ignores.
        return {"vulnerable": bool(verified), "findings": verified, "reflected": reflected}
