"""nikto : pas de paquet apt fiable (incident #2), wrapper shell sur clone GitHub."""
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
        # -maxtime est un flag reel de nikto (GetOptions: "maxtime=s"), pense
        # pour ce cas exact : bornes le pire cas d'un site lent/verbeux sans
        # changer ce que nikto trouve sur une cible normale (voir
        # docs/HISTORY.md, section 18).
        args = [
            binary, "-h", target, "-p", str(port), "-Format", "txt", "-output", "-",
            "-maxtime", settings.nikto_max_time,
        ]
        if ssl:
            args.append("-ssl")
        if cookie:
            # nikto 2.5.0 n'a pas d'option -Header (verifie dans le GetOptions reel de
            # program/plugins/nikto_core.plugin - absent de la liste). Le seul mecanisme
            # documente pour injecter un cookie est la cle de config STATIC-COOKIE
            # (nikto.conf.default), passee via -Option qui ne coupe que sur le premier
            # "=" ; chaque paire nom=valeur doit etre entre guillemets, separee par ";".
            # Un -Header invalide fait echouer GetOptions -> usage() -> exit indefini
            # (numifie a 0, donc percu comme un succes) : nikto ne scanne alors jamais
            # rien, et le texte d'aide affiche est confondu avec un vrai finding.
            pairs = [p.strip() for p in cookie.split(";") if p.strip()]
            static_cookie = ";".join(f'"{p}"' for p in pairs)
            args += ["-Option", f"STATIC-COOKIE={static_cookie}"]
        return args

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        # "+ requires a value" est la derniere ligne de l'ecran d'aide de nikto
        # (legende du suffixe "+" dans la liste d'options), jamais un vrai
        # finding : filet de securite si une future option invalide fait a
        # nouveau tomber nikto dans usage() (voir build_command).
        items: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line == "+ requires a value":
                continue
            if line.startswith("+ ") and "requested" not in line.lower():
                items.append(line[2:])
        return {"items": items}
