"""nmap : -Pn systematique (incident #8), SYN scan par defaut, connect scan en repli."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from core.config import get_settings
from .base import BaseTool, ToolResult


class NmapTool(BaseTool):
    name = "nmap"
    binary = "nmap"

    def build_command(self, target: str, mode: str = "ports", **kwargs: Any) -> list[str]:
        settings = get_settings()
        binary = self.binary_path()

        scan_flag = "-sS" if settings.nmap_scan_mode == "syn" else "-sT"
        if scan_flag == "-sS" and not self.is_root():
            # Le SYN scan exige des sockets brutes ; repli automatique sur le
            # connect scan plutot que d'echouer ou d'appeler sudo (incident #9).
            scan_flag = "-sT"

        # -Pn toujours present, sur tous les modes : sans lui, un hote qui
        # bloque l'ICMP (frequent depuis un pont Docker) est vu comme "down"
        # et le scan de ports est saute entierement (incident #8).
        base = [binary, "-Pn"]

        if mode == "discovery":
            return base + ["-sn", target]
        if mode == "vuln":
            return base + [scan_flag, "--script=vuln", "-oX", "-", target]
        return base + [scan_flag, "-sV", "-p-", "-oX", "-", target]

    def parse_output(self, result: ToolResult) -> dict[str, Any]:
        open_ports: list[dict[str, Any]] = []
        os_guess = None
        os_confidence = None
        host_up = False

        if not result.stdout.strip():
            return {"open_ports": open_ports, "os_guess": os_guess, "os_confidence": os_confidence, "host_up": host_up}

        try:
            root = ET.fromstring(result.stdout)
        except ET.ParseError:
            return {"open_ports": open_ports, "os_guess": os_guess, "os_confidence": os_confidence, "host_up": host_up}

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") == "up":
                host_up = True

            for port_el in host.findall("./ports/port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                port_info: dict[str, Any] = {
                    "port": int(port_el.get("portid")),
                    "protocol": port_el.get("protocol"),
                    "service": service_el.get("name") if service_el is not None else "unknown",
                    "product": service_el.get("product", "") if service_el is not None else "",
                    "version": service_el.get("version", "") if service_el is not None else "",
                }
                scripts = [
                    {"id": s.get("id"), "output": s.get("output", "")}
                    for s in port_el.findall("./script")
                ]
                if scripts:
                    port_info["scripts"] = scripts
                open_ports.append(port_info)

            osmatch = host.find("./os/osmatch")
            if osmatch is not None:
                os_guess = osmatch.get("name")
                os_confidence = int(osmatch.get("accuracy", "0")) / 100.0

        return {
            "open_ports": open_ports,
            "os_guess": os_guess,
            "os_confidence": os_confidence,
            "host_up": host_up,
        }
