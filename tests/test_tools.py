import json

import pytest

from tools.base import BaseTool, ToolResult
from tools.ffuf_tool import FfufTool
from tools.gobuster_tool import GobusterTool, resolve_wordlist
from tools.nikto_tool import NiktoTool
from tools.nmap_tool import NmapTool
from tools.sqlmap_tool import SqlmapTool

NMAP_XML_SAMPLE = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="8888">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_always_includes_pn_flag(monkeypatch):
    """Regression directe de l'incident #8 : sans -Pn, un hote qui bloque

    l'ICMP est vu comme down et le scan de ports est saute entierement.
    """
    tool = NmapTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(NmapTool, "is_root", staticmethod(lambda: True))
    for mode in ("discovery", "ports", "vuln"):
        args = tool.build_command(target="10.0.0.1", mode=mode)
        assert "-Pn" in args


def test_nmap_falls_back_to_connect_scan_without_root(monkeypatch):
    tool = NmapTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(NmapTool, "is_root", staticmethod(lambda: False))
    args = tool.build_command(target="10.0.0.1", mode="ports")
    assert "-sT" in args
    assert "-sS" not in args


def test_nmap_parses_open_port_on_nonstandard_port_with_icmp_down_host():
    tool = NmapTool()
    result = ToolResult(tool="nmap", command=[], returncode=0, stdout=NMAP_XML_SAMPLE, stderr="", success=True)
    parsed = tool.parse_output(result)
    assert parsed["open_ports"] == [
        {"port": 8888, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.18.0"}
    ]
    assert parsed["host_up"] is True


def test_gobuster_binary_name_is_never_gobuster3():
    """Regression directe de l'incident #6 (echec silencieux de l'enumeration)."""
    assert GobusterTool.binary == "gobuster"


def test_gobuster_wordlist_resolution_raises_when_nothing_exists(tmp_path, monkeypatch):
    monkeypatch.setattr("tools.gobuster_tool.KNOWN_WORDLIST_PATHS", [str(tmp_path / "nope.txt")])
    with pytest.raises(FileNotFoundError):
        resolve_wordlist(None)


def test_gobuster_wordlist_resolution_falls_back_to_known_path(tmp_path, monkeypatch):
    existing = tmp_path / "common.txt"
    existing.write_text("admin\n")
    monkeypatch.setattr("tools.gobuster_tool.KNOWN_WORDLIST_PATHS", [str(existing)])
    assert resolve_wordlist(None) == str(existing)


def test_gobuster_parses_status_codes():
    tool = GobusterTool()
    stdout = "/admin                (Status: 403)\n/index.html           (Status: 200)\n"
    result = ToolResult(tool="gobuster", command=[], returncode=0, stdout=stdout, stderr="", success=True)
    parsed = tool.parse_output(result)
    assert {"path": "/admin", "status_code": 403} in parsed["paths"]
    assert {"path": "/index.html", "status_code": 200} in parsed["paths"]


def test_nikto_build_command_includes_ssl_flag_when_requested(monkeypatch):
    tool = NiktoTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/local/bin/nikto")
    args = tool.build_command(target="10.0.0.1", port=443, ssl=True)
    assert "-ssl" in args
    assert "10.0.0.1" in args


def test_sqlmap_build_command_is_batch_by_default(monkeypatch):
    tool = SqlmapTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/local/bin/sqlmap")
    args = tool.build_command(url="http://10.0.0.1/?id=1")
    assert "--batch" in args


def test_ffuf_parses_json_results():
    tool = FfufTool()
    payload = json.dumps({"results": [{"input": {"FUZZ": "admin"}, "status": 403, "length": 10}]})
    result = ToolResult(tool="ffuf", command=[], returncode=0, stdout=payload, stderr="", success=True)
    parsed = tool.parse_output(result)
    assert parsed["paths"] == [{"path": "/admin", "status_code": 403, "length": 10}]


def test_is_root_never_raises_on_any_platform():
    assert BaseTool.is_root() in (True, False)
