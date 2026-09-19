import asyncio
import json
import sys

import pytest

from tools.base import BaseTool, ToolResult
from tools.commix_tool import CommixTool
from tools.dalfox_tool import DalfoxTool
from tools.ffuf_tool import FfufTool
from tools.gobuster_tool import GobusterTool, resolve_wordlist
from tools.nikto_tool import NiktoTool
from tools.nmap_tool import NmapTool
from tools.nuclei_tool import NucleiTool
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
    """Direct regression test for incident #8: without -Pn, a host that

    blocks ICMP is seen as down and the port scan is skipped entirely.
    """
    tool = NmapTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(NmapTool, "is_root", staticmethod(lambda: True))
    for mode in ("discovery", "ports", "vuln"):
        args = tool.build_command(target="10.0.0.1", mode=mode)
        assert "-Pn" in args


def test_nmap_ports_and_vuln_scans_include_speed_flags(monkeypatch):
    # -T4/--min-rate speed up a full -p- scan without ever reducing its
    # scope (the MVP validation criterion on a non-standard port stays
    # intact) - see docs/HISTORY.md, section 18.
    tool = NmapTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/bin/nmap")
    monkeypatch.setattr(NmapTool, "is_root", staticmethod(lambda: True))
    for mode in ("ports", "vuln"):
        args = tool.build_command(target="10.0.0.1", mode=mode)
        assert "-T4" in args
        assert "--min-rate" in args
    ports_args = tool.build_command(target="10.0.0.1", mode="ports")
    assert "-p-" in ports_args


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
    """Direct regression test for incident #6 (silent enumeration failure)."""
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


def test_gobuster_includes_cookie_flag_when_provided(monkeypatch, tmp_path):
    tool = GobusterTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/bin/gobuster")
    wordlist = tmp_path / "common.txt"
    wordlist.write_text("admin\n")
    args = tool.build_command(target="http://10.0.0.1", wordlist=str(wordlist), cookie="PHPSESSID=abc")
    assert "-c" in args
    assert "PHPSESSID=abc" in args


def test_gobuster_omits_cookie_flag_when_absent(monkeypatch, tmp_path):
    tool = GobusterTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/bin/gobuster")
    wordlist = tmp_path / "common.txt"
    wordlist.write_text("admin\n")
    args = tool.build_command(target="http://10.0.0.1", wordlist=str(wordlist))
    assert "-c" not in args


def test_ffuf_includes_cookie_flag_when_provided(monkeypatch, tmp_path):
    tool = FfufTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/bin/ffuf")
    wordlist = tmp_path / "common.txt"
    wordlist.write_text("admin\n")
    args = tool.build_command(target="http://10.0.0.1", wordlist=str(wordlist), cookie="PHPSESSID=abc")
    assert "-b" in args
    assert "PHPSESSID=abc" in args


def test_nikto_build_command_includes_ssl_flag_when_requested(monkeypatch):
    tool = NiktoTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/local/bin/nikto")
    args = tool.build_command(target="10.0.0.1", port=443, ssl=True)
    assert "-ssl" in args
    assert "10.0.0.1" in args


def test_nikto_includes_static_cookie_option_when_provided(monkeypatch):
    # nikto 2.5.0 has no -Header option (verified in its real GetOptions);
    # an invalid -Header makes nikto fall into usage() and exit with code
    # 0, which silently masks the scan failure (documented incident).
    tool = NiktoTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/local/bin/nikto")
    args = tool.build_command(target="10.0.0.1", port=80, cookie="PHPSESSID=abc; security=low")
    assert "-Header" not in args
    assert "-Option" in args
    assert 'STATIC-COOKIE="PHPSESSID=abc";"security=low"' in args


def test_nikto_omits_option_flag_when_cookie_absent(monkeypatch):
    tool = NiktoTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/local/bin/nikto")
    args = tool.build_command(target="10.0.0.1", port=80)
    assert "-Option" not in args


def test_nikto_includes_maxtime_bound(monkeypatch):
    # Bounds the worst case (slow/verbose site) without changing what
    # nikto finds on a normal target - see docs/HISTORY.md, section 18.
    tool = NiktoTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/local/bin/nikto")
    args = tool.build_command(target="10.0.0.1", port=80)
    assert "-maxtime" in args


def test_nikto_parse_output_ignores_usage_screen_legend_line():
    tool = NiktoTool()
    result = ToolResult(
        tool="nikto",
        command=["nikto"],
        stdout="+ Target IP: 10.0.0.1\n+ requires a value\n+ /admin/: Admin login page found.\n",
        stderr="",
        returncode=0,
        success=True,
    )
    parsed = tool.parse_output(result)
    assert "requires a value" not in parsed["items"]
    assert "/admin/: Admin login page found." in parsed["items"]


def test_sqlmap_build_command_is_batch_by_default(monkeypatch):
    tool = SqlmapTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/local/bin/sqlmap")
    args = tool.build_command(url="http://10.0.0.1/?id=1")
    assert "--batch" in args


def test_sqlmap_includes_cookie_flag_when_provided(monkeypatch):
    tool = SqlmapTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/local/bin/sqlmap")
    args = tool.build_command(url="http://10.0.0.1/?id=1", cookie="PHPSESSID=abc; security=low")
    assert "--cookie" in args
    assert "PHPSESSID=abc; security=low" in args


def test_sqlmap_omits_cookie_flag_when_absent(monkeypatch):
    tool = SqlmapTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/local/bin/sqlmap")
    args = tool.build_command(url="http://10.0.0.1/?id=1")
    assert "--cookie" not in args


def test_sqlmap_does_not_flag_negative_result_as_vulnerable():
    """Direct regression test: a real deployment scanned the framework's

    own root route (wrong target, not DVWA) and got a fabricated CRITICAL
    because the parsing combined "parameter" and "injectable" anywhere in
    the output - including in sqlmap's NEGATIVE message. See
    docs/HISTORY.md, section 6, incident 3.
    """
    tool = SqlmapTool()
    stdout = (
        "[INFO] testing 'AND boolean-based blind'\n"
        "[WARNING] GET parameter 'id' does not seem to be injectable\n"
        "[CRITICAL] all tested parameters do not appear to be injectable\n"
        "GET parameter 'id' is NOT injectable\n"
    )
    result = ToolResult(tool="sqlmap", command=[], returncode=1, stdout=stdout, stderr="", success=True)
    parsed = tool.parse_output(result)
    assert parsed["vulnerable"] is False


def test_sqlmap_flags_genuine_positive_result_as_vulnerable():
    tool = SqlmapTool()
    stdout = (
        "[INFO] testing 'AND boolean-based blind'\n"
        "GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N\n"
        "Parameter: id (GET)\n"
    )
    result = ToolResult(tool="sqlmap", command=[], returncode=0, stdout=stdout, stderr="", success=True)
    parsed = tool.parse_output(result)
    assert parsed["vulnerable"] is True


def test_sqlmap_is_success_accepts_clean_not_vulnerable_exit_code():
    tool = SqlmapTool()
    assert tool.is_success(0) is True
    assert tool.is_success(1) is True
    assert tool.is_success(2) is False


def test_ffuf_parses_json_results():
    tool = FfufTool()
    payload = json.dumps({"results": [{"input": {"FUZZ": "admin"}, "status": 403, "length": 10}]})
    result = ToolResult(tool="ffuf", command=[], returncode=0, stdout=payload, stderr="", success=True)
    parsed = tool.parse_output(result)
    assert parsed["paths"] == [{"path": "/admin", "status_code": 403, "length": 10}]


def test_is_root_never_raises_on_any_platform():
    assert BaseTool.is_root() in (True, False)


class _SleepTool(BaseTool):
    name = "sleep"
    binary = sys.executable

    def build_command(self, marker_path: str, **kwargs):
        return [sys.executable, "-c", f"import time; time.sleep(5); open({marker_path!r}, 'w').close()"]

    def parse_output(self, result: ToolResult) -> dict:
        return {}


@pytest.mark.asyncio
async def test_cancelling_a_tool_run_kills_the_subprocess_instead_of_orphaning_it(tmp_path):
    """A cancelled mission (POST .../abort) must never leave an external

    tool process (nmap, gobuster, ...) running in the background.
    """
    marker = tmp_path / "done.marker"
    tool = _SleepTool()

    task = asyncio.create_task(tool.run(marker_path=str(marker)))
    await asyncio.sleep(0.3)  # let the subprocess actually start
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    await asyncio.sleep(0.3)  # let the kill propagate
    assert not marker.exists()  # the subprocess never reached the end of its sleep(5)


def test_nuclei_build_command_uses_jsonl_and_no_cookie_flag(monkeypatch):
    tool = NucleiTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/local/bin/nuclei")
    args = tool.build_command(target="http://10.0.0.1", cookie="PHPSESSID=abc")
    assert "-jsonl" in args
    # nuclei has no dedicated cookie flag: it goes through a generic header.
    assert "-H" in args
    assert "Cookie: PHPSESSID=abc" in args
    assert "-cookie" not in args


def test_nuclei_omits_header_flag_without_cookie(monkeypatch):
    tool = NucleiTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/local/bin/nuclei")
    args = tool.build_command(target="http://10.0.0.1")
    assert "-H" not in args


def test_nuclei_parses_jsonl_matches():
    tool = NucleiTool()
    stdout = "\n".join(
        [
            json.dumps(
                {
                    "template-id": "exposed-panel",
                    "info": {"name": "Exposed Admin Panel", "severity": "high", "description": "desc"},
                    "matched-at": "http://10.0.0.1/admin",
                    "curl-command": "curl http://10.0.0.1/admin",
                }
            ),
            "",  # empty line, must be ignored without crashing
            "not json at all",  # malformed line, must be ignored without crashing
        ]
    )
    result = ToolResult(tool="nuclei", command=[], returncode=0, stdout=stdout, stderr="", success=True)
    parsed = tool.parse_output(result)
    assert len(parsed["matches"]) == 1
    match = parsed["matches"][0]
    assert match["template_id"] == "exposed-panel"
    assert match["name"] == "Exposed Admin Panel"
    assert match["severity"] == "high"
    assert match["matched_at"] == "http://10.0.0.1/admin"


def test_dalfox_build_command_uses_scan_subcommand_and_cookies_flag(monkeypatch):
    tool = DalfoxTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/local/bin/dalfox")
    args = tool.build_command(url="http://10.0.0.1/?q=1", cookie="PHPSESSID=abc")
    assert args[1] == "scan"
    assert "-f" in args and "jsonl" in args
    assert "--cookies" in args
    assert "PHPSESSID=abc" in args
    assert "--headers" not in args  # belonged to the old, outdated Go CLI


def test_dalfox_flags_verified_type_as_vulnerable():
    tool = DalfoxTool()
    stdout = json.dumps({"type": "V", "param": "q", "payload": "<script>alert(1)</script>", "severity": "High"})
    result = ToolResult(tool="dalfox", command=[], returncode=0, stdout=stdout, stderr="", success=True)
    parsed = tool.parse_output(result)
    assert parsed["vulnerable"] is True
    assert parsed["findings"][0]["param"] == "q"


def test_dalfox_does_not_flag_reflected_type_as_vulnerable():
    """Direct regression test: dalfox documents "R" (Reflected) as "not a

    vulnerability assertion" - yet a real deployment produced a fabricated
    CRITICAL because every parsed JSON line was treated as a confirmation,
    regardless of its "type". See docs/HISTORY.md.
    """
    tool = DalfoxTool()
    stdout = json.dumps({"type": "R", "param": "q", "payload": "<script>alert(1)</script>", "severity": "High"})
    result = ToolResult(tool="dalfox", command=[], returncode=0, stdout=stdout, stderr="", success=True)
    parsed = tool.parse_output(result)
    assert parsed["vulnerable"] is False
    assert parsed["findings"] == []
    assert len(parsed["reflected"]) == 1


def test_dalfox_ignores_informational_and_ast_detected_types():
    tool = DalfoxTool()
    stdout = "\n".join(
        [
            json.dumps({"type": "I", "param": "", "payload": ""}),
            json.dumps({"type": "A", "param": "q", "payload": ""}),
        ]
    )
    result = ToolResult(tool="dalfox", command=[], returncode=0, stdout=stdout, stderr="", success=True)
    parsed = tool.parse_output(result)
    assert parsed["vulnerable"] is False
    assert parsed["findings"] == []
    assert parsed["reflected"] == []


def test_dalfox_no_output_means_not_vulnerable():
    tool = DalfoxTool()
    result = ToolResult(tool="dalfox", command=[], returncode=0, stdout="", stderr="", success=True)
    parsed = tool.parse_output(result)
    assert parsed["vulnerable"] is False


def test_commix_build_command_uses_sqlmap_style_flags(monkeypatch):
    tool = CommixTool()
    monkeypatch.setattr(tool, "binary_path", lambda: "/usr/local/bin/commix")
    args = tool.build_command(url="http://10.0.0.1/?cmd=1", cookie="PHPSESSID=abc", data="a=1")
    assert "-u" in args
    assert "--cookie" in args and "PHPSESSID=abc" in args
    assert "--data" in args and "a=1" in args
    assert "--batch" in args


def test_commix_does_not_flag_negative_result_as_vulnerable():
    tool = CommixTool()
    stdout = "Detected a false positive or unexploitable injection point\nGET parameter 'cmd' seems unaffected.\n"
    result = ToolResult(tool="commix", command=[], returncode=0, stdout=stdout, stderr="", success=True)
    parsed = tool.parse_output(result)
    assert parsed["vulnerable"] is False


def test_commix_flags_genuine_positive_result_as_vulnerable():
    tool = CommixTool()
    stdout = "The (GET) 'cmd' parameter is vulnerable to Results-based Command Injection.\n"
    result = ToolResult(tool="commix", command=[], returncode=0, stdout=stdout, stderr="", success=True)
    parsed = tool.parse_output(result)
    assert parsed["vulnerable"] is True


def test_commix_is_success_accepts_clean_not_vulnerable_exit_code():
    tool = CommixTool()
    assert tool.is_success(0) is True
    assert tool.is_success(1) is True
    assert tool.is_success(2) is False
