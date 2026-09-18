"""Priorite absolue : le coeur deterministe. Chaque regle de CLAUDE.md,

section 7, doit avoir un test qui la verrouille - y compris la regression
directe de l'incident #10 (docs/HISTORY.md).
"""
from core.state import (
    PHASE_ORDER,
    Finding,
    MissionState,
    Severity,
    Target,
    cap_severity,
    compute_overall_risk,
    consolidate_denied_paths,
    enforce_progression,
    is_target_in_allowed_ranges,
)


def make_mission(**overrides) -> MissionState:
    defaults = dict(
        mission_id="m1",
        mission_name="test",
        operator="op",
        authorization_ref="AUTH-1",
        target=Target(host="10.0.0.1"),
    )
    defaults.update(overrides)
    return MissionState(**defaults)


def test_cap_severity_without_exploitation_never_exceeds_medium():
    assert cap_severity(Severity.CRITICAL, exploited=False) == Severity.MEDIUM
    assert cap_severity(Severity.HIGH, exploited=False) == Severity.MEDIUM


def test_cap_severity_with_exploitation_preserves_high_severity():
    assert cap_severity(Severity.CRITICAL, exploited=True) == Severity.CRITICAL
    assert cap_severity(Severity.HIGH, exploited=True) == Severity.HIGH


def test_cap_severity_leaves_low_and_medium_untouched():
    assert cap_severity(Severity.LOW, exploited=False) == Severity.LOW
    assert cap_severity(Severity.MEDIUM, exploited=False) == Severity.MEDIUM


def test_finding_auto_caps_even_if_agent_forgets_to_call_cap_severity():
    """Regression directe de l'incident #10 : un CRITICAL Heartbleed hallucine

    sur Apache httpd a traverse tout le pipeline faute d'un plafonnement
    applique par l'agent de reconnaissance. Meme sans appel explicite a
    cap_severity, le Finding lui-meme doit refuser de laisser passer un
    HIGH/CRITICAL sans preuve d'exploitation.
    """
    finding = Finding(
        title="Apache httpd vulnerable a Heartbleed (hallucine)",
        severity=Severity.CRITICAL,
        description="...",
        affected_component="10.0.0.1:80",
        evidence="",
        discovered_by="recon",
        exploited=False,
    )
    assert finding.severity == Severity.MEDIUM


def test_finding_preserves_critical_when_exploited_true():
    finding = Finding(
        title="Injection SQL confirmee",
        severity=Severity.CRITICAL,
        description="...",
        affected_component="http://x/?id=1",
        evidence="sqlmap output",
        discovered_by="exploit",
        exploited=True,
    )
    assert finding.severity == Severity.CRITICAL


def test_finding_appends_transparency_note_when_severity_is_capped():
    finding = Finding(
        title="Apache httpd vulnerable a Heartbleed (hallucine)",
        severity=Severity.CRITICAL,
        description="Description originale.",
        affected_component="10.0.0.1:80",
        evidence="",
        discovered_by="recon",
        exploited=False,
    )
    assert "Description originale." in finding.description
    assert "plafonnee a MEDIUM" in finding.description
    assert "CRITICAL" in finding.description


def test_finding_no_transparency_note_when_not_capped():
    finding = Finding(
        title="Chemins accessibles",
        severity=Severity.LOW,
        description="Description originale.",
        affected_component="x",
        evidence="",
        discovered_by="enum",
        exploited=False,
    )
    assert finding.description == "Description originale."


def test_finding_clears_cve_without_exploitation_proof():
    finding = Finding(
        title="Suspicion CVE",
        severity=Severity.LOW,
        description="...",
        affected_component="x",
        evidence="",
        discovered_by="recon",
        cve="CVE-2014-0160",
        exploited=False,
    )
    assert finding.cve is None


def test_compute_overall_risk_ignores_leads_and_uses_max_finding_severity():
    findings = [
        Finding("a", Severity.LOW, "", "c", "e", "recon"),
        Finding("b", Severity.MEDIUM, "", "c", "e", "enum"),
    ]
    assert compute_overall_risk(findings) == Severity.MEDIUM


def test_compute_overall_risk_returns_info_when_no_findings():
    assert compute_overall_risk([]) == Severity.INFO


def test_consolidate_denied_paths_merges_22_paths_into_one_low_finding():
    candidate_paths = [{"path": f"/admin{i}", "status_code": 401 if i % 2 else 403} for i in range(22)]
    finding = consolidate_denied_paths(candidate_paths, discovered_by="enum")
    assert finding is not None
    assert finding.severity == Severity.LOW
    assert finding.evidence.count("/admin") == 22


def test_consolidate_denied_paths_returns_none_without_denied_paths():
    candidate_paths = [{"path": "/index.html", "status_code": 200}]
    assert consolidate_denied_paths(candidate_paths, discovered_by="enum") is None


def test_enforce_progression_advances_normally_through_linear_order():
    mission = make_mission()
    next_phase = enforce_progression(mission, "recon", max_cycles=10)
    assert next_phase == "recon"
    assert mission.orchestration_cycles == 1


def test_enforce_progression_forces_report_when_max_cycles_exceeded():
    mission = make_mission()
    mission.orchestration_cycles = 10
    next_phase = enforce_progression(mission, "enum", max_cycles=10)
    assert next_phase == "report"


def test_enforce_progression_forces_end_after_report_once_cycle_limit_hit():
    mission = make_mission(completed_phases=["recon", "enum", "exploit", "postexploit", "report"])
    mission.orchestration_cycles = 10
    next_phase = enforce_progression(mission, "report", max_cycles=10)
    assert next_phase == "end"


def test_enforce_progression_redirects_repeated_phase_to_first_incomplete():
    mission = make_mission(completed_phases=["recon"])
    next_phase = enforce_progression(mission, "recon", max_cycles=10)
    assert next_phase == "enum"


def test_enforce_progression_forces_report_before_allowing_end():
    mission = make_mission(completed_phases=["recon", "enum", "exploit", "postexploit"])
    next_phase = enforce_progression(mission, "end", max_cycles=10)
    assert next_phase == "report"


def test_enforce_progression_allows_end_only_after_report_completed():
    mission = make_mission(completed_phases=list(PHASE_ORDER))
    next_phase = enforce_progression(mission, "end", max_cycles=10)
    assert next_phase == "end"


def test_enforce_progression_treats_invalid_phase_like_a_repeat():
    mission = make_mission(completed_phases=["recon"])
    next_phase = enforce_progression(mission, "not-a-real-phase", max_cycles=10)
    assert next_phase == "enum"


def test_is_target_in_allowed_ranges_unrestricted_when_empty():
    assert is_target_in_allowed_ranges("8.8.8.8", []) is True
    assert is_target_in_allowed_ranges("anything-not-even-an-ip", []) is True


def test_is_target_in_allowed_ranges_accepts_ip_inside_cidr():
    assert is_target_in_allowed_ranges("192.168.1.33", ["192.168.0.0/16"]) is True


def test_is_target_in_allowed_ranges_rejects_ip_outside_cidr():
    assert is_target_in_allowed_ranges("8.8.8.8", ["10.0.0.0/8", "192.168.0.0/16"]) is False


def test_is_target_in_allowed_ranges_fails_closed_on_unresolvable_hostname(monkeypatch):
    import socket

    def fake_gethostbyname(host):
        raise socket.gaierror("nom introuvable")

    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)
    assert is_target_in_allowed_ranges("does-not-resolve.invalid", ["10.0.0.0/8"]) is False
