"""Top priority: the deterministic core. Every rule in CLAUDE.md,

section 7, must have a test locking it down - including the direct
regression test for incident #10 (docs/HISTORY.md).
"""
from core.state import (
    PHASE_ORDER,
    Finding,
    Lead,
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
    """Direct regression test for incident #10: a hallucinated CRITICAL

    Heartbleed on Apache httpd made it through the whole pipeline for lack
    of capping applied by the reconnaissance agent. Even with no explicit
    call to cap_severity, the Finding itself must refuse to let a
    HIGH/CRITICAL through without proof of exploitation.
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


def test_add_finding_deduplicates_same_title_component_and_severity():
    mission = make_mission()
    finding_kwargs = dict(
        severity=Severity.LOW, description="d1", affected_component="/admin", evidence="", discovered_by="enum"
    )
    mission.add_finding(Finding(title="Chemins accessibles", **finding_kwargs))
    mission.add_finding(Finding(title="Chemins accessibles", **{**finding_kwargs, "description": "d2"}))
    assert len(mission.findings) == 1
    assert mission.findings[0].description == "d1"  # the first one is kept, not overwritten


def test_add_finding_normalizes_trailing_slash_for_dedup():
    mission = make_mission()
    mission.add_finding(
        Finding(title="X", severity=Severity.LOW, description="", affected_component="/admin/", evidence="", discovered_by="enum")
    )
    mission.add_finding(
        Finding(title="X", severity=Severity.LOW, description="", affected_component="/admin", evidence="", discovered_by="enum")
    )
    assert len(mission.findings) == 1


def test_add_finding_keeps_distinct_severities_separate():
    mission = make_mission()
    mission.add_finding(
        Finding(title="X", severity=Severity.LOW, description="", affected_component="c", evidence="", discovered_by="enum")
    )
    mission.add_finding(
        Finding(title="X", severity=Severity.MEDIUM, description="", affected_component="c", evidence="", discovered_by="enum")
    )
    assert len(mission.findings) == 2


def test_add_lead_deduplicates_same_title_and_source():
    mission = make_mission()
    mission.add_lead(Lead(title="Verifier X", rationale="r1", source="recon", confidence=0.3))
    mission.add_lead(Lead(title="Verifier X", rationale="r2", source="recon", confidence=0.5))
    assert len(mission.leads) == 1
    assert mission.leads[0].rationale == "r1"


def test_add_lead_keeps_same_title_from_different_sources():
    mission = make_mission()
    mission.add_lead(Lead(title="Verifier X", rationale="r1", source="recon", confidence=0.3))
    mission.add_lead(Lead(title="Verifier X", rationale="r2", source="enum", confidence=0.3))
    assert len(mission.leads) == 2


def test_add_finding_redacts_session_cookie_from_evidence_and_description():
    """Defense in depth (docs/HISTORY.md, section 20): nuclei already

    redacts its own curl-command, but sqlmap/dalfox/commix/nikto offer no
    equivalent guarantee on their raw output - nothing must expose the
    session cookie in the clear in a stored Finding.
    """
    mission = make_mission(target=Target(host="10.0.0.1", session_cookie="PHPSESSID=secret123"))
    mission.add_finding(
        Finding(
            title="X",
            severity=Severity.LOW,
            description="Vu avec le cookie PHPSESSID=secret123 dans la requete.",
            affected_component="c",
            evidence="Header envoye : Cookie: PHPSESSID=secret123",
            discovered_by="enum",
        )
    )
    finding = mission.findings[0]
    assert "secret123" not in finding.evidence
    assert "secret123" not in finding.description
    assert "***" in finding.evidence


def test_add_lead_redacts_session_cookie_from_rationale():
    mission = make_mission(target=Target(host="10.0.0.1", session_cookie="PHPSESSID=secret123"))
    mission.add_lead(
        Lead(
            title="X",
            rationale="payload reflete avec le cookie PHPSESSID=secret123",
            source="exploit",
            confidence=0.3,
        )
    )
    assert "secret123" not in mission.leads[0].rationale


def test_add_finding_leaves_evidence_untouched_without_session_cookie():
    mission = make_mission()  # no session_cookie
    mission.add_finding(
        Finding(title="X", severity=Severity.LOW, description="d", affected_component="c", evidence="preuve brute", discovered_by="enum")
    )
    assert mission.findings[0].evidence == "preuve brute"


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


def test_enforce_progression_rejects_a_forward_skip_suggestion():
    """Direct regression test: an LLM suggestion (MissionState.last_decision)

    skipped "enum" to go straight to "exploit" during a real deployment,
    depriving exploit_agent of the URLs enum would have discovered (fewer
    targets tested). A suggestion can no longer ever skip an incomplete
    intermediate phase - only the real next phase, or a direct skip to
    "report" (early completion), is honored.
    """
    mission = make_mission(completed_phases=["recon"])
    next_phase = enforce_progression(mission, "exploit", max_cycles=10)
    assert next_phase == "enum"


def test_enforce_progression_still_honors_an_early_report_suggestion():
    """The only skip that remains allowed: finishing early by going

    directly to "report", since nothing downstream depends on its result.
    """
    mission = make_mission(completed_phases=["recon", "enum"])
    next_phase = enforce_progression(mission, "report", max_cycles=10)
    assert next_phase == "report"


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
        raise socket.gaierror("name not found")

    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)
    assert is_target_in_allowed_ranges("does-not-resolve.invalid", ["10.0.0.0/8"]) is False
