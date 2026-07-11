"""
Tests for compliance_map — resolution, scored benchmark, scorecard.

Run:  python -m pytest tests/ -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import compliance_map as cm  # noqa: E402


def _f(check_id, severity="HIGH", device_type="ios", **kw):
    base = dict(check_id=check_id, title=check_id, severity=severity, category="Test",
                description="d", affected_items=["x"], remediation="r", references=[],
                details={}, device="rtr", device_type=device_type)
    base.update(kw)
    base["compliance"] = cm.resolve_compliance(check_id)
    return base


# ── resolution ───────────────────────────────────────────────────────────────

def test_resolve_exact_then_family_then_meta():
    # exact per-check entry wins
    r = cm.resolve_compliance("MGMT-010")
    assert "CIS" in r and "1.3.1" in r["CIS"]
    assert "NIST" in r
    # an unmapped id in a known family falls back to the family prefix
    fam = cm.resolve_compliance("MGMT-999")
    assert fam and "NIST" in fam       # family "MGMT" fallback
    # CVE family fallback
    assert "SI-2" in cm.resolve_compliance("CISCO-CVE-999").get("NIST", [])
    # meta / skip notices carry no compliance
    assert cm.resolve_compliance("MANAGEMENT-META-001") == {}
    assert cm.resolve_compliance("") == {}


def test_crosswalk_data_loaded():
    assert len(cm.COMPLIANCE_MAP) > 100      # per-check + family entries merged
    assert len(cm.CHECK_PLATFORMS) > 100


# ── benchmark ─────────────────────────────────────────────────────────────────

def test_benchmark_structure_and_fail_logic():
    findings = [_f("MGMT-010", "HIGH"), _f("LOG-001", "MEDIUM")]
    bm = cm.benchmark_score("NIST", findings)
    assert bm["framework"] == "NIST"
    assert bm["total_controls"] > 0
    assert bm["passed"] + bm["failed"] == bm["total_controls"]
    # the controls MGMT-010 maps to must be FAIL; every control has PASS/FAIL
    failed = {c["control"] for c in bm["controls"] if c["status"] == "FAIL"}
    for ctrl in cm.resolve_compliance("MGMT-010")["NIST"]:
        assert ctrl in failed
    assert all(c["status"] in ("PASS", "FAIL") for c in bm["controls"])


def test_benchmark_denominator_is_full_universe_not_just_failed():
    # one finding fails a few controls; the denominator is the WHOLE mapped universe
    bm = cm.benchmark_score("CIS", [_f("MGMT-010")])
    assert bm["total_controls"] > bm["failed"]        # most controls pass
    assert bm["score_pct"] == round(bm["passed"] / bm["total_controls"] * 100)


def test_benchmark_excludes_info_and_meta():
    # an INFO finding and a META finding must not fail any control
    findings = [_f("MGMT-010", "INFO"), _f("MANAGEMENT-META-001", "INFO")]
    bm = cm.benchmark_score("NIST", findings)
    assert bm["failed"] == 0 and bm["score_pct"] == 100


def test_benchmark_unknown_framework_raises():
    import pytest
    with pytest.raises(ValueError):
        cm.benchmark_score("NONSENSE", [])


def test_platform_scoping_restricts_universe():
    findings = [_f("MGMT-010", "HIGH", device_type="ios")]
    full = cm.benchmark_score("NIST", findings)
    asa = cm.benchmark_score("NIST", findings, platform="asa")
    # ASA universe excludes IOS-only checks -> smaller (or equal) universe
    assert asa["total_controls"] <= full["total_controls"]
    assert asa["platform"] == "asa"


# ── scorecard ─────────────────────────────────────────────────────────────────

def test_scorecard_rollup():
    sc = cm.compliance_scorecard([_f("MGMT-010", "HIGH"), _f("LOG-001", "MEDIUM")])
    assert set(sc) == set(cm.FRAMEWORKS)
    assert sc["NIST"]["failing_controls"] > 0
    assert sc["NIST"]["worst_severity"] == "HIGH"
