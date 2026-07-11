"""
Tests for risk_prioritizer — ThreatIntel, scoring, KEV floor, reachability gating.

Run:  python -m pytest tests/ -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import risk_prioritizer as rp  # noqa: E402


def _f(check_id, severity="HIGH", category="Management Plane", name="", cve=None, items=None):
    f = dict(check_id=check_id, title=(name or check_id), severity=severity, category=category,
             description="d", affected_items=items or ["x"], remediation="r", references=[],
             details={}, device="rtr", device_type="ios")
    if cve:
        f["details"]["cve"] = cve
    return f


class _FakeIntel(rp.ThreatIntel):
    def __init__(self, cves):
        self.path = None
        self.meta = {"snapshot_date": "2026-07-11"}
        self.cves = {k.upper(): v for k, v in cves.items()}


# ── ThreatIntel ────────────────────────────────────────────────────────────

def test_bundled_intel_loads():
    intel = rp.ThreatIntel()
    assert intel.available
    assert intel.kev_count >= 1
    assert intel.meta.get("cve_count") == len(intel.cves)


def test_intel_missing_degrades():
    intel = rp.ThreatIntel(path="/nonexistent/threat_intel.json")
    assert not intel.available and intel.get("CVE-2020-3452") is None


# ── scoring ───────────────────────────────────────────────────────────────

def test_severity_base_points():
    pz = rp.RiskPrioritizer(_FakeIntel({}))
    assert pz.assess(_f("A", "CRITICAL")).score == 50   # no KEV/exposure -> base only
    assert pz.assess(_f("A", "LOW")).score == 6


def test_kev_adds_points_and_floor():
    intel = _FakeIntel({"CVE-2020-3452": {"kev": True, "kev_date": "2021-11-03", "epss": 0.9, "epss_pct": 0.99}})
    pz = rp.RiskPrioritizer(intel)
    # a MEDIUM CVE that is KEV must be floored to at least P2
    r = pz.assess(_f("CISCO-CVE-X", "MEDIUM", category="CVE Detection", cve="CVE-2020-3452"))
    assert r.kev and r.tier_rank <= 1               # P1 or P2
    assert r.score >= 15 + rp.KEV_POINTS


def test_config_finding_gets_no_kev_epss():
    # a config (non-CVE) finding never gets KEV/EPSS even if an intel entry exists
    intel = _FakeIntel({"CVE-2020-3452": {"kev": True, "epss": 0.9}})
    r = rp.RiskPrioritizer(intel).assess(_f("MGMT-001", "HIGH"))  # cve is None
    assert r.kev is False and r.epss is None


def test_reachability_disabled_downranks_and_caps():
    intel = _FakeIntel({"CVE-2020-3452": {"kev": False, "epss": 0.5, "epss_pct": 0.9}})
    pz = rp.RiskPrioritizer(intel)
    f = _f("CISCO-CVE-X", "CRITICAL", category="CVE Detection", cve="CVE-2020-3452")
    disabled = {"CVE-2020-3452": {"verdict": rp.REACH_DISABLED, "evidence": "no webvpn configured"}}
    r = pz.assess(f, cve_reachability=disabled)
    # disabled -> penalty + capped out of P1 (non-KEV -> <= P3)
    assert r.tier in ("P3", "P4")


def test_kev_floor_holds_even_when_disabled():
    intel = _FakeIntel({"CVE-2020-3452": {"kev": True, "epss": 0.1, "epss_pct": 0.5}})
    pz = rp.RiskPrioritizer(intel)
    f = _f("CISCO-CVE-X", "CRITICAL", category="CVE Detection", cve="CVE-2020-3452")
    disabled = {"CVE-2020-3452": {"verdict": rp.REACH_DISABLED, "evidence": "feature off"}}
    r = pz.assess(f, cve_reachability=disabled)
    assert r.tier == "P2"                            # KEV floor caps at P2 (not P3)


# ── exposure context ────────────────────────────────────────────────────────

def test_exposure_context_mgmt_and_data():
    findings = [
        _f("MGMT-021", "HIGH", name="HTTP server enabled (unencrypted web management)"),
        _f("NGFW-005", "HIGH", category="NGFW Core Security", name="Permit any any rule present"),
    ]
    ctx = rp.RiskPrioritizer.exposure_context(findings)
    assert ctx["mgmt"] is True and ctx["data"] == "WIDE_OPEN"


def test_exposure_bonus_only_on_matching_plane():
    intel = _FakeIntel({})
    pz = rp.RiskPrioritizer(intel)
    ctx = {"data": "WIDE_OPEN", "mgmt": False}
    mgmt_only = pz.assess(_f("MGMT-001", "HIGH", category="Management Plane"), ctx)
    # a mgmt finding gets no bonus from a data-plane exposure
    assert not any(fac["label"] == "Exposed" for fac in mgmt_only.factors)


# ── ordering + to_dict ──────────────────────────────────────────────────────

def test_prioritize_orders_fix_first_and_to_dict():
    intel = _FakeIntel({"CVE-2020-3452": {"kev": True, "epss": 0.9, "epss_pct": 0.99}})
    pz = rp.RiskPrioritizer(intel)
    findings = [_f("MGMT-050", "LOW"),
                _f("CISCO-CVE-X", "CRITICAL", category="CVE Detection", cve="CVE-2020-3452")]
    res = pz.prioritize(findings, context_findings=findings)
    assert res[0].tier == "P1"                       # KEV critical first
    d = res[0].to_dict()
    for k in ("check_id", "tier", "tier_label", "priority_score", "kev", "epss", "internet_reachable"):
        assert k in d
