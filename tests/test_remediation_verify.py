"""
Tests for remediation_verify — the A/B "did my fixes land?" loop.

Covers REMEDIATED / PERSISTING / CHANGED / REGRESSION classification, host-scoped
matching (multi-device), the severity-floor guard, the clean verdict + exit gating,
per-device rollup, tier overlay (dict + object), and renderers.

Run:  python -m pytest tests/ -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import remediation_verify as rv  # noqa: E402


def _f(check_id, severity="HIGH", device="rtr1", items=None, name="", cve=None):
    items = items if items is not None else ["evidence-a", "evidence-b"]  # 2 -> entity gated off
    return dict(check_id=check_id, title=(name or check_id), severity=severity,
                category="Management Plane", description="d", affected_items=items,
                remediation="fix", references=[], details=({"cve": cve} if cve else {}),
                device=device, device_type="ios", device_file=f"{device}.cfg", _host_key=device)


def _sum(prior, current, **kw):
    return rv.build_verification(prior, current, **kw)


# ── classification ──────────────────────────────────────────────────────────

def test_remediated():
    r = _sum([_f("MGMT-010")], [])
    assert r["summary"]["remediated"] == 1 and r["summary"]["total_prior"] == 1
    assert r["items"][0]["status"] == "REMEDIATED" and r["summary"]["remediation_rate_pct"] == 100


def test_persisting_same_evidence():
    f = _f("MGMT-010", items=["ip http server", "x"])
    r = _sum([f], [_f("MGMT-010", items=["ip http server", "x"])])
    assert r["summary"]["persisting"] == 1 and r["items"][0]["status"] == "PERSISTING"
    assert r["items"][0]["before"] == r["items"][0]["after"] == "ip http server"


def test_changed_evidence_moved():
    # same check + host + (no) entity, but the evidence VALUE moved -> CHANGED, not remediated+new
    r = _sum([_f("MGMT-004", items=["exec-timeout 30", "x"])],
             [_f("MGMT-004", items=["exec-timeout 20", "x"])])
    assert r["summary"]["changed"] == 1 and r["summary"]["remediated"] == 0
    it = r["items"][0]
    assert it["status"] == "CHANGED" and it["before"] == "exec-timeout 30" and it["after"] == "exec-timeout 20"


def test_regression_new_finding():
    r = _sum([_f("MGMT-010")], [_f("MGMT-010"), _f("CRYPTO-002", severity="HIGH")])
    assert r["summary"]["regressions"] == 1 and r["regressions"][0]["rule_id"] == "CRYPTO-002"
    assert r["regressions"][0]["status"] == "REGRESSION"


def test_info_findings_ignored():
    r = _sum([_f("INFO-1", severity="INFO")], [_f("INFO-2", severity="INFO")])
    assert r["summary"]["total_prior"] == 0 and r["summary"]["regressions"] == 0


# ── severity-floor guard ──────────────────────────────────────────────────────

def test_severity_floor_suppresses_below_floor_regression():
    # prior report only contains HIGH -> a new LOW now could not have been in it -> not a regression
    r = _sum([_f("MGMT-010", severity="HIGH")],
             [_f("MGMT-010", severity="HIGH"), _f("SVC-009", severity="LOW")])
    assert r["summary"]["regressions"] == 0


def test_new_finding_at_floor_is_regression():
    r = _sum([_f("MGMT-010", severity="HIGH")],
             [_f("MGMT-010", severity="HIGH"), _f("SVC-009", severity="HIGH")])
    assert r["summary"]["regressions"] == 1


# ── host-scoped (multi-device) ────────────────────────────────────────────────

def test_same_check_two_devices_are_distinct():
    # X on rtr1 remediated, X on sw2 still persisting -> not conflated
    prior = [_f("MGMT-010", device="rtr1", items=["a", "b"]),
             _f("MGMT-010", device="sw2", items=["a", "b"])]
    current = [_f("MGMT-010", device="sw2", items=["a", "b"])]
    r = _sum(prior, current)
    assert r["summary"]["remediated"] == 1 and r["summary"]["persisting"] == 1
    bd = {d["host"]: d for d in r["summary"]["by_device"]}
    assert bd["rtr1"]["remediated"] == 1 and bd["rtr1"]["remediation_rate_pct"] == 100
    assert bd["sw2"]["persisting"] == 1 and bd["sw2"]["remediation_rate_pct"] == 0


def test_by_device_rollup_counts():
    prior = [_f("A-1", device="d1"), _f("A-2", device="d1"), _f("A-1", device="d2")]
    current = [_f("A-2", device="d1")]                      # d1: A-1 fixed, A-2 open; d2: A-1 fixed
    r = _sum(prior, current)
    bd = {d["host"]: d for d in r["summary"]["by_device"]}
    assert bd["d1"]["total_prior"] == 2 and bd["d1"]["remediated"] == 1 and bd["d1"]["persisting"] == 1
    assert bd["d2"]["total_prior"] == 1 and bd["d2"]["remediated"] == 1


# ── clean verdict + rate ──────────────────────────────────────────────────────

def test_clean_when_all_crit_high_fixed_no_new():
    r = _sum([_f("MGMT-010", severity="HIGH")], [])
    assert r["summary"]["clean"] is True


def test_not_clean_on_persisting_high():
    f = _f("MGMT-010", severity="HIGH", items=["z", "y"])
    r = _sum([f], [_f("MGMT-010", severity="HIGH", items=["z", "y"])])
    assert r["summary"]["clean"] is False and r["summary"]["unresolved_critical_high"] == 1


def test_not_clean_on_high_regression():
    r = _sum([_f("MGMT-010", severity="HIGH")],
             [_f("MGMT-010", severity="HIGH"), _f("NEW-1", severity="CRITICAL")])
    assert r["summary"]["clean"] is False and r["summary"]["regressions_critical_high"] == 1


def test_medium_persisting_is_still_clean():
    # clean only cares about CRITICAL/HIGH; a persisting MEDIUM does not block sign-off
    f = _f("SVC-005", severity="MEDIUM", items=["m", "n"])
    r = _sum([f], [_f("SVC-005", severity="MEDIUM", items=["m", "n"])])
    assert r["summary"]["clean"] is True and r["summary"]["persisting"] == 1


def test_rate_partial():
    prior = [_f("A-1"), _f("A-2"), _f("A-3"), _f("A-4")]
    current = [_f("A-1", items=["a", "b"])]                 # 3 of 4 remediated
    r = _sum(prior, current)
    assert r["summary"]["remediation_rate_pct"] == 75


# ── tier overlay (dict + object) + verify command ─────────────────────────────

class _PR:
    def __init__(self, tier):
        self.tier = tier


def test_tier_overlay_dict_and_object():
    cur1 = _f("MGMT-010", items=["p", "q"])
    r1 = _sum([_f("MGMT-010", items=["p", "q"])], [cur1], prio_by_id={id(cur1): {"tier": "P1"}})
    assert r1["items"][0]["tier"] == "P1"
    cur2 = _f("MGMT-010", items=["p", "q"])
    r2 = _sum([_f("MGMT-010", items=["p", "q"])], [cur2], prio_by_id={id(cur2): _PR("P2")})
    assert r2["items"][0]["tier"] == "P2"


def test_verify_cmd_from_kb():
    from remediation_kb import RemediationKB
    cur = _f("MGMT-010", items=["r", "s"])
    r = _sum([_f("MGMT-010", items=["r", "s"])], [cur], kb=RemediationKB())
    assert r["items"][0]["verify_cmd"]                      # MGMT family has a verify command


# ── renderers ─────────────────────────────────────────────────────────────────

def test_renderers_dont_crash():
    prior = [_f("MGMT-010", device="rtr1"), _f("CRYPTO-002", device="sw2", items=["x", "y"])]
    current = [_f("CRYPTO-002", device="sw2", items=["z", "y"]), _f("NEW-9", device="sw2", severity="HIGH")]
    r = _sum(prior, current)
    txt = rv.render_text(r, baseline_label="prev.json")
    html = rv.render_html(r, baseline_label="prev.json")
    assert "Remediation Verification" in txt and "Target report: prev.json" in txt
    assert "<!doctype html>" in html and "Remediation Verification" in html
