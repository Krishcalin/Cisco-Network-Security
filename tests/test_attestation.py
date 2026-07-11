"""
Tests for attestation — tamper-evident fleet compliance bundle.

Covers: canonical serialization, Merkle manifest, seal + verify, tamper detection,
HMAC keyed seal + seal-downgrade rejection, risk-acceptance (active + fail-open on
expiry), INFO exclusion, multi-device record-id uniqueness, fleet rollup, OSCAL.

Run:  python -m pytest tests/ -q
"""
import copy
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import attestation as att  # noqa: E402
from posture import Exceptions  # noqa: E402

FIXED = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)


def _f(check_id, severity="HIGH", device="rtr1", platform="ios", items=None,
       compliance=None, name="", cve=None):
    return dict(check_id=check_id, title=(name or check_id), severity=severity,
                category="Management Plane", description="d",
                affected_items=(items if items is not None else ["ip http server enabled"]),
                remediation="fix", references=[], details=({"cve": cve} if cve else {}),
                device=device, device_type=platform, device_file=f"{device}.cfg",
                _host_key=device, compliance=(compliance or {}))


def _bm(fw, controls):
    """controls = [(control_id, section, status), ...] -> a benchmark_score-shaped dict."""
    return {"framework": fw, "total_controls": len(controls),
            "controls": [{"control": c, "section": s, "status": st} for c, s, st in controls]}


def _device(host="rtr1", platform="ios", findings=None, benchmarks=None, src=None):
    return {"host": host,
            "device": {"hostname": host, "platform": platform, "config_file": f"{host}.cfg"},
            "findings": findings or [],
            "benchmarks": benchmarks or {},
            "source_artifact": src or {"filename": f"{host}.cfg", "sha256": "ab" * 32,
                                       "line_count": 120, "looks_truncated": False}}


def _build(devices, exceptions=None, report_dt=FIXED):
    return att.build_attestation(devices, tool_version="1.0",
                                 exceptions=exceptions if exceptions is not None else Exceptions([]),
                                 collection_dt=FIXED, report_dt=report_dt)


def _no_floats(obj, path="body"):
    if isinstance(obj, float):
        raise AssertionError(f"float found at {path}: {obj!r}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _no_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _no_floats(v, f"{path}[{i}]")


# ── canonical serialization ───────────────────────────────────────────────────

def test_canonical_bytes_sorted_and_no_spaces():
    assert att.canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonical_bytes_rejects_nan():
    import pytest
    with pytest.raises(ValueError):
        att.canonical_bytes(float("nan"))


def test_body_is_float_free():
    fw = _bm("CIS", [("1.1", "1", "PASS"), ("1.2", "1", "FAIL")])
    f = _f("MGMT-010", compliance={"CIS": ["1.2"]})
    body = _build([_device(findings=[f], benchmarks={"CIS": fw})])["body"]
    _no_floats(body)   # pass_rate is a string, counts are ints — nothing float


# ── Merkle manifest / build shape ──────────────────────────────────────────────

def test_build_shape_records_and_host_scoped_ids():
    fw = _bm("CIS", [("1.1", "1", "PASS"), ("1.2", "1", "FAIL"), ("1.3", "1", "PASS")])
    f = _f("MGMT-010", compliance={"CIS": ["1.2"]})
    body = _build([_device(findings=[f], benchmarks={"CIS": fw})])["body"]
    assert body["schema"] == "nss-cisco-attestation/1"
    assert len(body["devices"]) == 1
    dev = body["devices"][0]
    assert {"coverage", "results", "risk_acceptances", "host_key"} <= set(dev)
    # 3 control records (PASS + FAIL alike), 0 risk-acceptances
    assert body["manifest"]["record_count"] == 3
    ids = {e["id"] for e in body["manifest"]["records"]}
    assert ids == {"rtr1|CIS|1.1", "rtr1|CIS|1.2", "rtr1|CIS|1.3"}
    # the FAIL control carries the finding evidence
    ctrl = next(c for b in dev["results"] for c in b["controls"] if c["control"] == "1.2")
    assert ctrl["status"] == "FAIL" and ctrl["observations"][0]["rule_id"] == "MGMT-010"


# ── verify: clean / tamper ─────────────────────────────────────────────────────

def test_verify_clean():
    fw = _bm("CIS", [("1.1", "1", "PASS"), ("1.2", "1", "FAIL")])
    b = att.seal_attestation(_build([_device(findings=[_f("MGMT-010", compliance={"CIS": ["1.2"]})],
                                             benchmarks={"CIS": fw})]))
    r = att.verify_attestation(b)
    assert r["ok"] and not r["problems"] and r["alg"] == "SHA-256"


def test_reproducible_seal():
    fw = _bm("CIS", [("1.2", "1", "FAIL")])
    dev = _device(findings=[_f("MGMT-010", compliance={"CIS": ["1.2"]})], benchmarks={"CIS": fw})
    a = att.seal_attestation(_build([dev]))
    b = att.seal_attestation(_build([dev]))
    assert a["body"]["manifest"]["merkle_root"] == b["body"]["manifest"]["merkle_root"]
    assert a["seal"]["value"] == b["seal"]["value"]


def test_tamper_control_status_detected():
    fw = _bm("CIS", [("1.2", "1", "FAIL")])
    b = att.seal_attestation(_build([_device(findings=[_f("MGMT-010", compliance={"CIS": ["1.2"]})],
                                             benchmarks={"CIS": fw})]))
    b["body"]["devices"][0]["results"][0]["controls"][0]["status"] = "PASS"  # forge a pass
    r = att.verify_attestation(b)
    assert not r["ok"] and any("digest mismatch" in p for p in r["problems"])


def test_tamper_drop_record_detected():
    fw = _bm("CIS", [("1.1", "1", "PASS"), ("1.2", "1", "FAIL")])
    b = att.seal_attestation(_build([_device(findings=[_f("MGMT-010", compliance={"CIS": ["1.2"]})],
                                             benchmarks={"CIS": fw})]))
    b["body"]["devices"][0]["results"][0]["controls"].pop()  # silently drop a control record
    r = att.verify_attestation(b)
    assert not r["ok"]
    assert any("absent from body" in p for p in r["problems"]) or any("merkle" in p for p in r["problems"])


def test_tamper_body_toplevel_detected_by_seal():
    fw = _bm("CIS", [("1.2", "1", "FAIL")])
    b = att.seal_attestation(_build([_device(findings=[_f("MGMT-010", compliance={"CIS": ["1.2"]})],
                                             benchmarks={"CIS": fw})]))
    b["body"]["attestation"]["run_mode"] = "live-fabricated"  # not a manifested record
    r = att.verify_attestation(b)
    assert not r["ok"] and any("integrity digest INVALID" in p for p in r["problems"])


# ── HMAC keyed seal + seal-downgrade ────────────────────────────────────────────

def test_hmac_seal_roundtrip_and_wrong_key():
    fw = _bm("CIS", [("1.2", "1", "FAIL")])
    unsealed = _build([_device(findings=[_f("MGMT-010", compliance={"CIS": ["1.2"]})], benchmarks={"CIS": fw})])
    kb = att.seal_attestation(unsealed, key=b"topsecret", key_id="k1")
    assert kb["seal"]["alg"] == "HMAC-SHA256"
    assert att.verify_attestation(kb, key=b"topsecret")["ok"]
    assert not att.verify_attestation(kb, key=b"WRONG")["ok"]
    # key present in bundle but caller supplied none -> must not silently pass
    assert not att.verify_attestation(kb)["ok"]


def test_seal_downgrade_rejected():
    fw = _bm("CIS", [("1.2", "1", "FAIL")])
    unsealed = _build([_device(findings=[_f("MGMT-010", compliance={"CIS": ["1.2"]})], benchmarks={"CIS": fw})])
    kb = att.seal_attestation(unsealed, key=b"topsecret", key_id="k1")
    # attacker edits body, recomputes the PUBLIC manifest, swaps in a keyless SHA-256 seal
    kb["seal"] = att.seal_attestation(unsealed)["seal"]
    r = att.verify_attestation(kb, key=b"topsecret")
    assert not r["ok"] and any("seal downgrade" in p for p in r["problems"])


# ── INFO exclusion + risk acceptance ────────────────────────────────────────────

def test_info_finding_cannot_supply_evidence_or_accept():
    fw = _bm("CIS", [("1.2", "1", "FAIL")])
    info = _f("INFO-1", severity="INFO", compliance={"CIS": ["1.2"]})
    body = _build([_device(findings=[info], benchmarks={"CIS": fw})])["body"]
    ctrl = body["devices"][0]["results"][0]["controls"][0]
    assert ctrl["status"] == "FAIL" and ctrl["observations"] == []


def test_risk_acceptance_flips_control():
    fw = _bm("CIS", [("1.2", "1", "FAIL")])
    f = _f("SVC-001", compliance={"CIS": ["1.2"]})
    exc = Exceptions([{"host": "rtr1", "check_id": "SVC-001", "reason": "compensating control",
                       "approver": "ciso@example.com", "expires": "2099-01-01"}])
    body = _build([_device(findings=[f], benchmarks={"CIS": fw})], exceptions=exc)["body"]
    dev = body["devices"][0]
    ctrl = dev["results"][0]["controls"][0]
    assert ctrl["status"] == "RISK_ACCEPTED"
    assert dev["coverage"][0]["by_status"]["risk_accepted"] == 1
    assert len(dev["risk_acceptances"]) == 1
    ra = dev["risk_acceptances"][0]
    assert ra["approver"] == "ciso@example.com" and ra["id"] in ctrl["linked_risk_acceptances"]
    # the RA record is manifested too (sealed unit)
    assert att.verify_attestation(att.seal_attestation(_build(
        [_device(findings=[f], benchmarks={"CIS": fw})], exceptions=exc)))["ok"]


def test_expired_exception_fails_open():
    fw = _bm("CIS", [("1.2", "1", "FAIL")])
    f = _f("SVC-001", compliance={"CIS": ["1.2"]})
    exc = Exceptions([{"host": "rtr1", "check_id": "SVC-001", "reason": "lapsed",
                       "approver": "x", "expires": "2020-01-01"}])
    body = _build([_device(findings=[f], benchmarks={"CIS": fw})], exceptions=exc,
                  report_dt=FIXED)["body"]
    ctrl = body["devices"][0]["results"][0]["controls"][0]
    assert ctrl["status"] == "FAIL"                     # expired sign-off never downgrades
    assert ctrl.get("exception_expired") is True
    assert body["devices"][0]["risk_acceptances"] == []


# ── multi-device: unique ids + fleet rollup ─────────────────────────────────────

def test_multi_device_ids_unique_and_fleet_rollup():
    fw = _bm("CIS", [("1.1", "1", "PASS"), ("1.2", "1", "FAIL")])
    d1 = _device("rtr1", findings=[_f("MGMT-010", device="rtr1", compliance={"CIS": ["1.2"]})],
                 benchmarks={"CIS": fw})
    d2 = _device("sw2", platform="ios", findings=[_f("MGMT-010", device="sw2", compliance={"CIS": ["1.2"]})],
                 benchmarks={"CIS": fw})
    body = _build([d1, d2])["body"]
    ids = [e["id"] for e in body["manifest"]["records"]]
    assert len(ids) == len(set(ids)) == 4               # 2 controls x 2 devices, no collision
    fsum = body["fleet_summary"]["by_framework"]["CIS"]
    assert fsum["devices"] == 2 and fsum["pass"] == 2 and fsum["fail"] == 2
    assert att.verify_attestation(att.seal_attestation(_build([d1, d2])))["ok"]


def test_device_order_is_deterministic():
    fw = _bm("CIS", [("1.2", "1", "FAIL")])
    d1 = _device("aaa", findings=[_f("X", device="aaa", compliance={"CIS": ["1.2"]})], benchmarks={"CIS": fw})
    d2 = _device("zzz", findings=[_f("X", device="zzz", compliance={"CIS": ["1.2"]})], benchmarks={"CIS": fw})
    b1 = att.seal_attestation(_build([d1, d2]))
    b2 = att.seal_attestation(_build([d2, d1]))          # reversed input order
    assert b1["seal"]["value"] == b2["seal"]["value"]    # sorted by host_key -> same seal


# ── OSCAL projection ────────────────────────────────────────────────────────────

def test_oscal_projection_states():
    fw = _bm("CIS", [("1.1", "1", "PASS"), ("1.2", "1", "FAIL")])
    body = _build([_device(findings=[_f("MGMT-010", compliance={"CIS": ["1.2"]})], benchmarks={"CIS": fw})])["body"]
    ar = att.to_oscal(body)["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.1.2"
    assert len(ar["results"]) == 1                       # one result per device
    states = {f["target"]["target-id"]: f["target"]["status"]["state"]
              for f in ar["results"][0]["findings"]}
    assert states["CIS:1.1"] == "satisfied" and states["CIS:1.2"] == "not-satisfied"


def test_oscal_one_result_per_device():
    fw = _bm("CIS", [("1.2", "1", "FAIL")])
    d1 = _device("rtr1", findings=[_f("X", device="rtr1", compliance={"CIS": ["1.2"]})], benchmarks={"CIS": fw})
    d2 = _device("sw2", findings=[_f("X", device="sw2", compliance={"CIS": ["1.2"]})], benchmarks={"CIS": fw})
    ar = att.to_oscal(_build([d1, d2])["body"])["assessment-results"]
    assert len(ar["results"]) == 2


# ── review regressions: entity gating, non-finite, empty key, clean device ──────

def test_aggregate_finding_entity_gated_matches_posture():
    # HIGH bug (adversarial review): an ENTITY-scoped exception must NOT flip an
    # AGGREGATE (affected_count>1) control to RISK_ACCEPTED — posture uses entity=""
    # for aggregates, so attestation must too, or the two systems disagree.
    fw = _bm("CIS", [("1.2", "1", "FAIL")])
    f = _f("MGMT-004", items=["username admin secret 7 x", "username bob secret 7 y"],
           compliance={"CIS": ["1.2"]})
    exc = Exceptions([{"host": "rtr1", "check_id": "MGMT-004", "entity": "user:admin",
                       "approver": "x", "expires": "2099-01-01"}])
    body = _build([_device(findings=[f], benchmarks={"CIS": fw})], exceptions=exc)["body"]
    ctrl = body["devices"][0]["results"][0]["controls"][0]
    assert ctrl["status"] == "FAIL"                      # NOT risk-accepted
    assert body["devices"][0]["risk_acceptances"] == []


def test_single_instance_entity_exception_still_accepts():
    from posture import finding_entity
    fw = _bm("CIS", [("1.2", "1", "FAIL")])
    ev = "username admin secret 7 x"
    f = _f("MGMT-004", items=[ev], compliance={"CIS": ["1.2"]})   # single instance -> entity derived
    ent = finding_entity("MGMT-004", ev)
    assert ent                                            # sanity: this evidence yields an entity
    exc = Exceptions([{"host": "rtr1", "check_id": "MGMT-004", "entity": ent,
                       "approver": "x", "expires": "2099-01-01"}])
    body = _build([_device(findings=[f], benchmarks={"CIS": fw})], exceptions=exc)["body"]
    assert body["devices"][0]["results"][0]["controls"][0]["status"] == "RISK_ACCEPTED"


def test_verify_rejects_nonfinite_without_crashing():
    fw = _bm("CIS", [("1.2", "1", "FAIL")])
    b = att.seal_attestation(_build([_device(findings=[_f("X", compliance={"CIS": ["1.2"]})],
                                             benchmarks={"CIS": fw})]))
    # simulate a crafted bundle json.load'd with a non-finite number inside a record
    b["body"]["devices"][0]["results"][0]["controls"][0]["worst_severity"] = float("inf")
    r = att.verify_attestation(b)
    assert r["ok"] is False
    assert any("non-finite" in p or "canonicaliz" in p for p in r["problems"])


def test_empty_attest_key_file_rejected(tmp_path):
    import nss_scanner as ns
    p = tmp_path / "empty.key"
    p.write_bytes(b"")
    import pytest
    with pytest.raises(ValueError):
        ns._load_attest_key(str(p))


def test_zero_finding_device_is_all_pass():
    # a fully-clean device (no findings) still gets a block, all controls PASS
    fw = _bm("CIS", [("1.1", "1", "PASS"), ("1.2", "1", "PASS")])
    dev = _device(host="clean1", findings=[], benchmarks={"CIS": fw})
    body = _build([dev])["body"]
    cov = body["devices"][0]["coverage"][0]
    assert cov["by_status"]["pass"] == 2 and cov["by_status"]["fail"] == 0
    assert cov["pass_rate_of_evaluated"] == "100"
    assert att.verify_attestation(att.seal_attestation(_build([dev])))["ok"]


# ── renderers don't crash ───────────────────────────────────────────────────────

def test_renderers():
    fw = _bm("CIS", [("1.1", "1", "PASS"), ("1.2", "1", "FAIL")])
    b = att.seal_attestation(_build([_device(findings=[_f("MGMT-010", compliance={"CIS": ["1.2"]})],
                                             benchmarks={"CIS": fw})]))
    txt = att.render_attestation_text(b)
    html = att.render_attestation_html(b)
    assert "NSS COMPLIANCE ATTESTATION" in txt and "NOT a certification" in txt
    assert "<!doctype html>" in html and "Merkle root" in html and b["body"]["manifest"]["merkle_root"] in html
