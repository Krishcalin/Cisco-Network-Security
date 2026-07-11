"""
Tests for nss_export — SOAR/ticketing + SIEM builders, multi-device dedup, lifecycle.

Run:  python -m pytest tests/ -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nss_export as nx  # noqa: E402
import posture as pmod  # noqa: E402
import nss_scanner as ns  # noqa: E402


def _f(check_id, severity="HIGH", device="rtr", device_type="ios", items=None, cve=None, name=""):
    f = dict(check_id=check_id, title=(name or check_id), severity=severity, category="Management Plane",
             description="d", affected_items=items if items is not None else ["x"], remediation="fix it",
             references=[], details=({"cve": cve} if cve else {}), device=device,
             device_type=device_type, device_file=f"{device}.cfg", compliance={"NIST": ["IA-5"]})
    return f


def _prio(f, tier="P2", kev=False, score=50):
    return {"tier": tier, "priority_score": score, "kev": kev, "epss": 0.1 if kev else None,
            "epss_pct": 0.5, "internet_reachable": False, "ransomware": False,
            "kev_date": None, "tier_label": tier}


# ── dedup key ──────────────────────────────────────────────────────────────

def test_dedup_key_stable_and_host_scoped():
    f = _f("MGMT-010")
    k1 = nx._dedup_key("rtr", f)
    assert k1 == nx._dedup_key("rtr", _f("MGMT-010")) and len(k1) == 16
    assert nx._dedup_key("sw2", f) != k1                 # per-device


def test_multi_device_same_check_distinct_tickets():
    findings = [_f("CISCO-CVE-001", "CRITICAL", device="asa1", name="CVE-2025-20333 — x"),
                _f("CISCO-CVE-001", "CRITICAL", device="ftd1", name="CVE-2025-20333 — x")]
    env = nx.build_jira(findings)
    keys = [i["dedup_key"] for i in env["items"]]
    assert len(env["items"]) == 2 and len(set(keys)) == 2   # two devices -> two tickets
    assert env["meta"]["devices"] == ["asa1", "ftd1"]


def test_export_dedups_repeated_key():
    # same check fires twice on one device with the same identity -> one item
    findings = [_f("MGMT-004", items=["a", "b"]), _f("MGMT-004", items=["a", "b"])]
    env = nx.build_webhook(findings)
    assert len(env["items"]) == 1


# ── Jira ───────────────────────────────────────────────────────────────────

def test_jira_labels_and_adf():
    f = _f("MGMT-010", "HIGH")
    env = nx.build_jira([f], prio_by_id={id(f): _prio(f, "P2")}, project_key="NET")
    body = env["items"][0]["body"]
    assert body["fields"]["project"]["key"] == "NET"
    key = env["items"][0]["dedup_key"]
    labels = body["fields"]["labels"]
    assert f"nss-fp-{key}" in labels and all(" " not in l for l in labels)
    assert body["fields"]["description"]["type"] == "doc"    # ADF v3
    assert body["properties"][0]["value"]["fingerprint"] == key


def test_jira_v2_plain_string():
    f = _f("MGMT-010")
    env = nx.build_jira([f], api_version=2)
    assert isinstance(env["items"][0]["body"]["fields"]["description"], str)


# ── ServiceNow ─────────────────────────────────────────────────────────────

def test_servicenow_urgency_impact_no_priority():
    f = _f("MGMT-010", "HIGH")
    body = nx.build_servicenow([f], prio_by_id={id(f): _prio(f, "P1")})["items"][0]["body"]
    assert body["urgency"] == "1" and body["impact"] == "1" and "priority" not in body
    assert body["correlation_id"].startswith("nssscan:")
    assert len(body["short_description"]) <= 160 and len(body["description"]) <= 4000


# ── Splunk SOAR ────────────────────────────────────────────────────────────

def test_splunk_sdi_and_severity():
    f = _f("CISCO-CVE-001", "CRITICAL", name="CVE-2025-20333 — x")
    c = nx.build_splunk_soar([f], prio_by_id={id(f): _prio(f, "P1")})["items"][0]["body"]
    key = nx.build_splunk_soar([f])["items"][0]["dedup_key"]
    assert c["source_data_identifier"] == f"nssscan:{key}"
    assert c["severity"] in ("high", "medium", "low")
    art = c["artifacts"][0]
    assert art["source_data_identifier"].startswith("nssscan:") and "container_id" not in art


# ── webhook (CloudEvents) ────────────────────────────────────────────────────

def test_webhook_cloudevents_identity():
    f = _f("MGMT-010", "HIGH")
    ce = nx.build_webhook([f], now_iso="2026-07-11T00:00:00")["items"][0]["body"]
    assert ce["specversion"] == "1.0"
    key = ce["data"]["dedup_key"]
    assert ce["subject"] == key and ce["id"].startswith(key + "-") and ce["id"] != key
    assert ce["type"].endswith(".new") and ce["data"]["event"] == "new"


# ── lifecycle: resolved closures ─────────────────────────────────────────────

def test_resolved_emits_close_across_targets():
    # a resolved finding lives only in the posture delta, never in `findings`
    gone = _f("A-9", "HIGH", device="rtr")
    delta = pmod.PostureDelta()
    delta.host = "rtr"
    delta.resolved = [{"check_id": "A-9", "entity": "", "severity": "HIGH", "name": "A-9",
                       "tier": "P2", "resolved_at": "2026-07-11T00:00:00"}]
    deltas = {"rtr": delta}
    key = nx._dedup_key("rtr", gone)
    for builder in (nx.build_jira, nx.build_servicenow, nx.build_splunk_soar, nx.build_webhook):
        env = builder([], deltas=deltas)
        assert len(env["items"]) == 1 and env["items"][0]["op"] == "resolve"
        assert env["items"][0]["dedup_key"] == key


def test_lifecycle_new_update_from_delta():
    new_f = _f("A-1", device="rtr")
    carried_f = _f("B-2", device="rtr")
    delta = pmod.PostureDelta()
    delta.host = "rtr"
    delta.new = [{"check_id": "A-1", "entity": "", "severity": "HIGH", "tier": "P2"}]
    delta.carried = [{"check_id": "B-2", "entity": "", "severity": "HIGH", "tier": "P2"}]
    env = nx.build_webhook([new_f, carried_f], deltas={"rtr": delta})
    ops = {i["dedup_key"]: i["op"] for i in env["items"]}
    assert ops[nx._dedup_key("rtr", new_f)] == "create"
    assert ops[nx._dedup_key("rtr", carried_f)] == "update"


# ── min-tier filter ──────────────────────────────────────────────────────────

def test_min_tier_filters():
    hi = _f("A-1", "CRITICAL")
    lo = _f("B-2", "LOW")
    env = nx.build_webhook([hi, lo], prio_by_id={id(hi): _prio(hi, "P1"), id(lo): _prio(lo, "P4")}, min_tier="P2")
    ids = {i["body"]["data"]["check_id"] for i in env["items"]}
    assert ids == {"A-1"}


# ── disambiguated host key: no silent drop / no closure mismatch ──────────────
# Regression for the two HIGH export bugs: the exporter used to derive host from
# the plain device hostname (fv_host=device) while posture keyed deltas by a
# disambiguated '<host>|<file>'. The scanner now stamps a single `_host_key` that
# both paths read, so colliding/unknown hostnames neither merge nor mismatch.

def test_stamp_disambiguates_unknown_and_collision():
    a = _f("MGMT-010", device="unknown"); a["device_file"] = "rtrA.cfg"
    b = _f("MGMT-010", device="unknown"); b["device_file"] = "rtrB.cfg"
    c = _f("MGMT-010", device="core-sw"); c["device_file"] = "site1.cfg"
    d = _f("MGMT-010", device="core-sw"); d["device_file"] = "site2.cfg"
    e = _f("MGMT-010", device="edge-fw"); e["device_file"] = "edge-fw.cfg"
    ns._stamp_host_keys([a, b, c, d, e])
    assert a["_host_key"] == "unknown|rtrA.cfg" and b["_host_key"] == "unknown|rtrB.cfg"
    assert c["_host_key"] == "core-sw|site1.cfg" and d["_host_key"] == "core-sw|site2.cfg"
    assert e["_host_key"] == "edge-fw"           # unique hostname stays plain


def test_colliding_hostnames_not_silently_dropped():
    # two DISTINCT boxes sharing the hostname 'unknown' -> two tickets, both listed
    a = _f("CISCO-CVE-001", "CRITICAL", device="unknown", name="CVE-2025-20333 — x")
    a["device_file"] = "boxA.cfg"
    b = _f("CISCO-CVE-001", "CRITICAL", device="unknown", name="CVE-2025-20333 — x")
    b["device_file"] = "boxB.cfg"
    ns._stamp_host_keys([a, b])
    env = nx.build_jira([a, b])
    keys = [i["dedup_key"] for i in env["items"]]
    assert len(env["items"]) == 2 and len(set(keys)) == 2
    assert len(env["meta"]["devices"]) == 2


def test_carried_finding_on_unknown_host_matches_delta_key():
    # live carried finding + its posture delta on an 'unknown' box must share one
    # dedup_key (emitted as 'update', not a mismatched 'create' + stale leak).
    carried = _f("B-2", device="unknown"); carried["device_file"] = "boxA.cfg"
    ns._stamp_host_keys([carried])
    hk = carried["_host_key"]
    delta = pmod.PostureDelta(); delta.host = hk
    delta.carried = [{"check_id": "B-2", "entity": "", "severity": "HIGH", "tier": "P2"}]
    env = nx.build_webhook([carried], deltas={hk: delta})
    ops = {i["dedup_key"]: i["op"] for i in env["items"]}
    assert len(env["items"]) == 1
    assert ops[nx._dedup_key(hk, carried)] == "update"


def test_resolved_closure_key_uses_disambiguated_host():
    # a resolved finding on an 'unknown' box closes under the SAME composite key
    hk = "unknown|boxA.cfg"
    gone = _f("Z-9", "HIGH", device="unknown"); gone["_host_key"] = hk
    delta = pmod.PostureDelta(); delta.host = hk
    delta.resolved = [{"check_id": "Z-9", "entity": "", "severity": "HIGH", "name": "Z-9",
                       "tier": "P2", "resolved_at": "2026-07-11T00:00:00"}]
    env = nx.build_webhook([], deltas={hk: delta})
    assert len(env["items"]) == 1 and env["items"][0]["op"] == "resolve"
    assert env["items"][0]["dedup_key"] == nx._dedup_key(hk, gone)


# ── SARIF / OCSF ──────────────────────────────────────────────────────────────

def test_sarif_structure():
    f = _f("MGMT-010", "CRITICAL", cve="CVE-2020-3452")
    doc = nx.build_sarif([f], prio_by_id={id(f): _prio(f, "P1", kev=True)})
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "rtr.cfg"
    assert run["results"][0]["partialFingerprints"]["nssFindingHash"]


def test_ocsf_events():
    f = _f("MGMT-010", "CRITICAL")
    ev = nx.build_ocsf([f], epoch=123)[0]
    assert ev["class_uid"] == 2003 and ev["severity_id"] == 5 and ev["time"] == 123
    assert ev["compliance"]["requirements"] == ["NIST:IA-5"]
