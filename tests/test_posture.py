"""
Tests for posture.py — stable identity, exceptions (fail-open), lifecycle, SLA.

Run:  python -m pytest tests/ -q
"""
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import posture as p  # noqa: E402


def _f(check_id, severity="HIGH", items=None, **kw):
    base = dict(check_id=check_id, title=check_id, severity=severity, category="c",
                description="d", affected_items=items if items is not None else ["x", "y"],
                remediation="r", references=[], details={}, device="rtr", device_type="ios")
    base.update(kw)
    return base


# ── stable identity ───────────────────────────────────────────────────────────

def test_entity_extraction_cisco_idioms():
    assert p.finding_entity("X", "GigabitEthernet0/1 has no shutdown") == "iface:GigabitEthernet0/1"
    assert p.finding_entity("X", "line vty 0 4 permits telnet").startswith("line:vty")
    assert p.finding_entity("X", "username admin privilege 15") == "user:admin"
    assert p.finding_entity("X", "tunnel-group DefaultL2L type ipsec") == "tunnel-group:DefaultL2L"
    assert p.finding_entity("X", "access-list 101 permits any") == "acl:101"
    assert p.finding_entity("X", "no clear identifier here") == ""


def test_fingerprint_aggregate_vs_single():
    # aggregate finding (>1 affected item) -> keyed on check_id alone (stable)
    agg = _f("MGMT-004", items=["username a", "username b"])
    assert p.finding_fingerprint(agg) == "MGMT-004"
    # single-instance -> check_id|entity
    single = _f("DATA-003", items=["GigabitEthernet0/1"])
    assert p.finding_fingerprint(single) == "DATA-003|iface:GigabitEthernet0/1"
    # cosmetic change to an aggregate's contents does NOT change the key
    agg2 = _f("MGMT-004", items=["username a", "username c", "username d"])
    assert p.finding_fingerprint(agg2) == p.finding_fingerprint(agg)


# ── exceptions: fail open ──────────────────────────────────────────────────────

def test_exceptions_match_and_expiry_failopen():
    now = datetime(2026, 7, 11)
    exc = p.Exceptions([
        {"host": "rtr", "check_id": "MGMT-001", "reason": "x", "approver": "y", "expires": "2099-01-01"},
        {"host": "rtr", "check_id": "MGMT-002", "expires": "2000-01-01"},          # expired
        {"host": "rtr", "check_id": "MGMT-003", "expires": "not-a-date"},          # unparseable
        {"host": "*", "check_id": "LOG-001"},                                       # wildcard host, no expiry
    ])
    assert exc.match("rtr", "MGMT-001", "", now)[0] is not None                     # active
    e, expired = exc.match("rtr", "MGMT-002", "", now)
    assert e is None and expired is True                                            # expired -> fail open
    e, expired = exc.match("rtr", "MGMT-003", "", now)
    assert e is None and expired is True                                            # unparseable -> fail open
    assert exc.match("any-host", "LOG-001", "", now)[0] is not None                 # wildcard


# ── lifecycle ──────────────────────────────────────────────────────────────────

def test_lifecycle_new_carried_resolved_reopened(tmp_path):
    store_path = str(tmp_path / "h.json")
    t0 = datetime(2026, 7, 1)
    s = p.PostureStore(store_path)
    d = s.update("rtr", [_f("A-1"), _f("A-2")], now=t0)
    assert len(d.new) == 2 and not d.resolved
    s.save()

    # A-2 fixed -> resolved; A-1 carried
    s = p.PostureStore(store_path)
    d = s.update("rtr", [_f("A-1")], now=t0 + timedelta(days=1))
    assert [r["check_id"] for r in d.resolved] == ["A-2"]
    assert [r["check_id"] for r in d.carried] == ["A-1"]
    s.save()

    # A-2 returns -> reopened (SLA clock restarts)
    s = p.PostureStore(store_path)
    d = s.update("rtr", [_f("A-1"), _f("A-2")], now=t0 + timedelta(days=2))
    assert [r["check_id"] for r in d.reopened] == ["A-2"]


def test_accepted_risk_excluded_from_new(tmp_path):
    exc = p.Exceptions([{"host": "rtr", "check_id": "A-1", "reason": "ok", "approver": "z"}])
    s = p.PostureStore(str(tmp_path / "h.json"))
    d = s.update("rtr", [_f("A-1"), _f("A-2")], exceptions=exc, now=datetime(2026, 7, 1))
    assert [r["check_id"] for r in d.new] == ["A-2"]      # A-1 accepted -> not "new"
    assert d.open_accepted == 1 and d.open_active == 1


def test_sla_breach_uses_tier_window(tmp_path):
    # a PriorityResult-like object supplies the tier so SLA can be computed
    class Prio:
        def __init__(self, f, tier): self.finding = f; self.tier = tier; self.kev = False
    f = _f("A-1", "CRITICAL")
    t0 = datetime(2026, 7, 1)
    s = p.PostureStore(str(tmp_path / "h.json"))
    s.update("rtr", [f], priorities=[Prio(f, "P1")], now=t0)   # P1 SLA = 3 days
    s.save()
    s = p.PostureStore(str(tmp_path / "h.json"))
    d = s.update("rtr", [f], priorities=[Prio(f, "P1")], now=t0 + timedelta(days=5))
    assert len(d.sla_breaches) == 1 and d.sla_breaches[0]["window"] == 3


def test_corrupt_store_fails_open(tmp_path):
    pth = tmp_path / "h.json"
    pth.write_text("{ this is not json", encoding="utf-8")
    s = p.PostureStore(str(pth))                              # must not raise
    d = s.update("rtr", [_f("A-1")], now=datetime(2026, 7, 1))
    assert len(d.new) == 1                                    # started fresh
