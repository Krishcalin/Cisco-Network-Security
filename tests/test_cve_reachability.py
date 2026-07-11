"""
Tests for cve_reachability — config-gated CVE reachability + multi-device stamping,
and its downrank-never-suppress integration with the risk prioritizer.

Run:  python -m pytest tests/ -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cve_reachability as cr  # noqa: E402


class _Cfg:
    """Minimal ParsedConfig stand-in."""
    def __init__(self, raw, device_type="iosxe"):
        self.raw = raw
        self.device_type = device_type


IOSXE_WEB_ON = _Cfg("hostname r1\nip http server\nip http secure-server\nline vty 0 4\n")
IOSXE_WEB_ON_ACL = _Cfg("hostname r1\nip http secure-server\nip http access-class 10\n")
IOSXE_WEB_OFF = _Cfg("hostname r1\nno ip http server\nno ip http secure-server\n")
IOSXE_WEB_UNKNOWN = _Cfg("hostname r1\nline vty 0 4\n transport input ssh\n")
ASA_WEBVPN_ON = _Cfg("hostname fw1\nwebvpn\n enable outside\n anyconnect enable\n", "asa")
ASA_WEBVPN_PRESENT = _Cfg("hostname fw1\nwebvpn\n anyconnect image disk0:/x\n", "asa")
ASA_NO_WEBVPN = _Cfg("hostname fw1\ninterface g0\n", "asa")


# ── build_view ────────────────────────────────────────────────────────────────

def test_build_view_signals():
    v = cr.build_view(IOSXE_WEB_ON)
    assert v["http_on"] is True and v["http_access_class"] is False
    v2 = cr.build_view(IOSXE_WEB_OFF)
    assert v2["http_on"] is False and v2["http_off_explicit"] is True
    v3 = cr.build_view(ASA_WEBVPN_ON)
    assert v3["webvpn_present"] and v3["webvpn_enabled"] and v3["webvpn_external"]


# ── web-ui predicate ────────────────────────────────────────────────────────────

def test_web_ui_verdicts():
    assert cr.assess("web-ui", cr.build_view(IOSXE_WEB_ON))[0] == cr.CONFIRMED_REACHABLE
    assert cr.assess("web-ui", cr.build_view(IOSXE_WEB_ON_ACL))[0] == cr.CONFIGURED_NOT_EXPOSED
    assert cr.assess("web-ui", cr.build_view(IOSXE_WEB_OFF))[0] == cr.FEATURE_DISABLED
    assert cr.assess("web-ui", cr.build_view(IOSXE_WEB_UNKNOWN))[0] == cr.INDETERMINATE


# ── webvpn predicate ──────────────────────────────────────────────────────────

def test_webvpn_verdicts():
    assert cr.assess("webvpn-ssl", cr.build_view(ASA_WEBVPN_ON))[0] == cr.CONFIRMED_REACHABLE
    # block present but no 'enable <intf>' -> configured, not actively listening
    assert cr.assess("webvpn-ssl", cr.build_view(ASA_WEBVPN_PRESENT))[0] == cr.CONFIGURED_NOT_EXPOSED
    assert cr.assess("webvpn-ssl", cr.build_view(ASA_NO_WEBVPN))[0] == cr.FEATURE_DISABLED


def test_snmp_and_smart_install_and_nxapi():
    assert cr.assess("snmp", cr.build_view(_Cfg("snmp-server community public ro")))[0] == cr.CONFIGURED_NOT_EXPOSED
    assert cr.assess("snmp", cr.build_view(_Cfg("hostname x")))[0] == cr.FEATURE_DISABLED
    assert cr.assess("smart-install", cr.build_view(_Cfg("vstack\n")))[0] == cr.CONFIRMED_REACHABLE
    assert cr.assess("smart-install", cr.build_view(_Cfg("hostname x")))[0] == cr.FEATURE_DISABLED
    assert cr.assess("nxapi", cr.build_view(_Cfg("feature nxapi", "nxos")))[0] == cr.CONFIGURED_NOT_EXPOSED


def test_unknown_component_indeterminate():
    assert cr.assess("does-not-exist", cr.build_view(IOSXE_WEB_ON))[0] == cr.INDETERMINATE
    assert cr.assess(None, cr.build_view(IOSXE_WEB_ON))[0] == cr.INDETERMINATE


# ── multi-device stamping ─────────────────────────────────────────────────────

def _cve_finding(cve, device, device_file):
    return dict(check_id="CISCO-CVE-010", title=f"{cve} — IOS-XE Web UI", severity="CRITICAL",
                category="CVE Detection", description="d", affected_items=["17.9"],
                remediation="upgrade", references=[], details={"cve": cve},
                device=device, device_type="iosxe", device_file=device_file)


def test_stamp_reachability_multi_device():
    # SAME CVE on two devices: one has the web UI ON, the other explicitly OFF ->
    # different per-finding verdicts (the whole point of per-device gating).
    f_on = _cve_finding("CVE-2023-20198", "r-on", "on.cfg")
    f_off = _cve_finding("CVE-2023-20198", "r-off", "off.cfg")
    configs = [("on.cfg", IOSXE_WEB_ON), ("off.cfg", IOSXE_WEB_OFF)]
    n = cr.stamp_reachability(configs, [f_on, f_off])
    assert n == 2
    assert f_on["_cve_reach"]["verdict"] == cr.CONFIRMED_REACHABLE
    assert f_off["_cve_reach"]["verdict"] == cr.FEATURE_DISABLED
    assert f_on["_cve_reach"]["component"] == "web-ui"


def test_stamp_skips_unmapped_and_non_cve():
    f_unmapped = _cve_finding("CVE-2099-99999", "r1", "on.cfg")   # not in CVE_COMPONENT
    f_plain = dict(check_id="MGMT-010", title="telnet", severity="HIGH", affected_items=["x"],
                   device="r1", device_type="iosxe", device_file="on.cfg", details={}, references=[])
    n = cr.stamp_reachability([("on.cfg", IOSXE_WEB_ON)], [f_unmapped, f_plain])
    assert n == 0 and "_cve_reach" not in f_unmapped and "_cve_reach" not in f_plain


# ── prioritizer integration: downrank never suppress + KEV floor ──────────────

def _prio():
    from risk_prioritizer import RiskPrioritizer
    return RiskPrioritizer()


def test_disabled_scores_below_reachable():
    rp = _prio()
    base = _cve_finding("CVE-2023-20198", "r1", "x.cfg")
    reach = dict(base); reach["_cve_reach"] = {"verdict": cr.CONFIRMED_REACHABLE, "evidence": "on", "component": "web-ui"}
    dis = dict(base); dis["_cve_reach"] = {"verdict": cr.FEATURE_DISABLED, "evidence": "off", "component": "web-ui"}
    pr_reach = rp.assess(reach)
    pr_dis = rp.assess(dis)
    assert pr_reach.score > pr_dis.score
    labels = {fac.get("label") for fac in pr_dis.factors}
    assert "Feature disabled" in labels


def test_kev_floor_holds_even_when_disabled():
    # CVE-2023-20198 is CISA-KEV-listed -> even FEATURE_DISABLED must not fall below P2.
    rp = _prio()
    dis = _cve_finding("CVE-2023-20198", "r1", "x.cfg")
    dis["_cve_reach"] = {"verdict": cr.FEATURE_DISABLED, "evidence": "off", "component": "web-ui"}
    pr = rp.assess(dis)
    if pr.kev:                                   # only assert the floor when intel confirms KEV
        assert pr.tier in ("P1", "P2")
