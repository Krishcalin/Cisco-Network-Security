"""
Tests for finding_view._g — the alias layer the ported advanced modules read
findings through. If this contract drifts, every exporter/attestation/verify
serialization silently breaks, so it is guarded first.

Run:  python -m pytest tests/ -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import finding_view as fv  # noqa: E402


def _finding(**kw):
    base = dict(check_id="MGMT-004", title="Type-7 passwords in use", severity="HIGH",
                category="Management Plane", description="Reversible Type-7 secrets.",
                affected_items=["username admin password 7 0822455D0A16", "line vty 0 4 password 7 09"],
                affected_count=2, remediation="Replace with 'enable secret' / 'service password-encryption'.",
                references=["CIS 1.1.1", "CVE-2024-20359", "CWE-261"], details={},
                device="core-rtr", device_type="ios", device_file="router_core.cfg")
    base.update(kw)
    return base


def test_direct_and_aliased_fields():
    f = _finding()
    assert fv._g(f, "rule_id") == "MGMT-004"       # <- check_id
    assert fv._g(f, "name") == "Type-7 passwords in use"  # <- title
    assert fv._g(f, "severity") == "HIGH"
    assert fv._g(f, "category") == "Management Plane"
    assert fv._g(f, "recommendation").startswith("Replace")  # <- remediation
    assert fv._g(f, "file_path") == "router_core.cfg"        # <- device_file
    assert fv._g(f, "host") == "core-rtr"                    # <- device


def test_evidence_is_first_affected_item():
    f = _finding()
    assert fv._g(f, "line_content") == "username admin password 7 0822455D0A16"
    assert fv.fv_evidence(f) == "username admin password 7 0822455D0A16"
    assert fv.fv_affected_items(f) == f["affected_items"]
    # empty affected_items -> empty evidence, never crash
    assert fv._g(_finding(affected_items=[]), "line_content") == ""


def test_cve_cwe_from_details_then_references():
    # details wins
    f = _finding(details={"cve": "CVE-2025-20333", "cwe": "CWE-787"})
    assert fv._g(f, "cve") == "CVE-2025-20333" and fv._g(f, "cwe") == "CWE-787"
    # else parsed from references
    f2 = _finding(details={})
    assert fv._g(f2, "cve") == "CVE-2024-20359" and fv._g(f2, "cwe") == "CWE-261"
    # none present -> None
    f3 = _finding(details={}, references=["CIS 1.1.1"])
    assert fv._g(f3, "cve") is None and fv._g(f3, "cwe") is None


def test_remediation_cmd_from_details():
    f = _finding(details={"remediation_cmd": "no ip http server"})
    assert fv._g(f, "remediation_cmd") == "no ip http server"
    assert fv._g(_finding(), "remediation_cmd") == ""  # absent -> ""


def test_compliance_defaults_empty_then_reads_field():
    assert fv._g(_finding(), "compliance") == {}
    f = _finding(compliance={"CIS": ["1.1.1"]})
    assert fv._g(f, "compliance") == {"CIS": ["1.1.1"]}


def test_default_and_missing_key():
    assert fv._g(_finding(), "nonexistent", "fallback") == "fallback"
    assert fv._g(_finding(), "line_num", None) is None
