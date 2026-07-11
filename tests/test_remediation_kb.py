"""
Tests for remediation_kb — family resolution + graceful fallback.

Run:  python -m pytest tests/ -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from remediation_kb import RemediationKB  # noqa: E402

KB = RemediationKB()


def test_family_prefix_resolution():
    d = KB.detail_for({"check_id": "MGMT-010", "description": "d", "remediation": "r", "references": []})
    assert d["_detailed"] is True
    assert "ip ssh version 2" in d["cli"] and d["verify"]
    # CVE family
    c = KB.detail_for({"check_id": "CISCO-CVE-042", "description": "d", "remediation": "r"})
    assert c["_detailed"] is True and "REBOOT" in c["impact"]


def test_unmapped_falls_back_to_finding():
    d = KB.detail_for({"check_id": "ZZZ-1", "description": "the risk", "remediation": "do it",
                       "references": ["CWE-16"], "details": {}})
    assert d["_detailed"] is False
    assert d["risk"] == "the risk" and d["steps"] == ["do it"]


def test_all_fields_always_present():
    for cid in ("MGMT-001", "LOG-003", "NGFW-010", "ZZZ-9"):
        d = KB.detail_for({"check_id": cid, "description": "d", "remediation": "r"})
        for k in ("risk", "steps", "gui", "cli", "verify", "rollback", "impact", "references", "_detailed"):
            assert k in d


def test_kb_has_core_families():
    for fam in ("MGMT", "CRYPTO", "CTRL", "DATA", "SVC", "SW", "WIFI", "NGFW", "LOG", "CISCO-CVE"):
        assert KB.lookup(fam) is not None
