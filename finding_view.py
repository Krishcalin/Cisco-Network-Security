"""
finding_view — canonical field accessor for NSS finding dicts
=============================================================
The advanced modules (posture, risk_prioritizer, nss_export, attestation,
remediation_verify) are ported from the Fortinet scanner, where a ``Finding``
exposed fields like ``rule_id`` / ``name`` / ``line_content`` / ``recommendation``.
A Cisco NSS finding is a plain dict (built by ``BaseAuditor.finding()``) with
DIFFERENT key names (``check_id`` / ``title`` / ``affected_items`` / ``remediation``)
and an ``affected_items`` **list** instead of a single evidence line.

``_g(finding, key, default="")`` bridges the two so the ported modules can read
findings through one shared accessor and stay near-verbatim. It accepts the
Fortinet field name and returns the Cisco value, tolerating both dicts and objects.

Field mapping:

    Fortinet key      -> Cisco source
    rule_id           -> check_id            (the stable per-check rule id)
    name              -> title
    category          -> category
    severity          -> severity            (same CRITICAL/HIGH/MEDIUM/LOW/INFO vocab)
    file_path         -> device_file
    host              -> device              (hostname; the posture/ticket host)
    line_content      -> affected_items[0]   (evidence; Cisco is a list — first item)
    description       -> description
    recommendation    -> remediation
    remediation_cmd   -> details.remediation_cmd
    cve               -> details.cve  else a CVE-… token in references
    cwe               -> details.cwe  else a CWE-… token in references
    compliance        -> compliance          (added by base.finding() via compliance_map)
    line_num          -> (absent) -> default
"""
from __future__ import annotations

import re
from typing import Any, List

# Fortinet field name -> Cisco dict key (simple 1:1 renames).
_ALIAS = {
    "rule_id": "check_id",
    "name": "title",
    "recommendation": "remediation",
    "file_path": "device_file",
    "host": "device",
}
# Keys that need computed / fallback logic.
_SPECIAL = {"line_content", "remediation_cmd", "cve", "cwe", "compliance", "line_num"}

_RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_RE_CWE = re.compile(r"CWE-\d+", re.IGNORECASE)


def _token(finding: dict, rx: "re.Pattern") -> Any:
    """Find a CVE-/CWE-style token in references, then the title/description.
    CVE-Detection findings carry the CVE id in the TITLE (e.g. 'CVE-2025-20333 — …'),
    not in references, so the title is searched too."""
    for ref in (finding.get("references") or []):
        m = rx.search(str(ref))
        if m:
            return m.group(0).upper()
    for key in ("title", "description"):
        m = rx.search(str(finding.get(key, "")))
        if m:
            return m.group(0).upper()
    return None


def _g(finding: Any, key: str, default: Any = "") -> Any:
    """Read a Fortinet-style field from a Cisco NSS finding (dict or object)."""
    if not isinstance(finding, dict):
        # object fallback: try the Fortinet attr, then the Cisco alias
        val = getattr(finding, key, None)
        if val is not None:
            return val
        return getattr(finding, _ALIAS.get(key, key), default)

    if key in _SPECIAL:
        if key == "line_content":
            items = finding.get("affected_items")
            if items:
                return str(items[0])
            return finding.get("line_content", default) or default
        if key == "remediation_cmd":
            det = finding.get("details") or {}
            return det.get("remediation_cmd") or finding.get("remediation_cmd", "") or ""
        if key == "cve":
            det = finding.get("details") or {}
            return finding.get("cve") or det.get("cve") or _token(finding, _RE_CVE)
        if key == "cwe":
            det = finding.get("details") or {}
            return finding.get("cwe") or det.get("cwe") or _token(finding, _RE_CWE)
        if key == "compliance":
            return finding.get("compliance") or {}
        if key == "line_num":
            return finding.get("line_num", default)

    src = _ALIAS.get(key, key)
    val = finding.get(src)
    if val is None:
        # tolerate a finding already using the Fortinet key
        val = finding.get(key)
    return default if val is None else val


# ── convenience helpers (used where a bare accessor reads awkwardly) ──────────

def fv_rule_id(f: Any) -> str:
    return str(_g(f, "rule_id", ""))


def fv_evidence(f: Any) -> str:
    return str(_g(f, "line_content", ""))


def fv_affected_items(f: Any) -> List[str]:
    if isinstance(f, dict):
        return list(f.get("affected_items") or [])
    return list(getattr(f, "affected_items", []) or [])


def fv_cve(f: Any):
    return _g(f, "cve", None)


def fv_host(f: Any) -> str:
    return str(_g(f, "host", "") or "unknown")
