"""
remediation_kb — structured remediation knowledge base for NSS
==============================================================
Joins each finding to a structured remediation record — risk, numbered steps,
CLI, verify command, rollback, service impact, references — resolved by
``check_id`` with a family-prefix fallback (``MGMT-004`` → ``MGMT-004`` → ``MGMT``).

NSS findings already carry an inline ``remediation`` string, so ``detail_for()``
ALWAYS returns a fully-populated record: KB fields where authored, and graceful
fallbacks from the finding itself otherwise (``description`` → risk,
``remediation`` → steps/cli, references → cve/cwe). A report section is never
empty, and a check with no KB entry still gets usable guidance. Cisco CLI in the
KB is written generically; per-platform syntax (IOS vs NX-OS vs ASA) is noted
where it differs. Stdlib only.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

try:
    from finding_view import _g
except Exception:  # pragma: no cover
    def _g(f, key, default=""):
        return (f.get(key, default) if isinstance(f, dict) else getattr(f, key, default))

_HERE = os.path.dirname(os.path.abspath(__file__))
_KB_PATH = os.path.join(_HERE, "remediation_kb.json")

_FIELDS = ("risk", "steps", "gui", "cli", "verify", "rollback", "impact", "references")


def _blank() -> Dict[str, Any]:
    return {"risk": "", "steps": [], "gui": "", "cli": "", "verify": "",
            "rollback": "", "impact": "", "references": []}


class RemediationKB:
    """Loads remediation_kb.json and resolves a detailed record per finding."""

    def __init__(self, path: Optional[str] = None):
        self._kb: Dict[str, Dict[str, Any]] = {}
        self._load(path or _KB_PATH)

    def _load(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, ValueError, OSError):
            self._kb = {}
            return
        if isinstance(data, dict):
            self._kb = data.get("knowledge_base", data) if "knowledge_base" in data else data
        else:
            self._kb = {}

    @property
    def size(self) -> int:
        return len(self._kb)

    def lookup(self, check_id: str) -> Optional[Dict[str, Any]]:
        """Exact match, then progressively shorter family-prefix match:
        ``MGMT-004`` → ``MGMT`` ; ``CISCO-CVE-001`` → ``CISCO-CVE`` → ``CISCO``."""
        if not check_id:
            return None
        if check_id in self._kb:
            return self._kb[check_id]
        parts = check_id.split("-")
        while len(parts) > 1:
            parts = parts[:-1]
            key = "-".join(parts)
            if key in self._kb:
                return self._kb[key]
        return None

    def detail_for(self, finding: Any) -> Dict[str, Any]:
        """Structured remediation for a finding — always fully populated. Adds a
        boolean ``_detailed`` (True when a real KB entry matched)."""
        rid = str(_g(finding, "rule_id", "") or "")
        entry = self.lookup(rid)
        out = _blank()
        if entry:
            for k in _FIELDS:
                val = entry.get(k)
                if val:
                    out[k] = val

        # graceful fallbacks from the finding itself
        if not out["risk"]:
            out["risk"] = str(_g(finding, "description", "") or "")
        if not out["steps"]:
            rec = str(_g(finding, "recommendation", "") or "")
            out["steps"] = [rec] if rec else []
        if not out["cli"]:
            out["cli"] = str(_g(finding, "remediation_cmd", "") or "")
        if not out["references"]:
            refs: List[str] = []
            cwe = _g(finding, "cwe", None)
            cve = _g(finding, "cve", None)
            if cwe:
                refs.append(str(cwe))
            if cve:
                refs.append(str(cve))
            out["references"] = refs

        out["_detailed"] = entry is not None
        return out
