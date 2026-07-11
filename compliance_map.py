"""
compliance_map — framework crosswalk + scored benchmark for NSS
================================================================
Maps each NSS ``check_id`` to controls across six frameworks (CIS, PCI-DSS 4.0,
NIST SP 800-53 Rev5, SOC 2 TSC, HIPAA Security Rule, ISO 27001:2022) and scores
a device's config against them.

``resolve_compliance(check_id)`` does an exact-then-family-prefix lookup (e.g.
``MGMT-004`` → exact, else ``MGMT``; ``CISCO-CVE-001`` → ``CISCO-CVE`` → ``CISCO``),
mirroring the remediation-KB resolution style. ``base.finding()`` calls it so every
finding is auto-tagged with a ``compliance`` dict — no per-check-site edits.

``benchmark_score(framework, findings, platform=None)`` scores like a CIS benchmark:
the denominator is *the controls this tool evaluates* (all controls mapped by any
in-scope check), and a control FAILS if any reportable (non-INFO) finding references
it, else PASSES. Honest by construction — never claims coverage of the full external
benchmark. Pure stdlib; findings read through ``finding_view._g`` so dict findings
work unchanged.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from finding_view import _g
except Exception:  # pragma: no cover - allow standalone import
    def _g(f, k, d=""):
        return (f.get(k, d) if isinstance(f, dict) else getattr(f, k, d))

FRAMEWORKS = ("CIS", "PCI-DSS", "NIST", "SOC2", "HIPAA", "ISO27001")

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# --------------------------------------------------------------------------- #
#  COMPLIANCE_MAP: {check_id-or-family-prefix: {framework: [control ids]}}      #
#  Per-check entries (authored crosswalk) take precedence; family-prefix       #
#  entries below are the fallback so every check resolves to something         #
#  defensible. The authoring workflow refines the per-check layer.             #
# --------------------------------------------------------------------------- #

# Family-prefix fallbacks (network-device hardening → standard controls).
COMPLIANCE_MAP: Dict[str, Dict[str, List[str]]] = {
    "MGMT": {"NIST": ["IA-5", "AC-17", "AC-3", "IA-2"], "PCI-DSS": ["2.2.4", "8.3.6", "8.2.1"],
             "SOC2": ["CC6.1"], "HIPAA": ["164.312(a)(1)", "164.312(d)"], "ISO27001": ["A.8.5", "A.5.15"]},
    "CTRL": {"NIST": ["SC-5", "SC-7", "CM-6"], "PCI-DSS": ["1.2.1"], "SOC2": ["CC6.6"],
             "ISO27001": ["A.8.20", "A.8.9"]},
    "DATA": {"NIST": ["SC-7", "AC-4"], "PCI-DSS": ["1.2.1", "1.3.1"], "SOC2": ["CC6.6"],
             "ISO27001": ["A.8.20", "A.8.22"]},
    "SVC": {"NIST": ["CM-7"], "PCI-DSS": ["2.2.4"], "SOC2": ["CC6.1"], "ISO27001": ["A.8.9"]},
    "SW": {"NIST": ["SC-7", "AC-4"], "PCI-DSS": ["1.2.1"], "SOC2": ["CC6.6"], "ISO27001": ["A.8.20", "A.8.22"]},
    "WIFI": {"NIST": ["AC-18", "SC-8", "SC-13"], "PCI-DSS": ["4.2.1"], "SOC2": ["CC6.1"],
             "HIPAA": ["164.312(e)(1)"], "ISO27001": ["A.8.24"]},
    "NGFW": {"NIST": ["SC-7", "AC-4"], "PCI-DSS": ["1.2.1", "1.3.1"], "SOC2": ["CC6.6"],
             "ISO27001": ["A.8.20", "A.8.22"]},
    "LOG": {"NIST": ["AU-2", "AU-3", "AU-6", "AU-12"], "PCI-DSS": ["10.2.1", "10.3.1"],
            "SOC2": ["CC7.2"], "HIPAA": ["164.312(b)"], "ISO27001": ["A.8.15", "A.8.16"]},
    "CRYPTO": {"NIST": ["SC-8", "SC-13", "IA-5"], "PCI-DSS": ["4.2.1", "2.2.7"], "SOC2": ["CC6.1"],
               "HIPAA": ["164.312(e)(1)", "164.312(a)(2)(iv)"], "ISO27001": ["A.8.24"]},
    "CISCO-CVE": {"NIST": ["SI-2", "RA-5"], "PCI-DSS": ["6.3.3", "11.3.1"], "SOC2": ["CC7.1"],
                  "HIPAA": ["164.308(a)(1)(ii)(A)"], "ISO27001": ["A.8.8"]},
}

# {check_id-or-prefix: [device_type]} — which platforms a check applies to.
# Empty / absent = applies to all. Refined by the authoring workflow.
CHECK_PLATFORMS: Dict[str, List[str]] = {}

# Merge the generated per-check crosswalk OVER the family-prefix fallbacks above.
# Per-check entries win (resolve_compliance tries the exact check_id first), and a
# check with no per-check entry still falls back to its family. Guarded so the
# module works even if the generated data file is absent.
try:
    from compliance_data import COMPLIANCE_CROSSWALK as _CROSSWALK, CHECK_PLATFORMS as _PLATS
    COMPLIANCE_MAP.update(_CROSSWALK)
    CHECK_PLATFORMS.update(_PLATS)
except Exception:  # pragma: no cover - optional generated data
    pass

# Skip-notice / meta findings never carry compliance weight.
_META_MARKERS = ("-META-",)


def _is_meta(check_id: str) -> bool:
    return any(m in check_id for m in _META_MARKERS)


def _prefixes(check_id: str):
    """Yield exact id then progressively shorter family prefixes:
    CISCO-CVE-001 -> CISCO-CVE-001, CISCO-CVE, CISCO."""
    parts = check_id.split("-")
    yield check_id
    while len(parts) > 1:
        parts = parts[:-1]
        yield "-".join(parts)


def resolve_compliance(check_id: str) -> Dict[str, List[str]]:
    """Exact-then-family-prefix compliance lookup for a check_id."""
    if not check_id or _is_meta(check_id):
        return {}
    for key in _prefixes(check_id):
        if key in COMPLIANCE_MAP:
            return {fw: list(ctrls) for fw, ctrls in COMPLIANCE_MAP[key].items() if ctrls}
    return {}


def check_platforms(check_id: str) -> List[str]:
    for key in _prefixes(check_id):
        if key in CHECK_PLATFORMS:
            return list(CHECK_PLATFORMS[key])
    return []


# --------------------------------------------------------------------------- #
#  scoring                                                                      #
# --------------------------------------------------------------------------- #

def _control_section(framework: str, control: str) -> str:
    fw = framework.upper()
    if fw == "NIST":
        return control.split("-")[0]                    # AC-17 -> AC
    if fw == "HIPAA":
        return control.split("(")[0]                     # 164.312(a)(1) -> 164.312
    if fw == "ISO27001":
        p = control.split(".")
        return ".".join(p[:2]) if len(p) >= 2 else control  # A.8.5 -> A.8
    if fw == "SOC2":
        # CC6.1 -> CC6
        return control.split(".")[0]
    return control.split(".")[0]                          # CIS 2.1.3 -> 2 ; PCI 8.3.6 -> 8


def _reportable(findings: List[Any]) -> List[Any]:
    out = []
    for f in findings or []:
        cid = str(_g(f, "rule_id", ""))
        if _is_meta(cid):
            continue
        if str(_g(f, "severity", "")).upper() == "INFO":
            continue
        out.append(f)
    return out


def _finding_controls(finding: Any, framework: str) -> List[str]:
    """Controls this finding maps to in ``framework`` — prefer the finding's own
    resolved ``compliance`` dict, else resolve from its check_id."""
    comp = _g(finding, "compliance", {}) or {}
    ctrls = comp.get(framework)
    if ctrls is None:
        ctrls = resolve_compliance(str(_g(finding, "rule_id", ""))).get(framework, [])
    return list(ctrls or [])


def _universe(framework: str, platform: Optional[str]) -> set:
    """All controls this tool evaluates for ``framework`` (optionally platform-scoped)."""
    uni: set = set()
    for key, fws in COMPLIANCE_MAP.items():
        if platform and key in CHECK_PLATFORMS and platform not in CHECK_PLATFORMS[key]:
            continue
        for c in (fws.get(framework) or []):
            uni.add(c)
    return uni


def benchmark_score(framework: str, findings: List[Any], platform: Optional[str] = None) -> dict:
    """Score the config against ``framework``. Denominator = controls this tool
    evaluates (optionally restricted to ``platform``). A control FAILS if any
    reportable (non-INFO) finding references it, else PASSES."""
    framework = framework.upper()
    if framework not in FRAMEWORKS:
        raise ValueError(f"unknown framework {framework!r}; choose from {FRAMEWORKS}")
    universe = _universe(framework, platform)
    reportable = _reportable(findings)
    if platform:
        reportable = [f for f in reportable if str(_g(f, "device_type", "")) == platform
                      or not str(_g(f, "device_type", ""))]

    control_findings: Dict[str, set] = {}
    control_worst: Dict[str, str] = {}
    for f in reportable:
        for c in _finding_controls(f, framework):
            if c not in universe:
                continue
            control_findings.setdefault(c, set()).add(str(_g(f, "rule_id", "")))
            rank = _SEV_RANK.get(str(_g(f, "severity", "")).upper(), 4)
            if c not in control_worst or rank < _SEV_RANK.get(control_worst[c], 4):
                control_worst[c] = str(_g(f, "severity", "")).upper()

    failed = set(control_findings)
    sections: Dict[str, dict] = {}
    controls_out: List[dict] = []
    for c in sorted(universe):
        sec = _control_section(framework, c)
        s = sections.setdefault(sec, {"total": 0, "failed": 0})
        s["total"] += 1
        is_fail = c in failed
        if is_fail:
            s["failed"] += 1
        controls_out.append({
            "control": c, "section": sec,
            "status": "FAIL" if is_fail else "PASS",
            "findings": sorted(control_findings.get(c, [])),
            "worst_severity": control_worst.get(c),
        })
    for s in sections.values():
        s["passed"] = s["total"] - s["failed"]
        s["score_pct"] = round(s["passed"] / s["total"] * 100) if s["total"] else 100

    total = len(universe)
    n_pass = total - len(failed)

    def _sec_key(s: str):
        return (0, int(s)) if s.isdigit() else (1, s)
    return {
        "framework": framework,
        "platform": platform,
        "total_controls": total,
        "passed": n_pass,
        "failed": len(failed),
        "score_pct": round(n_pass / total * 100) if total else 100,
        "sections": {k: sections[k] for k in sorted(sections, key=_sec_key)},
        "controls": controls_out,
    }


def compliance_scorecard(findings: List[Any], platform: Optional[str] = None) -> dict:
    """Per-framework rollup: failing controls, finding count, worst severity."""
    out: Dict[str, dict] = {}
    reportable = _reportable(findings)
    for fw in FRAMEWORKS:
        controls: set = set()
        count = 0
        worst = None
        for f in reportable:
            fcs = [c for c in _finding_controls(f, fw)]
            if not fcs:
                continue
            count += 1
            controls.update(fcs)
            rank = _SEV_RANK.get(str(_g(f, "severity", "")).upper(), 4)
            if worst is None or rank < _SEV_RANK.get(worst, 4):
                worst = str(_g(f, "severity", "")).upper()
        out[fw] = {"failing_controls": len(controls),
                   "failing_control_ids": sorted(controls),
                   "findings": count, "worst_severity": worst}
    return out
