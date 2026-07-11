"""
NSS — Risk-Prioritization Engine (P1–P4 fix-first tiers)
========================================================
A post-scan overlay that answers "what do I fix first?" It fuses three signals
into a single 0–100 score and a P1–P4 tier per finding:

  * base severity (the intrinsic weakness rating),
  * real-world exploitability — CISA **KEV** membership (+ ransomware flag) and
    **FIRST.org EPSS** — for CVE findings, from a bundled offline snapshot, and
  * **reachability** — does this device actually expose the affected surface?
    (management plane reachable, NGFW any-any data path, and — when a per-CVE
    ``cve_reachability`` verdict is supplied — is the vulnerable feature enabled?)

Never mutates a finding (works on dicts via finding_view._g). KEV floor: a
known-exploited CVE never drops below P2. A CVE whose feature is proven disabled
is downranked (never suppressed) and capped out of P1. Stdlib only.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

try:
    from finding_view import _g
except Exception:  # pragma: no cover
    def _g(f, key, default=""):
        return (f.get(key, default) if isinstance(f, dict) else getattr(f, key, default))

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INTEL_PATH = os.path.join(_HERE, "threat_intel.json")

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# --- scoring model ---
BASE_POINTS: Dict[str, int] = {"CRITICAL": 50, "HIGH": 30, "MEDIUM": 15, "LOW": 6, "INFO": 0}
KEV_POINTS = 35
EPSS_MAX_POINTS = 20
EXPOSURE_POINTS = {"WIDE_OPEN": 20, "EXPOSED": 14, "NONE": 0}

REACH_CONFIRMED = "CONFIRMED_REACHABLE"
REACH_NOT_EXPOSED = "CONFIGURED_NOT_EXPOSED"
REACH_DISABLED = "FEATURE_DISABLED"
REACH_INDETERMINATE = "INDETERMINATE"
REACH_CONFIRMED_POINTS = 20
REACH_DISABLED_PENALTY = 25

TIER_THRESHOLDS = [(70, "P1"), (42, "P2"), (20, "P3"), (0, "P4")]
TIER_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
_RANK_TIER = {v: k for k, v in TIER_RANK.items()}

TIER_META: Dict[str, Dict[str, str]] = {
    "P1": {"label": "Fix Now", "window": "24–72 hours",
           "blurb": "Critical and actively exploited, or critical on the internet edge — treat as an incident."},
    "P2": {"label": "Fix This Week", "window": "within 7 days",
           "blurb": "Critical weakness, a known-exploited (KEV) vulnerability, or a high-risk exposure — schedule a change now."},
    "P3": {"label": "Planned Remediation", "window": "within 30 days",
           "blurb": "Meaningful hardening gap — fold into the next maintenance window."},
    "P4": {"label": "Backlog / Accept", "window": "next review cycle",
           "blurb": "Low residual risk — remediate opportunistically or formally accept."},
}

# Reachability planes (Cisco). A finding benefits only from the plane it lives on;
# CVE findings take the stronger of the two.
#   DATA  — the device's data path is exposed (NGFW any-any / permissive policy).
#   MGMT  — the device's own management plane is reachable insecurely.
DATA_CATEGORIES = {"NGFW Core Security", "NGFW Platform Security", "Data Plane"}
MGMT_CATEGORIES = {"Management Plane"}
CVE_CATEGORY = "CVE Detection"

# check_id + title signals that a management plane is insecurely reachable.
_MGMT_EXPOSURE_KW = ("http server", "telnet", "ssh version 1", "sshv1",
                     "transport input", "access-class", "aux port")
# NGFW/data-plane signals.
_DATA_WIDE_KW = ("any any", "any-any", "permit any", "overly permissive",
                 "0.0.0.0/0", "any source")
_DATA_EXPOSED_KW = ("exposed", "internet", "outside", "public-facing", "wan")


class ThreatIntel:
    """Loads the bundled KEV + EPSS snapshot. Missing/broken -> empty (score uses
    severity + reachability only)."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or DEFAULT_INTEL_PATH
        self.meta: Dict[str, Any] = {}
        self.cves: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                doc = json.load(fh)
            if isinstance(doc, dict):
                m = doc.get("meta")
                self.meta = m if isinstance(m, dict) else {}
                raw = doc.get("cves", {}) or {}
                if isinstance(raw, dict):
                    self.cves = {str(k).upper(): v for k, v in raw.items() if isinstance(v, dict)}
        except (OSError, ValueError):
            self.meta, self.cves = {}, {}

    def get(self, cve: Optional[str]) -> Optional[Dict[str, Any]]:
        return self.cves.get(str(cve).upper()) if cve else None

    @property
    def available(self) -> bool:
        return bool(self.cves)

    @property
    def snapshot_date(self) -> str:
        return str(self.meta.get("snapshot_date", "unknown"))

    @property
    def kev_count(self) -> int:
        return sum(1 for v in self.cves.values() if v.get("kev"))

    def age_days(self, today: Optional[Any] = None) -> Optional[int]:
        from datetime import date, datetime as _dt
        raw = self.meta.get("snapshot_date")
        if not raw:
            return None
        try:
            snap = _dt.strptime(str(raw), "%Y-%m-%d").date()
        except (TypeError, ValueError):
            return None
        return max(0, ((today or date.today()) - snap).days)

    def is_stale(self, threshold_days: int = 45, today: Optional[Any] = None) -> bool:
        age = self.age_days(today)
        return age is not None and age > threshold_days


class PriorityResult:
    __slots__ = ("finding", "tier", "score", "factors", "rationale",
                 "kev", "kev_date", "epss", "epss_pct", "reachable", "ransomware")

    def __init__(self, finding, tier, score, factors, rationale,
                 kev, kev_date, epss, epss_pct, reachable, ransomware=False):
        self.finding = finding
        self.tier = tier
        self.score = score
        self.factors = factors
        self.rationale = rationale
        self.kev = kev
        self.kev_date = kev_date
        self.epss = epss
        self.epss_pct = epss_pct
        self.reachable = reachable
        self.ransomware = ransomware

    @property
    def tier_rank(self) -> int:
        return TIER_RANK.get(self.tier, 9)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": _g(self.finding, "rule_id"),
            "severity": _g(self.finding, "severity"),
            "tier": self.tier,
            "tier_label": TIER_META[self.tier]["label"],
            "priority_score": self.score,
            "kev": self.kev,
            "kev_date": self.kev_date or None,
            "epss": self.epss,
            "epss_pct": self.epss_pct,
            "internet_reachable": self.reachable,
            "ransomware": self.ransomware,
            "rationale": self.rationale,
            "factors": self.factors,
        }


class RiskPrioritizer:
    def __init__(self, intel: Optional[ThreatIntel] = None):
        self.intel = intel or ThreatIntel()

    @staticmethod
    def exposure_context(findings: List[Any]) -> Dict[str, Any]:
        """Derive per-plane exposure from the scanner's own findings.
          data: WIDE_OPEN (NGFW any-any / permissive), EXPOSED, or NONE.
          mgmt: True when the management plane is reachable insecurely (HTTP
                server, Telnet/SSHv1, unrestricted VTY, no access-class)."""
        data = "NONE"
        mgmt = False
        for f in findings:
            rid = str(_g(f, "rule_id", ""))
            title = str(_g(f, "name", "")).lower()
            sev = str(_g(f, "severity", "")).upper()
            if rid.startswith("MGMT-") and any(k in title for k in _MGMT_EXPOSURE_KW):
                mgmt = True
            if rid.startswith("NGFW") and sev in ("CRITICAL", "HIGH", "MEDIUM"):
                if any(k in title for k in _DATA_WIDE_KW):
                    data = "WIDE_OPEN"
                elif data == "NONE" and any(k in title for k in _DATA_EXPOSED_KW):
                    data = "EXPOSED"
        return {"data": data, "mgmt": mgmt}

    @classmethod
    def _reachability(cls, f: Any, ctx: Dict[str, Any]):
        cat = str(_g(f, "category", ""))
        data_pts = EXPOSURE_POINTS.get(ctx.get("data", "NONE"), 0)
        mgmt_pts = EXPOSURE_POINTS["EXPOSED"] if ctx.get("mgmt") else 0
        is_mgmt = cat in MGMT_CATEGORIES
        is_data = cat in DATA_CATEGORIES
        is_cve = cat == CVE_CATEGORY
        if is_cve:
            if mgmt_pts >= data_pts and mgmt_pts > 0:
                return mgmt_pts, "mgmt"
            return data_pts, ("data" if data_pts else None)
        if is_mgmt:
            return mgmt_pts, ("mgmt" if mgmt_pts else None)
        if is_data:
            return data_pts, ("data" if data_pts else None)
        return 0, None

    def assess(self, f: Any, ctx: Optional[Dict[str, Any]] = None,
               cve_reachability: Optional[Dict[str, Any]] = None) -> PriorityResult:
        ctx = ctx or {"data": "NONE", "mgmt": False}
        sev = str(_g(f, "severity", "INFO")).upper()
        base = BASE_POINTS.get(sev, 0)
        score = base
        factors: List[Dict[str, Any]] = [
            {"label": "Severity", "detail": f"{sev.title()} weakness rating", "points": base},
        ]

        cve = _g(f, "cve", None)
        entry = self.intel.get(cve) if cve else None
        kev = bool(entry and entry.get("kev"))
        kev_date = str(entry.get("kev_date", "") or "") if entry else ""
        epss = epss_pct = None
        if entry:
            try:
                epss = float(entry.get("epss"))
            except (TypeError, ValueError):
                epss = None
            try:
                epss_pct = float(entry.get("epss_pct"))
            except (TypeError, ValueError):
                epss_pct = None
        ransomware = bool(entry and entry.get("ransomware"))
        if kev:
            score += KEV_POINTS
            when = f" (catalogued {kev_date})" if kev_date else ""
            rw = " — linked to known ransomware campaigns" if ransomware else ""
            factors.append({"label": "CISA KEV",
                            "detail": f"listed as actively exploited in the wild{when}{rw}",
                            "points": KEV_POINTS})
        if epss is not None:
            eb = int(round(epss * EPSS_MAX_POINTS))
            top = f"top {max(0.0, (1.0 - epss_pct) * 100):.1f}% of all CVEs" if epss_pct is not None else ""
            if eb:
                score += eb
                factors.append({"label": "EPSS",
                                "detail": (f"{epss * 100:.1f}% probability of exploitation in 30 days"
                                           + (f" — {top}" if top else "")), "points": eb})

        verdict = None
        evidence = ""
        if cve and cve_reachability:
            rec = cve_reachability.get(cve)
            if isinstance(rec, dict):
                verdict = rec.get("verdict")
                evidence = rec.get("evidence", "") or ""

        exp_pts, source = 0, None
        reach_note = ""
        if verdict in (REACH_CONFIRMED, REACH_NOT_EXPOSED, REACH_DISABLED):
            if verdict == REACH_CONFIRMED:
                exp_pts, source = REACH_CONFIRMED_POINTS, "reachable"
                reach_note = "vulnerable feature is enabled and reachable"
                score += exp_pts
                factors.append({"label": "Feature reachable", "detail": evidence or reach_note, "points": exp_pts})
            elif verdict == REACH_NOT_EXPOSED:
                reach_note = "vulnerable feature is enabled but not internet-facing"
                factors.append({"label": "Not internet-facing", "detail": evidence or reach_note, "points": 0})
            elif verdict == REACH_DISABLED:
                reach_note = "vulnerable feature is DISABLED on this device"
                score -= REACH_DISABLED_PENALTY
                factors.append({"label": "Feature disabled", "detail": evidence or reach_note,
                                "points": -REACH_DISABLED_PENALTY})
        else:
            exp_pts, source = self._reachability(f, ctx)
            if exp_pts and source:
                if source == "mgmt":
                    desc = "the device management plane is reachable insecurely"
                elif ctx.get("data") == "WIDE_OPEN":
                    desc = "reachable through an any-source / permissive data path"
                else:
                    desc = "on the exposed data-plane attack surface"
                score += exp_pts
                factors.append({"label": "Exposed", "detail": desc, "points": exp_pts})

        score = max(0, min(100, score))

        tier = "P4"
        for thr, name in TIER_THRESHOLDS:
            if score >= thr:
                tier = name
                break
        if kev and TIER_RANK[tier] > TIER_RANK["P2"]:
            tier = "P2"
        if verdict == REACH_DISABLED:
            cap_rank = TIER_RANK["P2"] if kev else TIER_RANK["P3"]
            if TIER_RANK[tier] < cap_rank:
                tier = _RANK_TIER[cap_rank]

        exposed = bool(exp_pts and source)
        rationale = self._rationale(tier, sev, kev, kev_date, epss, epss_pct,
                                    exposed, source, ctx.get("data", "NONE"),
                                    verdict, reach_note, ransomware)
        return PriorityResult(f, tier, score, factors, rationale,
                              kev, kev_date, epss, epss_pct, exposed, ransomware)

    @staticmethod
    def _rationale(tier, sev, kev, kev_date, epss, epss_pct, exposed, source, degree,
                   verdict=None, reach_note="", ransomware=False) -> str:
        bits: List[str] = []
        if kev:
            bits.append("actively exploited (CISA KEV"
                        + (f", {kev_date}" if kev_date else "")
                        + (", ransomware-linked" if ransomware else "") + ")")
        if epss is not None and epss >= 0.10:
            bits.append(f"{epss * 100:.0f}% EPSS exploit probability")
        if reach_note:
            bits.append(reach_note)
        elif exposed:
            if source == "mgmt":
                bits.append("management plane is reachable on this device")
            else:
                bits.append("reachable on this device"
                            + (" via a permissive data path" if degree == "WIDE_OPEN" else ""))
        drivers = "; ".join(bits) if bits else f"{sev.title()} severity"
        meta = TIER_META[tier]
        return f"{tier} ({meta['label']}, {meta['window']}): {drivers}. {meta['blurb']}"

    def prioritize(self, findings: List[Any],
                   context_findings: Optional[List[Any]] = None,
                   cve_reachability: Optional[Dict[str, Any]] = None) -> List[PriorityResult]:
        """Every finding as a PriorityResult, ordered fix-first. Pass the FULL
        unfiltered set as ``context_findings`` so a display filter can't weaken the
        reachability signal."""
        ctx = self.exposure_context(context_findings if context_findings is not None else findings)
        results = [self.assess(f, ctx, cve_reachability) for f in findings]
        results.sort(key=lambda r: (
            r.tier_rank, -r.score,
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                str(_g(r.finding, "severity", "INFO")).upper(), 9),
            str(_g(r.finding, "rule_id", "")),
        ))
        return results

    def tier_counts(self, results: List[PriorityResult]) -> Dict[str, int]:
        counts = {t: 0 for t in TIER_META}
        for r in results:
            counts[r.tier] = counts.get(r.tier, 0) + 1
        return counts


def by_finding(results: List[PriorityResult]) -> Dict[int, PriorityResult]:
    """id(finding) -> PriorityResult, for renderers/exporters that iterate the
    original finding list."""
    return {id(r.finding): r for r in results}


# --------------------------------------------------------------------------- #
#  online refresh + sneakernet (opt-in)                                        #
# --------------------------------------------------------------------------- #

def refresh_threat_intel(cve_ids: List[str], path: Optional[str] = None,
                         timeout: int = 30) -> Dict[str, Any]:
    """Rebuild threat_intel.json from the live CISA KEV catalog + FIRST.org EPSS
    for the given CVE IDs. Raises on failure. Stdlib urllib only."""
    import urllib.request
    import urllib.parse
    cve_ids = sorted({c.strip().upper() for c in cve_ids if c and c.strip()})
    if not cve_ids:
        raise ValueError("no CVE IDs supplied to refresh")

    def _fetch(url: str) -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": "nss-scanner/risk-intel"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.read()

    epss: Dict[str, Dict[str, float]] = {}
    for i in range(0, len(cve_ids), 60):
        chunk = cve_ids[i:i + 60]
        url = EPSS_API + "?" + urllib.parse.urlencode({"cve": ",".join(chunk)})
        data = json.loads(_fetch(url).decode("utf-8"))
        rows = data.get("data") if isinstance(data, dict) else None
        for row in (rows if isinstance(rows, list) else []):
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cve", "")).upper()
            if not cve:
                continue
            try:
                epss[cve] = {"epss": round(float(row.get("epss")), 5),
                             "epss_pct": round(float(row.get("percentile")), 5)}
            except (TypeError, ValueError):
                continue

    kev_doc = json.loads(_fetch(KEV_FEED).decode("utf-8"))
    kev_vulns = kev_doc.get("vulnerabilities") if isinstance(kev_doc, dict) else None
    kevmap: Dict[str, Dict[str, Any]] = {}
    for v in (kev_vulns if isinstance(kev_vulns, list) else []):
        if isinstance(v, dict) and v.get("cveID"):
            kevmap[str(v["cveID"]).upper()] = {
                "date": str(v.get("dateAdded", "")),
                "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"}

    cves: Dict[str, Dict[str, Any]] = {}
    for cve in cve_ids:
        e = epss.get(cve, {})
        entry: Dict[str, Any] = {"epss": e.get("epss", 0.0), "epss_pct": e.get("epss_pct", 0.0),
                                 "kev": cve in kevmap}
        if cve in kevmap:
            entry["kev_date"] = kevmap[cve]["date"]
            if kevmap[cve]["ransomware"]:
                entry["ransomware"] = True
        cves[cve] = entry

    from datetime import datetime
    doc = {"meta": {"schema": "nss-threat-intel/1",
                    "snapshot_date": datetime.now().strftime("%Y-%m-%d"),
                    "cve_count": len(cves),
                    "kev_count": sum(1 for c in cves.values() if c["kev"]),
                    "sources": {"kev": "CISA Known Exploited Vulnerabilities Catalog (cisa.gov/kev)",
                                "epss": "FIRST.org EPSS (first.org/epss)"},
                    "note": "Threat-intel snapshot for the NSS risk prioritizer. Refresh: nss_scanner.py --refresh-intel"},
           "cves": dict(sorted(cves.items()))}
    out = path or DEFAULT_INTEL_PATH
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return doc["meta"]


def _validate_intel_doc(doc: Any) -> Tuple[bool, str]:
    if not isinstance(doc, dict):
        return False, "top level is not a JSON object"
    if "meta" in doc and not isinstance(doc.get("meta"), dict):
        return False, "'meta' present but not an object"
    cves = doc.get("cves")
    if not isinstance(cves, dict) or not cves:
        return False, "missing or empty 'cves' map"
    bad = [k for k, v in cves.items() if not (isinstance(v, dict) and "epss" in v and "kev" in v)]
    if bad:
        return False, f"{len(bad)} of {len(cves)} cve entries malformed, e.g. {bad[0]}"
    return True, "ok"


def _normalize_cve_keys(doc: Dict[str, Any]) -> List[str]:
    cves = doc.get("cves")
    if not isinstance(cves, dict):
        return []
    norm: Dict[str, Any] = {}
    collisions: List[str] = []
    for k, v in cves.items():
        nk = str(k).strip().upper()
        if nk in norm:
            collisions.append(nk)
        norm[nk] = v
    doc["cves"] = norm
    return collisions


def _safe_meta(doc: Dict[str, Any]) -> Dict[str, Any]:
    m = doc.get("meta")
    meta = dict(m) if isinstance(m, dict) else {}
    cves = doc.get("cves", {}) if isinstance(doc.get("cves"), dict) else {}
    meta["cve_count"] = len(cves)
    meta["kev_count"] = sum(1 for v in cves.values() if isinstance(v, dict) and v.get("kev"))
    return meta


def export_intel(dest: str, src: Optional[str] = None) -> Dict[str, Any]:
    src = src or DEFAULT_INTEL_PATH
    with open(src, encoding="utf-8") as fh:
        doc = json.load(fh)
    _normalize_cve_keys(doc)
    ok, reason = _validate_intel_doc(doc)
    if not ok:
        raise ValueError(f"current snapshot at {src} is invalid ({reason})")
    meta = _safe_meta(doc)
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return meta


def import_intel(src: str, dest: Optional[str] = None) -> Dict[str, Any]:
    dest = dest or DEFAULT_INTEL_PATH
    with open(src, encoding="utf-8") as fh:
        doc = json.load(fh)
    _normalize_cve_keys(doc)
    ok, reason = _validate_intel_doc(doc)
    if not ok:
        raise ValueError(f"refusing to import {src}: {reason}")
    doc["meta"] = _safe_meta(doc)
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return doc["meta"]
