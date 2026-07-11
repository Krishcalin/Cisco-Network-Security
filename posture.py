"""
NSS — Continuous Posture State
==============================
Gives the Cisco scanner a memory: a file-based system of record that, run after
run, answers what is NEW / CARRIED / RESOLVED / REOPENED since last time, which
risks are formally ACCEPTED (reason/approver/expiry) and should stop nagging
until they expire, which open findings have blown their remediation SLA, which
just became newly KEV-listed, and how each device is trending.

Two safety principles (a system-of-record and a suppression channel are both
ways to silently hide a live finding):

  1. **Stable identity.** Findings are matched across scans by ``host | check_id |
     entity`` — NEVER by the evidence text (``affected_items``), which embeds
     volatile values. NSS findings usually *aggregate* many violations into one
     finding (e.g. one MGMT-004 lists every Type-7 user), so the entity is left
     empty and the key is *rule-per-device* — deriving an entity from list
     contents would make the key churn the moment one item is fixed. An entity is
     only extracted when a finding is a single, stably-identifiable instance
     (``affected_count == 1``: one interface / VTY line / username / ACL / …).
  2. **Fail open.** An expired or malformed exception is ignored and the finding
     re-appears — a suppression can never outlive its approval or hide a finding
     through a typo.

Standard library only.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

try:
    from finding_view import _g, fv_affected_items
except Exception:  # pragma: no cover - standalone fallback
    def _g(o, key, default=""):
        return (o.get(key, default) if isinstance(o, dict) else getattr(o, key, default))

    def fv_affected_items(f):
        return list((f.get("affected_items") if isinstance(f, dict) else getattr(f, "affected_items", [])) or [])

SCHEMA = "nss-posture/1"

# Remediation SLA windows per fix-first tier (days). P4 has no hard SLA.
TIER_SLA_DAYS = {"P1": 3, "P2": 7, "P3": 30, "P4": None}
EXPIRY_SOON_DAYS = 30


# --------------------------------------------------------------------------- #
#  stable finding identity (Cisco idioms)                                      #
# --------------------------------------------------------------------------- #

# A Cisco interface name, e.g. GigabitEthernet0/1, Te1/0/1, Vlan10, Port-channel2,
# Tunnel0, Loopback0, Management0/0, Ethernet1/1 (NX-OS).
_RE_IFACE = re.compile(
    r"\b((?:GigabitEthernet|TenGigabitEthernet|FortyGigE|HundredGigE|FastEthernet|"
    r"TwentyFiveGigE|Ethernet|Port-channel|Loopback|Tunnel|Serial|Management|Vlan|"
    r"Gi|Te|Fa|Eth|Po|Lo|Tu|Se|Mgmt|Vl)\d[\w./:-]*)", re.IGNORECASE)
# A VTY / console / aux line spec: "line vty 0 4", "line con 0".
_RE_LINE = re.compile(r"\bline\s+(vty|con(?:sole)?|aux|tty)\s+(\d+(?:\s+\d+)?)", re.IGNORECASE)
# A local username.
_RE_USER = re.compile(r"\busername\s+(\S+)", re.IGNORECASE)
# An ACL name or number.
_RE_ACL = re.compile(r"\b(?:ip\s+)?access-list\s+(?:standard\s+|extended\s+)?(\S+)|\baccess-list\s+(\d+)", re.IGNORECASE)
# ASA tunnel-group, crypto map, class/policy-map, SNMP community — named objects.
_RE_NAMED = re.compile(
    r"\b(tunnel-group|crypto\s+map|class-map|policy-map|route-map|snmp-server\s+community|"
    r"object-group|nameif)\s+(?:type\s+\S+\s+)?(\S+)", re.IGNORECASE)


def finding_entity(check_id: str, evidence: str) -> str:
    """Extract a STABLE sub-identity from a single-instance finding's evidence
    string. Returns "" when nothing clearly-identifiable is present (the common
    aggregate case). Conservative: only unambiguous Cisco identifiers qualify."""
    ev = evidence or ""
    m = _RE_IFACE.search(ev)
    if m:
        return "iface:" + m.group(1)
    m = _RE_LINE.search(ev)
    if m:
        return "line:" + (m.group(1) + " " + m.group(2).strip()).lower()
    m = _RE_USER.search(ev)
    if m:
        return "user:" + m.group(1)
    m = _RE_NAMED.search(ev)
    if m:
        return m.group(1).split()[0].lower() + ":" + m.group(2)
    m = _RE_ACL.search(ev)
    if m:
        return "acl:" + (m.group(1) or m.group(2))
    return ""


def finding_fingerprint(finding: Any) -> str:
    """Stable within-device key: ``check_id`` or ``check_id|entity``. Excludes the
    evidence text so a cosmetic change is the same finding. An entity is added
    ONLY for a single-instance finding (affected_count == 1); aggregate findings
    key on the check_id alone (see module docstring)."""
    rid = str(_g(finding, "rule_id", ""))
    items = fv_affected_items(finding)
    entity = finding_entity(rid, items[0]) if len(items) == 1 else ""
    return f"{rid}|{entity}" if entity else rid


# --------------------------------------------------------------------------- #
#  exceptions (risk acceptance / deferral)                                     #
# --------------------------------------------------------------------------- #

def _parse_date(s: Any) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(str(s)[:19], fmt)
        except (TypeError, ValueError):
            continue
    return None


class Exceptions:
    """Accepted/deferred risks. Each entry: {host, check_id (or rule_id), entity?,
    reason, approver, expires?, status}. Matching is host + check_id (+ entity if
    specified). FAIL OPEN: an expired or unparseable entry suppresses nothing and
    expired ones are reported so they get re-approved."""

    def __init__(self, entries: Optional[List[dict]] = None):
        self.entries = [e for e in (entries or []) if isinstance(e, dict)]

    @classmethod
    def load(cls, path: Optional[str]) -> "Exceptions":
        if not path:
            return cls([])
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            return cls([])
        if isinstance(doc, dict):
            doc = doc.get("exceptions", [])
        return cls(doc if isinstance(doc, list) else [])

    @staticmethod
    def _entry_check(e: dict) -> str:
        # accept either 'check_id' (Cisco) or 'rule_id' (Fortinet-style) in files
        return str(e.get("check_id", e.get("rule_id", "")))

    def match(self, host: str, check_id: str, entity: str, now: datetime
              ) -> Tuple[Optional[dict], bool]:
        """Return (active_exception, had_expired)."""
        expired = False
        for e in self.entries:
            eh = str(e.get("host", "*")) or "*"
            if eh not in ("*", host):
                continue
            if self._entry_check(e) != check_id:
                continue
            ent = str(e.get("entity", "") or "")
            if ent and ent != entity:
                continue
            if "expires" in e and e.get("expires") not in (None, ""):
                exp = _parse_date(e.get("expires"))
                if exp is None or now > exp:      # unparseable -> fail open (expired)
                    expired = True
                    continue
            return e, expired
        return None, expired


# --------------------------------------------------------------------------- #
#  posture delta                                                               #
# --------------------------------------------------------------------------- #

class PostureDelta:
    def __init__(self):
        self.host = ""
        self.prev_date: Optional[str] = None
        self.new: List[dict] = []
        self.carried: List[dict] = []
        self.resolved: List[dict] = []
        self.reopened: List[dict] = []
        self.accepted: List[dict] = []
        self.expired_exceptions: List[dict] = []
        self.sla_breaches: List[dict] = []
        self.newly_weaponized: List[dict] = []
        self.risk_score = 0
        self.prev_risk_score: Optional[int] = None
        self.open_active = 0
        self.open_accepted = 0

    @property
    def risk_delta(self) -> Optional[int]:
        if self.prev_risk_score is None:
            return None
        return self.risk_score - self.prev_risk_score

    def to_dict(self) -> Dict[str, Any]:
        def slim(recs, keys=("check_id", "entity", "severity", "name", "tier")):
            return [{k: r.get(k) for k in keys} for r in recs]
        return {
            "host": self.host, "prev_scan": self.prev_date,
            "risk_score": self.risk_score, "prev_risk_score": self.prev_risk_score,
            "risk_delta": self.risk_delta,
            "open_active": self.open_active, "open_accepted": self.open_accepted,
            "new": slim(self.new), "resolved": slim(self.resolved), "reopened": slim(self.reopened),
            "carried": len(self.carried),
            "accepted": [{**{k: a["rec"].get(k) for k in ("check_id", "entity", "severity", "name")},
                          "reason": a["exception"].get("reason"),
                          "approver": a["exception"].get("approver"),
                          "expires": a["exception"].get("expires")} for a in self.accepted],
            "expired_exceptions": self.expired_exceptions,
            "sla_breaches": [{**{k: b["rec"].get(k) for k in ("check_id", "severity", "name", "tier")},
                              "age_days": b["age_days"], "sla_days": b["window"]} for b in self.sla_breaches],
            "newly_weaponized": slim(self.newly_weaponized),
        }


# --------------------------------------------------------------------------- #
#  the store                                                                   #
# --------------------------------------------------------------------------- #

class PostureStore:
    RESOLVED_RETENTION_DAYS = 180

    def __init__(self, path: str):
        self.path = path
        self.data: Dict[str, Any] = {"schema": SCHEMA, "devices": {}}
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                doc = json.load(fh)
            if isinstance(doc, dict) and isinstance(doc.get("devices"), dict):
                self.data = doc
                self.data.setdefault("schema", SCHEMA)
        except (OSError, ValueError):
            pass  # first run / unreadable -> fresh (fail open)

    @staticmethod
    def _iso(dt: datetime) -> str:
        return dt.strftime("%Y-%m-%dT%H:%M:%S")

    def update(self, host: str, findings: List[Any], priorities: Optional[List[Any]] = None,
               exceptions: Optional[Exceptions] = None, now: Optional[datetime] = None,
               risk_score: int = 0) -> PostureDelta:
        now = now or datetime.now()
        exceptions = exceptions or Exceptions([])
        host = str(host or "unknown")
        dev = self.data["devices"].setdefault(host, {"findings": {}, "history": []})
        stored: Dict[str, dict] = dev["findings"]

        # priority overlay (tier/kev) keyed by fingerprint; unwrap PriorityResult
        prio_by_fp: Dict[str, dict] = {}
        for p in (priorities or []):
            pf = _g(p, "finding", p)
            prio_by_fp[finding_fingerprint(pf)] = {"tier": str(_g(p, "tier", "")),
                                                   "kev": bool(_g(p, "kev", False))}

        delta = PostureDelta()
        delta.host = host
        delta.risk_score = risk_score
        prev = dev["history"][-1] if dev["history"] else None
        if prev:
            delta.prev_date = prev.get("date")
            delta.prev_risk_score = prev.get("risk_score")

        current: Dict[str, Any] = {}
        for f in findings:
            current[finding_fingerprint(f)] = f

        for fp, f in current.items():
            pri = prio_by_fp.get(fp, {})
            kev = bool(pri.get("kev", False))
            tier = pri.get("tier", "")
            rid = str(_g(f, "rule_id", ""))
            items = fv_affected_items(f)
            entity = finding_entity(rid, items[0]) if len(items) == 1 else ""

            exc, had_expired = exceptions.match(host, rid, entity, now)
            accepted = exc is not None
            if had_expired and not accepted:
                delta.expired_exceptions.append({"check_id": rid, "entity": entity})

            rec = stored.get(fp)
            if rec is None:
                rec = stored[fp] = {
                    "check_id": rid, "entity": entity,
                    "severity": str(_g(f, "severity", "")), "name": str(_g(f, "name", "")),
                    "first_seen": self._iso(now), "last_seen": self._iso(now),
                    "status": "open", "kev": kev, "tier": tier,
                }
                if not accepted:
                    delta.new.append(rec)
            else:
                was_kev = bool(rec.get("kev"))
                if rec.get("status") == "resolved":
                    rec["status"] = "open"
                    rec["first_seen"] = self._iso(now)     # reopened -> SLA clock restarts
                    rec.pop("resolved_at", None)
                    if not accepted:
                        delta.reopened.append(rec)
                elif not accepted:
                    delta.carried.append(rec)
                if kev and not was_kev and not accepted:
                    delta.newly_weaponized.append(rec)
                rec["last_seen"] = self._iso(now)
                rec["severity"] = str(_g(f, "severity", ""))
                rec["name"] = str(_g(f, "name", "")) or rec.get("name", "")
                rec["kev"] = was_kev or kev             # KEV is sticky
                rec["tier"] = tier

            if accepted:
                delta.accepted.append({"rec": rec, "exception": exc})
                delta.open_accepted += 1
                continue
            delta.open_active += 1
            window = TIER_SLA_DAYS.get(rec.get("tier", ""))
            if window is not None:
                first = _parse_date(rec.get("first_seen"))
                if first is not None and (now - first) >= timedelta(days=window):
                    delta.sla_breaches.append({"rec": rec, "age_days": (now - first).days, "window": window})

        for fp, rec in stored.items():
            if rec.get("status") == "open" and fp not in current:
                rec["status"] = "resolved"
                rec["resolved_at"] = self._iso(now)
                delta.resolved.append(rec)

        self._prune_resolved(stored, now)
        delta.sla_breaches.sort(key=lambda b: -b["age_days"])

        counts: Dict[str, int] = {}
        for f in findings:
            sev = str(_g(f, "severity", "INFO")).upper()
            counts[sev] = counts.get(sev, 0) + 1
        dev["history"].append({
            "date": self._iso(now), "risk_score": risk_score,
            "open": len(current), "new": len(delta.new), "resolved": len(delta.resolved),
            "counts": counts,
        })
        if len(dev["history"]) > 200:
            dev["history"] = dev["history"][-200:]
        return delta

    def _prune_resolved(self, stored: Dict[str, dict], now: datetime) -> None:
        cutoff = now - timedelta(days=self.RESOLVED_RETENTION_DAYS)
        for fp in [k for k, r in stored.items()
                   if r.get("status") == "resolved"
                   and (_parse_date(r.get("resolved_at")) or now) < cutoff]:
            del stored[fp]

    def trend(self, host: str, n: int = 12) -> List[Dict[str, Any]]:
        dev = self.data["devices"].get(host, {})
        return list(dev.get("history", []))[-n:]

    def save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
