"""
nss_export — SOAR / ticketing + SIEM export for NSS
===================================================
Turns the prioritized findings into ready-to-POST payloads for the systems a
network team lives in, so the scanner's system-of-record becomes ACTION:

  * SOAR / ticketing — Jira issues, ServiceNow incidents, Splunk SOAR containers,
    or a vendor-neutral CloudEvents 1.0 webhook.
  * SIEM / CI        — SARIF 2.1.0 (code-scanning) and OCSF findings.

Every SOAR item carries a stable dedup key (device + the posture fingerprint,
hashed) so a re-scan UPDATES the same ticket instead of duplicating it; when a
posture delta is supplied, resolved findings emit CLOSE events so stale tickets
don't leak. Ported from the Fortinet exporter and adapted to NSS's MULTI-DEVICE
model: the host is derived PER FINDING (a scan spans many devices), and posture
deltas are supplied as a {host: PostureDelta} map. Pure stdlib / dict-tolerant
(findings read via finding_view._g). Each builder returns:
  {target, meta, items: [{op, dedup_key, body}]}.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

try:
    from finding_view import _g, fv_host
except Exception:  # pragma: no cover
    def _g(f, key, default=""):
        return (f.get(key, default) if isinstance(f, dict) else getattr(f, key, default))

    def fv_host(f):
        return str(_g(f, "host", "") or _g(f, "device", "") or "unknown")

_TIER_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
_SLA_HUMAN = {"P1": "24-72h", "P2": "7d", "P3": "30d", "P4": None}
_TIER_BY_SEV = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4", "INFO": "P4"}
_JIRA_PRI_BY_TIER = {"P1": ("Highest", "1"), "P2": ("High", "2"), "P3": ("Medium", "3"), "P4": ("Low", "4")}
_JIRA_PRI_BY_SEV = {"CRITICAL": ("Highest", "1"), "HIGH": ("High", "2"), "MEDIUM": ("Medium", "3"),
                    "LOW": ("Low", "4"), "INFO": ("Lowest", "5")}
_SN_UI_BY_TIER = {"P1": ("1", "1"), "P2": ("2", "1"), "P3": ("2", "2"), "P4": ("3", "3")}
_SN_UI_BY_SEV = {"CRITICAL": ("1", "1"), "HIGH": ("1", "2"), "MEDIUM": ("2", "2"),
                 "LOW": ("3", "2"), "INFO": ("3", "3")}
_SOAR_SEV_BY_TIER = {"P1": "high", "P2": "high", "P3": "medium", "P4": "low"}
_SOAR_SEV_BY_SEV = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "low"}
_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
_SECSEV = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0, "INFO": 1.0}
_OCSF_SEV = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

_SCANNER_NAME = "Network Security Scanner (NSS)"
_VENDOR = "Krishcalin"
_INFO_URI = "https://github.com/Krishcalin/Cisco-Network-Security"


# --------------------------------------------------------------------------- #
#  identity + planning                                                         #
# --------------------------------------------------------------------------- #

def _fp_string(check_id: Any, entity: Any) -> str:
    check_id = str(check_id or "")
    entity = str(entity or "")
    return f"{check_id}|{entity}" if entity else check_id


def _dedup_key(host: str, finding: Any) -> str:
    """sha1('host|check_id[|entity]')[:16] — the same posture fingerprint, host-
    scoped and hashed. Stable across scans, evidence-independent, label-safe."""
    try:
        from posture import finding_fingerprint
        fp = finding_fingerprint(finding)
    except Exception:  # pragma: no cover
        fp = str(_g(finding, "rule_id", ""))
    return hashlib.sha1(f"{host}|{fp}".encode("utf-8")).hexdigest()[:16]


def _dedup_key_from_rec(host: str, rec: Dict[str, Any]) -> str:
    """Same key for a slim posture rec (Cisco recs key on check_id+entity)."""
    fp = _fp_string(rec.get("check_id", rec.get("rule_id", "")), rec.get("entity", ""))
    return hashlib.sha1(f"{host}|{fp}".encode("utf-8")).hexdigest()[:16]


def _entity_of(finding: Any) -> str:
    try:
        from posture import finding_fingerprint
        fp = finding_fingerprint(finding)
        return fp.split("|", 1)[1] if "|" in fp else ""
    except Exception:  # pragma: no cover
        return ""


def _as_dict(p) -> Dict[str, Any]:
    """Normalize a prio_by_id value to a dict (accept a PriorityResult or a dict)."""
    if p is None:
        return {}
    return p.to_dict() if hasattr(p, "to_dict") else p


def _tier_of(prio: Dict[str, Any], finding: Any) -> str:
    if prio and prio.get("tier"):
        return str(prio["tier"])
    return _TIER_BY_SEV.get(str(_g(finding, "severity", "")).upper(), "P4")


def _tier_of_rec(rec: Dict[str, Any]) -> str:
    return rec.get("tier") or _TIER_BY_SEV.get(str(rec.get("severity", "")).upper(), "P4")


def _tier_ok(tier: Any, min_tier: str) -> bool:
    return _TIER_RANK.get(str(tier), 3) <= _TIER_RANK.get(str(min_tier).upper(), 3)


def _lifecycle_multi(deltas):
    """(op_by_key, resolved) merged across a {host: PostureDelta} map. Each rec is
    keyed with ITS device's host so keys line up with the per-finding live keys."""
    op: Dict[str, str] = {}
    resolved = []
    for host, delta in (deltas or {}).items():
        if delta is None:
            continue
        for r in getattr(delta, "new", []) or []:
            op[_dedup_key_from_rec(host, r)] = "create"
        for r in getattr(delta, "reopened", []) or []:
            op[_dedup_key_from_rec(host, r)] = "reopen"
        for r in getattr(delta, "carried", []) or []:
            op[_dedup_key_from_rec(host, r)] = "update"
        for r in getattr(delta, "resolved", []) or []:
            resolved.append((_dedup_key_from_rec(host, r), r, host))
    return op, resolved


def _kb_detail(kb: Any, finding: Any) -> Dict[str, Any]:
    if kb is not None:
        try:
            return kb.detail_for(finding)
        except Exception:  # pragma: no cover
            pass
    rec = str(_g(finding, "recommendation", "") or "")
    refs = [str(r) for r in (_g(finding, "cwe"), _g(finding, "cve")) if r]
    return {"risk": str(_g(finding, "description", "") or ""),
            "steps": [rec] if rec else [], "gui": "",
            "cli": str(_g(finding, "remediation_cmd", "") or ""),
            "verify": "", "rollback": "", "impact": "", "references": refs, "_detailed": False}


def _plan(findings: List[Any], prio_by_id, deltas, min_tier: str):
    """Shared multi-device planner. Returns (live, resolved):
      live:     [(finding, op, key, prio, host)] for findings at/above min_tier
      resolved: [(rec, key, host)] closures for resolved findings at/above min_tier."""
    prio_by_id = prio_by_id or {}
    op_by_key, resolved_pairs = _lifecycle_multi(deltas)
    live = []
    seen = set()
    for f in findings:
        prio = _as_dict(prio_by_id.get(id(f)))
        if not _tier_ok(_tier_of(prio, f), min_tier):
            continue
        host = fv_host(f)
        key = _dedup_key(host, f)
        if key in seen:      # a check may fire >1x per device with the same identity;
            continue         # emit ONE work item per (device, finding) key
        seen.add(key)
        live.append((f, op_by_key.get(key, "upsert"), key, prio, host))
    resolved = [(rec, key, host) for (key, rec, host) in resolved_pairs
                if key not in seen and _tier_ok(_tier_of_rec(rec), min_tier)]
    return live, resolved


def _devices(findings) -> List[str]:
    return sorted({fv_host(f) for f in findings})


def _envelope(target: str, scan_epoch: int, items, devices) -> Dict[str, Any]:
    return {"target": target,
            "meta": {"devices": devices, "scanner": _SCANNER_NAME, "vendor": _VENDOR,
                     "scan_epoch": int(scan_epoch or 0), "count": len(items)},
            "items": items}


def _compliance_flat(f: Any) -> str:
    comp = _g(f, "compliance", {}) or {}
    parts = []
    if isinstance(comp, dict):
        for fw, ctrls in comp.items():
            for c in (ctrls or []):
                parts.append(f"{fw}:{c}")
    return ", ".join(parts) or "-"


def _finding_summary(finding, prio) -> Dict[str, Any]:
    return {"check_id": _g(finding, "rule_id"), "name": _g(finding, "name"),
            "severity": _g(finding, "severity"), "category": _g(finding, "category"),
            "cve": _g(finding, "cve") or None, "cwe": _g(finding, "cwe") or None,
            "evidence": _g(finding, "line_content"), "compliance": _g(finding, "compliance") or {},
            "priority": {k: prio.get(k) for k in
                         ("tier", "priority_score", "kev", "epss", "internet_reachable")} if prio else {}}


# ---- KB flattening + ADF (Jira) ---------------------------------------------

def _kb_lines(detail):
    out = []
    if detail.get("risk"):
        out.append(("Risk", str(detail["risk"])))
    steps = [s for s in (detail.get("steps") or []) if str(s).strip()]
    if steps:
        out.append(("Remediation steps", "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))))
    for lbl, key in (("GUI path", "gui"), ("CLI", "cli"), ("Verify", "verify"),
                     ("Rollback", "rollback"), ("Service impact", "impact")):
        if detail.get(key):
            out.append((lbl, str(detail[key])))
    refs = [r for r in (detail.get("references") or []) if str(r).strip()]
    if refs:
        out.append(("References", "\n".join(f"- {r}" for r in refs)))
    return out


def _kb_text(detail, limit=None) -> str:
    text = "\n\n".join(f"{lbl}:\n{body}" for lbl, body in _kb_lines(detail))
    if limit and len(text) > limit:
        text = text[: max(0, limit - 1)].rstrip() + "…"
    return text


def _webhook_remediation(detail):
    if not detail:
        return {}
    return {"summary": detail.get("risk", ""), "steps": detail.get("steps", []),
            "gui": detail.get("gui", ""), "cli": detail.get("cli", ""),
            "verify": detail.get("verify", ""), "rollback": detail.get("rollback", ""),
            "service_impact": detail.get("impact", ""), "references": detail.get("references", [])}


def _adf_text(s):
    return {"type": "text", "text": str(s)}


def _adf_para(s):
    return {"type": "paragraph", "content": [_adf_text(s)]}


def _adf_heading(s, level=3):
    return {"type": "heading", "attrs": {"level": level}, "content": [_adf_text(s)]}


def _adf_code(s, language="shell"):
    return {"type": "codeBlock", "attrs": {"language": language}, "content": [_adf_text(s)]}


def _adf_list(items, ordered=True):
    node = "orderedList" if ordered else "bulletList"
    return {"type": node, "content": [{"type": "listItem", "content": [_adf_para(it)]}
                                      for it in items if str(it).strip()]}


def _adf_from_kb(detail, header):
    content = [_adf_para(header)]
    if detail.get("risk"):
        content += [_adf_heading("Risk"), _adf_para(detail["risk"])]
    steps = [s for s in (detail.get("steps") or []) if str(s).strip()]
    if steps:
        content += [_adf_heading("Remediation steps"), _adf_list(steps, True)]
    if detail.get("gui"):
        content += [_adf_heading("GUI path"), _adf_para(detail["gui"])]
    for lbl, key in (("CLI", "cli"), ("Verify", "verify"), ("Rollback", "rollback")):
        if detail.get(key):
            content += [_adf_heading(lbl), _adf_code(detail[key])]
    if detail.get("impact"):
        content += [_adf_heading("Service impact"), _adf_para(detail["impact"])]
    refs = [r for r in (detail.get("references") or []) if str(r).strip()]
    if refs:
        content += [_adf_heading("References"), _adf_list(refs, False)]
    return {"type": "doc", "version": 1, "content": content}


def _jira_labels(base_labels, severity, tier, key):
    labels = list(base_labels)
    sev = str(severity or "").lower()
    if sev:
        labels.append(f"sev-{sev}")
    if tier:
        labels.append(f"tier-{str(tier).lower()}")
    labels.append(f"nss-fp-{key}")
    return ["_".join(str(l).split()) for l in labels]


# --------------------------------------------------------------------------- #
#  SOAR / ticketing builders                                                   #
# --------------------------------------------------------------------------- #

def build_jira(findings, *, prio_by_id=None, kb=None, deltas=None, min_tier="P4",
               project_key="SEC", issuetype="Bug", api_version=3,
               base_labels=("cisco", "network-hardening"), set_priority=True, scan_epoch=0):
    live, resolved = _plan(findings, prio_by_id, deltas, min_tier)
    v = 2 if str(api_version) == "2" else 3
    items = []
    for f, op, key, prio, host in live:
        sev = str(_g(f, "severity", "")).upper()
        rid = str(_g(f, "rule_id", ""))
        name = str(_g(f, "name", "") or rid)
        tier = _tier_of(prio, f)
        detail = _kb_detail(kb, f)
        header = f"Finding {rid} on {host} — severity {sev}, priority tier {tier}."
        fields = {"project": {"key": project_key}, "issuetype": {"name": issuetype},
                  "summary": f"[{host}] {name} ({rid})"[:255],
                  "labels": _jira_labels(base_labels, sev, tier, key)}
        if set_priority:
            pname, pid = (_JIRA_PRI_BY_TIER.get(tier) if prio.get("tier") else None) \
                or _JIRA_PRI_BY_SEV.get(sev, ("Medium", "3"))
            fields["priority"] = {"name": pname, "id": pid}
        fields["description"] = _adf_from_kb(detail, header) if v == 3 else (header + "\n\n" + _kb_text(detail)).strip()
        prop = {"fingerprint": key, "host": host, "checkId": rid, "entity": _entity_of(f),
                "severity": sev, "tier": tier, "cve": _g(f, "cve") or None, "cwe": _g(f, "cwe") or None,
                "kev": bool(prio.get("kev", False)), "epss": prio.get("epss"), "scanner": _SCANNER_NAME}
        items.append({"op": op, "dedup_key": key,
                      "body": {"fields": fields, "properties": [{"key": "nssFinding", "value": prop}]}})
    for rec, key, host in resolved:
        items.append({"op": "resolve", "dedup_key": key, "body": {
            "jql": f'project = {project_key} AND labels = "nss-fp-{key}"',
            "transition_hint": "Done",
            "comment": "No longer detected by NSS as of this scan."}})
    return _envelope("jira", scan_epoch, items, _devices(findings))


def build_servicenow(findings, *, prio_by_id=None, kb=None, deltas=None, min_tier="P4",
                     category="network", subcategory=None, assignment_group_sysid=None,
                     caller_sysid=None, cmdb_ci_sysid=None, contact_type="integration", scan_epoch=0):
    live, resolved = _plan(findings, prio_by_id, deltas, min_tier)
    items = []
    for f, op, key, prio, host in live:
        sev = str(_g(f, "severity", "")).upper()
        rid = str(_g(f, "rule_id", ""))
        name = str(_g(f, "name", "") or rid)
        tier = _tier_of(prio, f)
        urgency, impact = (_SN_UI_BY_TIER.get(tier) if prio.get("tier") else None) \
            or _SN_UI_BY_SEV.get(sev, ("2", "2"))
        detail = _kb_detail(kb, f)
        header = (f"Device: {host}\nCheck: {rid}\nSeverity: {sev}   Priority tier: {tier}\n"
                  f"Category: {_g(f, 'category', '')}\nEvidence: {_g(f, 'line_content', '')}\n"
                  f"CVE: {_g(f, 'cve') or '-'}   CWE: {_g(f, 'cwe') or '-'}\n"
                  f"Compliance: {_compliance_flat(f)}")
        body = {"short_description": f"{name} on {host} ({rid})"[:160],
                "description": (header + "\n\n" + _kb_text(detail))[:4000],
                "category": category, "urgency": urgency, "impact": impact,
                "contact_type": contact_type, "correlation_id": f"nssscan:{key}",
                "correlation_display": _SCANNER_NAME}
        if subcategory:
            body["subcategory"] = subcategory
        if assignment_group_sysid:
            body["assignment_group"] = assignment_group_sysid
        if caller_sysid:
            body["caller_id"] = caller_sysid
        if cmdb_ci_sysid:
            body["cmdb_ci"] = cmdb_ci_sysid
        items.append({"op": op, "dedup_key": key, "body": body})
    for rec, key, host in resolved:
        items.append({"op": "resolve", "dedup_key": key, "body": {
            "correlation_id": f"nssscan:{key}", "state": "6", "close_code": "Resolved by caller",
            "close_notes": "Finding no longer detected by NSS as of this scan.",
            "work_notes": "Auto-resolved by Network Security Scanner."}})
    return _envelope("servicenow", scan_epoch, items, _devices(findings))


def build_splunk_soar(findings, *, prio_by_id=None, kb=None, deltas=None, min_tier="P4",
                      label="events", artifact_label="event", sensitivity="amber", asset_id=None, scan_epoch=0):
    live, resolved = _plan(findings, prio_by_id, deltas, min_tier)
    items = []
    for f, op, key, prio, host in live:
        sev = str(_g(f, "severity", "")).upper()
        rid = str(_g(f, "rule_id", ""))
        name = str(_g(f, "name", "") or rid)
        tier = _tier_of(prio, f)
        soar_sev = (_SOAR_SEV_BY_TIER.get(tier) if prio.get("tier") else None) or _SOAR_SEV_BY_SEV.get(sev, "medium")
        detail = _kb_detail(kb, f)
        sdi = f"nssscan:{key}"
        cef = {"deviceHostName": host, "cs1Label": "checkId", "cs1": rid,
               "cs2Label": "intrinsicSeverity", "cs2": sev, "cs3Label": "priorityTier", "cs3": tier,
               "msg": (str(_g(f, "description", "")) or name)[:1000]}
        if _g(f, "cve"):
            cef["cs4Label"], cef["cs4"] = "cve", _g(f, "cve")
        if prio.get("priority_score") is not None:
            cef["cn1Label"], cef["cn1"] = "priorityScore", prio.get("priority_score")
        container = {"name": f"Cisco finding: {name} ({host})"[:250], "label": label,
                     "description": str(_g(f, "description", "")) or name, "severity": soar_sev,
                     "sensitivity": sensitivity, "status": "new", "source_data_identifier": sdi,
                     "tags": ["cisco", rid, f"sev-{sev.lower()}", f"tier-{tier.lower()}"],
                     "data": {"scanner_finding": _finding_summary(f, prio)},
                     "artifacts": [{"name": name[:250], "label": artifact_label, "severity": soar_sev,
                                    "source_data_identifier": f"{sdi}:1", "cef": cef,
                                    "cef_types": {"deviceHostName": ["host name"]},
                                    "data": {"remediation": detail}}]}
        if asset_id is not None:
            container["asset_id"] = asset_id
        items.append({"op": op, "dedup_key": key, "body": container})
    for rec, key, host in resolved:
        items.append({"op": "resolve", "dedup_key": key,
                      "body": {"source_data_identifier": f"nssscan:{key}", "status": "closed"}})
    return _envelope("splunk_soar", scan_epoch, items, _devices(findings))


def build_webhook(findings, *, prio_by_id=None, kb=None, deltas=None, min_tier="P4",
                  source_prefix="/nss-scanner", scan_epoch=0, now_iso="", tool_version="",
                  dataschema="https://github.com/Krishcalin/Cisco-Network-Security/schemas/finding/1.0"):
    live, resolved = _plan(findings, prio_by_id, deltas, min_tier)
    _EVENT = {"create": "new", "update": "existing", "reopen": "reopened", "resolve": "resolved", "upsert": "new"}
    items = []

    def _ce(key, event, host, data):
        ce = {"specversion": "1.0", "id": f"{key}-{int(scan_epoch or 0)}",
              "source": f"{source_prefix}/{host}", "type": f"com.krishcalin.nss.finding.{event}",
              "subject": key, "datacontenttype": "application/json", "dataschema": dataschema, "data": data}
        if now_iso:
            ce["time"] = now_iso
        return ce

    for f, op, key, prio, host in live:
        event = _EVENT.get(op, "new")
        sev = str(_g(f, "severity", "")).upper()
        rid = str(_g(f, "rule_id", ""))
        tier = _tier_of(prio, f)
        detail = _kb_detail(kb, f)
        loc = f"{_g(f, 'file_path', '')}".strip()
        data = {"dedup_key": key, "event": event, "check_id": rid,
                "title": str(_g(f, "name", "") or rid), "severity": sev,
                "priority": {"tier": tier, "score": prio.get("priority_score"),
                             "label": prio.get("tier_label"), "sla": _SLA_HUMAN.get(tier)},
                "threat": {"kev": bool(prio.get("kev", False)), "kev_date": prio.get("kev_date"),
                           "epss": prio.get("epss"), "epss_percentile": prio.get("epss_pct"),
                           "ransomware": bool(prio.get("ransomware", False)),
                           "internet_reachable": bool(prio.get("internet_reachable", False))},
                "vulnerability": {"cve": _g(f, "cve") or None, "cwe": _g(f, "cwe") or None},
                "compliance": _g(f, "compliance") or {},
                "evidence": {"asset": host, "device_type": _g(f, "device_type"),
                             "category": _g(f, "category"), "location": loc,
                             "snippet": _g(f, "line_content")},
                "remediation": _webhook_remediation(detail), "status": "open",
                "source_tool": {"name": _SCANNER_NAME, "vendor": _VENDOR, "version": str(tool_version or "")}}
        items.append({"op": op, "dedup_key": key, "body": _ce(key, event, host, data)})
    for rec, key, host in resolved:
        data = {"dedup_key": key, "event": "resolved", "check_id": rec.get("check_id"),
                "title": rec.get("name"), "severity": str(rec.get("severity", "")).upper(),
                "priority": {"tier": rec.get("tier"), "score": None, "label": None,
                             "sla": _SLA_HUMAN.get(rec.get("tier"))},
                "status": "resolved", "resolved_at": rec.get("resolved_at"),
                "source_tool": {"name": _SCANNER_NAME, "vendor": _VENDOR, "version": str(tool_version or "")}}
        items.append({"op": "resolve", "dedup_key": key, "body": _ce(key, "resolved", host, data)})
    return _envelope("webhook", scan_epoch, items, _devices(findings))


# --------------------------------------------------------------------------- #
#  SIEM / CI: SARIF 2.1.0 + OCSF                                               #
# --------------------------------------------------------------------------- #

def _tags(f):
    tags = ["security", "cisco"]
    cat = str(_g(f, "category", "")).strip()
    if cat:
        tags.append(cat.lower().replace(" ", "-"))
    if _g(f, "cve"):
        tags.append("cve")
    return tags


def _help_uri(f):
    cve = _g(f, "cve")
    if cve:
        return f"https://nvd.nist.gov/vuln/detail/{cve}"
    cwe = str(_g(f, "cwe", "") or "")
    if cwe.upper().startswith("CWE-") and cwe[4:].isdigit():
        return f"https://cwe.mitre.org/data/definitions/{cwe[4:]}.html"
    return None


def build_sarif(findings, *, tool_version="", prio_by_id=None):
    """SARIF 2.1.0 log. Each result's artifact location is the finding's device
    config file (multi-device aware); properties carry P-tier/KEV/EPSS/compliance."""
    prio_by_id = prio_by_id or {}
    rules, order = {}, []
    for f in findings:
        rid = str(_g(f, "rule_id", "") or "")
        if not rid or rid in rules:
            continue
        order.append(rid)
        sev = str(_g(f, "severity", "")).upper()
        rule = {"id": rid, "name": (str(_g(f, "name", "") or rid))[:120],
                "shortDescription": {"text": (str(_g(f, "name", "") or rid))[:1000]},
                "fullDescription": {"text": (str(_g(f, "description", "") or ""))[:3000]},
                "defaultConfiguration": {"level": _LEVEL.get(sev, "warning")},
                "properties": {"security-severity": str(_SECSEV.get(sev, 5.0)), "tags": _tags(f)}}
        hu = _help_uri(f)
        if hu:
            rule["helpUri"] = hu
        rec = str(_g(f, "recommendation", "") or "")
        if rec:
            rule["help"] = {"text": rec[:2000]}
        rules[rid] = rule
    results = []
    for f in findings:
        rid = str(_g(f, "rule_id", "") or "")
        sev = str(_g(f, "severity", "")).upper()
        pr = _as_dict(prio_by_id.get(id(f)))
        props = {}
        if pr.get("tier"):
            props["priority_tier"] = pr["tier"]
        if pr.get("priority_score") is not None:
            props["priority_score"] = pr["priority_score"]
        if pr.get("kev"):
            props["kev"] = True
        if pr.get("epss") is not None:
            props["epss"] = pr["epss"]
        for k in ("cve", "cwe"):
            if _g(f, k):
                props[k] = _g(f, k)
        if _g(f, "compliance"):
            props["compliance"] = _g(f, "compliance")
        uri = str(_g(f, "file_path", "") or "cisco-config")
        res = {"ruleId": rid, "level": _LEVEL.get(sev, "warning"),
               "message": {"text": str(_g(f, "description", "") or _g(f, "name", "") or rid)},
               "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
               "partialFingerprints": {"nssFindingHash": _dedup_key(fv_host(f), f)}}
        if props:
            res["properties"] = props
        results.append(res)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": _SCANNER_NAME, "informationUri": _INFO_URI,
                                          "version": str(tool_version or "0"),
                                          "rules": [rules[r] for r in order]}},
                      "results": results}]}


def build_ocsf(findings, *, epoch=0, prio_by_id=None):
    """OCSF Compliance Finding (class_uid 2003) events for SIEM ingestion."""
    prio_by_id = prio_by_id or {}
    events = []
    for f in findings:
        sev = str(_g(f, "severity", "")).upper()
        pr = _as_dict(prio_by_id.get(id(f)))
        comp = _g(f, "compliance") or {}
        reqs = [f"{fw}:{c}" for fw, cs in (comp.items() if isinstance(comp, dict) else []) for c in (cs or [])]
        events.append({
            "class_uid": 2003, "class_name": "Compliance Finding", "category_uid": 2,
            "category_name": "Findings", "type_uid": 200301, "type_name": "Compliance Finding: Create",
            "activity_id": 1, "activity_name": "Create", "severity_id": _OCSF_SEV.get(sev, 1),
            "severity": (sev.title() if sev else "Informational"), "status": "New", "time": int(epoch or 0),
            "message": str(_g(f, "name", "") or _g(f, "rule_id", "")),
            "metadata": {"product": {"name": _SCANNER_NAME, "vendor_name": _VENDOR,
                                     "version": str(pr.get("tool_version", ""))}, "version": "1.3.0"},
            "finding_info": {"uid": _g(f, "rule_id"), "title": _g(f, "name"), "desc": _g(f, "description")},
            "compliance": {"requirements": reqs},
            "remediation": {"desc": _g(f, "recommendation")},
            "resources": [{"name": fv_host(f), "type": "Network Device",
                           "uid": str(_g(f, "device_type", "") or "")}],
            "unmapped": {"category": _g(f, "category"), "cve": _g(f, "cve") or None,
                         "cwe": _g(f, "cwe") or None, "compliance": comp,
                         "priority_tier": pr.get("tier"), "priority_score": pr.get("priority_score"),
                         "kev": bool(pr.get("kev", False)), "epss": pr.get("epss"),
                         "device": fv_host(f)}})
    return events
