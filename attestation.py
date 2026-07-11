"""
Network Security Scanner (NSS) — Compliance Attestation Pack
============================================================
Turns a scan into a **tamper-evident, point-in-time compliance evidence bundle**
an auditor can actually use — per-control PASS / FAIL / RISK-ACCEPTED across
CIS / PCI-DSS / NIST 800-53 / SOC 2 / HIPAA / ISO 27001, each failing control
carrying the finding evidence that produced it, plus risk-acceptance sign-offs
(approver + expiry) and a hash-manifest an auditor can verify.

Unlike the FortiGate scanner this is ported from, an NSS scan covers a **fleet**:
one run examines many Cisco devices (IOS / IOS-XE / NX-OS / ASA / FTD / WLC). The
sealed body therefore carries a ``devices`` array — one coverage/results/risk-
acceptance block per device, each PASS/FAIL scored against that device's PLATFORM
benchmark — under a single fleet envelope and a single Merkle-sealed manifest.

Design decisions (mirrors the FortiGate attestation pack):

* **Bespoke ``{body, seal}`` bundle that borrows OSCAL's vocabulary**, with an
  optional loosely-aligned OSCAL-1.1.2 assessment-results projection (``to_oscal``).
  The sealed system-of-record is our own JSON (we control canonicalization); OSCAL
  is emitted on request and labelled *aligned, not strictly conformant*.
* **Tamper-evidence** = canonical JSON -> per-record SHA-256 manifest -> RFC 6962
  Merkle root -> detached **SHA-256 integrity digest** (or an optional
  **HMAC-SHA256 keyed seal** with ``--attest-key``). Honest naming only: this is
  an *integrity digest* / *keyed integrity seal*, **never** a "digital signature"
  (the stdlib has no asymmetric signing).
* **Anti-overclaim is a feature.** This is *auditor input, not a compliance
  certification*. Pass-rate denominator is "controls this tool evaluates"; the
  method is Examine-only; nothing here says "PCI compliant".
* **Reuse, don't fork.** Control PASS/FAIL comes from ``compliance_map.
  benchmark_score``; risk-acceptance from ``posture.Exceptions.match`` +
  ``posture.finding_entity`` — so the attestation and the posture report can never
  disagree. Findings are read through ``finding_view._g`` so the NSS dict shape
  (check_id / title / affected_items / remediation) maps to the ported field names.

Pure standard library (``json`` / ``hashlib`` / ``hmac`` / ``uuid`` / ``datetime``)
so the offline / air-gapped guarantee holds.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from finding_view import _g  # NSS field-alias accessor (rule_id->check_id, etc.)

TOOL_NAME = "Network Security Scanner (NSS)"
VENDOR = "Krishcalin"
SCHEMA = "nss-cisco-attestation/1"

# Exact, recorded canonicalization profile (a verifier reproduces the bytes from this).
_CANON_PROFILE = ("json:sort_keys,sep=(',',':'),ensure_ascii=false,"
                  "allow_nan=false,utf-8;floats-forbidden")

_UUID_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/Krishcalin/Cisco-Network-Security")

# Published framework control totals (M). Deliberately SPARSE: an unverified M is
# worse than none — coverage_percent_of_framework is emitted ONLY for entries here,
# so the tool never fabricates a "% of framework" number. Operators may extend this
# with their own audited totals.
FRAMEWORK_TOTALS: Dict[str, Dict[str, Any]] = {
    # "PCI-DSS": {"version": "4.0.1", "total": 264},
}

# Best-effort version labels (shown for context; NOT asserted as coverage).
_FW_VERSION = {"CIS": "CIS Cisco Benchmark", "PCI-DSS": "4.0", "NIST": "800-53 Rev 5",
               "SOC2": "TSC 2017", "HIPAA": "Security Rule", "ISO27001": "27001:2022"}

DISCLAIMER = (
    "Automated Examine-only evidence of network-device configuration state as of the "
    "collection timestamp. This is auditor INPUT, not an attestation of compliance: it does "
    "not establish PCI-DSS / SOC 2 / ISO 27001 / CIS / HIPAA / NIST compliance, does not cover "
    "Observe or Interview procedures, and does not evidence operating effectiveness over a "
    "period. The pass rate is measured only against the controls this tool evaluates, not the "
    "full framework."
)


# --------------------------------------------------------------------------- #
#  canonical serialization + hashing (the tamper-evidence core)               #
# --------------------------------------------------------------------------- #

def canonical_bytes(obj: Any) -> bytes:
    """Reproducible JSON bytes for hashing. Every kwarg is load-bearing:
      sort_keys       -> deterministic member order (keys are ASCII/BMP so Python's
                         code-point sort matches JCS UTF-16 order)
      separators      -> Python DEFAULTS to ", "/": " WITH spaces; must override
      ensure_ascii=False -> emit UTF-8 literals (fixed & recorded in the profile)
      allow_nan=False -> raise on NaN/Infinity (invalid JSON) instead of poisoning the digest
    Floats are BANNED from attestation content (Python repr vs ECMAScript float
    formatting is not cross-implementation reproducible) — numbers are ints or
    decimal strings; ``assert_float_free`` enforces it in tests."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _merkle_nodes(leaves: List[bytes]) -> bytes:
    """RFC 6962 Merkle tree root (bytes) over leaf-hash nodes. Domain-separation
    prefixes (0x00 leaf / 0x01 node) are applied by the caller for leaves and here
    for internal nodes — mandatory for second-preimage resistance."""
    n = len(leaves)
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:            # largest power of two STRICTLY < n
        k *= 2
    left = _merkle_nodes(leaves[:k])
    right = _merkle_nodes(leaves[k:])
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_root_hex(leaves: List[bytes]) -> str:
    if not leaves:
        return sha256_hex(b"")
    return _merkle_nodes(leaves).hex()


def build_manifest(records: List[Tuple[str, dict]]) -> dict:
    """Per-record SHA-256 manifest + RFC 6962 Merkle root over the ordered records.
    ``records`` = [(id, record_dict), ...]; sorted by id so order is canonical and a
    single altered record is localized to its manifest entry."""
    records = sorted(records, key=lambda r: r[0])
    entries: List[dict] = []
    leaves: List[bytes] = []
    for i, (rid, rec) in enumerate(records):
        cb = canonical_bytes(rec)
        entries.append({"index": i, "id": rid, "sha256": sha256_hex(cb)})
        leaves.append(hashlib.sha256(b"\x00" + cb).digest())
    return {
        "manifest_version": "1",
        "hash_alg": "SHA-256",
        "canonicalization": _CANON_PROFILE,
        "merkle_scheme": "RFC6962:leaf=0x00,node=0x01",
        "record_count": len(entries),
        "records": entries,
        "merkle_root": _merkle_root_hex(leaves),
    }


def seal_body(body: dict, key: Optional[bytes], key_id: Optional[str]) -> dict:
    """Detached seal over ``canonical_bytes(body)``. A SHA-256 integrity digest by
    default; a keyed HMAC-SHA256 seal when ``key`` is supplied. NEVER a signature."""
    cb = canonical_bytes(body)
    if key:
        return {"alg": "HMAC-SHA256", "key_id": key_id or "unspecified",
                "value": hmac.new(key, cb, hashlib.sha256).hexdigest(),
                "computed_over": "canonical_bytes(body)",
                "note": ("Keyed integrity seal (HMAC-SHA256). Proves authenticity to "
                         "key-holders only; it is NOT a digital signature.")}
    return {"alg": "SHA-256", "value": sha256_hex(cb),
            "computed_over": "canonical_bytes(body)",
            "note": ("Integrity digest (SHA-256). Detects accidental/naive edits; it is "
                     "NOT a digital signature and anyone who edits the body can recompute "
                     "it. Supply a key (--attest-key) for a forgery-resistant HMAC seal.")}


# --------------------------------------------------------------------------- #
#  the load-bearing record set (build AND verify share this exact extractor)   #
# --------------------------------------------------------------------------- #

def _attestation_records(body: dict) -> List[Tuple[str, dict]]:
    """The atomic sealed units = every per-control result + every risk-acceptance,
    across EVERY device, keyed by their (globally unique, host-scoped) stable id.
    Evidence is nested INSIDE each control result, so a changed evidence line changes
    exactly that control's record hash (localized tamper). ``coverage`` / ``fleet_
    summary`` / ``attestation`` are covered by the whole-body seal, not separately
    manifested (they are derived from these records)."""
    recs: List[Tuple[str, dict]] = []
    for dev in body.get("devices", []) or []:
        if not isinstance(dev, dict):
            continue
        for block in dev.get("results", []) or []:
            if not isinstance(block, dict):
                continue
            for c in block.get("controls", []) or []:
                if isinstance(c, dict) and c.get("id"):
                    recs.append((str(c["id"]), c))
        for ra in dev.get("risk_acceptances", []) or []:
            if isinstance(ra, dict) and ra.get("id"):
                recs.append((str(ra["id"]), ra))
    recs.sort(key=lambda r: r[0])
    return recs


# --------------------------------------------------------------------------- #
#  build                                                                       #
# --------------------------------------------------------------------------- #

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _controls_for(finding: Any, fw: str) -> List[str]:
    comp = _g(finding, "compliance", {}) or {}
    return list(comp.get(fw) or [])


def _worse(cur: Optional[str], new: Optional[str]) -> Optional[str]:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    if not new:
        return cur
    if cur is None or order.get(new, 5) < order.get(cur, 5):
        return new
    return cur


def build_device_block(
    findings: List[Any],
    *,
    benchmarks: Dict[str, dict],
    host: str,
    device: Optional[dict] = None,
    source_artifact: Optional[dict] = None,
    coverage_meta: Optional[Dict[str, dict]] = None,
    exceptions: Any = None,
    now_naive: Optional[datetime] = None,
) -> dict:
    """Compute one device's compliance block: {device, host_key, source_artifact,
    coverage, results, risk_acceptances}. ``findings`` are THIS DEVICE's findings
    (already the unfiltered, pre-``--severity`` set); INFO is dropped to agree with
    ``benchmark_score``'s FAIL basis so a display filter can't inflate a pass rate.
    ``host`` is the disambiguated posture host key (device + config file when the
    hostname is 'unknown' or collides) so control/risk-acceptance record ids are
    globally unique across the fleet and match the posture system of record."""
    coverage_meta = coverage_meta if coverage_meta is not None else FRAMEWORK_TOTALS
    findings = [f for f in findings if str(_g(f, "severity", "")).upper() != "INFO"]

    # risk-acceptance aggregation: (rule_id, entity) -> {exc, severity, affected[(fw,ctrl)]}
    risk_map: Dict[Tuple[str, str], dict] = {}
    results: List[dict] = []
    coverage: List[dict] = []

    for fw, bm in benchmarks.items():
        controls_out: List[dict] = []
        counts = {"pass": 0, "fail": 0, "risk_accepted": 0, "not_assessed": 0}
        for c in bm.get("controls", []):
            control_id = c.get("control", "")
            rec_id = f"{host}|{fw}|{control_id}"
            base_status = c.get("status", "PASS")
            if base_status == "PASS":
                counts["pass"] += 1
                controls_out.append({
                    "id": rec_id, "control": control_id, "section": c.get("section", ""),
                    "status": "PASS", "worst_severity": None,
                    "method": "examine:automated-config-inspection",
                    "observations": [], "linked_risk_acceptances": [],
                })
                continue

            # FAIL: gather the actual failing findings for (fw, control)
            failing = [f for f in findings if control_id in _controls_for(f, fw)]
            observations = []
            all_accepted = bool(failing)
            any_expired = False
            covering: List[Tuple[str, str, dict]] = []  # (rule_id, entity, exc)
            for f in failing:
                rid = str(_g(f, "rule_id", ""))
                items = list(f.get("affected_items") or []) if isinstance(f, dict) else []
                # Derive the entity EXACTLY as posture does — only for a single-instance
                # finding (len(items)==1); aggregate findings key on the check_id alone
                # (entity=""). This gating is load-bearing: the Exceptions.match call and
                # the risk-acceptance record id below MUST match posture.finding_fingerprint,
                # else an entity-scoped exception would wrongly flip an AGGREGATE control to
                # RISK_ACCEPTED in the sealed attestation while posture keeps it FAIL.
                try:
                    from posture import finding_entity
                    entity = finding_entity(rid, str(items[0])) if len(items) == 1 else ""
                except Exception:
                    entity = ""
                observations.append({
                    "rule_id": rid, "name": str(_g(f, "name", "")),
                    "severity": str(_g(f, "severity", "")),
                    "line_num": _g(f, "line_num", None),
                    "evidence": str(_g(f, "line_content", "")),
                    "affected_count": len(items),
                    "cve": _g(f, "cve") or None, "cwe": _g(f, "cwe") or None,
                })
                exc = None
                had_expired = False
                if exceptions is not None:
                    try:
                        exc, had_expired = exceptions.match(host, rid, entity, now_naive)
                    except Exception:
                        exc, had_expired = None, False
                any_expired = any_expired or had_expired
                if exc is not None:
                    covering.append((rid, entity, exc))
                else:
                    all_accepted = False

            worst = None
            for o in observations:
                worst = _worse(worst, o["severity"])

            linked_ids: List[str] = []
            if all_accepted and covering:
                status = "RISK_ACCEPTED"
                counts["risk_accepted"] += 1
                for rid, entity, exc in covering:
                    ra_key = (rid, entity)
                    ra_id = f"{host}|{rid}|{entity}" if entity else f"{host}|{rid}"
                    linked_ids.append(ra_id)
                    slot = risk_map.setdefault(ra_key, {
                        "id": ra_id, "rule_id": rid, "entity": entity, "exc": exc,
                        "severity": None, "affected": []})
                    slot["affected"].append({"framework": fw, "control": control_id})
                    slot["severity"] = _worse(slot["severity"], worst)
            else:
                status = "FAIL"
                counts["fail"] += 1

            control_rec = {
                "id": rec_id, "control": control_id, "section": c.get("section", ""),
                "status": status, "worst_severity": worst,
                "method": "examine:automated-config-inspection",
                "observations": observations,
                "linked_risk_acceptances": sorted(set(linked_ids)),
            }
            if any_expired:
                # Fail-open: an expired sign-off never downgrades — surfaced, not hidden.
                control_rec["exception_expired"] = True
            controls_out.append(control_rec)

        results.append({"framework": fw, "controls": controls_out})

        # ---- coverage disclosure (anti-overclaim) ----
        n = bm.get("total_controls", 0)
        cov = {
            "framework": fw,
            "framework_version": _FW_VERSION.get(fw, ""),
            "controls_in_scope_for_tool": n,
            "controls_evaluated": n,
            "by_status": counts,
            "pass_rate_of_evaluated": str(round(counts["pass"] / n * 100)) if n else "100",
            "method_limitation_note": ("Examine-only automated config inspection; controls "
                                       "requiring Observe/Interview or period-based operating-"
                                       "effectiveness testing are out of automated scope."),
        }
        m_meta = (coverage_meta or {}).get(fw) or {}
        if m_meta.get("total"):
            m = m_meta["total"]
            cov["controls_total_in_framework"] = m
            cov["coverage_percent_of_framework"] = str(round(n / m * 100, 1)) if m else "0"
            if m_meta.get("version"):
                cov["framework_version"] = m_meta["version"]
        coverage.append(cov)

    # ---- risk-acceptance sign-offs ----
    risk_acceptances: List[dict] = []
    for slot in sorted(risk_map.values(), key=lambda s: s["id"]):
        exc = slot["exc"] or {}
        risk_acceptances.append({
            "id": slot["id"], "rule_id": slot["rule_id"], "entity": slot["entity"],
            "affected_controls": sorted(slot["affected"], key=lambda a: (a["framework"], a["control"])),
            "reason": str(exc.get("reason", "") or ""),
            "approver": str(exc.get("approver", "") or ""),
            "expires": (str(exc.get("expires")) if exc.get("expires") else None),
            "status": "active",
            "severity": slot["severity"],
        })

    return {
        "host_key": host,
        "device": device or {},
        "source_artifact": source_artifact or {},
        "coverage": coverage,
        "results": results,
        "risk_acceptances": risk_acceptances,
    }


def _fleet_summary(devices: List[dict]) -> dict:
    """Aggregate per-framework PASS/FAIL/risk-accepted across every device block."""
    by_fw: Dict[str, dict] = {}
    for dev in devices:
        for cov in dev.get("coverage", []):
            fw = cov["framework"]
            bs = cov.get("by_status", {})
            slot = by_fw.setdefault(fw, {"pass": 0, "fail": 0, "risk_accepted": 0,
                                         "evaluated": 0, "devices": 0})
            slot["pass"] += int(bs.get("pass", 0))
            slot["fail"] += int(bs.get("fail", 0))
            slot["risk_accepted"] += int(bs.get("risk_accepted", 0))
            slot["evaluated"] += int(cov.get("controls_evaluated", 0))
            slot["devices"] += 1
    for slot in by_fw.values():
        ev = slot["evaluated"]
        slot["pass_rate_of_evaluated"] = str(round(slot["pass"] / ev * 100)) if ev else "100"
    return {"device_count": len(devices),
            "by_framework": {k: by_fw[k] for k in sorted(by_fw)}}


def build_attestation(
    devices: List[dict],
    *,
    attester: Optional[dict] = None,
    attester_org: str = "",
    run_mode: str = "offline-config-parse",
    tool_version: str = "",
    intel: Optional[dict] = None,
    coverage_meta: Optional[Dict[str, dict]] = None,
    exceptions: Any = None,
    collection_dt: Optional[datetime] = None,
    report_dt: Optional[datetime] = None,
) -> dict:
    """Build the (unsealed) FLEET attestation body over ``devices``.

    ``devices`` = list of per-device inputs, each a dict with:
        host          -> disambiguated posture host key (globally unique)
        device        -> {hostname, platform, config_file, ...} metadata
        findings      -> THIS device's unfiltered (pre-``--severity``) findings
        benchmarks    -> {display_name: benchmark_score(fw, findings, platform)}
        source_artifact (optional) -> provenance {filename, sha256, ...}

    Returns ``{"body": {...}}`` with one coverage/results/risk-acceptance block per
    device, a fleet rollup, and a Merkle-sealed manifest over all control/RA records."""
    coverage_meta = coverage_meta if coverage_meta is not None else FRAMEWORK_TOTALS
    collection_dt = collection_dt or _now_utc()
    report_dt = report_dt or _now_utc()
    # Exceptions.match compares against NAIVE parsed dates — use a naive UTC 'now'.
    now_naive = report_dt.astimezone(timezone.utc).replace(tzinfo=None) if report_dt.tzinfo else report_dt

    device_blocks: List[dict] = []
    for d in devices:
        block = build_device_block(
            d.get("findings", []) or [],
            benchmarks=d.get("benchmarks", {}) or {},
            host=d.get("host", "") or "unknown",
            device=d.get("device"),
            source_artifact=d.get("source_artifact"),
            coverage_meta=coverage_meta,
            exceptions=exceptions,
            now_naive=now_naive,
        )
        device_blocks.append(block)
    # Deterministic device order (by host key) so the body — and thus the seal — is
    # byte-reproducible regardless of scan order.
    device_blocks.sort(key=lambda b: b.get("host_key", ""))

    # ---- envelope ----
    # Deterministic id (uuid5 over the sorted host keys + both timestamps): unique per
    # real run (timestamps differ) yet reproducible under fixed inputs.
    scope_key = ",".join(b.get("host_key", "") for b in device_blocks)
    att = {
        "attestation_id": str(uuid.uuid5(_UUID_NS, f"{scope_key}|{_iso(collection_dt)}|{_iso(report_dt)}")),
        "tool": {"name": TOOL_NAME, "vendor": VENDOR, "version": str(tool_version or "")},
        "scope": "fleet",
        "device_count": len(device_blocks),
        "run_mode": run_mode,
        "evidence_basis": "point-in-time",
        "method": "examine",
        "attester": attester or {"principal": "", "host": "", "org": attester_org},
        "timestamps": {
            "collection_utc": _iso(collection_dt),
            "report_generation_utc": _iso(report_dt),
        },
        "threat_intel": intel or {},
        "disclaimer": DISCLAIMER,
    }
    if attester_org and att["attester"].get("org") in (None, ""):
        att["attester"]["org"] = attester_org

    body = {
        "schema": SCHEMA,
        "oscal_aligned": True,
        "attestation": att,
        "devices": device_blocks,
        "fleet_summary": _fleet_summary(device_blocks),
    }
    body["manifest"] = build_manifest(_attestation_records(body))
    return {"body": body}


def seal_attestation(unsealed: dict, key: Optional[bytes] = None,
                     key_id: Optional[str] = None) -> dict:
    body = unsealed["body"]
    return {"body": body, "seal": seal_body(body, key, key_id)}


def verify_attestation(bundle: dict, key: Optional[bytes] = None) -> dict:
    """Re-derive the record set with the SAME extractor build used, recompute every
    per-record digest + the Merkle root + the body seal, and compare (constant-time).
    Returns {ok, problems, record_count, alg}."""
    problems: List[str] = []
    if not isinstance(bundle, dict):
        return {"ok": False, "problems": ["not an attestation bundle (expected a JSON object)"],
                "record_count": 0, "alg": None}
    body, seal = bundle.get("body"), bundle.get("seal")
    if not isinstance(body, dict) or not isinstance(seal, dict):
        return {"ok": False, "problems": ["malformed attestation bundle: missing/!dict 'body' or 'seal'"],
                "record_count": 0, "alg": None}
    manifest = body.get("manifest") if isinstance(body.get("manifest"), dict) else {}

    records = _attestation_records(body)
    try:
        by_id = {rid: sha256_hex(canonical_bytes(rec)) for rid, rec in records}
        cb = canonical_bytes(body)
    except (ValueError, TypeError) as exc:
        # A crafted bundle with a non-finite number (json.load accepts NaN/Infinity by
        # default) makes canonical_bytes(allow_nan=False) raise. Report it as a failed
        # verification instead of crashing — verify must honor the 0/2 contract.
        return {"ok": False, "problems": [f"un-canonicalizable content (non-finite number?): {exc}"],
                "record_count": len(records), "alg": seal.get("alg")}
    for e in manifest.get("records", []):
        if by_id.get(e.get("id")) != e.get("sha256"):
            problems.append(f"record digest mismatch: {e.get('id')}")
    live_ids = set(by_id)
    manifest_ids = {e.get("id") for e in manifest.get("records", [])}
    for missing in sorted(live_ids - manifest_ids):
        problems.append(f"record present in body but absent from manifest: {missing}")
    for extra in sorted(manifest_ids - live_ids):
        problems.append(f"manifest lists a record absent from body: {extra}")

    recomputed_root = build_manifest(records)["merkle_root"]
    if recomputed_root != manifest.get("merkle_root"):
        problems.append("merkle_root mismatch (records altered/reordered)")

    alg = seal.get("alg")
    if key is not None:
        # A key was supplied => the CALLER requires a keyed seal. The untrusted bundle
        # does NOT get to pick the algorithm: refusing to fall back to a keyless SHA-256
        # digest is what stops a seal-downgrade forgery (edit body -> recompute the public
        # manifest/Merkle root -> swap in a keyless seal), the alg-confusion / alg:none attack.
        if alg != "HMAC-SHA256":
            problems.append(f"seal downgrade: a key was supplied but the seal alg is {alg!r}, "
                            "not HMAC-SHA256 — refusing to accept a keyless seal as authenticated")
        elif not hmac.compare_digest(hmac.new(key, cb, hashlib.sha256).hexdigest(),
                                     str(seal.get("value", ""))):
            problems.append("HMAC seal INVALID (body tampered or wrong key)")
    elif alg == "HMAC-SHA256":
        problems.append("HMAC seal present but no key supplied to verify")
    elif alg == "SHA-256":
        if not hmac.compare_digest(sha256_hex(cb), str(seal.get("value", ""))):
            problems.append("integrity digest INVALID (body tampered)")
    else:
        problems.append(f"unknown seal algorithm: {alg!r}")

    return {"ok": not problems, "problems": problems,
            "record_count": len(records), "alg": alg}


# --------------------------------------------------------------------------- #
#  OSCAL 1.1.2-aligned projection (optional; --attest-oscal)                   #
# --------------------------------------------------------------------------- #

def _u(*parts: str) -> str:
    """Stable UUID5 so re-scans keep identifiers diffable."""
    return str(uuid.uuid5(_UUID_NS, "|".join(str(p) for p in parts)))


def _oscal_result_for_device(dev: dict, collected: str, report_ts: str) -> dict:
    """One OSCAL assessment result per device (findings/observations/risks scoped to it)."""
    host = dev.get("device", {}).get("hostname") or dev.get("host_key") or "target"
    scope = dev.get("host_key") or host
    control_sel: List[dict] = []
    observations: List[dict] = []
    findings: List[dict] = []
    risks: List[dict] = []

    risk_uuid_by_id: Dict[str, str] = {}
    for ra in dev.get("risk_acceptances", []):
        ru = _u(scope, "risk", ra["id"])
        risk_uuid_by_id[ra["id"]] = ru
        entry = {
            "uuid": ru,
            "title": f"Risk acceptance: {ra['rule_id']}"
                     + (f" ({ra['entity']})" if ra.get("entity") else ""),
            "description": ra.get("reason") or "Accepted risk.",
            "statement": ra.get("reason") or "Accepted risk.",
            "status": "deviation-approved",
            "risk-log": {"entries": [{
                "uuid": _u(scope, "risklog", ra["id"]),
                "title": "Risk acceptance recorded",
                "start": report_ts,
                "status-change": "deviation-approved",
                "remarks": (f"Approver: {ra.get('approver') or 'unspecified'}."),
            }]},
        }
        if ra.get("expires"):
            # OSCAL 'deadline' is dateTime-with-timezone; the exception expiry is a
            # tz-naive date/datetime string. Normalize through the same path as every
            # other OSCAL timestamp; if unparseable, keep it as a prop, never emit a
            # schema-invalid bare date.
            try:
                from posture import _parse_date
                dl = _parse_date(ra["expires"])
            except Exception:
                dl = None
            if dl is not None:
                entry["deadline"] = _iso(dl)
            else:
                entry.setdefault("props", []).append(
                    {"name": "expires-raw", "value": str(ra["expires"])})
        risks.append(entry)

    for block in dev.get("results", []):
        fw = block["framework"]
        ids: List[dict] = []
        for c in block.get("controls", []):
            target_id = f"{fw}:{c['control']}"
            ids.append({"control-id": target_id})
            state = "satisfied" if c["status"] in ("PASS", "RISK_ACCEPTED") else "not-satisfied"
            reason = {"PASS": "pass", "RISK_ACCEPTED": "other", "FAIL": "fail"}.get(c["status"], "other")
            rel_obs: List[dict] = []
            for i, o in enumerate(c.get("observations", [])):
                ou = _u(scope, "obs", c["id"], str(i))
                observations.append({
                    "uuid": ou,
                    "description": f"{o['rule_id']}: {o['name']}",
                    "methods": ["TEST"],
                    "types": ["finding"],
                    "relevant-evidence": [{
                        "description": o.get("evidence") or "(no evidence line)",
                        "props": [
                            {"name": "rule-id", "value": o["rule_id"]},
                            {"name": "severity", "value": o.get("severity") or ""},
                            {"name": "config-line", "value": str(o.get("line_num") or "")},
                        ],
                    }],
                    "collected": collected,
                })
                rel_obs.append({"observation-uuid": ou})
            rel_risks = [{"risk-uuid": risk_uuid_by_id[r]} for r in c.get("linked_risk_acceptances", [])
                         if r in risk_uuid_by_id]
            finding = {
                "uuid": _u(scope, "finding", c["id"]),
                "title": f"{fw} {c['control']}",
                "description": f"Control {c['control']} ({fw}) — {c['status']}.",
                "target": {
                    "type": "objective-id", "target-id": target_id,
                    "title": f"{fw} {c['control']}",
                    "status": {"state": state, "reason": reason},
                },
            }
            if rel_obs:
                finding["related-observations"] = rel_obs
            if rel_risks:
                finding["related-risks"] = rel_risks
            findings.append(finding)
        control_sel.append({
            "props": [{"name": "framework", "value": fw}],
            "include-controls": ids,
        })

    return {
        "uuid": _u(scope, "result", report_ts),
        "title": f"Automated configuration examination — {host}",
        "description": DISCLAIMER,
        "start": collected,
        "end": report_ts,
        "props": [{"name": "target-host", "value": host},
                  {"name": "target-platform", "value": dev.get("device", {}).get("platform", "")}],
        "reviewed-controls": {"control-selections": control_sel},
        "observations": observations,
        "risks": risks,
        "findings": findings,
    }


def to_oscal(body: dict) -> dict:
    """Loosely-conformant OSCAL 1.1.2 assessment-results projection (a pure re-shape).
    NOT strictly conformant: import-ap is a '#' placeholder, no NIST catalog UUIDs, no
    metaschema validation. One assessment ``result`` per device; PASS/FAIL is
    finding.target.status.state (satisfied/not-satisfied); cross-links resolve."""
    att = body.get("attestation", {})
    ts = att.get("timestamps", {})
    report_ts = ts.get("report_generation_utc") or _iso(_now_utc())
    collected = ts.get("collection_utc") or report_ts
    devices = body.get("devices", [])
    n = len(devices)

    results = [_oscal_result_for_device(dev, collected, report_ts) for dev in devices]
    return {"assessment-results": {
        "uuid": _u("fleet", "assessment-results", report_ts),
        "metadata": {
            "title": f"Cisco network configuration assessment — fleet ({n} device{'s' if n != 1 else ''})",
            "last-modified": report_ts,
            "version": (att.get("tool") or {}).get("version") or "0",
            "oscal-version": "1.1.2",
            "props": [{"name": "assessment-type", "value": "self-assessment"},
                      {"name": "device-count", "value": str(n)}],
        },
        "import-ap": {"href": "#"},
        "results": results,
        "_note": "OSCAL-1.1.2-aligned projection, not strictly conformant (import-ap is a placeholder).",
    }}


# --------------------------------------------------------------------------- #
#  human-readable statement (text + self-contained HTML)                       #
# --------------------------------------------------------------------------- #

def render_attestation_text(bundle: dict) -> str:
    body, seal = bundle["body"], bundle.get("seal", {})
    att = body.get("attestation", {})
    ts = att.get("timestamps", {})
    fs = body.get("fleet_summary", {})
    lines: List[str] = []
    W = 78
    lines.append("=" * W)
    lines.append("  NSS COMPLIANCE ATTESTATION — auditor evidence (NOT a certification)")
    lines.append("=" * W)
    lines.append(f"  Scope    : fleet — {att.get('device_count', 0)} device(s)")
    lines.append(f"  Collected: {ts.get('collection_utc','?')}   Report: {ts.get('report_generation_utc','?')}")
    tool = att.get("tool", {})
    lines.append(f"  Tool     : {tool.get('name','')} v{tool.get('version','')}  "
                 f"({att.get('run_mode','')}, method: examine)")
    lines.append("")
    lines.append("  " + DISCLAIMER)
    lines.append("")
    lines.append("  FLEET ROLLUP (controls this tool evaluates — not the full framework)")
    lines.append("  " + "-" * (W - 2))
    for fw, s in (fs.get("by_framework") or {}).items():
        lines.append(f"    {fw:<9} {s.get('pass_rate_of_evaluated','?'):>3}% pass  "
                     f"[pass {s.get('pass',0)} / fail {s.get('fail',0)} / "
                     f"risk-accepted {s.get('risk_accepted',0)} of {s.get('evaluated',0)}]  "
                     f"across {s.get('devices',0)} device(s)")
    for dev in body.get("devices", []):
        d = dev.get("device", {})
        sa = dev.get("source_artifact") or {}
        lines.append("")
        hdr = f"  DEVICE: {d.get('hostname','?')}  ({d.get('platform','?')})"
        if d.get("config_file"):
            hdr += f"  [{d.get('config_file')}]"
        lines.append(hdr)
        if sa.get("sha256"):
            trunc = "  [!] LOOKS TRUNCATED" if sa.get("looks_truncated") else ""
            lines.append(f"    source: {sa.get('filename','')}  sha256={sa['sha256'][:16]}…  "
                         f"{sa.get('line_count','?')} lines{trunc}")
        lines.append("  " + "-" * (W - 2))
        for cov in dev.get("coverage", []):
            bs = cov.get("by_status", {})
            extra = ""
            if "coverage_percent_of_framework" in cov:
                extra = f"  ({cov['coverage_percent_of_framework']}% of {cov.get('controls_total_in_framework')} framework controls)"
            lines.append(f"    {cov['framework']:<9} {cov.get('pass_rate_of_evaluated','?'):>3}% pass  "
                         f"[pass {bs.get('pass',0)} / fail {bs.get('fail',0)} / "
                         f"risk-accepted {bs.get('risk_accepted',0)} of {cov.get('controls_evaluated',0)}]{extra}")
        ras = dev.get("risk_acceptances", [])
        if ras:
            lines.append("    Risk acceptances:")
            for ra in ras:
                aff = ", ".join(f"{a['framework']} {a['control']}" for a in ra.get("affected_controls", []))
                lines.append(f"      {ra['rule_id']}"
                             + (f" [{ra['entity']}]" if ra.get("entity") else "")
                             + f"  approver={ra.get('approver') or '?'}  expires={ra.get('expires') or 'n/a'}")
                if aff:
                    lines.append(f"          controls: {aff}")
    man = body.get("manifest", {})
    lines.append("")
    lines.append("  INTEGRITY")
    lines.append("  " + "-" * (W - 2))
    lines.append(f"    Merkle root : {man.get('merkle_root','')[:32]}…  ({man.get('record_count',0)} records)")
    lines.append(f"    Seal        : {seal.get('alg','?')}  {str(seal.get('value',''))[:32]}…")
    lines.append(f"    {seal.get('note','')}")
    lines.append("    Verify with:  --attest-verify <file>" +
                 ("  --attest-key <spec>" if seal.get("alg") == "HMAC-SHA256" else ""))
    lines.append("=" * W)
    return "\n".join(lines) + "\n"


def _esc(s: Any) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def render_attestation_html(bundle: dict) -> str:
    body, seal = bundle["body"], bundle.get("seal", {})
    att = body.get("attestation", {})
    ts = att.get("timestamps", {})
    man = body.get("manifest", {})
    fs = body.get("fleet_summary", {})

    fleet_rows = []
    for fw, s in (fs.get("by_framework") or {}).items():
        fleet_rows.append(
            f"<tr><td>{_esc(fw)}</td><td class='num'>{_esc(s.get('pass_rate_of_evaluated'))}%</td>"
            f"<td class='num'>{s.get('pass',0)}</td><td class='num'>{s.get('fail',0)}</td>"
            f"<td class='num'>{s.get('risk_accepted',0)}</td><td class='num'>{s.get('evaluated',0)}</td>"
            f"<td class='num'>{s.get('devices',0)}</td></tr>")

    dev_sections = []
    for dev in body.get("devices", []):
        d = dev.get("device", {})
        sa = dev.get("source_artifact") or {}
        rows = []
        for cov in dev.get("coverage", []):
            bs = cov.get("by_status", {})
            cofw = ""
            if "coverage_percent_of_framework" in cov:
                cofw = f"{cov['coverage_percent_of_framework']}% of {cov.get('controls_total_in_framework')}"
            rows.append(
                f"<tr><td>{_esc(cov['framework'])}</td><td class='num'>{_esc(cov.get('pass_rate_of_evaluated'))}%</td>"
                f"<td class='num'>{bs.get('pass',0)}</td><td class='num'>{bs.get('fail',0)}</td>"
                f"<td class='num'>{bs.get('risk_accepted',0)}</td><td class='num'>{cov.get('controls_evaluated',0)}</td>"
                f"<td>{_esc(cofw)}</td></tr>")
        ra_rows = []
        for ra in dev.get("risk_acceptances", []):
            aff = ", ".join(f"{a['framework']} {a['control']}" for a in ra.get("affected_controls", []))
            ra_rows.append(
                f"<tr><td>{_esc(ra['rule_id'])}{(' [' + _esc(ra['entity']) + ']') if ra.get('entity') else ''}</td>"
                f"<td>{_esc(ra.get('approver') or '?')}</td><td>{_esc(ra.get('expires') or 'n/a')}</td>"
                f"<td>{_esc(ra.get('reason') or '-')}</td><td>{_esc(aff)}</td></tr>")
        ra_section = ("<h3>Risk acceptances (sign-offs)</h3><table><tr><th>Finding</th><th>Approver</th>"
                      "<th>Expires</th><th>Reason</th><th>Controls</th></tr>" + "".join(ra_rows) + "</table>"
                      ) if ra_rows else ""
        src = ""
        if sa.get("sha256"):
            trunc = " ⚠ looks truncated" if sa.get("looks_truncated") else ""
            src = (f"<div class='src'>source: {_esc(sa.get('filename',''))} · "
                   f"sha256 {_esc(sa['sha256'][:16])}… · {_esc(sa.get('line_count','?'))} lines{trunc}</div>")
        dev_sections.append(
            f"<div class='device'><h2>{_esc(d.get('hostname','?'))} "
            f"<span class='plat'>{_esc(d.get('platform','?'))}</span></h2>{src}"
            f"<table><tr><th>Framework</th><th>Pass %</th><th>Pass</th><th>Fail</th>"
            f"<th>Risk-accepted</th><th>Evaluated</th><th>vs framework</th></tr>"
            f"{''.join(rows)}</table>{ra_section}</div>")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NSS Compliance Attestation — fleet ({att.get('device_count',0)} devices)</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f7f9;color:#1a1b2e}}
 .wrap{{max-width:980px;margin:0 auto;padding:28px}}
 h1{{font-size:20px;margin:0 0 4px}} h2{{font-size:16px;margin:22px 0 4px}}
 h3{{font-size:13px;margin:14px 0 6px;color:#556}}
 .sec{{font-size:15px;margin:26px 0 8px;border-bottom:2px solid #049fd9;padding-bottom:4px;font-weight:600}}
 .sub{{color:#556;margin-bottom:16px}}
 .plat{{font-size:12px;color:#fff;background:#049fd9;border-radius:4px;padding:2px 7px;vertical-align:middle}}
 .src{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#667;margin-bottom:6px}}
 .device{{background:#fff;border-radius:8px;padding:14px 16px;margin:12px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 .disclaimer{{background:#fff8e1;border:1px solid #f0c36d;border-radius:8px;padding:12px 14px;margin:16px 0;font-size:13px}}
 table{{border-collapse:collapse;width:100%;background:#fff;border-radius:8px;overflow:hidden;margin-top:6px}}
 th,td{{padding:7px 10px;text-align:left;border-bottom:1px solid #eef0f3}} th{{background:#1a1b2e;color:#fff;font-size:12px}}
 td.num{{text-align:right;font-variant-numeric:tabular-nums}}
 .meta{{font-size:13px;background:#fff;border-radius:8px;padding:12px 14px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 .meta b{{display:inline-block;min-width:150px;color:#556}}
 .integrity{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:#0f1021;color:#c7d0e0;border-radius:8px;padding:12px 14px;word-break:break-all}}
 code{{font-family:ui-monospace,Menlo,Consolas,monospace}}
</style></head><body><div class="wrap">
<h1>NSS Compliance Attestation</h1>
<div class="sub">Auditor evidence — <b>NOT</b> a compliance certification · fleet of {att.get('device_count',0)} device(s)</div>
<div class="meta">
 <div><b>Collected (UTC)</b> {_esc(ts.get('collection_utc','?'))}</div>
 <div><b>Report (UTC)</b> {_esc(ts.get('report_generation_utc','?'))}</div>
 <div><b>Tool</b> {_esc((att.get('tool') or {}).get('name',''))} v{_esc((att.get('tool') or {}).get('version',''))} · {_esc(att.get('run_mode',''))} · method: examine</div>
 <div><b>Attestation ID</b> <code>{_esc(att.get('attestation_id',''))}</code></div>
</div>
<div class="disclaimer">{_esc(DISCLAIMER)}</div>
<div class="sec">Fleet rollup (controls this tool evaluates)</div>
<table><tr><th>Framework</th><th>Pass %</th><th>Pass</th><th>Fail</th><th>Risk-accepted</th><th>Evaluated</th><th>Devices</th></tr>
{''.join(fleet_rows)}</table>
<div class="sec">Per-device evidence</div>
{''.join(dev_sections)}
<div class="sec">Integrity</div>
<div class="integrity">Merkle root: {_esc(man.get('merkle_root',''))}<br>
Records: {man.get('record_count',0)} · Canonicalization: {_esc(man.get('canonicalization',''))}<br>
Seal ({_esc(seal.get('alg','?'))}): {_esc(seal.get('value',''))}<br>
{_esc(seal.get('note',''))}</div>
</div></body></html>"""
