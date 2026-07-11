#!/usr/bin/env python3
"""
Network Security Scanner (NSS)
================================
A Python-based security scanner for Cisco switches, routers,
wireless access points, and next-generation firewalls.

Parses running-config exports and evaluates against CIS Benchmarks,
Cisco Hardening Guides, and NSA NGFW guidance.

Usage:
    python nss_scanner.py --data-dir ./sample_configs --output report.html
    python nss_scanner.py --data-dir ./exports --modules mgmt ctrl data --severity HIGH
"""

import argparse
import json
import sys
import datetime
from pathlib import Path

# Reconfigure stdout/stderr to UTF-8 with errors='replace' so the banner's
# box-drawing characters (╔ ═ ║ ╚) and any non-ASCII finding text don't crash
# Windows consoles that default to cp1252.
for _stream in (sys.stdout, sys.stderr):
    _reconfigure = getattr(_stream, "reconfigure", None)
    if callable(_reconfigure):
        try:
            _reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass

from modules.base import load_configs
from modules.mgmt_plane import ManagementPlaneAuditor
from modules.ctrl_plane import ControlPlaneAuditor
from modules.data_plane import DataPlaneAuditor
from modules.services import ServicesProtocolsAuditor
from modules.switch_security import SwitchSecurityAuditor
from modules.wireless import WirelessSecurityAuditor
from modules.ngfw_core import NgfwCoreAuditor
from modules.ngfw_platform import NgfwPlatformAuditor
from modules.logging import LoggingMonitoringAuditor
from modules.crypto import CryptoPostureAuditor
from modules.cve_detection import CveDetectionAuditor
from modules.report_generator import ReportGenerator


def banner():
    print(r"""
  ╔═══════════════════════════════════════════════════════════════╗
  ║   Network Security Scanner (NSS) v1.0                        ║
  ║   Cisco Switches · Routers · WAP · NGFW                      ║
  ║   CIS Benchmark · Cisco Hardening Guide · NSA FTD Guide      ║
  ╚═══════════════════════════════════════════════════════════════╝
    """)


MODULE_MAP = {
    "mgmt":     ("Management Plane Security", ManagementPlaneAuditor),
    "ctrl":     ("Control Plane Security", ControlPlaneAuditor),
    "data":     ("Data Plane Security", DataPlaneAuditor),
    "services": ("Services & Protocols", ServicesProtocolsAuditor),
    "switch":   ("Switch-Specific Security", SwitchSecurityAuditor),
    "wireless": ("Wireless Security", WirelessSecurityAuditor),
    "ngfw":     ("NGFW Core Security", NgfwCoreAuditor),
    "ngfwplat": ("NGFW Platform Security", NgfwPlatformAuditor),
    "logging":  ("Logging & Monitoring", LoggingMonitoringAuditor),
    "crypto":   ("Cryptographic Posture", CryptoPostureAuditor),
    "cve":      ("CVE Detection", CveDetectionAuditor),
}


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Network Security Scanner — Cisco device config audit"
    )
    parser.add_argument("--data-dir", default=None,
        help="Directory containing device config files (.cfg/.txt/.conf)")
    parser.add_argument("--output", default="nss_security_report.html",
        help="Output HTML report filename")
    parser.add_argument("--json", dest="json_out", default=None, metavar="FILE",
        help="Also write a machine-readable JSON findings report (feeds --verify-against, diffs, pipelines)")
    parser.add_argument("--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"], default="ALL")
    parser.add_argument("--modules", nargs="+",
        choices=list(MODULE_MAP.keys()) + ["all"], default=["all"])
    parser.add_argument("--config", default=None,
        help="Custom baseline config JSON")
    parser.add_argument("--fail-on", dest="fail_on", default=None,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Exit non-zero (2) if any finding at or above this severity is present (CI gating). Default: always exit 0.")
    parser.add_argument("--history", default=None, metavar="FILE",
        help="Continuous posture: update a system-of-record JSON and report new/resolved/reopened/SLA per device")
    parser.add_argument("--exceptions", default=None, metavar="FILE",
        help="Risk-acceptance file (JSON) for --history: accepted findings stop nagging until they expire (fail-open)")
    parser.add_argument("--top", type=int, nargs="?", const=15, default=None, metavar="N",
        help="Print the risk-prioritized fix-first queue (top N, default 15)")
    parser.add_argument("--jira", metavar="FILE", help="Export ready-to-POST Jira create/update issue payloads")
    parser.add_argument("--servicenow", metavar="FILE", help="Export ready-to-POST ServiceNow Incident records")
    parser.add_argument("--splunk-soar", dest="splunk_soar", metavar="FILE", help="Export Splunk SOAR container+artifact payloads")
    parser.add_argument("--webhook", metavar="FILE", help="Export vendor-neutral CloudEvents 1.0 finding events")
    parser.add_argument("--sarif", metavar="FILE", help="Export SARIF 2.1.0 (GitHub code-scanning / CI ingestion)")
    parser.add_argument("--ocsf", metavar="FILE", help="Export OCSF Compliance Finding events (SIEM)")
    parser.add_argument("--jira-project", dest="jira_project", default="SEC", metavar="KEY", help="Jira project key for --jira (default: SEC)")
    parser.add_argument("--soar-min-tier", dest="soar_min_tier", choices=["P1", "P2", "P3", "P4"], default="P4",
        help="Only export findings at/above this priority tier to SOAR/ticketing (default: P4 = all)")
    parser.add_argument("--refresh-intel", dest="refresh_intel", action="store_true",
        help="Refresh the bundled KEV+EPSS threat-intel snapshot from CISA + FIRST.org, then exit (needs internet)")
    parser.add_argument("--export-intel", dest="export_intel", default=None, metavar="FILE",
        help="Copy the threat-intel snapshot to FILE for air-gapped transfer, then exit")
    parser.add_argument("--import-intel", dest="import_intel", default=None, metavar="FILE",
        help="Install a hand-carried threat-intel snapshot from FILE (validated), then exit")
    parser.add_argument("--attest", metavar="FILE", default=None,
        help="Emit a tamper-evident compliance attestation bundle (JSON) — auditor evidence, NOT a compliance certification")
    parser.add_argument("--attest-key", dest="attest_key", metavar="SPEC", default=None,
        help="Keyed HMAC-SHA256 seal for --attest/--attest-verify. SPEC = 'env:NAME' or a key-file path")
    parser.add_argument("--attest-html", dest="attest_html", metavar="FILE", default=None,
        help="Also write a human-readable HTML attestation statement (use with --attest)")
    parser.add_argument("--attest-oscal", dest="attest_oscal", metavar="FILE", default=None,
        help="Also write an OSCAL-1.1.2-aligned assessment-results projection (use with --attest)")
    parser.add_argument("--attest-org", dest="attest_org", metavar="NAME", default="",
        help="Attester organization recorded in the attestation envelope")
    parser.add_argument("--attest-verify", dest="attest_verify", metavar="FILE", default=None,
        help="Verify an existing attestation bundle's integrity (with --attest-key if keyed), then exit")
    parser.add_argument("--verify-against", dest="verify_against", metavar="FILE", default=None,
        help="Remediation-verification loop: re-scan and prove which findings in a prior --json report are REMEDIATED / PERSISTING / CHANGED (+ regressions). Exit 0 if clean, 2 otherwise")
    parser.add_argument("--verify-html", dest="verify_html", metavar="FILE", default=None,
        help="Also write the remediation-verification report as HTML (use with --verify-against)")
    parser.add_argument("--verify-json", dest="verify_json", metavar="FILE", default=None,
        help="Also write the remediation-verification report as JSON (use with --verify-against)")

    args = parser.parse_args()

    # ── threat-intel maintenance actions (standalone; no scan needed) ──
    if args.refresh_intel or args.export_intel or args.import_intel:
        sys.exit(_intel_action(args))

    # ── attestation verification (standalone; no scan needed) ──
    if args.attest_verify:
        sys.exit(_attest_verify_action(args.attest_verify, args.attest_key))

    if not args.data_dir:
        parser.error("--data-dir is required (unless using --refresh-intel/--export-intel/--import-intel)")
    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"[ERROR] Data directory not found: {data_dir}")
        sys.exit(1)

    print("[*] Loading device configurations...")
    configs = load_configs(data_dir)
    if not configs:
        print("[ERROR] No config files found (.cfg/.txt/.conf)")
        sys.exit(1)
    print(f"    Loaded {len(configs)} device configuration(s)\n")

    baseline = {}
    if args.config:
        with open(args.config) as f:
            baseline = json.load(f)
        print(f"[*] Loaded baseline from {args.config}")

    run_modules = list(MODULE_MAP.keys()) if "all" in args.modules else args.modules
    all_findings = []

    for filename, parsed_config in configs:
        print(f"[*] Scanning: {filename} ({parsed_config.hostname}, {parsed_config.device_type})")
        for mod_key in run_modules:
            if mod_key not in MODULE_MAP:
                continue
            label, auditor_cls = MODULE_MAP[mod_key]
            auditor = auditor_cls(parsed_config, baseline)
            findings = auditor.run_all_checks()
            # Tag findings with device info
            for f in findings:
                f["device"] = parsed_config.hostname
                f["device_file"] = filename
                f["device_type"] = parsed_config.device_type
            all_findings.extend(findings)

    # Stamp a single disambiguated posture/ticket host key onto every finding so
    # posture, the exporters, and the resolved-closure keys all derive host
    # IDENTICALLY. A hostname-less ('unknown') or hostname-colliding device gets a
    # '<host>|<file>' key so two boxes can't merge and closures line up. The
    # authoritative device list (from configs) seeds the collision map so a device
    # that produced zero findings still disambiguates a same-hostname sibling.
    _stamp_host_keys(all_findings, device_files=[(pc.hostname, fn) for fn, pc in configs])

    # Capture the FULL, pre-severity-filter finding set. Benchmark scoring,
    # attestation and remediation-verification must run on this (a --severity
    # display filter must never inflate a pass rate or fabricate regressions).
    all_findings_unfiltered = list(all_findings)

    # Filter by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    if args.severity != "ALL":
        threshold = severity_order.get(args.severity, 4)
        all_findings = [
            f for f in all_findings
            if severity_order.get(f.get("severity", "INFO"), 4) <= threshold
        ]

    scan_meta = {
        "scan_time": datetime.datetime.now().isoformat(),
        "data_directory": str(data_dir),
        "modules_run": run_modules,
        "severity_filter": args.severity,
        "devices_scanned": len(configs),
        "device_list": [f"{fn} ({pc.hostname})" for fn, pc in configs],
    }

    print(f"\n[*] Generating report: {args.output}")
    generator = ReportGenerator(all_findings, scan_meta)
    generator.generate(args.output)

    if args.json_out:
        _save_json(args.json_out, all_findings, scan_meta)
        print(f"[*] JSON findings report: {args.json_out}")

    # CVE reachability: stamp a per-finding verdict (is the vulnerable feature enabled
    # on THIS device's config?) so the prioritizer downranks — never suppresses — a CVE
    # whose feature is off, while the CISA-KEV floor still holds. Per device (multi-device).
    try:
        from cve_reachability import stamp_reachability
        n_reach = stamp_reachability(configs, all_findings_unfiltered)
        if n_reach:
            print(f"[*] CVE reachability: {n_reach} finding(s) gated by config (feature enabled/disabled)")
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[WARN] CVE reachability unavailable: {exc}")

    # Risk-prioritization overlay (P1-P4). Computed on the FULL set so a --severity
    # display filter can't weaken the exposure signal; keyed by id(finding) for the
    # posture SLA/weaponization pass and later exporters.
    prio_by_id, prio_results = _prioritize(all_findings_unfiltered)
    if args.top:
        _print_top(prio_results, args.top)

    # Continuous posture runs on the FULL (unfiltered) finding set so a --severity
    # display filter can never record a finding as resolved. Per device (NSS is
    # multi-device); the returned deltas are stashed for later exporters.
    posture_deltas = {}
    if args.history:
        posture_deltas = _update_posture(args.history, args.exceptions, all_findings_unfiltered, prio_by_id)

    # SOAR / SIEM exports (dispatched after posture so resolved findings emit close
    # events). Export the displayed finding set; min-tier is the additional gate.
    _export_all(args, all_findings, prio_by_id, posture_deltas)

    # Compliance attestation pack (tamper-evident auditor evidence). Built on the
    # FULL unfiltered set (minus INFO, inside attestation) so a --severity display
    # filter can never inflate a pass rate. Per device, platform-scoped benchmarks.
    if args.attest:
        _save_attestation(args, all_findings_unfiltered, configs, data_dir)

    crit = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in all_findings if f["severity"] == "LOW")

    print(f"\n{'='*65}")
    print(f"  SCAN COMPLETE — {len(configs)} device(s), {len(all_findings)} finding(s)")
    print(f"  CRITICAL: {crit}  |  HIGH: {high}  |  MEDIUM: {med}  |  LOW: {low}")
    print(f"  Report: {args.output}")
    print(f"{'='*65}\n")

    # Remediation-verification loop (terminal A/B action): classify the prior report's
    # findings against this scan and exit with its verdict code (0 clean / 2 not).
    if args.verify_against:
        sys.exit(_verify_fixes(args, all_findings_unfiltered, prio_by_id))

    # Severity-gated exit code for CI (default: always 0, unchanged behaviour).
    if args.fail_on:
        gate = severity_order.get(args.fail_on, 4)
        if any(severity_order.get(f.get("severity", "INFO"), 4) <= gate for f in all_findings):
            print(f"[!] Findings at or above {args.fail_on} present — exiting 2 (--fail-on).")
            sys.exit(2)


_SEV_WEIGHT = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}


def _prioritize(findings):
    """Return (prio_by_id, prio_results). Degrades to ({}, []) if the module is
    unavailable so the rest of the scan still runs."""
    try:
        from risk_prioritizer import RiskPrioritizer, ThreatIntel, by_finding
    except Exception as exc:  # pragma: no cover
        print(f"[WARN] risk-prioritizer unavailable: {exc}")
        return {}, []
    intel = ThreatIntel()
    results = RiskPrioritizer(intel).prioritize(findings, context_findings=findings)
    if intel.available and intel.is_stale():
        print(f"[!] Threat-intel snapshot is stale ({intel.age_days()}d old) — run --refresh-intel.")
    return by_finding(results), results


def _print_top(prio_results, n):
    from risk_prioritizer import TIER_META
    tiers = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for r in prio_results:
        tiers[r.tier] = tiers.get(r.tier, 0) + 1
    print("\n[*] Risk-prioritized fix-first queue:")
    for t in ("P1", "P2", "P3", "P4"):
        print(f"    {t}  {TIER_META[t]['label']:<20} {tiers[t]:>4}   ({TIER_META[t]['window']})")
    from finding_view import _g
    print()
    for i, r in enumerate(prio_results[:n], 1):
        cve = _g(r.finding, "cve", None)
        tags = []
        if r.kev:
            tags.append("KEV")
        if r.epss:
            tags.append(f"EPSS {int(r.epss*100)}%")
        if r.reachable:
            tags.append("reachable")
        tagstr = ("  [" + ", ".join(tags) + "]") if tags else ""
        print(f"  {i:>2}. {r.tier} {_g(r.finding,'severity'):<8} {_g(r.finding,'rule_id'):<14} "
              f"{str(_g(r.finding,'name',''))[:46]}" + (f" ({cve})" if cve else "") + tagstr
              + f"   score {r.score}/100 · {_g(r.finding,'device','')}")


def _intel_action(args):
    """Handle --refresh-intel / --export-intel / --import-intel, then exit."""
    try:
        from risk_prioritizer import refresh_threat_intel, export_intel, import_intel
        from modules import cve_detection as _cd
    except Exception as exc:
        print(f"[ERROR] intel module unavailable: {exc}")
        return 1
    if args.export_intel:
        try:
            meta = export_intel(args.export_intel)
            print(f"[+] Exported threat-intel snapshot ({meta.get('cve_count')} CVEs) to {args.export_intel}")
            return 0
        except (OSError, ValueError) as exc:
            print(f"[ERROR] export failed: {exc}"); return 1
    if args.import_intel:
        try:
            meta = import_intel(args.import_intel)
            print(f"[+] Imported threat-intel snapshot ({meta.get('cve_count')} CVEs, {meta.get('kev_count')} KEV)")
            return 0
        except (OSError, ValueError) as exc:
            print(f"[ERROR] import failed: {exc}"); return 1
    # refresh
    cves = [v for k, v in vars(_cd).items() if isinstance(v, list) and v
            and isinstance(v[0], dict) and v[0].get("cve")]
    ids = sorted({c["cve"] for c in (cves[0] if cves else [])})
    print(f"[*] Refreshing threat intel for {len(ids)} tracked CVE(s) from CISA KEV + FIRST.org EPSS ...")
    try:
        meta = refresh_threat_intel(ids)
        print(f"[+] Snapshot updated: {meta['cve_count']} CVE(s), {meta['kev_count']} KEV-listed ({meta['snapshot_date']}).")
        return 0
    except Exception as exc:
        print(f"[ERROR] refresh failed: {exc}\n    (offline? the bundled snapshot remains in use.)")
        return 1


def _host_key_map(device_files):
    """Build hostname -> {config filenames} from (hostname, filename) pairs."""
    from collections import defaultdict
    files_by_host = defaultdict(set)
    for h, fn in device_files:
        files_by_host[h or "unknown"].add(fn or "")
    return files_by_host


def _host_key_for(hostname, filename, files_by_host):
    """The stable posture/ticket host key: the hostname, disambiguated with the config
    filename when the hostname is 'unknown' or collides across multiple configs."""
    h = hostname or "unknown"
    if h == "unknown" or len(files_by_host.get(h, ())) > 1:
        return f"{h}|{filename or ''}"
    return h


def _stamp_host_keys(findings, device_files=None):
    """Stamp a stable posture/ticket host key onto every finding as ``_host_key``.

    Uses the device hostname, but disambiguates with the config filename when the
    hostname is 'unknown' or collides across multiple files (so two distinct boxes
    can't merge in the system of record OR in a SOAR/ticket dedup key). This is the
    SINGLE source of truth: posture groups by ``_host_key`` and ``fv_host`` reads it,
    so posture, exports, and resolved-closure keys all derive host identically.

    ``device_files`` (optional) = the AUTHORITATIVE (hostname, filename) list from the
    scanned configs. When given, the collision map accounts for EVERY scanned device —
    including a same-hostname sibling that produced zero findings — so the stamped keys
    stay consistent with the attestation's per-config enumeration. Falls back to the
    findings' own (device, device_file) pairs when omitted (used by unit tests)."""
    if device_files is not None:
        files_by_host = _host_key_map(device_files)
    else:
        files_by_host = _host_key_map((f.get("device"), f.get("device_file")) for f in findings)
    for f in findings:
        f["_host_key"] = _host_key_for(f.get("device"), f.get("device_file"), files_by_host)


def _update_posture(history_path, exceptions_path, findings, prio_by_id=None):
    """Update the file-based posture store per device and print what changed.
    prio_by_id (id(finding)->PriorityResult) drives SLA/weaponization when the
    risk-prioritizer is available; None degrades gracefully."""
    try:
        from posture import PostureStore, Exceptions
    except Exception as exc:  # pragma: no cover
        print(f"[WARN] posture module unavailable: {exc}")
        return {}
    from collections import defaultdict
    groups = defaultdict(list)
    for f in findings:
        groups[f.get("_host_key") or f.get("device", "unknown") or "unknown"].append(f)
    store = PostureStore(history_path)
    exc = Exceptions.load(exceptions_path)
    deltas = {}
    print("\n[*] Posture update (system of record):")
    for host, fs in sorted(groups.items()):
        risk = min(100, sum(_SEV_WEIGHT.get(f.get("severity", ""), 0) for f in fs))
        prio = None
        if prio_by_id:
            prio = [prio_by_id[id(f)] for f in fs if id(f) in prio_by_id] or None
        d = store.update(host, fs, prio, exc, risk_score=risk)
        deltas[host] = d
        since = f"since {d.prev_date[:10]}" if d.prev_date else "baseline recorded"
        line = (f"    {host}: +{len(d.new)} new  -{len(d.resolved)} resolved"
                f"  ~{len(d.reopened)} reopened  (carried {len(d.carried)}, {since})")
        if d.sla_breaches:
            line += f"  [!] {len(d.sla_breaches)} SLA breach(es)"
        if d.newly_weaponized:
            line += f"  [!] {len(d.newly_weaponized)} newly weaponized"
        if d.open_accepted:
            line += f"  ({d.open_accepted} accepted-risk)"
        print(line)
    try:
        store.save()
    except OSError as exc:
        print(f"    [WARN] could not write history '{history_path}': {exc}")
    return deltas


def _export_all(args, findings, prio_by_id, deltas):
    """Dispatch the SOAR/ticketing + SIEM exports requested on the CLI."""
    want = (args.jira or args.servicenow or args.splunk_soar or args.webhook
            or args.sarif or args.ocsf)
    if not want:
        return
    try:
        import nss_export as nx
        from remediation_kb import RemediationKB
    except Exception as exc:  # pragma: no cover
        print(f"[WARN] export module unavailable: {exc}")
        return
    kb = RemediationKB()
    epoch = int(datetime.datetime.now().timestamp() * 1000)
    common = dict(prio_by_id=prio_by_id, kb=kb, deltas=deltas,
                  min_tier=args.soar_min_tier, scan_epoch=epoch)

    def _dump(path, doc, label, count):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False, default=str)
        print(f"[*] {label}: {path} ({count} item(s))")

    if args.jira:
        d = nx.build_jira(findings, project_key=args.jira_project, **common)
        _dump(args.jira, d, "Jira export", len(d["items"]))
    if args.servicenow:
        d = nx.build_servicenow(findings, **common)
        _dump(args.servicenow, d, "ServiceNow export", len(d["items"]))
    if args.splunk_soar:
        d = nx.build_splunk_soar(findings, **common)
        _dump(args.splunk_soar, d, "Splunk SOAR export", len(d["items"]))
    if args.webhook:
        d = nx.build_webhook(findings, now_iso=datetime.datetime.now().isoformat(timespec="seconds"), **common)
        _dump(args.webhook, d, "Webhook export", len(d["items"]))
    if args.sarif:
        doc = nx.build_sarif(findings, prio_by_id=prio_by_id)
        _dump(args.sarif, doc, "SARIF report", len(doc["runs"][0]["results"]))
    if args.ocsf:
        events = nx.build_ocsf(findings, epoch=epoch, prio_by_id=prio_by_id)
        _dump(args.ocsf, events, "OCSF events", len(events))


# ── Compliance attestation pack ──────────────────────────────────────────────

NSS_VERSION = "1.0"

# Attestation framework -> benchmark_score() framework name (compliance_map.FRAMEWORKS).
_ATTEST_FRAMEWORKS = ("CIS", "PCI-DSS", "NIST", "SOC2", "HIPAA", "ISO27001")


def _load_attest_key(spec):
    """Resolve --attest-key into (key_bytes, key_id). 'env:NAME' reads an env var;
    otherwise a key-file path. The key is NEVER embedded in the bundle (that would
    defeat the seal). Returns (None, None) when no key was requested."""
    if not spec:
        return None, None
    import os
    if str(spec).startswith("env:"):
        name = str(spec)[4:]
        val = os.environ.get(name)
        if not val:
            raise ValueError(f"--attest-key env:{name} is not set")
        return val.encode("utf-8"), f"env:{name}"
    with open(spec, "rb") as fh:
        data = fh.read()
    if not data:
        # An empty key must be an ERROR, not a silent downgrade to a keyless (forgeable)
        # SHA-256 seal — which would then also FAIL verification with the same --attest-key.
        raise ValueError(f"--attest-key file '{spec}' is empty")
    return data, f"file:{os.path.basename(spec)}"


def _attest_verify_action(path, key_spec):
    """Verify an attestation bundle's integrity standalone (no scan needed).
    Exit 0 = intact, 2 = tampered/invalid."""
    from attestation import verify_attestation

    def _reject_nonfinite(_tok):
        # json.load accepts NaN/Infinity/-Infinity by default; a canonical, finite bundle
        # never contains them, so treat their presence as a malformed/hostile bundle.
        raise ValueError("non-finite number (NaN/Infinity) in bundle")

    try:
        with open(path, "r", encoding="utf-8") as fh:
            bundle = json.load(fh, parse_constant=_reject_nonfinite)
    except (OSError, ValueError) as exc:
        print(f"[!] Cannot read attestation bundle '{path}': {exc}", file=sys.stderr)
        return 2
    try:
        key, _ = _load_attest_key(key_spec)
    except (OSError, ValueError) as exc:
        print(f"[!] --attest-key: {exc}", file=sys.stderr)
        return 2
    res = verify_attestation(bundle, key=key)
    if res["ok"]:
        print(f"[+] Attestation INTACT: {res['record_count']} record(s) verified "
              f"(seal: {res['alg']}).")
        return 0
    print(f"[!] Attestation FAILED verification (seal: {res.get('alg')}):", file=sys.stderr)
    for p in res.get("problems", []):
        print(f"      - {p}", file=sys.stderr)
    return 2


def _source_artifact(data_dir, filename):
    """Provenance anchor: hash the raw source config so the sealed bundle is bound to
    a specific artifact (never tamper-seal fiction). 'looks_truncated' is a light
    heuristic (a real Cisco config is more than a handful of lines)."""
    import hashlib as _hl
    try:
        p = Path(data_dir) / filename
        raw = p.read_bytes()
        text = raw.decode("utf-8", "replace")
        return {"kind": "cisco-config", "filename": filename,
                "sha256": _hl.sha256(raw).hexdigest(),
                "byte_length": len(raw), "line_count": text.count("\n") + 1,
                "looks_truncated": bool(len(text.strip().splitlines()) < 5),
                "config_export_utc": None}
    except OSError:
        return {"kind": "unknown", "filename": filename, "sha256": None,
                "byte_length": None, "line_count": None,
                "looks_truncated": False, "config_export_utc": None}


def _intel_snapshot_meta():
    """Best-effort threat-intel provenance for the attestation envelope (optional)."""
    try:
        p = Path(__file__).with_name("threat_intel.json")
        meta = (json.loads(p.read_text(encoding="utf-8")) or {}).get("meta", {})
        return {"snapshot_date": meta.get("snapshot_date"),
                "kev_count": meta.get("kev_count"),
                "cve_count": meta.get("cve_count")}
    except Exception:
        return {}


def _save_attestation(args, findings_unfiltered, configs, data_dir):
    """Emit a tamper-evident FLEET compliance attestation bundle (auditor evidence,
    NOT a compliance certification). Reuses benchmark_score() for control PASS/FAIL
    and posture Exceptions for risk-acceptance, so it can never disagree with them.
    One coverage/results block per device, PASS/FAIL scored against that device's
    PLATFORM benchmark, grouped by the same disambiguated host key as posture."""
    try:
        from attestation import (build_attestation, seal_attestation,
                                 render_attestation_html, to_oscal)
        from compliance_map import benchmark_score
        from posture import Exceptions
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[WARN] attestation module unavailable: {exc}")
        return
    from collections import OrderedDict

    try:
        key, key_id = _load_attest_key(args.attest_key)
    except (OSError, ValueError) as exc:
        print(f"[!] --attest-key: {exc}", file=sys.stderr)
        raise SystemExit(2)

    # Group the unfiltered findings by the SAME stamped host key posture/exports use.
    groups = OrderedDict()
    for f in findings_unfiltered:
        hk = f.get("_host_key") or f.get("device", "unknown") or "unknown"
        groups.setdefault(hk, []).append(f)

    # Enumerate EVERY scanned config (authoritative device list) — not just devices that
    # produced findings — so a fully-clean device still gets an attestation block (all
    # controls PASS) and device_count is honest. Host keys use the same rule as the
    # stamped findings (seeded from the full config set), so groups line up exactly.
    files_by_host = _host_key_map([(pc.hostname, fn) for fn, pc in configs])
    exceptions = Exceptions.load(args.exceptions)
    devices_input = []
    seen_hk = set()
    for fn, pc in configs:
        hk = _host_key_for(pc.hostname, fn, files_by_host)
        if hk in seen_hk:
            continue                      # identical hostname+filename twice — one block
        seen_hk.add(hk)
        fs = groups.get(hk, [])
        platform = str(pc.device_type or "")
        benchmarks = {}
        for fw in _ATTEST_FRAMEWORKS:
            try:
                bm = benchmark_score(fw, fs, platform=platform or None)
            except Exception:
                continue
            if bm.get("total_controls"):
                benchmarks[fw] = bm
        devices_input.append({
            "host": hk,
            "device": {"hostname": str(pc.hostname or "unknown"),
                       "platform": platform or "unknown",
                       "config_file": fn},
            "findings": fs,
            "benchmarks": benchmarks,
            "source_artifact": _source_artifact(data_dir, fn),
        })

    unsealed = build_attestation(
        devices_input,
        attester_org=args.attest_org,
        run_mode="offline-config-parse",
        tool_version=NSS_VERSION,
        intel=_intel_snapshot_meta(),
        exceptions=exceptions,
    )
    bundle = seal_attestation(unsealed, key=key, key_id=key_id)
    with open(args.attest, "w", encoding="utf-8") as fh:
        # Pretty on disk; the seal is over canonical_bytes(body), a SEPARATE
        # serialization — verify re-canonicalizes, so indentation is irrelevant.
        json.dump(bundle, fh, indent=2, ensure_ascii=False)
    print(f"[+] Attestation bundle saved to: {args.attest} "
          f"(seal: {bundle['seal']['alg']}, {bundle['body']['manifest']['record_count']} records, "
          f"{len(devices_input)} device(s))")
    if args.attest_html:
        with open(args.attest_html, "w", encoding="utf-8") as fh:
            fh.write(render_attestation_html(bundle))
        print(f"[+] Attestation statement (HTML) saved to: {args.attest_html}")
    if args.attest_oscal:
        with open(args.attest_oscal, "w", encoding="utf-8") as fh:
            json.dump(to_oscal(bundle["body"]), fh, indent=2, ensure_ascii=False)
        print(f"[+] OSCAL-aligned assessment-results saved to: {args.attest_oscal}")


def _verify_fixes(args, current_findings, prio_by_id):
    """Remediation-verification loop: classify each finding in a prior --json report
    as REMEDIATED / PERSISTING / CHANGED given this scan (plus new REGRESSIONS), with
    before->after evidence and the KB verify command. Prints the report and returns an
    exit code: 0 = clean (every prior CRITICAL/HIGH remediated, no new CRITICAL/HIGH),
    else 2. Runs on the UNFILTERED current set so a --severity filter can't mask a
    persisting/regressed finding."""
    try:
        with open(args.verify_against, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"[!] Could not load prior report '{args.verify_against}': {exc}", file=sys.stderr)
        return 2
    raw = doc.get("findings", []) if isinstance(doc, dict) else (doc if isinstance(doc, list) else [])
    prior = [d for d in raw if isinstance(d, dict)]
    try:
        from remediation_verify import build_verification, render_text, render_html
        from remediation_kb import RemediationKB
    except Exception as exc:  # pragma: no cover
        print(f"[WARN] remediation-verify module unavailable: {exc}")
        return 2
    report = build_verification(prior, current_findings, kb=RemediationKB(),
                                prio_by_id=prio_by_id, host="")
    import os as _os
    label = _os.path.basename(args.verify_against)
    print()
    print(render_text(report, baseline_label=label))
    if args.verify_json:
        with open(args.verify_json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
        print(f"[+] Verification JSON saved to: {args.verify_json}")
    if args.verify_html:
        with open(args.verify_html, "w", encoding="utf-8") as fh:
            fh.write(render_html(report, baseline_label=label))
        print(f"[+] Verification HTML saved to: {args.verify_html}")
    return 0 if report["summary"]["clean"] else 2


def _save_json(path, findings, scan_meta):
    """Write a machine-readable findings report. The stable base other tooling
    (remediation-verification, diffs, exporters) reads. Schema v1."""
    report = {
        "scanner": "Network Security Scanner (NSS)",
        "schema_version": 1,
        "generated": datetime.datetime.now().isoformat(),
        "scan_meta": scan_meta,
        "total_findings": len(findings),
        "findings": findings,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)


if __name__ == "__main__":
    main()
