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

    args = parser.parse_args()

    # ── threat-intel maintenance actions (standalone; no scan needed) ──
    if args.refresh_intel or args.export_intel or args.import_intel:
        sys.exit(_intel_action(args))

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
    # '<host>|<file>' key so two boxes can't merge and closures line up.
    _stamp_host_keys(all_findings)

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

    crit = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in all_findings if f["severity"] == "LOW")

    print(f"\n{'='*65}")
    print(f"  SCAN COMPLETE — {len(configs)} device(s), {len(all_findings)} finding(s)")
    print(f"  CRITICAL: {crit}  |  HIGH: {high}  |  MEDIUM: {med}  |  LOW: {low}")
    print(f"  Report: {args.output}")
    print(f"{'='*65}\n")

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


def _stamp_host_keys(findings):
    """Stamp a stable posture/ticket host key onto every finding as ``_host_key``.

    Uses the device hostname, but disambiguates with the config filename when the
    hostname is 'unknown' or collides across multiple files (so two distinct boxes
    can't merge in the system of record OR in a SOAR/ticket dedup key). This is the
    SINGLE source of truth: posture groups by ``_host_key`` and ``fv_host`` reads it,
    so posture, exports, and resolved-closure keys all derive host identically."""
    from collections import defaultdict
    files_by_host = defaultdict(set)
    for f in findings:
        files_by_host[f.get("device", "unknown") or "unknown"].add(f.get("device_file", ""))
    for f in findings:
        h = f.get("device", "unknown") or "unknown"
        if h == "unknown" or len(files_by_host.get(h, ())) > 1:
            f["_host_key"] = f"{h}|{f.get('device_file', '')}"
        else:
            f["_host_key"] = h


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
