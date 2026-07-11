# CLAUDE.md — Network Security Scanner (NSS)

## Project Overview

Network Security Scanner — a stdlib-only Python tool that parses Cisco device
running-config exports and audits them against CIS Benchmarks, Cisco/NSA
hardening guides, and the published Cisco PSIRT advisory database. Designed
for offline use: no SSH, SNMP, or API access to live devices is required.

- **Language**: Python 3.8+ (stdlib only — `argparse`, `re`, `json`, `pathlib`, `html`, `datetime`)
- **Entry point**: `nss_scanner.py`
- **Version**: 1.0
- **License**: MIT
- **Supported platforms**: Cisco IOS, IOS-XE (Catalyst), NX-OS (Nexus, MDS),
  Firepower Threat Defense, ASA, WLC (AireOS / Catalyst 9800)

## Architecture

```
nss_scanner.py                 # CLI entry, MODULE_MAP, run loop
└── modules/
    ├── base.py                # BaseAuditor, ParsedConfig, load_configs
    ├── mgmt_plane.py          # 25 checks — passwords, AAA, SSH, VTY, banners
    ├── ctrl_plane.py          # 11 checks — CoPP, routing auth, NTP, STP, CDP
    ├── data_plane.py          # 9  checks — uRPF, DHCP snooping, DAI, storm ctl
    ├── services.py            # 9  checks — unused services, SNMP, timestamps
    ├── switch_security.py     # 8  checks — port security, VLAN, trunk, BPDU
    ├── wireless.py            # 10 checks — SSID encryption, WPA, rogue AP, MFP
    ├── ngfw_core.py           # 9  checks — access control, IPS, AMP, SI, SSL
    ├── ngfw_platform.py       # 7  checks — FTD mgmt, accounts, FXOS, DNS
    ├── logging.py             # 10 checks — syslog, SNMP traps, NetFlow, archive
    ├── crypto.py              # 10 checks — SSH keys, TLS, IPsec, ISAKMP, DH
    ├── cve_detection.py       # 40 published Cisco CVEs (2018-2026)
    └── report_generator.py    # Dark-theme HTML dashboard
```

## Auditor Pattern

Every check module subclasses `BaseAuditor`, declares its `SUPPORTED_PLATFORMS`,
and implements `run_all_checks()`:

```python
from modules.base import BaseAuditor

class MyAuditor(BaseAuditor):
    # Restrict to specific device types. Without this guard, IOS-syntax
    # checks would fire against ASA / NX-OS / FTD / WLC and produce
    # false positives (e.g. flagging ASA for missing 'enable secret' or
    # NX-OS for missing 'aaa new-model'). Leave None to run everywhere.
    SUPPORTED_PLATFORMS = {"ios", "iosxe", "wlc"}

    def run_all_checks(self):
        if not self.supports_platform():
            return self._emit_skip_notice("My Category")
        self.check_a()
        self.check_b()
        return self.findings

    def check_a(self):
        if self.config.has_line(r"^bad-pattern"):
            self.finding(
                "MYAUD-001",                       # check_id (stable rule id)
                "Short title",                     # title shown in report
                self.SEVERITY_HIGH,                # CRITICAL / HIGH / MEDIUM / LOW / INFO
                "My Category",                    # category bucket
                "Why this is a problem.",         # description
                affected_items=[...],             # optional list of evidence lines
                remediation="config command",     # how to fix it
                references=["CIS 1.1.1", "URL"],  # standards / advisory links
            )
```

The auditor is created with a `ParsedConfig` instance and an optional baseline
dict. `nss_scanner.main()` iterates every (device, module) pair, tags each
finding with `device`, `device_file`, `device_type`, then aggregates them for
the HTML report.

## Finding Schema

Every check produces a dict with the fields below. The report generator and
any future export sink (JSON, CSV) reads from these:

| Field | Type | Notes |
|-------|------|-------|
| `check_id` | str | Stable scanner-local id, e.g. `MGMT-001`, `CISCO-CVE-013` |
| `title` | str | Short, one-line description |
| `severity` | str | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `category` | str | Free-text bucket (`Management Plane`, `CVE Detection`, …) |
| `description` | str | 1-3 sentence explanation |
| `affected_items` | list[str] | Evidence (matched config lines) |
| `affected_count` | int | Auto-derived from `affected_items` length |
| `remediation` | str | Cisco CLI fix or upgrade guidance |
| `references` | list[str] | CIS section, advisory URL, CWE id |
| `details` | dict | Free-form extra fields (used by CVE module for CVSS, KEV, CWE) |
| `timestamp` | str | ISO format, set automatically |
| `device` / `device_file` / `device_type` | str | Tagged in by the run loop |

## ParsedConfig

`modules/base.py:ParsedConfig` ingests a raw config string and exposes:

- `device_type` — auto-detected: `ios` / `iosxe` / `nxos` / `asa` / `ftd` / `wlc`.
  ASA detection looks for distinctive tokens (`ASA Version`, `webvpn`, `names`,
  `anyconnect`, `tunnel-group`, `nameif`, extended ACL syntax) before falling
  through to IOS/IOS-XE classification.
- `hostname` — parsed from `hostname X`.
- `_sections` — top-level config sections (interface, line, router, snmp-server, …).
- Helper methods: `has_line(regex)`, `find_lines(regex)`, `get_value(regex, group)`,
  `get_interfaces()`, `get_vty_lines()`, `get_console_lines()`, `get_section(prefix)`.

## CVE Detection Module (`modules/cve_detection.py`)

Distinct from the other auditors: it doesn't grep for misconfigurations, it
matches the detected software version against a curated database of published
Cisco PSIRT advisories.

### Database (`CISCO_CVES`)

40 entries (2018-2026) covering CRITICAL/HIGH/MEDIUM CVEs across:

- **ASA / FTD** — ArcaneDoor (CVE-2025-20333/20362/20363), persistent local RCE
  (CVE-2024-20359), WebVPN path traversal (CVE-2020-3452), info-disclosure
  (CVE-2020-3259), WebVPN double-free (CVE-2018-0101).
- **IOS / IOS-XE** — BadCandy chain (CVE-2023-20198 + 20273), SNMP RCE
  (CVE-2025-20352), Wireless AP-image RCE (CVE-2025-20188), GET VPN RCE
  (CVE-2023-20109).
- **NX-OS** — Velvet Ant CLI injection (CVE-2024-20399), Python/Bash sandbox
  escapes (CVE-2024-20271/20272), image-signature bypass (CVE-2024-20275).
- **WLC** — Catalyst 9800 auth bypass (CVE-2022-20695), IPv6 DoS, CAPWAP DTLS DoS.

Each entry records `id`, `cve`, `severity`, `cvss`, `title`, `description`,
`platforms` (list of device_type keys), `trains` (list of "major.minor" strings),
`fixed_advice`, `advisory` URL, `kev` (bool), `exploited` (bool), `cwe`.

### Version Detection

`detect_version(raw_text, device_type)` extracts the running train. Patterns
target each platform's `show version` output:

| Platform | Pattern | Example match |
|----------|---------|---------------|
| ios | `^\s*version\s+(\d+\.\d+)` | `version 15.7` → `15.7` |
| iosxe | `Cisco IOS XE Software, Version (\d+\.\d+)` | `Version 17.09.04` → `17.9` |
| nxos | `NX-OS Software, Version (\d+\.\d+)` | `Version 9.3(11)` → `9.3` |
| asa | `ASA (?:Software )?Version (\d+\.\d+)` | `ASA Version 9.18(2)` → `9.18` |
| ftd | `(?:FTD\|Firepower Threat Defense)[^V]*Version (\d+\.\d+)` | `Version 7.4.1` → `7.4` |
| wlc | `(?:AireOS\|Wireless LAN Controller)[^,]*,?\s*(?:Software Release\|Version) (\d+\.\d+)` | `Version 8.10` → `8.10` |

The captured train is normalised so `17.09` and `17.9` both match the same
CVE entry (Cisco PSIRT advisories use the un-padded form).

### ASA Disambiguation

`ParsedConfig._detect_type` has no ASA marker — ASA configs look like
classic IOS to the parser. The CVE auditor calls `_looks_like_asa(raw_text)`
which checks for ASA-specific tokens (`ASA Version`, `names`, `webvpn`,
`anyconnect`, `tunnel-group`, `nameif`, extended ACL syntax). When the parser
says `ios`/`iosxe` but the heuristic fires, the effective platform is
re-classified to `asa` before CVE matching.

### Precision Caveat

The `trains` list uses `major.minor` granularity (e.g. `"17.9"`, `"9.18"`)
rather than full patch versions. Cisco PSIRT advisory pages render the
"first fixed release" table via JavaScript, so the exact patch-level
vulnerability window can't be reliably scraped at scanner build time. The
auditor therefore flags **any device running an affected train** and links
to the official advisory URL; operators verify the patch level with the
Cisco Software Checker linked in each finding.

For audit purposes this is conservative — false positives (a device that
was patched within the train but the scanner can't tell) are acceptable;
false negatives (an unpatched device escaping detection) are not.

### Meta-Findings

The CVE module emits `INFO`-severity meta-findings to communicate scan
coverage even when no CVEs match:

- `CVE-META-001` — no version line found in the config; CVE matching skipped.
  Operators are told to append `show version` output to the config file.
- `CVE-META-002` — version detected but no CVE entry matches. Useful to
  confirm the device train is outside the scanner's database (e.g. very
  recent release, or platform-specific advisories not yet added).

## Sample Configs

`sample_configs/` ships 7 device configs that exercise the full check matrix:

| File | Platform | Train | Notable findings triggered |
|------|----------|-------|----------------------------|
| `router_core.cfg` | IOS | 15.7 | Type-7 passwords, telnet on VTY, default SNMP communities |
| `switch_access.cfg` | IOS | 15.x | Trunk on access port, no BPDU guard, no port-security |
| `catalyst_9300_outdated.cfg` | IOS-XE | 17.9 | BadCandy chain (CVE-2023-20198/20273), SNMP RCE, AP-image RCE |
| `nexus_9k_outdated.cfg` | NX-OS | 9.3 | Velvet Ant CLI injection, telnet enabled, default SNMP |
| `asa_5516_outdated.cfg` | ASA | 9.18 | ArcaneDoor trio, WebVPN exposed, http server on outside |
| `wlc_9800_outdated.cfg` | WLC (IOS-XE) | 17.9 | AP image download RCE, WLC auth bypass, CAPWAP DTLS DoS |
| `ftd_firewall.cfg` | FTD | 7.2 | ArcaneDoor trio, FTD-specific checks |

Running all modules across all samples produces 246 findings (17 CRITICAL,
78 HIGH, 81 MEDIUM, 33 LOW, 37 INFO meta-notices marking modules skipped due
to platform mismatch) — a useful end-to-end smoke test. The 37 INFO entries
are the cross-platform skip notices: e.g. switch-security and IOS-mgmt
modules correctly skipped on ASA/NX-OS/FTD samples.

## Security-Operations Layer (finding lifecycle)

Beyond the config audit, a set of stdlib-only modules add a full finding
lifecycle, ported from the Fortinet/FortiGate scanner and adapted to NSS's
**multi-device** model (one scan = many devices). They read findings through
`finding_view._g`, which aliases the Cisco dict shape (`check_id` / `title` /
`affected_items` / `remediation`) to the ported field names (`rule_id` / `name`
/ `line_content` / `recommendation`) so the ported code stays near-verbatim.

| Module | Purpose | CLI |
|--------|---------|-----|
| `finding_view.py` | Canonical field accessor + `fv_host` (reads the stamped `_host_key`) | — |
| `compliance_map.py` + `compliance_data.py` | check_id → CIS/PCI-DSS/NIST/SOC2/HIPAA/ISO27001 crosswalk; `benchmark_score(fw, findings, platform)` | (auto, embedded in findings) |
| `risk_prioritizer.py` + `threat_intel.json` | P1–P4 scoring (severity × CISA-KEV/EPSS × reachability); KEV floor ≥P2 | `--top`, `--refresh-intel`, `--export-intel`, `--import-intel` |
| `cve_reachability.py` | Per-device config gate: is the vulnerable feature enabled? Downrank never suppress | (auto, stamps `f["_cve_reach"]`) |
| `posture.py` | Continuous system of record: new/resolved/reopened, SLA, exceptions (fail-open) | `--history`, `--exceptions` |
| `remediation_kb.py` + `.json` | Structured Cisco CLI remediation records (exact→family-prefix) | (used by exports + verify) |
| `remediation_verify.py` | A/B loop: REMEDIATED/PERSISTING/CHANGED/REGRESSION vs a prior report | `--verify-against`, `--verify-html`, `--verify-json` |
| `nss_export.py` | Jira/ServiceNow/Splunk SOAR/webhook + SARIF/OCSF; host-scoped dedup + posture-driven lifecycle | `--jira`, `--servicenow`, `--splunk-soar`, `--webhook`, `--sarif`, `--ocsf`, `--soar-min-tier` |
| `attestation.py` | Tamper-evident fleet compliance bundle (SHA-256 manifest → RFC6962 Merkle → SHA-256/HMAC seal) + OSCAL | `--attest`, `--attest-key`, `--attest-html`, `--attest-oscal`, `--attest-org`, `--attest-verify` |

### Cross-cutting invariants (do not regress)

- **Host identity is a single source of truth.** `nss_scanner._stamp_host_keys`
  stamps `_host_key` on every finding (hostname, or `<host>|<file>` when the
  hostname is `unknown` or collides). Posture grouping, `fv_host` (exports), and
  the attestation per-device enumeration all derive host from it — so two boxes
  never merge and resolved-closure keys always match the opened ticket.
- **Anti-overclaim / posture parity.** Attestation and posture derive the finding
  `entity` identically (`finding_entity` only when `affected_count == 1`); the
  attestation reuses `benchmark_score` (PASS/FAIL) and posture `Exceptions`
  (risk-acceptance) so it can never disagree with the posture system of record.
- **Downrank never suppress + KEV floor.** Reachability only lowers priority;
  a CISA-KEV-listed finding never drops below P2.
- **Reproducible + tamper-evident.** Attestation content is float-free and
  canonicalised (sorted keys, no spaces, UTF-8); all bundle I/O is `utf-8`; the
  keyed path refuses a seal-downgrade to keyless.
- **Unfiltered set for lifecycle.** Prioritization, posture, attestation, and
  remediation-verify run on the pre-`--severity` finding set so a display filter
  can't inflate a pass rate or hide a persisting/regressed finding.

### Tests & CI

`tests/` holds the pytest suite (102 tests). `.github/workflows/ci.yml` runs it
on Python 3.8–3.12 plus capability smoke tests (attestation build+verify+tamper,
keyed HMAC roundtrip, exports, remediation-verify). Gate commits on the real
pytest exit code — never let a piped `pytest | tail` mask a failure.

## Development Guidelines

### Adding a new check module
1. Create `modules/<short_name>.py` with a `class FooAuditor(BaseAuditor)`.
2. Implement `run_all_checks()` calling individual `check_*` methods that
   each may emit findings via `self.finding(...)`.
3. Pick a stable rule-id prefix (e.g. `FOO-001`, `FOO-002`).
4. Register in `nss_scanner.py:MODULE_MAP`:
   ```python
   "foo": ("Foo Security", FooAuditor),
   ```
5. Document the rule ids and references in the docstring at the top of the file.

### Adding a new check inside an existing module
1. Add the `check_*` method and call it from `run_all_checks()`.
2. Use the next available rule id in that module's prefix sequence.
3. Always include `description`, `remediation`, and at least one `references`
   entry (CIS section, Cisco advisory URL, NIST control, or CWE).
4. Sanitise any evidence lines that may contain passwords / community strings
   before placing them in `affected_items` (see `mgmt_plane.check_type7_passwords`
   for an example using `re.sub`).

### Adding a new CVE to `cve_detection.py`
1. Append to `CISCO_CVES` with the next sequential `id` (`CISCO-CVE-NNN`).
2. Populate `platforms` from the matching device_type keys.
3. `trains` should list every `major.minor` train the advisory marks as
   affected. Use `"9.x"` to catch every 9.* train when the upper bound is
   open, or `"*"` for "any version on this platform" (rare).
4. `advisory` should link to the canonical
   `https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/...`
   URL so operators can resolve patch-level versions via the Software Checker.
5. Mark `kev: True` if the CVE appears in the CISA Known Exploited
   Vulnerabilities catalog, and `exploited: True` if Cisco TALOS / PSIRT
   confirms in-the-wild exploitation. These tags surface in the finding title
   so operators can prioritise.

### Conventions
- Single-file scanner orchestration; per-module check files.
- No third-party packages — Python stdlib only. Keep it that way.
- Regex matches are case-insensitive by default (`re.IGNORECASE`).
- HTML report theme: dark JetBrains Mono / DM Sans, colour-coded by severity.
- `nss_scanner.py` reconfigures stdout/stderr to UTF-8 at startup so the
  banner's box-drawing characters don't crash Windows cp1252 consoles.

## Running

```bash
# Default: all modules, all configs
python nss_scanner.py --data-dir ./sample_configs --output report.html

# Subset of modules
python nss_scanner.py --data-dir ./configs --modules mgmt ctrl crypto cve

# Filter by severity (only show HIGH+)
python nss_scanner.py --data-dir ./configs --severity HIGH

# Custom baseline overrides
python nss_scanner.py --data-dir ./configs --config baseline.json
```

CI gating: `--fail-on {CRITICAL|HIGH|MEDIUM|LOW}` exits 2 when any finding at or
above that severity is present (default exit 0). `--verify-against prior.json`
exits 2 when the remediation A/B is not clean, and `--attest-verify` exits 2 on a
tampered/invalid attestation bundle — all three are CI-gateable.

```bash
# Lifecycle examples
python nss_scanner.py --data-dir ./configs --top 15 --history posture.json
python nss_scanner.py --data-dir ./configs --attest att.json --attest-key env:NSS_ATT_KEY
python nss_scanner.py --attest-verify att.json --attest-key env:NSS_ATT_KEY
python nss_scanner.py --data-dir ./configs --jira jira.json --sarif out.sarif --soar-min-tier P2
python nss_scanner.py --data-dir ./configs --verify-against baseline.json --fail-on HIGH
```
