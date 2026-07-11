"""
HTML Report Generator
======================
Generates a professional, interactive HTML security dashboard
with findings summary, severity breakdown, and detailed findings.
"""

import json
import html
from typing import Dict, List, Any


class ReportGenerator:

    def __init__(self, findings: List[Dict[str, Any]], meta: Dict[str, Any],
                 priorities: "List[Any] | None" = None):
        self.findings = findings
        self.meta = meta
        # Detailed remediation knowledge base — supplies the long-form observation,
        # step-by-step fix, verify/rollback/impact per check_id. Optional: if it can't
        # load, findings fall back to their own description/remediation.
        self._kb = None
        try:
            from remediation_kb import RemediationKB
            self._kb = RemediationKB()
        except Exception:
            self._kb = None
        # Risk-prioritization overlay (P1-P4). Supplied by the scanner (computed on the
        # unfiltered set, with CVE reachability). If absent, compute here so a report
        # generated standalone still shows tiers; degrade to none if unavailable.
        self._prio_by_id = {}
        self._tier_meta = {}
        if priorities is None:
            try:
                from risk_prioritizer import RiskPrioritizer
                priorities = RiskPrioritizer().prioritize(findings, context_findings=findings)
            except Exception:
                priorities = []
        try:
            from risk_prioritizer import TIER_META
            self._tier_meta = TIER_META
        except Exception:
            self._tier_meta = {}
        for p in (priorities or []):
            fnd = getattr(p, "finding", None)
            if fnd is not None:
                self._prio_by_id[id(fnd)] = p

    _TIER_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

    def _tier_of(self, f):
        """Return the PriorityResult for a finding, or None."""
        return self._prio_by_id.get(id(f))

    def generate(self, output_path: str):
        """Generate complete HTML report."""
        # Compute stats
        total = len(self.findings)
        by_severity = {}
        by_category = {}
        for f in self.findings:
            sev = f["severity"]
            cat = f["category"]
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_category[cat] = by_category.get(cat, 0) + 1

        crit = by_severity.get("CRITICAL", 0)
        high = by_severity.get("HIGH", 0)
        med = by_severity.get("MEDIUM", 0)
        low = by_severity.get("LOW", 0)
        info = by_severity.get("INFO", 0)

        # Priority tier counts (P1-P4) over the displayed findings.
        tier_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for f in self.findings:
            pr = self._tier_of(f)
            if pr is not None and getattr(pr, "tier", None) in tier_counts:
                tier_counts[pr.tier] += 1
        priority_html = self._render_priority_section(tier_counts)

        # Risk score (weighted)
        risk_score = min(100, crit * 25 + high * 10 + med * 4 + low * 1)
        if risk_score >= 75:
            risk_label, risk_color = "Critical", "#dc2626"
        elif risk_score >= 50:
            risk_label, risk_color = "High", "#ea580c"
        elif risk_score >= 25:
            risk_label, risk_color = "Medium", "#d97706"
        else:
            risk_label, risk_color = "Low", "#16a34a"

        findings_html = self._render_findings()
        category_chart_data = json.dumps([
            {"name": k, "count": v} for k, v in sorted(by_category.items(), key=lambda x: -x[1])
        ])

        report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Security — Network Device Security Audit</title>
<style>
  /* Self-contained: no external font/CDN fetch, so the report renders identically
     offline / air-gapped. Preferred faces are used when installed locally, otherwise
     the stack falls back cleanly to platform system fonts. */

  :root {{
    --bg-primary: #0a0e17;
    --bg-secondary: #111827;
    --bg-card: #1a2332;
    --bg-card-hover: #1f2b3d;
    --border: #2a3548;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --accent: #10b981;
    --accent-dim: rgba(56, 189, 248, 0.1);
    --critical: #ef4444;
    --critical-bg: rgba(239, 68, 68, 0.08);
    --high: #f97316;
    --high-bg: rgba(249, 115, 22, 0.08);
    --medium: #eab308;
    --medium-bg: rgba(234, 179, 8, 0.08);
    --low: #22c55e;
    --low-bg: rgba(34, 197, 94, 0.08);
    --info-c: #10b981;
    --info-bg: rgba(56, 189, 248, 0.08);
    --font-sans: 'DM Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    --font-mono: 'JetBrains Mono', 'Cascadia Code', 'SF Mono', Menlo, Consolas, 'Fira Code', 'Liberation Mono', monospace;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    font-family: var(--font-sans);
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
  }}

  .noise {{
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");
    pointer-events: none;
    z-index: 0;
  }}

  .container {{
    max-width: 1280px;
    margin: 0 auto;
    padding: 2rem;
    position: relative;
    z-index: 1;
  }}

  /* Header */
  .header {{
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 2.5rem;
    padding-bottom: 2rem;
    border-bottom: 1px solid var(--border);
  }}

  .header-left h1 {{
    font-family: var(--font-mono);
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.02em;
    margin-bottom: 0.25rem;
  }}

  .header-left .subtitle {{
    font-size: 0.875rem;
    color: var(--text-muted);
    font-family: var(--font-mono);
  }}

  .header-right {{
    text-align: right;
    font-size: 0.8rem;
    color: var(--text-muted);
    font-family: var(--font-mono);
  }}

  .header-right span {{
    display: block;
  }}

  /* Summary Grid */
  .summary-grid {{
    display: grid;
    grid-template-columns: 280px 1fr;
    gap: 1.5rem;
    margin-bottom: 2.5rem;
  }}

  /* Risk Score */
  .risk-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 2rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    position: relative;
    overflow: hidden;
  }}

  .risk-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: {risk_color};
  }}

  .risk-score-ring {{
    width: 140px;
    height: 140px;
    position: relative;
    margin-bottom: 1rem;
  }}

  .risk-score-ring svg {{
    transform: rotate(-90deg);
    width: 140px;
    height: 140px;
  }}

  .risk-score-ring .score-text {{
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
  }}

  .risk-score-ring .score-number {{
    font-family: var(--font-mono);
    font-size: 2.5rem;
    font-weight: 700;
    color: {risk_color};
    line-height: 1;
  }}

  .risk-score-ring .score-label {{
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }}

  .risk-level {{
    font-family: var(--font-mono);
    font-size: 0.875rem;
    font-weight: 600;
    color: {risk_color};
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}

  /* Severity Cards */
  .severity-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    align-content: start;
  }}

  .sev-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.25rem;
    position: relative;
    overflow: hidden;
    transition: background 0.2s;
  }}

  .sev-card:hover {{
    background: var(--bg-card-hover);
  }}

  .sev-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
  }}

  .sev-card.critical::before {{ background: var(--critical); }}
  .sev-card.high::before {{ background: var(--high); }}
  .sev-card.medium::before {{ background: var(--medium); }}
  .sev-card.low::before {{ background: var(--low); }}

  .sev-card .sev-count {{
    font-family: var(--font-mono);
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
  }}

  .sev-card.critical .sev-count {{ color: var(--critical); }}
  .sev-card.high .sev-count {{ color: var(--high); }}
  .sev-card.medium .sev-count {{ color: var(--medium); }}
  .sev-card.low .sev-count {{ color: var(--low); }}

  .sev-card .sev-label {{
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 0.25rem;
  }}

  /* Category breakdown bar */
  .categories-section {{
    margin-bottom: 2.5rem;
  }}

  .categories-section h2 {{
    font-family: var(--font-mono);
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 1rem;
  }}

  .cat-bars {{
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }}

  .cat-bar-row {{
    display: grid;
    grid-template-columns: 220px 1fr 50px;
    align-items: center;
    gap: 1rem;
  }}

  .cat-bar-label {{
    font-size: 0.8rem;
    color: var(--text-secondary);
    font-family: var(--font-mono);
    text-align: right;
  }}

  .cat-bar-track {{
    height: 20px;
    background: var(--bg-secondary);
    border-radius: 4px;
    overflow: hidden;
  }}

  .cat-bar-fill {{
    height: 100%;
    background: linear-gradient(90deg, var(--accent), #818cf8);
    border-radius: 4px;
    min-width: 2px;
    transition: width 0.8s ease-out;
  }}

  .cat-bar-count {{
    font-family: var(--font-mono);
    font-size: 0.8rem;
    color: var(--text-muted);
  }}

  /* Filter bar */
  .filter-bar {{
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
    flex-wrap: wrap;
    align-items: center;
  }}

  .filter-bar label {{
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-right: 0.5rem;
  }}

  .filter-btn {{
    font-family: var(--font-mono);
    font-size: 0.75rem;
    padding: 0.4rem 0.8rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: transparent;
    color: var(--text-secondary);
    cursor: pointer;
    transition: all 0.2s;
  }}

  .filter-btn:hover {{
    border-color: var(--accent);
    color: var(--accent);
  }}

  .filter-btn.active {{
    background: var(--accent-dim);
    border-color: var(--accent);
    color: var(--accent);
  }}

  /* Findings */
  .findings-section h2 {{
    font-family: var(--font-mono);
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 1rem;
  }}

  .finding-card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 0.75rem;
    overflow: hidden;
    transition: background 0.2s;
  }}

  .finding-card:hover {{
    background: var(--bg-card-hover);
  }}

  .finding-header {{
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 1rem 1.25rem;
    cursor: pointer;
    user-select: none;
  }}

  .sev-badge {{
    font-family: var(--font-mono);
    font-size: 0.65rem;
    font-weight: 700;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    letter-spacing: 0.05em;
    min-width: 72px;
    text-align: center;
    flex-shrink: 0;
  }}

  .sev-badge.CRITICAL {{ background: var(--critical-bg); color: var(--critical); border: 1px solid rgba(239,68,68,0.2); }}
  .sev-badge.HIGH {{ background: var(--high-bg); color: var(--high); border: 1px solid rgba(249,115,22,0.2); }}
  .sev-badge.MEDIUM {{ background: var(--medium-bg); color: var(--medium); border: 1px solid rgba(234,179,8,0.2); }}
  .sev-badge.LOW {{ background: var(--low-bg); color: var(--low); border: 1px solid rgba(34,197,94,0.2); }}
  .sev-badge.INFO {{ background: var(--info-bg); color: var(--info-c); border: 1px solid rgba(56,189,248,0.2); }}

  /* ── Priority tiers (P1–P4) ─────────────────────────────────────────────── */
  .prio-section {{ margin: 1.5rem 0; }}
  .prio-sub {{
    font-size: 0.8rem; color: var(--text-secondary); line-height: 1.6;
    margin: -0.25rem 0 1rem;
  }}
  .prio-grid {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.9rem;
  }}
  .tier-card {{
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: 12px; padding: 1rem 1.1rem; border-top: 3px solid var(--text-muted);
  }}
  .tier-card .tier-top {{ display: flex; align-items: baseline; gap: 0.5rem; }}
  .tier-card .tier-id {{ font-size: 1.7rem; font-weight: 800; letter-spacing: -0.02em; font-family: var(--font-mono); }}
  .tier-card .tier-n {{ font-size: 1.1rem; font-weight: 700; color: var(--text-primary); }}
  .tier-card .tier-lab {{
    font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em;
    color: var(--text-secondary); font-weight: 700; margin-top: 0.35rem;
  }}
  .tier-card .tier-win {{ font-size: 0.72rem; color: var(--text-muted); margin-top: 0.15rem; }}
  .tier-card.P1 {{ border-top-color: var(--critical); }} .tier-card.P1 .tier-id {{ color: var(--critical); }}
  .tier-card.P2 {{ border-top-color: var(--high); }} .tier-card.P2 .tier-id {{ color: var(--high); }}
  .tier-card.P3 {{ border-top-color: var(--medium); }} .tier-card.P3 .tier-id {{ color: var(--medium); }}
  .tier-card.P4 {{ border-top-color: var(--low); }} .tier-card.P4 .tier-id {{ color: var(--low); }}
  @media (max-width: 720px) {{ .prio-grid {{ grid-template-columns: repeat(2, 1fr); }} }}

  /* Per-finding priority badge (tier · score) */
  .p-badge {{
    font-family: var(--font-mono); font-size: 0.68rem; font-weight: 700;
    padding: 0.25rem 0.5rem; border-radius: 4px; flex-shrink: 0; letter-spacing: 0.02em;
  }}
  .p-badge.P1 {{ background: var(--critical-bg); color: var(--critical); border: 1px solid rgba(239,68,68,0.3); }}
  .p-badge.P2 {{ background: var(--high-bg); color: var(--high); border: 1px solid rgba(249,115,22,0.3); }}
  .p-badge.P3 {{ background: var(--medium-bg); color: var(--medium); border: 1px solid rgba(234,179,8,0.3); }}
  .p-badge.P4 {{ background: var(--low-bg); color: var(--low); border: 1px solid rgba(34,197,94,0.3); }}
  /* KEV / exposure micro-tags on the priority queue */
  .p-tags {{ display: inline-flex; gap: 0.3rem; flex-wrap: wrap; }}
  .p-tag {{
    font-family: var(--font-mono); font-size: 0.6rem; font-weight: 700; text-transform: uppercase;
    padding: 0.12rem 0.35rem; border-radius: 3px; letter-spacing: 0.03em;
  }}
  .p-tag.kev {{ background: rgba(239,68,68,0.15); color: var(--critical); }}
  .p-tag.epss {{ background: rgba(129,140,248,0.15); color: #a5b4fc; }}
  .p-tag.exp {{ background: rgba(249,115,22,0.15); color: var(--high); }}
  .p-tag.rw {{ background: rgba(239,68,68,0.22); color: #fca5a5; }}

  /* "Top to fix first" queue */
  .tr-title {{
    font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.07em;
    color: var(--text-muted); font-weight: 700; margin: 1.2rem 0 0.6rem;
  }}
  .toprisks {{ display: flex; flex-direction: column; gap: 0.45rem; }}
  .tr-row {{
    display: grid; grid-template-columns: auto auto 1fr auto; gap: 0.8rem; align-items: center;
    background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 0.6rem 0.9rem;
  }}
  .tr-rank {{ font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted); font-weight: 700; min-width: 1.1rem; text-align: center; }}
  .tr-name {{ font-size: 0.85rem; font-weight: 600; color: var(--text-primary); }}
  .tr-why {{ font-size: 0.72rem; color: var(--text-secondary); margin-top: 0.2rem; line-height: 1.5; }}
  @media (max-width: 720px) {{
    .tr-row {{ grid-template-columns: auto 1fr; }}
    .tr-score, .p-tags {{ grid-column: 2; }}
  }}

  .finding-title {{
    font-size: 0.875rem;
    font-weight: 600;
    color: var(--text-primary);
    flex: 1;
  }}

  .finding-id {{
    font-family: var(--font-mono);
    font-size: 0.7rem;
    color: var(--text-muted);
    flex-shrink: 0;
  }}

  .finding-chevron {{
    font-size: 0.75rem;
    color: var(--text-muted);
    transition: transform 0.2s;
  }}

  .finding-card.open .finding-chevron {{
    transform: rotate(90deg);
  }}

  .finding-body {{
    display: none;
    padding: 0 1.25rem 1.25rem;
    border-top: 1px solid var(--border);
  }}

  .finding-card.open .finding-body {{
    display: block;
  }}

  .finding-section {{
    margin-top: 1rem;
  }}

  .finding-section-title {{
    font-family: var(--font-mono);
    font-size: 0.7rem;
    font-weight: 600;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 0.4rem;
  }}

  .finding-section p {{
    font-size: 0.825rem;
    color: var(--text-secondary);
    line-height: 1.7;
  }}

  .affected-list {{
    list-style: none;
    padding: 0;
    margin: 0;
    background: var(--bg-primary);
    border-radius: 6px;
    padding: 0.75rem 1rem;
    max-height: 200px;
    overflow-y: auto;
  }}

  .affected-list li {{
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--text-secondary);
    padding: 0.2rem 0;
    border-bottom: 1px solid rgba(42, 53, 72, 0.5);
  }}

  .affected-list li:last-child {{ border: none; }}

  .ref-list {{
    list-style: none;
    padding: 0;
  }}

  .ref-list li {{
    font-size: 0.8rem;
    color: var(--accent);
    padding: 0.15rem 0;
  }}

  .ref-list li::before {{
    content: '→ ';
    color: var(--text-muted);
  }}

  .remediation-text {{
    background: rgba(34, 197, 94, 0.05);
    border-left: 3px solid var(--low);
    padding: 0.75rem 1rem;
    border-radius: 0 6px 6px 0;
    font-size: 0.825rem;
    color: var(--text-secondary);
    line-height: 1.7;
  }}

  /* Detailed observation prose */
  .observation-text {{
    font-size: 0.825rem;
    color: var(--text-secondary);
    line-height: 1.75;
  }}
  .observation-text p {{ margin: 0 0 0.65rem; }}
  .observation-text p:last-child {{ margin-bottom: 0; }}

  /* Step-by-step remediation */
  .step-list {{
    margin: 0;
    padding-left: 1.35rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }}
  .step-list li {{
    font-size: 0.825rem;
    color: var(--text-secondary);
    line-height: 1.65;
    padding-left: 0.25rem;
  }}
  .step-list li::marker {{
    color: var(--accent);
    font-family: var(--font-mono);
    font-weight: 600;
  }}

  /* CLI / verify code blocks */
  .code-block {{
    background: #05070d;
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 6px;
    padding: 0.8rem 1rem;
    margin: 0;
    overflow-x: auto;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    line-height: 1.6;
    color: #cfe3ff;
    white-space: pre;
    tab-size: 2;
  }}
  .verify-block {{
    border-left-color: #818cf8;
    color: #d7dcff;
  }}
  .finding-section code {{
    font-family: var(--font-mono);
    font-size: 0.78em;
    background: rgba(129, 140, 248, 0.12);
    padding: 0.05rem 0.3rem;
    border-radius: 3px;
    color: #cfe3ff;
  }}

  /* Rollback / impact callouts */
  .callout {{
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.65rem;
    align-items: start;
    font-size: 0.8rem;
    color: var(--text-secondary);
    line-height: 1.65;
    background: var(--bg-primary);
    border-radius: 6px;
    padding: 0.6rem 0.85rem;
  }}
  .callout .callout-label {{
    font-family: var(--font-mono);
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-muted);
    white-space: nowrap;
    padding-top: 0.1rem;
  }}
  .callout.impact {{ border-left: 3px solid var(--medium); }}
  .callout.rollback {{ border-left: 3px solid var(--text-muted); }}

  /* Footer */
  .footer {{
    margin-top: 3rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    text-align: center;
    font-family: var(--font-mono);
    font-size: 0.7rem;
    color: var(--text-muted);
  }}

  /* Responsive */
  @media (max-width: 900px) {{
    .summary-grid {{ grid-template-columns: 1fr; }}
    .severity-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .cat-bar-row {{ grid-template-columns: 140px 1fr 40px; }}
  }}

  /* Print */
  @media print {{
    body {{ background: white; color: #111; }}
    .finding-body {{ display: block !important; }}
    .noise {{ display: none; }}
  }}
</style>
</head>
<body>
<div class="noise"></div>
<div class="container">

  <div class="header">
    <div class="header-left">
      <h1>&#x1f6e1; Network Security</h1>
      <div class="subtitle">Network Device Security Audit</div>
    </div>
    <div class="header-right">
      <span>Scan: {html.escape(self.meta.get('scan_time', 'N/A')[:19])}</span>
      <span>Source: {html.escape(self.meta.get('data_directory', 'N/A'))}</span>
      <span>Modules: {html.escape(', '.join(self.meta.get('modules_run', [])))}</span>
    </div>
  </div>

  <!-- Summary Grid -->
  <div class="summary-grid">
    <div class="risk-card">
      <div class="risk-score-ring">
        <svg viewBox="0 0 140 140">
          <circle cx="70" cy="70" r="60" fill="none" stroke="#1e293b" stroke-width="10"/>
          <circle cx="70" cy="70" r="60" fill="none" stroke="{risk_color}" stroke-width="10"
            stroke-dasharray="{risk_score * 3.77} {377 - risk_score * 3.77}"
            stroke-linecap="round"/>
        </svg>
        <div class="score-text">
          <div class="score-number">{risk_score}</div>
          <div class="score-label">Risk Score</div>
        </div>
      </div>
      <div class="risk-level">{risk_label} Risk</div>
    </div>

    <div class="severity-grid">
      <div class="sev-card critical">
        <div class="sev-count">{crit}</div>
        <div class="sev-label">Critical</div>
      </div>
      <div class="sev-card high">
        <div class="sev-count">{high}</div>
        <div class="sev-label">High</div>
      </div>
      <div class="sev-card medium">
        <div class="sev-count">{med}</div>
        <div class="sev-label">Medium</div>
      </div>
      <div class="sev-card low">
        <div class="sev-count">{low}</div>
        <div class="sev-label">Low</div>
      </div>
    </div>
  </div>

  <!-- Priority Tiers (P1-P4) -->
  {priority_html}

  <!-- Category Breakdown -->
  <div class="categories-section">
    <h2>Findings by Category</h2>
    <div class="cat-bars">
      {self._render_category_bars(by_category, total)}
    </div>
  </div>

  <!-- Filter Bar -->
  <div class="filter-bar">
    <label>Priority:</label>
    <button class="filter-btn active" onclick="filterFindings('ALL')">All ({total})</button>
    <button class="filter-btn" onclick="filterFindings('P1')">P1 &middot; Fix Now ({tier_counts['P1']})</button>
    <button class="filter-btn" onclick="filterFindings('P2')">P2 &middot; This Week ({tier_counts['P2']})</button>
    <button class="filter-btn" onclick="filterFindings('P3')">P3 &middot; Planned ({tier_counts['P3']})</button>
    <button class="filter-btn" onclick="filterFindings('P4')">P4 &middot; Backlog ({tier_counts['P4']})</button>
    <label style="margin-left:0.75rem">Severity:</label>
    <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical ({crit})</button>
    <button class="filter-btn" onclick="filterFindings('HIGH')">High ({high})</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium ({med})</button>
    <button class="filter-btn" onclick="filterFindings('LOW')">Low ({low})</button>
  </div>

  <!-- Findings -->
  <div class="findings-section">
    <h2>Detailed Findings ({total})</h2>
    {findings_html}
  </div>

  <div class="footer">
    Network Security Security Scanner &middot; Generated {html.escape(self.meta.get('scan_time', '')[:19])} &middot;
    For authorized security assessments only
  </div>
</div>

<script>
// Toggle finding details
document.querySelectorAll('.finding-header').forEach(el => {{
  el.addEventListener('click', () => {{
    el.parentElement.classList.toggle('open');
  }});
}});

// Filter by priority tier (P1-P4) or severity — tiers and severities are distinct
// tokens, so one function matches either the card's data-tier or data-severity.
function filterFindings(key) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding-card').forEach(card => {{
    const show = (key === 'ALL' || card.dataset.tier === key || card.dataset.severity === key);
    card.style.display = show ? '' : 'none';
  }});
}}

// Expand all for print
window.addEventListener('beforeprint', () => {{
  document.querySelectorAll('.finding-card').forEach(c => c.classList.add('open'));
}});
</script>
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)

    # ── rich-text helpers ────────────────────────────────────────────────────

    @staticmethod
    def _inline(text: str) -> str:
        """Escape, then render `backtick` spans as inline <code>."""
        import re
        out, last = [], 0
        for m in re.finditer(r"`([^`]+)`", str(text)):
            out.append(html.escape(text[last:m.start()]))
            out.append(f"<code>{html.escape(m.group(1))}</code>")
            last = m.end()
        out.append(html.escape(str(text)[last:]))
        return "".join(out)

    def _prose(self, text: str) -> str:
        """Multi-paragraph prose: split on blank lines (or single newlines) into <p>."""
        text = str(text or "").strip()
        if not text:
            return ""
        blocks = [b.strip() for b in text.split("\n\n") if b.strip()]
        if len(blocks) <= 1:
            blocks = [b.strip() for b in text.split("\n") if b.strip()] or [text]
        return "".join(f"<p>{self._inline(b)}</p>" for b in blocks)

    def _section(self, title: str, inner: str) -> str:
        if not inner:
            return ""
        return (f'<div class="finding-section"><div class="finding-section-title">'
                f'{html.escape(title)}</div>{inner}</div>')

    def _prio_tags(self, pr) -> str:
        """KEV / EPSS / exposure micro-tags for a PriorityResult."""
        tags = []
        if getattr(pr, "kev", False):
            kd = getattr(pr, "kev_date", None)
            tags.append(f'<span class="p-tag kev">KEV{(" " + html.escape(str(kd))) if kd else ""}</span>')
        if getattr(pr, "ransomware", False):
            tags.append('<span class="p-tag rw">Ransomware</span>')
        epss = getattr(pr, "epss", None)
        if epss is not None and epss >= 0.10:
            tags.append(f'<span class="p-tag epss">EPSS {epss * 100:.0f}%</span>')
        if getattr(pr, "reachable", False):
            tags.append('<span class="p-tag exp">Exposed</span>')
        return "".join(tags)

    def _render_priority_section(self, tier_counts) -> str:
        """P1-P4 tier summary cards + a 'top to fix first' queue (P1/P2 by score)."""
        if not self._prio_by_id or not self._tier_meta:
            return ""
        sub = ("Findings ranked by severity &times; real-world exploitability (CISA KEV + FIRST.org "
               "EPSS) &times; on-device config reachability. Work the queue top-down: P1 first.")
        cards = []
        for t in ("P1", "P2", "P3", "P4"):
            m = self._tier_meta.get(t, {})
            cards.append(
                f'<div class="tier-card {t}"><div class="tier-top">'
                f'<span class="tier-id">{t}</span><span class="tier-n">{tier_counts.get(t, 0)}</span></div>'
                f'<div class="tier-lab">{html.escape(m.get("label", ""))}</div>'
                f'<div class="tier-win">{html.escape(m.get("window", ""))}</div></div>')

        ranked = []
        for f in self.findings:
            pr = self._tier_of(f)
            if pr is not None:
                ranked.append((f, pr))
        ranked.sort(key=lambda x: (self._TIER_RANK.get(x[1].tier, 9), -getattr(x[1], "score", 0)))
        top = [(f, pr) for f, pr in ranked if pr.tier in ("P1", "P2")][:10]
        top_html = ""
        if top:
            rows = []
            for i, (f, pr) in enumerate(top, 1):
                dev = (f'<span class="finding-id">{html.escape(str(f.get("device", "")))}</span>'
                       if f.get("device") else "")
                rows.append(
                    f'<div class="tr-row"><div class="tr-rank">{i}</div>'
                    f'<div class="tr-score"><span class="p-badge {pr.tier}">{pr.tier} &middot; '
                    f'{getattr(pr, "score", 0)}</span></div>'
                    f'<div class="tr-main"><span class="tr-name">{html.escape(f.get("title", ""))}</span> '
                    f'<span class="finding-id">{html.escape(f.get("check_id", ""))}</span> {dev}'
                    f'<div class="tr-why">{html.escape(getattr(pr, "rationale", "") or "")}</div></div>'
                    f'<div class="p-tags">{self._prio_tags(pr)}</div></div>')
            top_html = (f'<div class="tr-title">Top {len(top)} to fix first</div>'
                        f'<div class="toprisks">{"".join(rows)}</div>')
        return (f'<div class="prio-section"><h2>Risk-Prioritized Remediation Queue</h2>'
                f'<div class="prio-sub">{sub}</div>'
                f'<div class="prio-grid">{"".join(cards)}</div>{top_html}</div>')

    def _render_findings(self) -> str:
        """Render all findings as HTML cards, enriched from the remediation KB
        (detailed observation, step-by-step remediation, CLI, verify, rollback,
        operational impact) with graceful fallback to the finding's own fields."""
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        def _sortkey(f):
            pr = self._tier_of(f)
            trank = self._TIER_RANK.get(getattr(pr, "tier", None), 9) if pr is not None else 9
            score = -getattr(pr, "score", 0) if pr is not None else 0
            return (trank, order.get(f.get("severity"), 4), score)
        # Fix-first order: P1 -> P4, then by severity, then by score within tier.
        sorted_findings = sorted(self.findings, key=_sortkey)

        parts = []
        for f in sorted_findings:
            detail = {}
            if self._kb is not None:
                try:
                    detail = self._kb.detail_for(f) or {}
                except Exception:
                    detail = {}
            detailed = bool(detail.get("_detailed"))

            # ── Observation (long-form; KB 'risk' else the finding description) ──
            observation = detail.get("risk") or f.get("description", "")
            obs_html = self._section(
                "Observation",
                f'<div class="observation-text">{self._prose(observation)}</div>')

            # ── Affected items ──
            affected_html = ""
            if f.get("affected_items"):
                items = "".join(f"<li>{html.escape(str(i))}</li>"
                                for i in f["affected_items"][:50])
                if len(f["affected_items"]) > 50:
                    items += f"<li>... and {len(f['affected_items']) - 50} more</li>"
                affected_html = self._section(
                    f"Affected configuration ({f.get('affected_count', len(f['affected_items']))})",
                    f'<ul class="affected-list">{items}</ul>')

            # ── Remediation: step-by-step (KB) else the short remediation string ──
            steps = detail.get("steps") if detailed else None
            if steps:
                li = "".join(f"<li>{self._inline(s)}</li>" for s in steps if str(s).strip())
                remediation_html = self._section(
                    "Remediation — step by step", f'<ol class="step-list">{li}</ol>')
            else:
                rem = f.get("remediation") or detail.get("steps")
                rem_txt = rem[0] if isinstance(rem, list) and rem else (rem if isinstance(rem, str) else "")
                remediation_html = self._section(
                    "Remediation",
                    f'<div class="remediation-text">{self._inline(rem_txt)}</div>' if rem_txt else "")

            # ── CLI / verify / rollback / impact ──
            cli = detail.get("cli") if detailed else ""
            cli_html = self._section(
                "Configuration commands",
                f'<pre class="code-block">{html.escape(str(cli))}</pre>' if cli else "")
            verify = detail.get("verify") if detailed else ""
            verify_html = self._section(
                "Verification",
                f'<pre class="code-block verify-block">{html.escape(str(verify))}</pre>' if verify else "")
            impact = detail.get("impact") if detailed else ""
            impact_html = ""
            if impact:
                impact_html = (f'<div class="finding-section"><div class="callout impact">'
                               f'<span class="callout-label">Operational impact</span>'
                               f'<span>{self._inline(impact)}</span></div></div>')
            rollback = detail.get("rollback") if detailed else ""
            rollback_html = ""
            if rollback:
                rollback_html = (f'<div class="finding-section"><div class="callout rollback">'
                                 f'<span class="callout-label">Rollback</span>'
                                 f'<span>{self._inline(rollback)}</span></div></div>')

            # ── References (merge KB + finding, de-duped, order-preserving) ──
            refs = []
            for r in (f.get("references") or []):
                if r and r not in refs:
                    refs.append(r)
            for r in (detail.get("references") or []):
                if r and r not in refs:
                    refs.append(r)
            refs_html = ""
            if refs:
                ref_items = "".join(f"<li>{html.escape(str(r))}</li>" for r in refs)
                refs_html = self._section("References", f'<ul class="ref-list">{ref_items}</ul>')

            device_tag = ""
            if f.get("device"):
                device_tag = f'<span class="finding-id">{html.escape(str(f["device"]))}</span>'

            pr = self._tier_of(f)
            p_badge, data_tier = "", ""
            if pr is not None and getattr(pr, "tier", None):
                p_badge = (f'<span class="p-badge {pr.tier}" title="{html.escape(getattr(pr, "rationale", "") or "")}">'
                           f'{pr.tier} &middot; {getattr(pr, "score", 0)}</span>')
                data_tier = f' data-tier="{html.escape(pr.tier)}"'

            parts.append(f"""
    <div class="finding-card" data-severity="{html.escape(f['severity'])}" data-category="{html.escape(f['category'])}"{data_tier}>
      <div class="finding-header">
        <span class="sev-badge {html.escape(f['severity'])}">{html.escape(f['severity'])}</span>
        {p_badge}
        <span class="finding-title">{html.escape(f['title'])}</span>
        {device_tag}
        <span class="finding-id">{html.escape(f['check_id'])}</span>
        <span class="finding-chevron">&#9654;</span>
      </div>
      <div class="finding-body">
        {obs_html}
        {affected_html}
        {remediation_html}
        {cli_html}
        {verify_html}
        {impact_html}
        {rollback_html}
        {refs_html}
      </div>
    </div>""")

        return "\n".join(parts) if parts else '<p style="color: var(--text-muted); text-align: center; padding: 2rem;">No findings to display.</p>'

    def _render_category_bars(self, by_category: Dict[str, int], total: int) -> str:
        """Render horizontal bar chart for categories."""
        if not by_category or total == 0:
            return ""

        max_count = max(by_category.values())
        rows = []
        for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
            pct = (count / max_count) * 100 if max_count > 0 else 0
            rows.append(f"""
      <div class="cat-bar-row">
        <div class="cat-bar-label">{html.escape(cat)}</div>
        <div class="cat-bar-track"><div class="cat-bar-fill" style="width: {pct}%"></div></div>
        <div class="cat-bar-count">{count}</div>
      </div>""")
        return "\n".join(rows)
