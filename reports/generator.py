"""
VulnScan Reports - HTML and JSON report generation
"""
import json
import os
from datetime import datetime
from typing import List
try:
    from ..scanner.core import ScanResult
except ImportError:
    from scanner.core import ScanResult


SEVERITY_COLOR = {
    "critical": "#ff2d55",
    "high":     "#ff6b35",
    "medium":   "#ffd60a",
    "low":      "#30d158",
    "info":     "#636366",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLOR.get(severity, "#636366")
    return f'<span class="badge" style="background:{color}">{severity.upper()}</span>'


def generate_html_report(results: List[ScanResult], output_path: str) -> str:
    """Generate a dark-themed HTML report for one or more scan results."""

    total_vulns = sum(len(r.vulnerabilities) for r in results)
    total_open  = sum(len(r.open_ports) for r in results)
    highest_risk = max((r.risk_score for r in results), default=0)

    # Count by severity across all results
    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        for v in r.vulnerabilities:
            sev_counts[v.get("severity", "info")] += 1

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Build target cards ──────────────────────────────────────────────────
    target_cards_html = ""
    for r in results:
        port_rows = ""
        for p in sorted(r.ports, key=lambda x: x.port):
            if p.state != "open":
                continue
            banner_cell = f'<code class="banner">{p.banner[:80]}</code>' if p.banner else "—"
            port_rows += f"""
            <tr>
              <td>{p.port}</td>
              <td><span class="svc">{p.service}</span></td>
              <td><span class="state-open">OPEN</span></td>
              <td>{p.latency_ms} ms</td>
              <td>{banner_cell}</td>
            </tr>"""

        vuln_rows = ""
        sorted_vulns = sorted(r.vulnerabilities,
                              key=lambda v: SEVERITY_ORDER.index(v.get("severity", "info")))
        for v in sorted_vulns:
            vuln_rows += f"""
            <tr>
              <td>{_severity_badge(v['severity'])}</td>
              <td><strong>{v['title']}</strong><br>
                  <small style="color:#8e8e93">{v['description']}</small></td>
              <td>Port {v.get('port','—')}</td>
              <td><small>{v['remediation']}</small></td>
            </tr>"""

        risk_color = "#ff2d55" if r.risk_score >= 70 else "#ff6b35" if r.risk_score >= 40 else "#ffd60a" if r.risk_score >= 15 else "#30d158"

        target_cards_html += f"""
        <section class="target-card">
          <div class="target-header">
            <div>
              <h2 class="target-title">{r.target}</h2>
              <p class="target-meta">IP: {r.ip} &nbsp;·&nbsp; Scanned: {r.scan_start.strftime('%H:%M:%S')} &nbsp;·&nbsp; Duration: {r.duration_seconds:.1f}s</p>
            </div>
            <div class="risk-badge" style="border-color:{risk_color};color:{risk_color}">
              <span class="risk-label">RISK</span>
              <span class="risk-num">{r.risk_score}</span>
            </div>
          </div>

          <h3 class="section-heading">Open Ports ({len(r.open_ports)})</h3>
          {"<p class='empty-note'>No open ports detected.</p>" if not r.open_ports else f'''
          <div class="table-wrap">
          <table>
            <thead><tr><th>Port</th><th>Service</th><th>State</th><th>Latency</th><th>Banner</th></tr></thead>
            <tbody>{port_rows}</tbody>
          </table>
          </div>'''}

          <h3 class="section-heading">Vulnerabilities ({len(r.vulnerabilities)})</h3>
          {"<p class='empty-note'>No vulnerabilities detected.</p>" if not r.vulnerabilities else f'''
          <div class="table-wrap">
          <table>
            <thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Remediation</th></tr></thead>
            <tbody>{vuln_rows}</tbody>
          </table>
          </div>'''}
        </section>"""

    # ── Severity bar chart (pure CSS) ───────────────────────────────────────
    max_count = max(sev_counts.values(), default=1) or 1
    bar_chart_html = '<div class="bar-chart">'
    for sev in SEVERITY_ORDER:
        cnt = sev_counts[sev]
        pct = int((cnt / max_count) * 100)
        color = SEVERITY_COLOR[sev]
        bar_chart_html += f"""
        <div class="bar-row">
          <span class="bar-label">{sev.upper()}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%;background:{color}"></div>
          </div>
          <span class="bar-count" style="color:{color}">{cnt}</span>
        </div>"""
    bar_chart_html += "</div>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnScan Report — {now}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');

  :root {{
    --bg: #0a0a0f;
    --surface: #13131a;
    --border: #2c2c3a;
    --text: #e5e5ea;
    --muted: #636366;
    --accent: #7b5ef8;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'Syne', sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 0 0 80px;
  }}

  /* ── Header ── */
  .report-header {{
    background: linear-gradient(135deg, #0d0d1a 0%, #13102b 100%);
    border-bottom: 1px solid var(--border);
    padding: 48px 60px 40px;
    position: relative;
    overflow: hidden;
  }}
  .report-header::before {{
    content: '';
    position: absolute; inset: 0;
    background: radial-gradient(ellipse 60% 80% at 80% 50%, rgba(123,94,248,.12) 0%, transparent 70%);
    pointer-events: none;
  }}
  .logo {{ font-size: 11px; letter-spacing: .3em; color: var(--accent); text-transform: uppercase; margin-bottom: 12px; }}
  h1 {{ font-size: clamp(28px, 4vw, 42px); font-weight: 800; }}
  .report-ts {{ color: var(--muted); font-size: 13px; margin-top: 6px; font-family: 'JetBrains Mono', monospace; }}

  /* ── Stats bar ── */
  .stats-bar {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1px;
    background: var(--border);
    border-bottom: 1px solid var(--border);
  }}
  .stat {{
    background: var(--surface);
    padding: 28px 32px;
    display: flex; flex-direction: column; gap: 6px;
  }}
  .stat-label {{ font-size: 11px; letter-spacing: .15em; color: var(--muted); text-transform: uppercase; }}
  .stat-value {{ font-size: 36px; font-weight: 800; line-height: 1; }}

  /* ── Layout ── */
  .container {{ max-width: 1200px; margin: 0 auto; padding: 0 40px; }}

  /* ── Summary section ── */
  .summary-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
    margin: 40px 0;
  }}
  @media(max-width:700px){{ .summary-grid{{ grid-template-columns:1fr; }} }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 28px 32px;
  }}
  .card-title {{ font-size: 11px; letter-spacing: .2em; color: var(--muted); text-transform: uppercase; margin-bottom: 20px; }}

  /* ── Bar chart ── */
  .bar-chart {{ display: flex; flex-direction: column; gap: 12px; }}
  .bar-row {{ display: flex; align-items: center; gap: 12px; }}
  .bar-label {{ font-size: 11px; letter-spacing: .12em; color: var(--muted); width: 64px; text-align: right; }}
  .bar-track {{ flex: 1; height: 8px; background: rgba(255,255,255,.05); border-radius: 4px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 4px; transition: width .6s ease; }}
  .bar-count {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; font-weight: 700; width: 28px; }}

  /* ── Target cards ── */
  .target-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 32px 36px;
    margin: 24px 0;
  }}
  .target-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 28px; gap: 20px; }}
  .target-title {{ font-size: 22px; font-weight: 700; }}
  .target-meta {{ color: var(--muted); font-size: 12px; margin-top: 5px; font-family: 'JetBrains Mono', monospace; }}

  .risk-badge {{
    border: 2px solid;
    border-radius: 10px;
    padding: 10px 18px;
    text-align: center;
    min-width: 80px;
    flex-shrink: 0;
  }}
  .risk-label {{ display: block; font-size: 9px; letter-spacing: .25em; opacity: .7; }}
  .risk-num {{ display: block; font-size: 28px; font-weight: 800; line-height: 1.1; }}

  .section-heading {{
    font-size: 11px; letter-spacing: .2em; text-transform: uppercase;
    color: var(--muted); margin: 24px 0 12px;
    padding-bottom: 8px; border-bottom: 1px solid var(--border);
  }}

  /* ── Tables ── */
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  thead tr {{ border-bottom: 1px solid var(--border); }}
  th {{ padding: 10px 14px; text-align: left; font-size: 10px; letter-spacing: .15em; color: var(--muted); text-transform: uppercase; }}
  td {{ padding: 12px 14px; border-bottom: 1px solid rgba(255,255,255,.03); vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,.02); }}

  .state-open {{ color: #30d158; font-family: 'JetBrains Mono', monospace; font-size: 11px; letter-spacing: .1em; }}
  .svc {{ font-family: 'JetBrains Mono', monospace; color: var(--accent); }}
  .banner {{ font-size: 11px; color: var(--muted); word-break: break-all; }}

  .badge {{
    display: inline-block; padding: 3px 9px; border-radius: 4px;
    font-size: 10px; font-weight: 700; letter-spacing: .08em; color: #fff;
  }}
  .empty-note {{ color: var(--muted); font-size: 13px; padding: 12px 0; }}

  .footer {{ text-align: center; color: var(--muted); font-size: 11px; margin-top: 60px; letter-spacing: .1em; }}
</style>
</head>
<body>

<header class="report-header">
  <p class="logo">Vulnerability Scanner</p>
  <h1>Security Scan Report</h1>
  <p class="report-ts">Generated: {now}</p>
</header>

<div class="stats-bar">
  <div class="stat">
    <span class="stat-label">Targets Scanned</span>
    <span class="stat-value" style="color:#7b5ef8">{len(results)}</span>
  </div>
  <div class="stat">
    <span class="stat-label">Open Ports</span>
    <span class="stat-value" style="color:#0a84ff">{total_open}</span>
  </div>
  <div class="stat">
    <span class="stat-label">Vulnerabilities</span>
    <span class="stat-value" style="color:#ff6b35">{total_vulns}</span>
  </div>
  <div class="stat">
    <span class="stat-label">Highest Risk Score</span>
    <span class="stat-value" style="color:#ff2d55">{highest_risk}</span>
  </div>
  <div class="stat">
    <span class="stat-label">Critical Findings</span>
    <span class="stat-value" style="color:#ff2d55">{sev_counts['critical']}</span>
  </div>
</div>

<div class="container">

  <div class="summary-grid">
    <div class="card">
      <p class="card-title">Findings by Severity</p>
      {bar_chart_html}
    </div>
    <div class="card">
      <p class="card-title">Scan Summary</p>
      <table>
        <tbody>
          {''.join(f"<tr><td style='color:var(--muted);font-size:12px'>{r.target}</td><td style='font-family:JetBrains Mono,monospace;font-size:12px'>{r.ip}</td><td style='font-family:JetBrains Mono,monospace;font-size:12px;color:{'#ff2d55' if r.risk_score>=70 else '#ff6b35' if r.risk_score>=40 else '#ffd60a' if r.risk_score>=15 else '#30d158'}'>Risk: {r.risk_score}</td></tr>" for r in results)}
        </tbody>
      </table>
    </div>
  </div>

  <h2 style="font-size:14px;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);margin:40px 0 0">Detailed Results</h2>
  {target_cards_html}

</div>

<p class="footer">VulnScan &nbsp;·&nbsp; By <a href="https://github.com/Ravirazchauhan" style="color:var(--accent);text-decoration:none">RAVI CHAUHAN</a> &nbsp;·&nbsp; For authorised testing only &nbsp;·&nbsp; {now}</p>
</body>
</html>"""

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


def generate_json_report(results: List[ScanResult], output_path: str) -> str:
    """Export results as structured JSON."""
    data = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "targets": len(results),
            "total_open_ports": sum(len(r.open_ports) for r in results),
            "total_vulnerabilities": sum(len(r.vulnerabilities) for r in results),
        },
        "results": [
            {
                "target": r.target,
                "ip": r.ip,
                "scan_start": r.scan_start.isoformat(),
                "scan_end": r.scan_end.isoformat() if r.scan_end else None,
                "duration_seconds": r.duration_seconds,
                "risk_score": r.risk_score,
                "open_ports": [
                    {"port": p.port, "service": p.service, "latency_ms": p.latency_ms, "banner": p.banner}
                    for p in r.open_ports
                ],
                "vulnerabilities": r.vulnerabilities,
            }
            for r in results
        ],
    }
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return output_path
