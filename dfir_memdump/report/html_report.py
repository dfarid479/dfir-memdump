"""
HTML Triage Report Generator.

Produces a self-contained, single-file HTML report with:
  - Print/save button
  - Color-coded severity badges
  - Process risk leaderboard
  - ASCII process tree
  - Chronological event timeline (flagged events highlighted at top)
  - Full findings with per-finding explanations
  - IOC table with copy-to-clipboard
  - MITRE ATT&CK technique coverage
  - "About this data" collapsible on every section explaining each data point

No external dependencies — all CSS and JS are inline.
"""

from __future__ import annotations
import html as _html
import logging
from pathlib import Path

from dfir_memdump.models import Severity, TriageReport
from dfir_memdump.report.markdown_report import (
    _build_process_tree,
    _build_timeline,
    _parse_vol_time,
)

logger = logging.getLogger(__name__)

# ── Severity styling ──────────────────────────────────────────────────────────
_SEV_COLOR = {
    "CRITICAL": ("#ff4d4d", "#2a0a0a"),
    "HIGH":     ("#ff9933", "#2a1800"),
    "MEDIUM":   ("#f0c040", "#2a2000"),
    "LOW":      ("#4caf50", "#0a1f0a"),
    "INFO":     ("#9e9e9e", "#1a1a1a"),
}
_SEV_ICON = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪",
}

_MITRE_BASE = "https://attack.mitre.org/techniques/"


def write_html_report(report: TriageReport, path: Path) -> Path:
    content = _render(report)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    logger.info("HTML report written to %s", path)
    return path


def _e(s: object) -> str:
    """HTML-escape a value."""
    return _html.escape(str(s))


def _render(report: TriageReport) -> str:
    m        = report.metadata
    findings = report.findings_by_severity()

    # Pre-compute sets for the timeline
    suspicious_pids: set[int] = {f.affected_pid for f in findings if f.affected_pid is not None}

    # Build timeline events
    timeline_all: list[tuple[object, str, str, str, bool]] = []  # (dt, ts_str, label, detail, flagged)
    pid_finding_map: dict[int, list[str]] = {}
    for f in findings:
        if f.affected_pid:
            pid_finding_map.setdefault(f.affected_pid, []).append(f.title)

    for proc in report.processes:
        if not proc.create_time:
            continue
        dt = _parse_vol_time(proc.create_time)
        if dt is None:
            continue
        flagged = proc.pid in suspicious_pids
        ftitles = pid_finding_map.get(proc.pid, [])
        detail = proc.cmdline.strip()[:100] if proc.cmdline else ""
        label = f"PROCESS START &nbsp; PID {proc.pid} &nbsp; <strong>{_e(proc.name)}</strong>"
        if ftitles:
            label += f" &nbsp; <span class='flag-tag'>⚠ {_e(ftitles[0][:50])}</span>"
        timeline_all.append((dt, dt.strftime("%Y-%m-%d %H:%M:%S"), label, _e(detail), flagged))

    for conn in report.connections:
        if not conn.created_time:
            continue
        dt = _parse_vol_time(conn.created_time)
        if dt is None:
            continue
        flagged = conn.pid in suspicious_pids
        label = (
            f"NET &nbsp; <code>{_e(conn.proto)}</code> &nbsp;"
            f"{_e(conn.local_addr)}:{conn.local_port} → "
            f"<strong>{_e(conn.foreign_addr)}:{conn.foreign_port}</strong>"
        )
        if flagged:
            label += " &nbsp; <span class='flag-tag'>⚠ flagged process</span>"
        timeline_all.append((dt, dt.strftime("%Y-%m-%d %H:%M:%S"),
                              label, _e(conn.process_name or ""), flagged))

    timeline_all.sort(key=lambda e: e[0])
    flagged_events   = [(ts, lbl, det) for _, ts, lbl, det, fl in timeline_all if fl]
    all_events_rows  = timeline_all

    # Process tree (reuse markdown renderer, strip markdown code fences)
    tree_lines = _build_process_tree(report)
    tree_text  = "\n".join(
        ln for ln in tree_lines
        if ln not in ("```text", "```", "") and not ln.startswith("_[!]")
    )

    # Risk leaderboard
    top_risks = report.process_risk_scores[:15]

    # MITRE techniques
    mitre_techs = []
    seen_t = set()
    for f in findings:
        if f.mitre and f.mitre.technique_id not in seen_t:
            seen_t.add(f.mitre.technique_id)
            mitre_techs.append(f.mitre)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Memory Forensics Triage Report — {_e(Path(m.image_path).name)}</title>
<style>
{_CSS}
</style>
</head>
<body>

<!-- ══════════════════ HEADER ══════════════════ -->
<div class="report-header">
  <div class="header-left">
    <div class="report-title">Memory Forensics Triage Report</div>
    <div class="report-subtitle">dfir-memdump {_e(m.tool_version)} &nbsp;|&nbsp; {_e(m.analysis_start[:19])} UTC</div>
  </div>
  <div class="header-right">
    <button class="print-btn" onclick="window.print()">🖨&nbsp; Print / Save PDF</button>
  </div>
</div>

<!-- ══════════════════ CASE METADATA ══════════════════ -->
<section class="section">
  <div class="meta-grid">
    <div class="meta-item"><span class="meta-label">Image</span><span class="meta-value">{_e(m.image_path)}</span></div>
    <div class="meta-item"><span class="meta-label">Size</span><span class="meta-value">{m.image_size_mb:.1f} MB</span></div>
    <div class="meta-item"><span class="meta-label">MD5</span><span class="meta-value">{_e(m.image_md5 or 'not computed')}</span></div>
    <div class="meta-item"><span class="meta-label">SHA256</span><span class="meta-value">{_e(m.image_sha256 or 'not computed')}</span></div>
    <div class="meta-item"><span class="meta-label">Analysis Start</span><span class="meta-value">{_e(m.analysis_start)}</span></div>
    <div class="meta-item"><span class="meta-label">Analysis End</span><span class="meta-value">{_e(m.analysis_end)}</span></div>
    {f'<div class="meta-item"><span class="meta-label">Profile</span><span class="meta-value">{_e(m.profile)}</span></div>' if m.profile else ''}
    {f'<div class="meta-item"><span class="meta-label">OS</span><span class="meta-value">{_e(m.os_info)}</span></div>' if m.os_info else ''}
  </div>
</section>

<!-- ══════════════════ EXECUTIVE SUMMARY ══════════════════ -->
<section class="section">
  <h2>Executive Summary</h2>
  <details class="about"><summary>ℹ What is this?</summary>
    <p>A plain-language narrative summarising the most important findings from this memory image.
    It is automatically generated from the intelligence findings and is intended to be the first
    thing an incident responder reads. CRITICAL items indicate confirmed malicious activity
    requiring immediate escalation.</p>
  </details>
  <div class="exec-box">
    {'<br>'.join(_e(ln) for ln in (report.executive_summary or 'No findings.').splitlines())}
  </div>
</section>

<!-- ══════════════════ STATISTICS ══════════════════ -->
<section class="section">
  <h2>Analysis Statistics</h2>
  <details class="about"><summary>ℹ What is this?</summary>
    <p>High-level counts from the raw Volatility3 plugin output. <strong>Suspicious</strong> = processes
    with at least one finding. <strong>Injected</strong> = processes with PAGE_EXECUTE_READWRITE memory
    not backed by a loaded DLL (process injection indicator). <strong>Hollow</strong> = processes
    replaced with malicious code (process hollowing). <strong>LOLBAS</strong> = Living-off-the-Land
    Binary and Script use. C2 Matches = connections to known command-and-control infrastructure.</p>
  </details>
  <div class="stats-grid">
    <div class="stat-box"><div class="stat-val">{report.process_summary.total}</div><div class="stat-lbl">Total Processes</div></div>
    <div class="stat-box {'stat-warn' if report.process_summary.suspicious else ''}"><div class="stat-val">{report.process_summary.suspicious}</div><div class="stat-lbl">Suspicious</div></div>
    <div class="stat-box {'stat-crit' if report.process_summary.injected else ''}"><div class="stat-val">{report.process_summary.injected}</div><div class="stat-lbl">Injected</div></div>
    <div class="stat-box {'stat-crit' if report.process_summary.hollow else ''}"><div class="stat-val">{report.process_summary.hollow}</div><div class="stat-lbl">Hollow</div></div>
    <div class="stat-box {'stat-warn' if report.process_summary.lolbas else ''}"><div class="stat-val">{report.process_summary.lolbas}</div><div class="stat-lbl">LOLBAS</div></div>
    <div class="stat-box"><div class="stat-val">{report.network_summary.total_connections}</div><div class="stat-lbl">Connections</div></div>
    <div class="stat-box {'stat-crit' if report.network_summary.c2_matches else ''}"><div class="stat-val">{report.network_summary.c2_matches}</div><div class="stat-lbl">C2 Matches</div></div>
    <div class="stat-box"><div class="stat-val">{len(findings)}</div><div class="stat-lbl">Total Findings</div></div>
  </div>
</section>

<!-- ══════════════════ PROCESS RISK LEADERBOARD ══════════════════ -->
{_render_risk_leaderboard(top_risks)}

<!-- ══════════════════ PROCESS TREE ══════════════════ -->
<section class="section">
  <h2>Process Tree</h2>
  <details class="about"><summary>ℹ What is this?</summary>
    <p>A parent→child hierarchy of all running processes reconstructed from the memory image.
    Each line shows: <code>[PID] process_name &nbsp; » command_line</code>.
    Processes marked <strong>[!]</strong> have one or more intelligence findings attached.
    Unexpected parent-child relationships (e.g. Word spawning cmd.exe) are key indicators
    of macro malware execution. The process tree shows the full attack chain from initial
    access through to lateral movement tooling.</p>
  </details>
  <pre class="tree-pre">{_e(tree_text)}</pre>
</section>

<!-- ══════════════════ TIMELINE ══════════════════ -->
<section class="section">
  <h2>Event Timeline</h2>
  <details class="about"><summary>ℹ What is this?</summary>
    <p>A chronological record of process creation and network connection events extracted from
    the memory image. Timestamps come from Windows kernel structures (EPROCESS.CreateTime,
    TCP_ENDPOINT.CreateTime). <strong>Flagged events</strong> (⚠) are those involving
    processes that triggered at least one intelligence finding — these are the events most
    relevant to the incident. The timeline lets you reconstruct the attack sequence:
    initial compromise → execution → C2 beaconing → lateral movement.</p>
    <p><em>Note: timestamps may be absent for some processes depending on the memory image
    and Volatility profile. If the timeline is empty, use the process list and findings
    sections to reconstruct the sequence.</em></p>
  </details>
  {_render_flagged_events(flagged_events)}
  {_render_timeline_table(all_events_rows)}
</section>

<!-- ══════════════════ ATTACK CHAIN ══════════════════ -->
{_render_attack_chain(report.attack_chain)}

<!-- ══════════════════ FINDINGS ══════════════════ -->
<section class="section">
  <h2>Intelligence Findings <span class="count-badge">{len(findings)}</span></h2>
  <details class="about"><summary>ℹ What is this?</summary>
    <p>Each finding is generated by an intelligence module that analysed the raw Volatility3
    plugin output. Findings are sorted by severity (CRITICAL first). Each finding includes:</p>
    <ul>
      <li><strong>Severity</strong> — CRITICAL / HIGH / MEDIUM / LOW based on confidence and impact</li>
      <li><strong>Category</strong> — what type of threat behaviour this represents</li>
      <li><strong>MITRE ATT&amp;CK</strong> — the adversary technique ID and tactic from the MITRE framework</li>
      <li><strong>Evidence</strong> — the exact data (process name, cmdline, memory address, IP, hash) that triggered the finding</li>
      <li><strong>IOCs</strong> — extracted Indicators of Compromise ready for threat intel platform import</li>
    </ul>
  </details>
  <div class="findings-list">
    {_render_findings(findings)}
  </div>
</section>

<!-- ══════════════════ MITRE ATT&CK ══════════════════ -->
{_render_mitre(mitre_techs)}

<!-- ══════════════════ IOC SUMMARY ══════════════════ -->
{_render_iocs(report.iocs)}

<!-- ══════════════════ FOOTER ══════════════════ -->
<div class="footer">
  Generated by dfir-memdump {_e(m.tool_version)} &nbsp;|&nbsp;
  Image: {_e(Path(m.image_path).name)} &nbsp;|&nbsp;
  {_e(m.analysis_end[:19])} UTC
</div>

<script>
{_JS}
</script>
</body>
</html>"""


# ── Section renderers ─────────────────────────────────────────────────────────

def _render_risk_leaderboard(top_risks) -> str:
    if not top_risks:
        return ""
    rows = ""
    for i, r in enumerate(top_risks, 1):
        sev   = r.top_severity or "LOW"
        color, bg = _SEV_COLOR.get(sev, ("#9e9e9e", "#1a1a1a"))
        icon  = _SEV_ICON.get(sev, "⚪")
        titles_html = "<br>".join(f"<small>• {_e(t)}</small>" for t in r.finding_titles[:3])
        rows += f"""<tr>
          <td class="rank">#{i}</td>
          <td><code>{r.pid}</code></td>
          <td><strong>{_e(r.name)}</strong></td>
          <td><span class="sev-badge" style="color:{color};background:{bg}">{icon} {_e(sev)}</span></td>
          <td class="score-cell">{r.score}</td>
          <td>{r.finding_count}</td>
          <td>{titles_html}</td>
        </tr>"""
    return f"""
<section class="section">
  <h2>Process Risk Leaderboard</h2>
  <details class="about"><summary>ℹ What is this?</summary>
    <p>Each process involved in at least one finding is assigned a weighted risk score:
    CRITICAL finding = +10 pts, HIGH = +5, MEDIUM = +2, LOW = +1. The score reflects the
    total severity weight of all findings for that process. Use this table to immediately
    identify which process(es) require the most urgent investigation — the higher the score,
    the more and/or worse the findings associated with that process.</p>
  </details>
  <table class="data-table">
    <thead><tr>
      <th>Rank</th><th>PID</th><th>Process</th>
      <th>Worst Severity</th><th>Score</th><th>Findings</th><th>Finding Titles</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""


def _render_attack_chain(chain) -> str:
    if not chain:
        return ""
    steps_html = ""
    for step in chain:
        mitre_badges = " ".join(
            f'<a class="mitre-badge-sm" href="https://attack.mitre.org/techniques/{mid.replace(".","/")}" target="_blank">{_e(mid)}</a>'
            for mid in step.mitre_ids
        )
        finding_items = "".join(
            f"<li class='chain-finding'>{_e(t[:100])}</li>"
            for t in step.findings[:5]
        )
        more = f"<li class='chain-finding dim'>… {len(step.findings)-5} more</li>" if len(step.findings) > 5 else ""
        steps_html += f"""
  <div class="chain-step">
    <div class="chain-stage-header">
      <span class="chain-num">{step.stage_order + 1}</span>
      <span class="chain-stage">{_e(step.stage)}</span>
      <span class="chain-mitre">{mitre_badges}</span>
    </div>
    <div class="chain-narrative">{_e(step.narrative)}</div>
    <details class="chain-detail">
      <summary>📋 {len(step.findings)} finding(s)</summary>
      <ul class="chain-findings-list">{finding_items}{more}</ul>
    </details>
  </div>
  <div class="chain-arrow">▼</div>"""

    return f"""
<section class="section">
  <h2>Attack Chain Reconstruction</h2>
  <details class="about"><summary>ℹ What is this?</summary>
    <p>The attack chain groups all findings by their MITRE ATT&amp;CK tactic and orders them
    along the standard cyber kill chain — from Initial Access through to Impact. Each stage
    summarises what the attacker did and references the specific findings and technique IDs
    that support it. Use this section to brief leadership or write an incident timeline without
    having to read through every individual finding.</p>
  </details>
  <div class="attack-chain">{steps_html}</div>
</section>"""


def _render_flagged_events(flagged_events) -> str:
    if not flagged_events:
        return "<p class='dim'>No timestamped flagged events available.</p>"
    rows = "".join(
        f"<tr class='flagged-row'><td><code>{_e(ts)}</code></td><td>{lbl}</td><td class='dim'>{_e(det)}</td></tr>"
        for ts, lbl, det in flagged_events[:50]
    )
    return f"""
  <div class="flagged-box">
    <div class="flagged-title">⚠ Flagged Events — processes with intelligence findings</div>
    <table class="data-table">
      <thead><tr><th>Timestamp (UTC)</th><th>Event</th><th>Detail</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>"""


def _render_timeline_table(events) -> str:
    if not events:
        return "<p class='dim'>No timestamp data available from this memory image.</p>"
    cap = 500
    rows = ""
    for _, ts, lbl, det, flagged in events[:cap]:
        row_class = "flagged-row" if flagged else ""
        rows += f"<tr class='{row_class}'><td><code>{_e(ts)}</code></td><td>{lbl}</td><td class='dim'>{det}</td></tr>"
    truncated = f"<tr><td colspan='3' class='dim'>… {len(events) - cap} more events (use JSON output for full list)</td></tr>" if len(events) > cap else ""
    return f"""
  <details class="timeline-full">
    <summary>📋 Full Chronological Timeline ({len(events)} events)</summary>
    <table class="data-table timeline-table">
      <thead><tr><th>Timestamp (UTC)</th><th>Event</th><th>Detail</th></tr></thead>
      <tbody>{rows}{truncated}</tbody>
    </table>
  </details>"""


def _render_findings(findings) -> str:
    if not findings:
        return "<p class='dim'>No findings.</p>"
    out = ""
    for i, f in enumerate(findings, 1):
        sev   = f.severity.value
        color, bg = _SEV_COLOR.get(sev, ("#9e9e9e", "#1a1a1a"))
        icon  = _SEV_ICON.get(sev, "⚪")
        mitre_html = ""
        if f.mitre:
            url = f.mitre.url or f"{_MITRE_BASE}{f.mitre.technique_id.replace('.','/')}"
            mitre_html = (
                f'<div class="finding-meta-row">'
                f'<span class="meta-label">MITRE ATT&amp;CK</span>'
                f'<a class="mitre-link" href="{_e(url)}" target="_blank">'
                f'{_e(f.mitre.technique_id)} — {_e(f.mitre.technique_name)}</a>'
                f' <span class="tactic-badge">{_e(f.mitre.tactic)}</span>'
                f'</div>'
            )
        ioc_html = ""
        if f.iocs:
            ioc_html = (
                '<div class="finding-meta-row"><span class="meta-label">IOCs</span>'
                + " ".join(f'<code class="ioc-chip" onclick="copyText(this)">{_e(ioc)}</code>' for ioc in f.iocs)
                + "</div>"
            )
        pid_html = ""
        if f.affected_pid:
            pid_html = (
                f'<div class="finding-meta-row">'
                f'<span class="meta-label">Process</span>'
                f'<code>{_e(f.affected_process or "")} (PID {f.affected_pid})</code>'
                f'</div>'
            )
        out += f"""
<details class="finding-card" {'open' if sev == 'CRITICAL' else ''}>
  <summary>
    <span class="sev-badge" style="color:{color};background:{bg}">{icon} {_e(sev)}</span>
    <span class="finding-num">#{i}</span>
    <span class="finding-title">{_e(f.title)}</span>
    <span class="cat-badge">{_e(f.category.value)}</span>
  </summary>
  <div class="finding-body">
    <div class="finding-description">{_e(f.description)}</div>
    {pid_html}
    <div class="finding-meta-row">
      <span class="meta-label">Source</span>
      <code>{_e(f.source_module)} / {_e(f.source_plugin)}</code>
    </div>
    {mitre_html}
    <div class="finding-meta-row">
      <span class="meta-label">Evidence</span>
      <pre class="evidence-pre">{_e(f.evidence)}</pre>
    </div>
    {ioc_html}
  </div>
</details>"""
    return out


def _render_mitre(mitre_techs) -> str:
    if not mitre_techs:
        return ""
    badges = ""
    for t in sorted(mitre_techs, key=lambda x: x.technique_id):
        url = t.url or f"{_MITRE_BASE}{t.technique_id.replace('.','/')}"
        badges += (
            f'<a class="mitre-badge" href="{_e(url)}" target="_blank">'
            f'<span class="mitre-id">{_e(t.technique_id)}</span>'
            f'<span class="mitre-name">{_e(t.technique_name)}</span>'
            f'<span class="mitre-tactic">{_e(t.tactic)}</span>'
            f'</a>'
        )
    return f"""
<section class="section">
  <h2>MITRE ATT&amp;CK Coverage</h2>
  <details class="about"><summary>ℹ What is this?</summary>
    <p>The MITRE ATT&amp;CK framework catalogues adversary tactics, techniques, and procedures (TTPs).
    Each badge represents a technique observed in this memory image. The technique ID (T1055, etc.)
    links to the MITRE website for full documentation, detection guidance, and mitigation advice.
    The tactic (bottom of each badge) is the adversary goal — e.g. <em>Execution</em>,
    <em>Defense Evasion</em>, <em>Lateral Movement</em>.</p>
  </details>
  <div class="mitre-grid">{badges}</div>
</section>"""


def _render_iocs(iocs) -> str:
    if not iocs:
        return ""
    rows = ""
    for ioc in iocs[:200]:
        rows += (
            f'<tr><td><span class="ioc-type">{_e(ioc.type)}</span></td>'
            f'<td><code class="ioc-chip" onclick="copyText(this)">{_e(ioc.value)}</code></td>'
            f'<td class="dim">{_e(ioc.context[:70])}</td>'
            f'<td>{ioc.pid or ""}</td></tr>'
        )
    truncated = f'<tr><td colspan="4" class="dim">… {len(iocs) - 200} more IOCs (see JSON report)</td></tr>' if len(iocs) > 200 else ""
    return f"""
<section class="section">
  <h2>IOC Summary <span class="count-badge">{len(iocs)}</span></h2>
  <details class="about"><summary>ℹ What is this?</summary>
    <p>Indicators of Compromise (IOCs) extracted from all findings. Click any value to copy it
    to your clipboard for import into your SIEM, threat intel platform, or firewall blocklist.
    IOC types: <strong>ip</strong> = remote IP address, <strong>hash_sha256</strong> = file hash
    for VirusTotal lookup, <strong>process_name</strong> = suspicious executable name,
    <strong>cmdline</strong> = command line with suspicious arguments,
    <strong>filepath</strong> = file path on disk, <strong>mutex</strong> = malware mutex name,
    <strong>url</strong> = embedded URL from memory strings,
    <strong>regkey</strong> = registry key accessed by a suspicious process.</p>
  </details>
  <table class="data-table">
    <thead><tr><th>Type</th><th>Value</th><th>Context</th><th>PID</th></tr></thead>
    <tbody>{rows}{truncated}</tbody>
  </table>
</section>"""


# ── CSS ───────────────────────────────────────────────────────────────────────
_CSS = """
  :root {
    --bg:        #0d1117;
    --bg2:       #161b22;
    --bg3:       #21262d;
    --border:    #30363d;
    --text:      #c9d1d9;
    --text-dim:  #8b949e;
    --accent:    #58a6ff;
    --crit:      #ff4d4d;
    --high:      #ff9933;
    --med:       #f0c040;
    --low:       #4caf50;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
    font-size: 13px;
    line-height: 1.6;
    padding: 0 0 60px 0;
  }

  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  code { background: var(--bg3); padding: 1px 5px; border-radius: 3px; font-family: "Consolas","Courier New",monospace; font-size: 12px; }
  pre { background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; padding: 12px; overflow-x: auto; font-size: 12px; }

  /* ── Header ── */
  .report-header {
    background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    border-bottom: 2px solid var(--accent);
    padding: 20px 32px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: sticky; top: 0; z-index: 100;
  }
  .report-title { font-size: 20px; font-weight: 700; color: var(--accent); }
  .report-subtitle { font-size: 12px; color: var(--text-dim); margin-top: 2px; }
  .print-btn {
    background: var(--accent); color: #000; border: none;
    padding: 8px 18px; border-radius: 6px; font-size: 13px;
    font-weight: 600; cursor: pointer;
  }
  .print-btn:hover { background: #79b8ff; }

  /* ── Sections ── */
  .section { max-width: 1200px; margin: 24px auto; padding: 0 24px; }
  .section h2 { font-size: 16px; font-weight: 600; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 12px; }

  /* ── About collapsible ── */
  details.about { background: #0e1a2e; border: 1px solid #1c3a5e; border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; }
  details.about summary { cursor: pointer; color: var(--text-dim); font-size: 12px; user-select: none; }
  details.about p, details.about ul { color: var(--text-dim); font-size: 12px; margin-top: 6px; }
  details.about ul { padding-left: 16px; }
  details.about li { margin-top: 3px; }

  /* ── Case metadata ── */
  .meta-grid { display: flex; flex-wrap: wrap; gap: 12px; }
  .meta-item { background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; padding: 8px 14px; min-width: 200px; }
  .meta-label { display: block; font-size: 10px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; }
  .meta-value { font-family: monospace; font-size: 12px; color: var(--text); word-break: break-all; }

  /* ── Executive summary ── */
  .exec-box { background: var(--bg2); border-left: 4px solid var(--accent); border-radius: 0 6px 6px 0; padding: 14px 18px; font-size: 13px; white-space: pre-line; }

  /* ── Stats grid ── */
  .stats-grid { display: flex; flex-wrap: wrap; gap: 10px; }
  .stat-box { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; min-width: 120px; text-align: center; }
  .stat-box.stat-warn { border-color: var(--high); }
  .stat-box.stat-crit { border-color: var(--crit); background: #1a0a0a; }
  .stat-val { font-size: 28px; font-weight: 700; color: var(--text); }
  .stat-lbl { font-size: 11px; color: var(--text-dim); margin-top: 2px; }

  /* ── Risk leaderboard ── */
  .rank { color: var(--text-dim); font-weight: 600; }
  .score-cell { font-size: 16px; font-weight: 700; color: var(--crit); }

  /* ── Data tables ── */
  .data-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .data-table th { background: var(--bg3); color: var(--text-dim); text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--border); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; }
  .data-table td { padding: 6px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  .data-table tr:last-child td { border-bottom: none; }
  .data-table tr:hover td { background: var(--bg3); }
  .flagged-row td { background: #1a1200 !important; }
  .flagged-row:hover td { background: #221800 !important; }

  /* ── Timeline ── */
  .flagged-box { background: #160f00; border: 1px solid var(--high); border-radius: 8px; padding: 14px; margin-bottom: 16px; }
  .flagged-title { color: var(--high); font-weight: 600; font-size: 13px; margin-bottom: 10px; }
  .flag-tag { background: #2a1800; color: var(--high); border-radius: 4px; padding: 1px 6px; font-size: 11px; }
  details.timeline-full > summary { cursor: pointer; color: var(--accent); font-size: 13px; padding: 8px 0; }
  .timeline-table td:first-child { white-space: nowrap; }

  /* ── Process tree ── */
  .tree-pre { font-family: "Consolas","Courier New",monospace; font-size: 12px; line-height: 1.5; }

  /* ── Severity badges ── */
  .sev-badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }

  /* ── Findings ── */
  .count-badge { background: var(--bg3); color: var(--text-dim); border-radius: 12px; padding: 1px 8px; font-size: 12px; font-weight: normal; margin-left: 6px; }
  details.finding-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 8px; overflow: hidden; }
  details.finding-card > summary { padding: 10px 14px; cursor: pointer; display: flex; align-items: center; gap: 8px; user-select: none; list-style: none; }
  details.finding-card > summary::-webkit-details-marker { display: none; }
  details.finding-card > summary:hover { background: var(--bg3); }
  .finding-num { color: var(--text-dim); font-size: 11px; min-width: 28px; }
  .finding-title { flex: 1; font-weight: 500; font-size: 13px; }
  .cat-badge { background: var(--bg3); color: var(--text-dim); border-radius: 4px; padding: 1px 7px; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em; }
  .finding-body { padding: 12px 16px; border-top: 1px solid var(--border); }
  .finding-description { color: var(--text-dim); font-size: 12px; margin-bottom: 10px; line-height: 1.6; }
  .finding-meta-row { display: flex; align-items: flex-start; gap: 10px; margin-bottom: 7px; }
  .meta-label { min-width: 100px; font-size: 11px; color: var(--text-dim); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; padding-top: 1px; }
  .evidence-pre { margin: 0; font-size: 11px; padding: 8px 10px; }
  .mitre-link { font-weight: 600; }
  .tactic-badge { background: var(--bg3); color: var(--text-dim); border-radius: 4px; padding: 1px 6px; font-size: 10px; }

  /* ── IOCs ── */
  .ioc-type { background: var(--bg3); color: var(--text-dim); border-radius: 4px; padding: 1px 6px; font-size: 10px; text-transform: uppercase; }
  .ioc-chip { cursor: pointer; user-select: all; }
  .ioc-chip:hover { background: #1c3a5e; color: var(--accent); }
  .dim { color: var(--text-dim); }

  /* ── MITRE grid ── */
  .mitre-grid { display: flex; flex-wrap: wrap; gap: 8px; }
  .mitre-badge { display: flex; flex-direction: column; background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; min-width: 180px; text-decoration: none; }
  .mitre-badge:hover { border-color: var(--accent); text-decoration: none; }
  .mitre-id { font-size: 13px; font-weight: 700; color: var(--accent); }
  .mitre-name { font-size: 11px; color: var(--text); margin-top: 2px; }
  .mitre-tactic { font-size: 10px; color: var(--text-dim); margin-top: 3px; text-transform: uppercase; letter-spacing: 0.05em; }

  /* ── Attack chain ── */
  .attack-chain { display: flex; flex-direction: column; align-items: flex-start; gap: 0; }
  .chain-step { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; width: 100%; }
  .chain-arrow { color: var(--text-dim); font-size: 18px; padding: 4px 18px; }
  .chain-stage-header { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
  .chain-num { background: var(--accent); color: #000; border-radius: 50%; width: 22px; height: 22px; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; flex-shrink: 0; }
  .chain-stage { font-size: 14px; font-weight: 600; color: var(--text); }
  .chain-mitre { display: flex; flex-wrap: wrap; gap: 4px; }
  .mitre-badge-sm { background: var(--bg3); border: 1px solid var(--border); border-radius: 4px; padding: 1px 6px; font-size: 11px; color: var(--accent); text-decoration: none; }
  .mitre-badge-sm:hover { border-color: var(--accent); }
  .chain-narrative { color: var(--text-dim); font-size: 12px; margin-bottom: 8px; }
  details.chain-detail > summary { cursor: pointer; color: var(--accent); font-size: 12px; }
  .chain-findings-list { list-style: disc; padding-left: 20px; margin-top: 6px; }
  .chain-finding { font-size: 12px; color: var(--text-dim); margin-bottom: 2px; }

  /* ── Footer ── */
  .footer { max-width: 1200px; margin: 40px auto 0; padding: 12px 24px; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 11px; }

  /* ── Print styles ── */
  @media print {
    body { background: #fff; color: #000; font-size: 11px; }
    .report-header { background: #fff; border-bottom: 2px solid #000; position: static; }
    .report-title { color: #000; }
    .report-subtitle { color: #666; }
    .print-btn { display: none; }
    .section { max-width: 100%; padding: 0 12px; margin: 16px auto; }
    .section h2 { color: #000; border-color: #ccc; }
    details { display: block; }
    details.about { display: none; }
    details.finding-card, details.timeline-full { display: block; }
    summary { display: none; }
    details.finding-card > .finding-body { display: block; border-top: 1px solid #ccc; }
    details.timeline-full > table { display: table; }
    pre, code { background: #f5f5f5; color: #000; border: 1px solid #ccc; }
    .data-table th { background: #eee; color: #000; }
    .data-table tr:hover td { background: transparent; }
    .flagged-row td { background: #fff8e1 !important; }
    .exec-box { background: #f0f8ff; border-color: #0066cc; color: #000; }
    .stats-grid .stat-box { border: 1px solid #ccc; background: #fafafa; }
    .stat-val { color: #000; }
    .stat-lbl { color: #666; }
    .sev-badge { border: 1px solid currentColor; }
    a { color: #000; }
    .mitre-badge { border: 1px solid #ccc; background: #fafafa; }
    .mitre-id { color: #003399; }
    .mitre-name, .mitre-tactic { color: #333; }
    .footer { color: #666; border-color: #ccc; }
    .finding-card { border: 1px solid #ccc; page-break-inside: avoid; }
  }
"""

# ── JavaScript ────────────────────────────────────────────────────────────────
_JS = """
function copyText(el) {
  const text = el.textContent || el.innerText;
  navigator.clipboard.writeText(text).then(() => {
    const orig = el.style.background;
    el.style.background = '#0e4429';
    setTimeout(() => { el.style.background = orig; }, 600);
  }).catch(() => {
    const r = document.createRange();
    r.selectNode(el);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
  });
}
"""
