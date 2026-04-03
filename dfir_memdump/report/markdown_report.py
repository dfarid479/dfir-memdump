"""
Markdown IR report writer.

Renders a human-readable incident response report using Jinja2.
Falls back to a built-in template if the external template file is missing.

Sections (in order):
  1. Header / metadata
  2. Executive Summary
  3. Statistics
  4. Process Tree          ← new
  5. Event Timeline        ← new
  6. Findings
  7. MITRE ATT&CK Coverage
  8. IOC Summary
"""

from __future__ import annotations
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from collections import Counter

from dfir_memdump.models import ProcessInfo, TriageReport, Severity

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates"
_TEMPLATE_FILE = _TEMPLATES_DIR / "report.md.j2"

# ── Severity emoji map ────────────────────────────────────────────────────────
SEV_BADGE = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH:     "🟠 HIGH",
    Severity.MEDIUM:   "🟡 MEDIUM",
    Severity.LOW:      "🟢 LOW",
    Severity.INFO:     "⚪ INFO",
}


def write_markdown_report(report: TriageReport, path: Path) -> Path:
    """Render the markdown report and write to path. Returns path."""
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        if _TEMPLATE_FILE.exists():
            env = Environment(
                loader=FileSystemLoader(str(_TEMPLATES_DIR)),
                autoescape=select_autoescape([]),
                trim_blocks=True,
                lstrip_blocks=True,
            )
            env.filters["sev_badge"] = lambda s: SEV_BADGE.get(s, str(s))
            template = env.get_template("report.md.j2")
            content = template.render(report=report, SEV_BADGE=SEV_BADGE)
        else:
            logger.warning("Template not found at %s — using built-in renderer", _TEMPLATE_FILE)
            content = _render_builtin(report)
    except ImportError:
        logger.warning("Jinja2 not installed — using built-in renderer")
        content = _render_builtin(report)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# ── Timeline helpers ──────────────────────────────────────────────────────────

def _parse_vol_time(s: str) -> Optional[datetime]:
    """
    Parse Volatility 3 timestamp strings into datetime objects.
    Handles ISO 8601, 'YYYY-MM-DD HH:MM:SS UTC+0000', and similar variants.
    Returns None if the string cannot be parsed.
    """
    if not s or s.strip() in ("N/A", "None", "-", ""):
        return None
    s = s.strip()
    # Strip trailing timezone label if present (e.g. " UTC+0000")
    for suffix in (" UTC+0000", " UTC", " utc"):
        if s.endswith(suffix):
            s = s[: -len(suffix)]
            break
    # Strip microseconds for simpler format matching
    s_no_us = s.split(".")[0]
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(s_no_us, fmt)
        except ValueError:
            continue
    # Last resort: python-dateutil (optional dependency)
    try:
        from dateutil import parser as _du
        return _du.parse(s)
    except (ImportError, ValueError, OverflowError):
        return None


def _build_process_tree(report: TriageReport) -> list[str]:
    """
    Render an ASCII parent→child process tree.

    Processes with findings are flagged with [!].
    Unknown-parent processes (orphans) each become a root.

    Example output:
        ├── [4] System
        │   └── [388] smss.exe
        │       └── [512] csrss.exe
        └── [1234] malware.exe [!]
    """
    if not report.processes:
        return ["_No process data available._", ""]

    suspicious_pids: set[int] = {
        f.affected_pid for f in report.findings if f.affected_pid is not None
    }
    pid_map: dict[int, ProcessInfo] = {p.pid: p for p in report.processes}

    # Build children index
    children: dict[int, list[int]] = {}
    for proc in report.processes:
        children.setdefault(proc.ppid, []).append(proc.pid)

    # Roots = processes whose ppid is not a known pid
    roots: list[int] = [
        p.pid for p in report.processes if p.ppid not in pid_map
    ]
    # Sort roots for deterministic output (System first, then by pid)
    roots.sort()

    tree_lines: list[str] = []

    def _render(pid: int, prefix: str, is_last: bool) -> None:
        proc = pid_map.get(pid)
        if proc is None:
            return
        connector = "└── " if is_last else "├── "
        flag = " [!]" if pid in suspicious_pids else ""
        cmd_hint = ""
        if proc.cmdline and proc.cmdline.strip() not in (proc.name, ""):
            # Show first 60 chars of cmdline as a hint
            hint = proc.cmdline.strip()[:60]
            if len(proc.cmdline.strip()) > 60:
                hint += "…"
            cmd_hint = f"  » {hint}"
        tree_lines.append(f"{prefix}{connector}[{pid}] {proc.name}{flag}{cmd_hint}")
        child_pids = sorted(children.get(pid, []))
        for i, child_pid in enumerate(child_pids):
            extension = "    " if is_last else "│   "
            _render(child_pid, prefix + extension, i == len(child_pids) - 1)

    for i, root_pid in enumerate(roots):
        _render(root_pid, "", i == len(roots) - 1)

    lines: list[str] = ["```text"]
    lines.extend(tree_lines)
    lines += [
        "```",
        "",
        "_[!] = one or more intelligence findings attached to this process_",
        "",
    ]
    return lines


def _build_timeline(report: TriageReport) -> list[str]:
    """
    Build a chronological event timeline from process creation timestamps
    and network connection creation timestamps.

    Events with associated findings are annotated with ⚠️.
    """
    suspicious_pids: set[int] = {
        f.affected_pid for f in report.findings if f.affected_pid is not None
    }

    # Collect (datetime, type, description, detail) tuples
    events: list[tuple[datetime, str, str, str]] = []

    for proc in report.processes:
        if not proc.create_time:
            continue
        dt = _parse_vol_time(proc.create_time)
        if dt is None:
            continue
        flag = " ⚠️" if proc.pid in suspicious_pids else ""
        label = f"PROC START  PID {proc.pid:<6} {proc.name}{flag}"
        detail = proc.cmdline.strip()[:80] if proc.cmdline else ""
        events.append((dt, "process", label, detail))

    for conn in report.connections:
        if not conn.created_time:
            continue
        dt = _parse_vol_time(conn.created_time)
        if dt is None:
            continue
        flag = " ⚠️" if conn.pid in suspicious_pids else ""
        label = (
            f"NET  {conn.proto:<6} "
            f"{conn.local_addr}:{conn.local_port} → "
            f"{conn.foreign_addr}:{conn.foreign_port}{flag}"
        )
        detail = conn.process_name or ""
        events.append((dt, "network", label, detail))

    if not events:
        return [
            "_No timestamp data available — Volatility did not produce CreateTime / Created fields "
            "for this image. This is common with some memory profiles._",
            "",
        ]

    events.sort(key=lambda e: e[0])

    lines: list[str] = [
        "| Timestamp (UTC) | Event | Detail |",
        "|-----------------|-------|--------|",
    ]
    cap = 300
    for dt, _etype, label, detail in events[:cap]:
        ts = dt.strftime("%Y-%m-%d %H:%M:%S")
        detail_safe = detail.replace("|", "\\|")[:70]
        lines.append(f"| `{ts}` | {label} | {detail_safe} |")

    if len(events) > cap:
        lines.append(f"| … | _({len(events) - cap} more events — use JSON output for full list)_ | |")

    lines.append("")
    return lines


# ── Attack chain ─────────────────────────────────────────────────────────────

def _build_attack_chain_section(report: TriageReport) -> list[str]:
    """Render the attack chain as an ordered Markdown list of kill-chain stages."""
    if not report.attack_chain:
        return []

    lines = [
        "## Attack Chain",
        "",
        "_Observed kill-chain stages ordered from initial access to impact:_",
        "",
    ]
    for step in report.attack_chain:
        mitre_str = " · ".join(step.mitre_ids) if step.mitre_ids else ""
        lines.append(f"**{step.stage_order + 1}. {step.stage}**"
                     + (f"  `{mitre_str}`" if mitre_str else ""))
        lines.append("")
        lines.append(f"> {step.narrative}")
        lines.append("")

    lines += ["---", ""]
    return lines


# ── Main renderer ─────────────────────────────────────────────────────────────

def _render_builtin(report: TriageReport) -> str:
    """Pure-Python fallback renderer — no Jinja2 dependency."""
    m   = report.metadata
    ps  = report.process_summary
    ns  = report.network_summary
    findings = report.findings_by_severity()

    lines = [
        "# Memory Forensics Triage Report",
        "",
        f"**Image:** `{m.image_path}`  ",
        f"**Size:** {m.image_size_mb:.1f} MB  ",
        f"**MD5:** `{m.image_md5 or 'not computed'}`  ",
        f"**SHA256:** `{m.image_sha256 or 'not computed'}`  ",
        f"**Started:** {m.analysis_start}  ",
        f"**Completed:** {m.analysis_end}  ",
        f"**Tool Version:** {m.tool_version}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        report.executive_summary or "_No summary available._",
        "",
        "---",
        "",
        "## Statistics",
        "",
        "### Processes",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total processes | {ps.total} |",
        f"| Suspicious | {ps.suspicious} |",
        f"| Injected | {ps.injected} |",
        f"| Hollow | {ps.hollow} |",
        f"| LOLBAS | {ps.lolbas} |",
        "",
        "### Network",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total connections | {ns.total_connections} |",
        f"| Established | {ns.established} |",
        f"| Listening | {ns.listening} |",
        f"| C2 matches | {ns.c2_matches} |",
        f"| Feodo matches | {ns.feodo_matches} |",
        "",
        "---",
        "",
        "## Process Tree",
        "",
        *_build_process_tree(report),
        "---",
        "",
        "## Event Timeline",
        "",
        *_build_timeline(report),
        "---",
        "",
        *_build_attack_chain_section(report),
        f"## Findings ({len(findings)} total)",
        "",
    ]

    for i, f in enumerate(findings, 1):
        badge = SEV_BADGE.get(f.severity, f.severity.value)
        lines += [
            f"### {i}. {badge} — {f.title}",
            "",
            f"**Category:** {f.category.value}  ",
            f"**Source:** {f.source_module} / {f.source_plugin}  ",
        ]
        if f.affected_pid:
            lines.append(f"**PID:** {f.affected_pid} ({f.affected_process or 'unknown'})  ")
        if f.mitre:
            lines.append(
                f"**MITRE ATT&CK:** [{f.mitre.technique_id} — {f.mitre.technique_name}]({f.mitre.url}) "
                f"({f.mitre.tactic})  "
            )
        lines += [
            "",
            f"**Description:** {f.description}",
            "",
            "**Evidence:**",
            "```",
            f.evidence,
            "```",
        ]
        if f.iocs:
            lines += [
                "",
                "**IOCs:** " + " | ".join(f"`{ioc}`" for ioc in f.iocs),
            ]
        lines.append("")

    # Encryption key artifacts
    lines += [
        "---",
        "",
        "## 🔑 Encryption Key Artifacts",
        "",
    ]
    if not report.encryption_keys:
        lines += [
            "_Plugin ran — no encryption key material recovered from this image._  ",
            "_BitLocker FVEKs require an active encrypted volume mounted at collection time. "
            "AES candidates require `aeskeyfind` or `bulk_extractor` on PATH. "
            "VeraCrypt/TrueCrypt detection requires the mount process to have been running._",
            "",
        ]
    else:
        lines += [
            f"**{len(report.encryption_keys)} key artifact(s) recovered.**",
            "",
        ]
        for key in report.encryption_keys:
            lines += [
                f"### {key.key_type} — {key.algorithm}",
                "",
                f"**Source:** `{key.source}`" + (f"  **PID:** {key.pid} ({key.process_name})" if key.pid else ""),
                "",
            ]
            if key.key_hex:
                lines += [
                    "**Key (hex):**",
                    "```",
                    key.key_hex,
                    "```",
                ]
            if key.dislocker_cmd:
                lines += [
                    "**Mount command:**",
                    "```bash",
                    key.dislocker_cmd,
                    "```",
                ]
            if key.file_offset:
                lines.append(f"**File offset:** `{key.file_offset}`")
            if key.notes:
                lines += ["", f"_{key.notes}_"]
            lines.append("")

    # MITRE ATT&CK coverage
    techniques = report.unique_mitre_techniques()
    if techniques:
        lines += [
            "---",
            "",
            "## MITRE ATT&CK Coverage",
            "",
            f"Techniques observed: {', '.join(techniques)}",
            "",
        ]

    # IOC summary (grouped by type, full list collapsed)
    if report.iocs:
        type_counts = Counter(ioc.type for ioc in report.iocs)
        summary_line = " | ".join(
            f"**{cnt}** {ioc_type}"
            for ioc_type, cnt in sorted(type_counts.items(), key=lambda x: -x[1])
        )
        lines += [
            "---",
            "",
            "## IOC Summary",
            "",
            f"{len(report.iocs)} total IOCs — {summary_line}",
            "",
            "<details><summary>Full IOC list</summary>",
            "",
            "| Type | Value | Context |",
            "|------|-------|---------| ",
        ]
        for ioc in report.iocs[:200]:
            lines.append(f"| {ioc.type} | `{ioc.value}` | {ioc.context[:60]} |")
        if len(report.iocs) > 200:
            lines.append(f"| … | _({len(report.iocs) - 200} more — use JSON output)_ | |")
        lines += ["", "</details>", ""]

    lines += [
        "---",
        "",
        f"_Report generated by dfir-memdump {m.tool_version}_",
        "",
    ]

    return "\n".join(lines)
