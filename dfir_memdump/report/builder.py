"""
Report builder — dispatches to JSON, Markdown, or HTML renderer.
"""

from __future__ import annotations
from pathlib import Path
from typing import Literal

from dfir_memdump.models import TriageReport
from dfir_memdump.report.json_report      import write_json_report
from dfir_memdump.report.markdown_report  import write_markdown_report
from dfir_memdump.report.html_report      import write_html_report


ReportFormat = Literal["json", "markdown", "html", "all"]


def build_report(
    report: TriageReport,
    output_dir: Path,
    stem: str,
    fmt: ReportFormat = "all",
) -> list[Path]:
    """
    Write the triage report to output_dir in the requested format(s).
    Returns a list of paths to generated report files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []

    if fmt in ("json", "all"):
        p = write_json_report(report, output_dir / f"{stem}.json")
        generated.append(p)

    if fmt in ("markdown", "all"):
        p = write_markdown_report(report, output_dir / f"{stem}.md")
        generated.append(p)

    if fmt in ("html", "all"):
        p = write_html_report(report, output_dir / f"{stem}.html")
        generated.append(p)

    return generated
