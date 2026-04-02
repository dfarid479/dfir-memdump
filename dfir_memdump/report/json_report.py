"""
JSON report writer — serializes the full TriageReport as pretty-printed JSON.
"""

from __future__ import annotations
import json
from pathlib import Path

from dfir_memdump.models import TriageReport


def write_json_report(report: TriageReport, path: Path) -> Path:
    """Write report to path as JSON. Returns path."""
    data = report.model_dump(mode="json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    return path
