"""windows.cmdline.CmdLine — process command line arguments."""

from __future__ import annotations
import logging
from dfir_memdump.models import CmdlineEntry
from dfir_memdump.plugins import BasePlugin

logger = logging.getLogger(__name__)


class CmdLinePlugin(BasePlugin[CmdlineEntry]):
    plugin_name  = "windows.cmdline.CmdLine"
    output_model = CmdlineEntry

    def _parse(self, raw_output: str) -> list[CmdlineEntry]:
        rows    = self._parse_json_rows(raw_output)
        entries = []

        for row in rows:
            try:
                entry = CmdlineEntry(
                    pid     = int(row.get("PID") or row.get("pid", 0)),
                    name    = str(row.get("Process") or row.get("name", "")),
                    cmdline = str(row.get("Args") or row.get("cmdline") or "") or None,
                )
                entries.append(entry)
            except Exception as exc:
                logger.debug("CmdLine row parse error: %s | row=%s", exc, row)

        logger.debug("CmdLine parsed %d entries", len(entries))
        return entries
