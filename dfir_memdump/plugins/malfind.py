"""windows.malfind.Malfind — VAD regions with suspicious memory protections."""

from __future__ import annotations
import logging
from dfir_memdump.models import MalfindEntry
from dfir_memdump.plugins import BasePlugin

logger = logging.getLogger(__name__)


class MalfindPlugin(BasePlugin[MalfindEntry]):
    plugin_name  = "windows.malfind.Malfind"
    output_model = MalfindEntry

    def _parse(self, raw_output: str) -> list[MalfindEntry]:
        rows    = self._parse_json_rows(raw_output)
        entries = []

        for row in rows:
            try:
                entry = MalfindEntry(
                    pid          = int(row.get("PID") or 0),
                    process_name = str(row.get("Process") or ""),
                    vad_start    = hex(int(row.get("Start VPN") or row.get("start", 0))),
                    vad_end      = hex(int(row.get("End VPN")   or row.get("end",   0))),
                    tag          = str(row.get("Tag")        or ""),
                    protection   = str(row.get("Protection") or ""),
                    vad_type     = str(row.get("CommitCharge") or ""),
                    file_path    = str(row.get("File output") or "") or None,
                    hex_dump     = str(row.get("Hexdump")    or "") or None,
                    disasm       = str(row.get("Disasm")     or "") or None,
                )
                entries.append(entry)
            except Exception as exc:
                logger.debug("Malfind row parse error: %s | row=%s", exc, row)

        logger.debug("Malfind parsed %d entries", len(entries))
        return entries
