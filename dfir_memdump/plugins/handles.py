"""windows.handles.Handles — open handle enumeration per process."""

from __future__ import annotations
import logging
from dfir_memdump.models import HandleEntry
from dfir_memdump.plugins import BasePlugin

logger = logging.getLogger(__name__)


class HandlesPlugin(BasePlugin[HandleEntry]):
    plugin_name  = "windows.handles.Handles"
    output_model = HandleEntry

    def _parse(self, raw_output: str) -> list[HandleEntry]:
        rows    = self._parse_json_rows(raw_output)
        handles = []

        for row in rows:
            try:
                name_raw = row.get("Name") or row.get("name") or ""
                h = HandleEntry(
                    pid           = int(row.get("PID") or row.get("pid", 0)),
                    process_name  = str(row.get("Process") or row.get("process", "")),
                    handle_value  = str(row.get("HandleValue") or row.get("handle_value", "")),
                    handle_type   = str(row.get("Type") or row.get("type", "")),
                    granted_access= str(row.get("GrantedAccess") or row.get("granted_access", "")),
                    name          = str(name_raw).strip() or None,
                )
                handles.append(h)
            except Exception as exc:
                logger.debug("Handles row parse error: %s | row=%s", exc, row)

        logger.debug("HandlesPlugin parsed %d handles", len(handles))
        return handles
