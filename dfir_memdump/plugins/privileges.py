"""windows.privileges.Privs — per-process privilege enumeration."""

from __future__ import annotations
import logging
from dfir_memdump.models import PrivilegeEntry
from dfir_memdump.plugins import BasePlugin

logger = logging.getLogger(__name__)


class PrivilegesPlugin(BasePlugin[PrivilegeEntry]):
    plugin_name  = "windows.privileges.Privs"
    output_model = PrivilegeEntry

    def _parse(self, raw_output: str) -> list[PrivilegeEntry]:
        rows   = self._parse_json_rows(raw_output)
        result = []

        for row in rows:
            try:
                # Volatility3 columns: PID, Process, Value, Privilege, Description, Enabled, Default
                enabled_raw = row.get("Enabled") or row.get("enabled") or False
                default_raw = row.get("Default") or row.get("DefaultEnabled") or row.get("default") or False
                entry = PrivilegeEntry(
                    pid           = int(row.get("PID") or row.get("pid", 0)),
                    process_name  = str(row.get("Process") or row.get("process", "")),
                    privilege     = str(row.get("Privilege") or row.get("privilege", "")),
                    enabled       = str(enabled_raw).lower() in ("true", "1", "yes", "present"),
                    default_enabled = str(default_raw).lower() in ("true", "1", "yes", "present"),
                )
                result.append(entry)
            except Exception as exc:
                logger.debug("Privileges row parse error: %s | row=%s", exc, row)

        logger.debug("PrivilegesPlugin parsed %d privilege entries", len(result))
        return result
