"""windows.dlllist.DllList — loaded DLL enumeration per process."""

from __future__ import annotations
import logging
from dfir_memdump.models import DllInfo
from dfir_memdump.plugins import BasePlugin

logger = logging.getLogger(__name__)


class DllListPlugin(BasePlugin[DllInfo]):
    plugin_name  = "windows.dlllist.DllList"
    output_model = DllInfo

    def _parse(self, raw_output: str) -> list[DllInfo]:
        rows = self._parse_json_rows(raw_output)
        dlls = []

        for row in rows:
            try:
                base_raw = row.get("Base") or row.get("base") or "0"
                dll = DllInfo(
                    pid  = int(row.get("PID") or row.get("pid", 0)),
                    base = hex(int(str(base_raw), 16 if str(base_raw).startswith("0x") else 10)),
                    size = int(row.get("Size") or row.get("size") or 0),
                    path = str(row.get("Path") or row.get("path") or "") or None,
                    name = str(row.get("Name") or row.get("name") or "") or None,
                )
                dlls.append(dll)
            except Exception as exc:
                logger.debug("DllList row parse error: %s | row=%s", exc, row)

        logger.debug("DllList parsed %d DLL entries", len(dlls))
        return dlls
