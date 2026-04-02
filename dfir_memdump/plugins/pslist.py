"""windows.pslist.PsList — process listing with tree reconstruction."""

from __future__ import annotations
import logging
from dfir_memdump.models import ProcessInfo
from dfir_memdump.plugins import BasePlugin

logger = logging.getLogger(__name__)


class PsListPlugin(BasePlugin[ProcessInfo]):
    plugin_name  = "windows.pslist.PsList"
    output_model = ProcessInfo

    def _parse(self, raw_output: str) -> list[ProcessInfo]:
        rows     = self._parse_json_rows(raw_output)
        procs    = []
        pid_map: dict[int, ProcessInfo] = {}

        for row in rows:
            try:
                proc = ProcessInfo(
                    pid        = int(row.get("PID") or row.get("pid", 0)),
                    ppid       = int(row.get("PPID") or row.get("ppid", 0)),
                    name       = str(row.get("ImageFileName") or row.get("name", "")),
                    create_time= str(row.get("CreateTime") or ""),
                    exit_time  = str(row.get("ExitTime") or ""),
                    threads    = int(row.get("Threads") or 0),
                    handles    = int(row.get("Handles") or 0),
                    session_id = _int_or_none(row.get("SessionId")),
                    wow64      = bool(row.get("Wow64") or False),
                )
                procs.append(proc)
                pid_map[proc.pid] = proc
            except Exception as exc:
                logger.debug("PsList row parse error: %s | row=%s", exc, row)

        # Build parent→children links
        for proc in procs:
            parent = pid_map.get(proc.ppid)
            if parent and parent.pid != proc.pid:
                if proc.pid not in parent.children:
                    parent.children.append(proc.pid)

        logger.debug("PsList parsed %d processes", len(procs))
        return procs


def _int_or_none(val) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None
