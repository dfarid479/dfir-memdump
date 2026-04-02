"""windows.netscan.NetScan — active and closed network connections."""

from __future__ import annotations
import logging
from dfir_memdump.models import NetworkConnection
from dfir_memdump.plugins import BasePlugin

logger = logging.getLogger(__name__)


class NetScanPlugin(BasePlugin[NetworkConnection]):
    plugin_name  = "windows.netscan.NetScan"
    output_model = NetworkConnection

    def _parse(self, raw_output: str) -> list[NetworkConnection]:
        rows  = self._parse_json_rows(raw_output)
        conns = []

        for row in rows:
            try:
                local_addr,  local_port  = _split_addr(row.get("LocalAddr")  or row.get("local_addr",  ""))
                foreign_addr, foreign_port = _split_addr(row.get("ForeignAddr") or row.get("foreign_addr", ""))

                conn = NetworkConnection(
                    pid          = int(row.get("PID") or row.get("pid", 0)),
                    proto        = str(row.get("Proto") or row.get("proto", "")),
                    local_addr   = local_addr,
                    local_port   = local_port,
                    foreign_addr = foreign_addr,
                    foreign_port = foreign_port,
                    state        = str(row.get("State") or row.get("state") or ""),
                    process_name = str(row.get("Owner") or row.get("process_name") or ""),
                    created_time = str(row.get("Created") or ""),
                )
                conns.append(conn)
            except Exception as exc:
                logger.debug("NetScan row parse error: %s | row=%s", exc, row)

        logger.debug("NetScan parsed %d connections", len(conns))
        return conns


def _split_addr(addr_str: str) -> tuple[str, int]:
    """Split '192.168.1.1:443' or '[::1]:80' into (ip, port)."""
    addr_str = str(addr_str).strip()
    if not addr_str or addr_str in ("-", "N/A", "*"):
        return ("0.0.0.0", 0)
    # IPv6 bracket notation: [::1]:80
    if addr_str.startswith("["):
        bracket_end = addr_str.find("]")
        ip   = addr_str[1:bracket_end]
        port = int(addr_str[bracket_end + 2:] or 0)
        return (ip, port)
    # IPv4: 1.2.3.4:80
    if ":" in addr_str:
        parts = addr_str.rsplit(":", 1)
        try:
            return (parts[0], int(parts[1]))
        except (ValueError, IndexError):
            return (addr_str, 0)
    return (addr_str, 0)
