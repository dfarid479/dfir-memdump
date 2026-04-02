"""
C2 detector — cross-references network connections against:
  1. Known C2 framework default ports / patterns
  2. Feodo botnet C2 IP feed (abuse.ch)
  3. Suspicious connection patterns (internal C2, non-standard protocols)
"""

from __future__ import annotations
import ipaddress
import json
import logging
import time
from pathlib import Path

import requests

from dfir_memdump.config import settings
from dfir_memdump.exceptions import FeedError
from dfir_memdump.models import Finding, FindingCategory, Severity, NetworkConnection
from dfir_memdump.intelligence import BaseIntelModule, IntelContext
from dfir_memdump.intelligence.attck_mapper import get_mitre

logger = logging.getLogger(__name__)

# ─── Known C2 Framework Default Ports ────────────────────────────────────────
C2_PORTS: dict[int, str] = {
    # Cobalt Strike defaults
    50050: "Cobalt Strike Team Server",
    2222:  "Cobalt Strike alt",
    # Metasploit
    4444:  "Metasploit default handler",
    4445:  "Metasploit alt",
    # Empire / Starkiller
    1337:  "Empire/Starkiller default",
    # Havoc C2
    40056: "Havoc C2 default",
    # Sliver
    31337: "Sliver C2 default",
    8888:  "Sliver/misc C2",
    # Brute Ratel
    53755: "Brute Ratel default",
    # Generic RAT ports
    9999:  "Common RAT port",
    6666:  "Common RAT port",
    7777:  "Common RAT port",
}

# Well-known C2 over common ports — flag if used by unexpected processes
SUSPICIOUS_PORT_PROCS: dict[int, str] = {
    443:  "HTTPS C2 — common Cobalt Strike / implant channel",
    80:   "HTTP C2 — common implant channel",
    8080: "HTTP alt C2",
    53:   "DNS C2 — possible DNS tunneling",
}

# Private IP ranges — flag high-port connections for lateral movement
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Processes that should NEVER have outbound network connections
NO_NETWORK_PROCS = {"lsass.exe", "csrss.exe", "wininit.exe", "smss.exe", "services.exe"}


class C2Detector(BaseIntelModule):
    name = "c2_detector"

    def __init__(self):
        self._feodo: dict[str, dict] = {}
        self._feodo_loaded = False

    def analyze(self, ctx: IntelContext) -> list[Finding]:
        self._load_feodo()
        findings: list[Finding] = []

        for conn in ctx.connections:
            if conn.state not in (None, "", "ESTABLISHED", "CLOSE_WAIT", "SYN_SENT"):
                continue
            if conn.foreign_addr in ("0.0.0.0", "127.0.0.1", "::", "::1", "*"):
                continue

            # 1. Feodo botnet C2 IP match
            feodo_entry = self._feodo.get(conn.foreign_addr)
            if feodo_entry:
                proc_name = ctx.pid_to_process.get(conn.pid, type("x", (), {"name": conn.process_name or "unknown"})()).name
                findings.append(Finding(
                    severity         = Severity.CRITICAL,
                    category         = FindingCategory.C2,
                    title            = f"Feodo botnet C2: {conn.foreign_addr}:{conn.foreign_port} ({feodo_entry.get('malware', 'unknown')})",
                    description      = (
                        f"PID {conn.pid} ({proc_name}) has an active connection to a known Feodo "
                        f"botnet C2 IP: {conn.foreign_addr}:{conn.foreign_port}. "
                        f"Malware family: {feodo_entry.get('malware', 'unknown')}. "
                        f"First seen: {feodo_entry.get('first_seen', 'unknown')}."
                    ),
                    evidence         = f"{conn.proto} {conn.local_addr}:{conn.local_port} → {conn.foreign_addr}:{conn.foreign_port} [{conn.state}]",
                    mitre            = get_mitre("feodo_c2"),
                    source_module    = self.name,
                    source_plugin    = "windows.netscan.NetScan",
                    affected_pid     = conn.pid,
                    affected_process = proc_name,
                    iocs             = [f"ip:{conn.foreign_addr}", f"port:{conn.foreign_port}"],
                ))
                continue

            # 2. Known C2 framework default port
            if conn.foreign_port in C2_PORTS:
                proc_name = conn.process_name or "unknown"
                findings.append(Finding(
                    severity         = Severity.HIGH,
                    category         = FindingCategory.C2,
                    title            = f"C2 framework default port: {conn.foreign_addr}:{conn.foreign_port} ({C2_PORTS[conn.foreign_port]})",
                    description      = (
                        f"PID {conn.pid} ({proc_name}) is connected to {conn.foreign_addr}:{conn.foreign_port}. "
                        f"This port is the default for {C2_PORTS[conn.foreign_port]}."
                    ),
                    evidence         = f"{conn.proto} → {conn.foreign_addr}:{conn.foreign_port} [{conn.state}]",
                    mitre            = get_mitre("c2_known_port"),
                    source_module    = self.name,
                    source_plugin    = "windows.netscan.NetScan",
                    affected_pid     = conn.pid,
                    affected_process = proc_name,
                    iocs             = [f"ip:{conn.foreign_addr}", f"port:{conn.foreign_port}"],
                ))

            # 3. System processes with unexpected network connections
            proc = ctx.pid_to_process.get(conn.pid)
            proc_name_lower = (proc.name if proc else conn.process_name or "").lower()
            if proc_name_lower in NO_NETWORK_PROCS:
                findings.append(Finding(
                    severity         = Severity.CRITICAL,
                    category         = FindingCategory.ANOMALY,
                    title            = f"System process with network connection: {proc_name_lower}",
                    description      = (
                        f"{proc_name_lower} (PID {conn.pid}) has an outbound connection to "
                        f"{conn.foreign_addr}:{conn.foreign_port}. This process should never "
                        "initiate network connections and this strongly indicates process injection."
                    ),
                    evidence         = f"{conn.proto} → {conn.foreign_addr}:{conn.foreign_port} [{conn.state}]",
                    mitre            = get_mitre("process_injection"),
                    source_module    = self.name,
                    source_plugin    = "windows.netscan.NetScan",
                    affected_pid     = conn.pid,
                    affected_process = proc_name_lower,
                    iocs             = [f"ip:{conn.foreign_addr}", f"pid:{conn.pid}"],
                ))

        logger.info("C2Detector: %d findings", len(findings))
        return findings

    def _load_feodo(self) -> None:
        """Load Feodo IP blocklist from cache or fetch fresh."""
        if self._feodo_loaded:
            return

        cache_path: Path = settings.feodo_cache_path
        ttl_hours = settings.feodo_cache_ttl_hours

        # Use cache if fresh enough
        if cache_path.exists():
            mtime = cache_path.stat().st_mtime
            age_hours = (time.time() - mtime) / 3600
            if age_hours < ttl_hours:
                try:
                    with open(cache_path) as f:
                        self._feodo = json.load(f)
                    self._feodo_loaded = True
                    logger.debug("Feodo: loaded %d IPs from cache", len(self._feodo))
                    return
                except Exception as exc:
                    logger.warning("Feodo cache load failed: %s", exc)

        # Fetch fresh
        try:
            resp = requests.get(settings.feodo_feed_url, timeout=15)
            resp.raise_for_status()
            raw = resp.json()

            # Feed format: list of {"ip_address": ..., "port": ..., "malware": ..., "first_seen": ...}
            self._feodo = {}
            for entry in (raw if isinstance(raw, list) else raw.get("blocklist", [])):
                ip = entry.get("ip_address") or entry.get("ip")
                if ip:
                    self._feodo[ip] = {
                        "port":       entry.get("port"),
                        "malware":    entry.get("malware", "unknown"),
                        "first_seen": entry.get("first_seen"),
                    }

            # Save to cache
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(cache_path, "w") as f:
                json.dump(self._feodo, f)

            self._feodo_loaded = True
            logger.info("Feodo: fetched and cached %d C2 IPs", len(self._feodo))

        except Exception as exc:
            logger.warning("Feodo feed fetch failed (using empty list): %s", exc)
            self._feodo = {}
            self._feodo_loaded = True
