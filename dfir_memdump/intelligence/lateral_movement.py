"""
Lateral Movement Detector.

Detects indicators of host-to-host movement:
  1. Network connections on lateral-movement ports (SMB, RDP, WinRM, RPC/DCOM)
     initiated by non-system processes
  2. Known lateral movement tool names in process names or command lines
     (psexec, wmiexec, crackmapexec, impacket, etc.)
  3. Lateral movement command patterns in cmdlines
     (net use \\host, wmic /node:, invoke-command -ComputerName, etc.)
  4. lsass.exe connections to remote hosts (pass-the-hash / credential reuse)
"""

from __future__ import annotations
import logging
import re

from dfir_memdump.models import Finding, FindingCategory, Severity
from dfir_memdump.intelligence import BaseIntelModule, IntelContext
from dfir_memdump.intelligence.attck_mapper import get_mitre

logger = logging.getLogger(__name__)

# ── Lateral movement port signatures ─────────────────────────────────────────
# port → (protocol_label, mitre_key, description)
LATERAL_PORTS: dict[int, tuple[str, str, str]] = {
    445:  ("SMB",        "smb_shares",   "SMB / Windows Admin Shares (C$, ADMIN$, IPC$)"),
    139:  ("NetBIOS",    "smb_shares",   "NetBIOS Session Service — SMB over NetBIOS"),
    135:  ("RPC/DCOM",   "dcom",         "Microsoft RPC / DCOM endpoint mapper"),
    3389: ("RDP",        "rdp",          "Remote Desktop Protocol"),
    5985: ("WinRM-HTTP", "winrm",        "Windows Remote Management (HTTP)"),
    5986: ("WinRM-HTTPS","winrm",        "Windows Remote Management (HTTPS)"),
    22:   ("SSH",        "ssh",          "SSH — uncommon on Windows, may indicate attacker tooling"),
    23:   ("Telnet",     "cmd_shell",    "Telnet — legacy, high suspicion on modern Windows"),
    4444: ("Meterpreter","c2_http",      "Default Metasploit/Meterpreter listener port"),
    1234: ("Generic C2", "c2_http",      "Common default C2 listener port"),
}

# System process names that legitimately initiate connections on these ports
_SYSTEM_NET_PROCS = {
    "system", "svchost.exe", "lsass.exe", "services.exe",
    "wininit.exe", "smss.exe", "csrss.exe",
}

# ── Known lateral movement tool signatures ───────────────────────────────────
# (substring_to_match_in_name_or_cmdline, mitre_key, label)
LATERAL_TOOLS: list[tuple[str, str, str]] = [
    ("psexec",         "psexec",        "PsExec — remote process execution"),
    ("paexec",         "psexec",        "PaExec — PsExec clone"),
    ("wmiexec",        "dcom",          "Impacket wmiexec — WMI-based remote execution"),
    ("smbexec",        "smb_shares",    "Impacket smbexec — SMB-based remote execution"),
    ("atexec",         "scheduled_task","Impacket atexec — AT service remote execution"),
    ("dcomexec",       "dcom",          "Impacket dcomexec — DCOM remote execution"),
    ("crackmapexec",   "smb_shares",    "CrackMapExec — mass credential spraying / lateral movement"),
    ("cme",            "smb_shares",    "CrackMapExec (cme)"),
    ("bloodhound",     "ldap_enum",     "BloodHound — Active Directory enumeration"),
    ("sharphound",     "ldap_enum",     "SharpHound — BloodHound data collector"),
    ("invoke-psremoting","winrm",       "PowerShell Remoting"),
    ("impacket",       "smb_shares",    "Impacket framework"),
    ("mimikatz",       "credential_dump","Mimikatz — credential harvester"),
    ("rubeus",         "credential_dump","Rubeus — Kerberos ticket manipulation"),
    ("kerberoast",     "credential_dump","Kerberoasting attack tool"),
    ("secretsdump",    "credential_dump","Impacket secretsdump — remote credential extraction"),
]

# ── Command-line lateral movement patterns ───────────────────────────────────
# (compiled_regex, mitre_key, label)
LATERAL_CMD_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r'net\s+use\s+\\\\',               re.I), "smb_shares",    "net use — mapping a remote share"),
    (re.compile(r'net\s+view\s+\\\\',              re.I), "discovery",     "net view — remote host enumeration"),
    (re.compile(r'\bat\s+\\\\',                    re.I), "scheduled_task","AT command — remote scheduled task"),
    (re.compile(r'\bsc\s+\\\\',                    re.I), "service_create","SC — remote service creation"),
    (re.compile(r'wmic\s+/node:',                  re.I), "dcom",          "WMIC /node — remote WMI execution"),
    (re.compile(r'invoke-command\s+-computer',      re.I), "winrm",         "Invoke-Command -ComputerName — PS remoting"),
    (re.compile(r'enter-pssession',                 re.I), "winrm",         "Enter-PSSession — interactive PS remote session"),
    (re.compile(r'new-pssession',                   re.I), "winrm",         "New-PSSession — PS remote session"),
    (re.compile(r'runas\s+/netonly',               re.I), "token_impersonate","runas /netonly — network-only token"),
    (re.compile(r'reg\s+add\s+\\\\.*\\run',        re.I), "registry_run",  "Remote registry run-key persistence"),
    (re.compile(r'copy\s+.*\\\\\w+\\(?:admin|c)\$',re.I), "smb_shares",    "File copy to admin share"),
    (re.compile(r'xcopy\s+.*\\\\\w+\\',            re.I), "smb_shares",    "xcopy to remote share"),
    (re.compile(r'robocopy\s+.*\\\\\w+\\',         re.I), "smb_shares",    "robocopy to remote share"),
]


class LateralMovementDetector(BaseIntelModule):
    name = "lateral_movement"

    def analyze(self, ctx: IntelContext) -> list[Finding]:
        findings: list[Finding] = []

        pid_map = ctx.pid_to_process

        # ── 1. Lateral movement port connections ──────────────────────────────
        for conn in ctx.connections:
            port = conn.foreign_port
            if port not in LATERAL_PORTS:
                continue

            # Skip loopback
            if conn.foreign_addr in ("127.0.0.1", "::1", "0.0.0.0", ""):
                continue

            proc_name_lower = (conn.process_name or "").lower()
            if proc_name_lower in _SYSTEM_NET_PROCS:
                continue

            proto_label, mitre_key, port_desc = LATERAL_PORTS[port]
            findings.append(Finding(
                severity        = Severity.HIGH,
                category        = FindingCategory.NETWORK,
                title           = f"Lateral movement port: {proc_name_lower} → {conn.foreign_addr}:{port} ({proto_label})",
                description     = (
                    f"Process '{conn.process_name}' (PID {conn.pid}) has an {conn.state or 'active'} "
                    f"{proto_label} connection to {conn.foreign_addr}:{port}. "
                    f"{port_desc}. "
                    "Non-system processes connecting on lateral movement ports warrant investigation."
                ),
                evidence        = (
                    f"PID {conn.pid} ({conn.process_name})\n"
                    f"  {conn.proto}  {conn.local_addr}:{conn.local_port} → "
                    f"{conn.foreign_addr}:{conn.foreign_port}  [{conn.state or 'N/A'}]"
                ),
                mitre           = get_mitre(mitre_key),
                source_module   = self.name,
                source_plugin   = "windows.netscan.NetScan",
                affected_pid    = conn.pid,
                affected_process= conn.process_name,
                iocs            = [
                    f"ip:{conn.foreign_addr}",
                    f"pid:{conn.pid}",
                    f"port:{conn.foreign_port}",
                ],
            ))

        # ── 2. Known lateral movement tool names ──────────────────────────────
        for proc in ctx.processes:
            name_lower = proc.name.lower()
            cmdline_lower = ""
            cmdline_entry = ctx.pid_to_cmdline.get(proc.pid)
            if cmdline_entry and cmdline_entry.cmdline:
                cmdline_lower = cmdline_entry.cmdline.lower()

            for substring, mitre_key, label in LATERAL_TOOLS:
                if substring in name_lower or substring in cmdline_lower:
                    findings.append(Finding(
                        severity        = Severity.CRITICAL,
                        category        = FindingCategory.NETWORK,
                        title           = f"Lateral movement tool: {label} (PID {proc.pid})",
                        description     = (
                            f"Process '{proc.name}' (PID {proc.pid}) matches the signature of a known "
                            f"lateral movement tool: {label}. These tools are used to move between "
                            "hosts using stolen credentials, pass-the-hash, or Kerberos ticket abuse."
                        ),
                        evidence        = (
                            f"Process: {proc.name} (PID {proc.pid})\n"
                            f"Path: {proc.image_path or 'N/A'}\n"
                            f"Cmdline: {cmdline_entry.cmdline if cmdline_entry else 'N/A'}"
                        ),
                        mitre           = get_mitre(mitre_key),
                        source_module   = self.name,
                        source_plugin   = "windows.pslist.PsList",
                        affected_pid    = proc.pid,
                        affected_process= proc.name,
                        iocs            = [
                            f"process_name:{proc.name}",
                            f"pid:{proc.pid}",
                        ],
                    ))
                    break  # one finding per process per tool match

        # ── 3. Lateral movement command patterns in cmdlines ──────────────────
        for entry in ctx.cmdlines:
            if not entry.cmdline:
                continue
            for pattern, mitre_key, label in LATERAL_CMD_PATTERNS:
                if pattern.search(entry.cmdline):
                    proc = pid_map.get(entry.pid)
                    proc_name = proc.name if proc else entry.name
                    findings.append(Finding(
                        severity        = Severity.HIGH,
                        category        = FindingCategory.NETWORK,
                        title           = f"Lateral movement cmdline: {label} (PID {entry.pid})",
                        description     = (
                            f"The command line of PID {entry.pid} ({proc_name}) matches the pattern "
                            f"'{label}'. This command is commonly used to interact with remote hosts, "
                            "execute code remotely, or stage files for lateral movement."
                        ),
                        evidence        = f"PID {entry.pid} ({proc_name})\nCmdline: {entry.cmdline}",
                        mitre           = get_mitre(mitre_key),
                        source_module   = self.name,
                        source_plugin   = "windows.cmdline.CmdLine",
                        affected_pid    = entry.pid,
                        affected_process= proc_name,
                        iocs            = [
                            f"cmdline:{entry.cmdline[:120]}",
                            f"pid:{entry.pid}",
                        ],
                    ))
                    break  # one finding per cmdline

        # ── 4. lsass outbound connections (pass-the-hash / credential reuse) ──
        for conn in ctx.connections:
            if (conn.process_name or "").lower() != "lsass.exe":
                continue
            if conn.foreign_addr in ("127.0.0.1", "::1", "0.0.0.0", ""):
                continue
            if conn.state not in ("ESTABLISHED", None):
                continue
            findings.append(Finding(
                severity        = Severity.CRITICAL,
                category        = FindingCategory.CREDENTIAL,
                title           = f"lsass.exe outbound connection: → {conn.foreign_addr}:{conn.foreign_port}",
                description     = (
                    "lsass.exe (Local Security Authority Subsystem) has an outbound connection to a "
                    f"remote host ({conn.foreign_addr}:{conn.foreign_port}). lsass normally does not "
                    "initiate outbound connections. This is a strong indicator of pass-the-hash, "
                    "pass-the-ticket, or overpass-the-hash credential reuse for lateral movement."
                ),
                evidence        = (
                    f"lsass.exe (PID {conn.pid})\n"
                    f"  {conn.proto}  {conn.local_addr}:{conn.local_port} → "
                    f"{conn.foreign_addr}:{conn.foreign_port}  [{conn.state or 'N/A'}]"
                ),
                mitre           = get_mitre("pass_the_hash"),
                source_module   = self.name,
                source_plugin   = "windows.netscan.NetScan",
                affected_pid    = conn.pid,
                affected_process= "lsass.exe",
                iocs            = [
                    f"ip:{conn.foreign_addr}",
                    f"pid:{conn.pid}",
                ],
            ))

        logger.info("LateralMovementDetector: %d findings", len(findings))
        return findings
