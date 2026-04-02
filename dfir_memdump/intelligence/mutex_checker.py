"""
Mutex / Handle Checker.

Analyses the windows.handles output for:
  1. Named mutexes matching known malware signatures (exact and regex)
  2. Suspicious handle patterns: process handles opened cross-process
     (one process holding a handle to another process's memory — injection indicator)
  3. High-value registry key handles (SAM, SECURITY — credential access)

Mutexes are highly malware-specific — Cobalt Strike, Meterpreter, RATs, and
ransomware families all use characteristic named mutex strings that survive
long after the binary has been obfuscated or renamed.
"""

from __future__ import annotations
import logging
import re

from dfir_memdump.models import Finding, FindingCategory, Severity
from dfir_memdump.intelligence import BaseIntelModule, IntelContext
from dfir_memdump.intelligence.attck_mapper import get_mitre

logger = logging.getLogger(__name__)

# ── Known-bad mutex signatures ────────────────────────────────────────────────
# (pattern_type, value_or_regex, label, mitre_key)
# pattern_type: "exact" (case-insensitive substring) or "regex"
KNOWN_BAD_MUTEXES: list[tuple[str, str, str, str]] = [
    # Cobalt Strike default/generated beacon mutexes
    ("regex",  r"Global\\[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}",
               "Cobalt Strike GUID-style global mutex", "process_injection"),
    ("exact",  "AMSINT32",          "Amadey banking trojan mutex",            "process_injection"),
    ("exact",  "MeterpreterMutex",  "Metasploit Meterpreter mutex",           "process_injection"),
    ("exact",  "winmgr_mutex",      "WannaCry ransomware mutex",              "impact_data"),
    ("exact",  "Global\\MsWinZonesCacheCounterMutexA",
               "WannaCry variant mutex",                                       "impact_data"),
    ("exact",  "Mutex_For_Process", "Generic RAT synchronisation mutex",      "process_injection"),
    # Common RAT mutexes
    ("exact",  "NjRat",             "NjRAT remote access trojan",             "c2_http"),
    ("exact",  "DarkComet",         "DarkComet RAT",                          "c2_http"),
    ("exact",  "Quasar",            "Quasar RAT",                             "c2_http"),
    ("exact",  "AsyncRAT",          "AsyncRAT remote access trojan",          "c2_http"),
    ("exact",  "BlackRAT",          "BlackRAT remote access trojan",          "c2_http"),
    ("exact",  "RemcosRAT",         "Remcos RAT",                             "c2_http"),
    ("exact",  "AgentTesla",        "Agent Tesla infostealer",                "credential_dump"),
    ("exact",  "RedLineMutex",      "RedLine Stealer",                        "credential_dump"),
    # Mimikatz
    ("exact",  "Mimikatz",          "Mimikatz credential dumper mutex",       "credential_dump"),
    # Ransomware
    ("exact",  "Global\\REvil",     "REvil/Sodinokibi ransomware mutex",      "impact_data"),
    ("exact",  "LockBit",           "LockBit ransomware mutex",               "impact_data"),
    ("exact",  "BlackCat",          "BlackCat/ALPHV ransomware mutex",        "impact_data"),
    ("regex",  r"RYUK_[A-Za-z0-9]+","Ryuk ransomware mutex pattern",          "impact_data"),
    # Empire / Havoc / Sliver
    ("exact",  "Global\\DefaultMutexNameDotnet", "Empire/.NET default mutex", "process_injection"),
    # Generic high-suspicion patterns
    ("regex",  r"^[A-F0-9]{32}$",   "32-char hex mutex — possible malware GUID", "process_injection"),
]

# Compile regex patterns once
_COMPILED_BAD: list[tuple[str, re.Pattern | str, str, str]] = []
for _ptype, _val, _label, _mitre in KNOWN_BAD_MUTEXES:
    if _ptype == "regex":
        _COMPILED_BAD.append((_ptype, re.compile(_val, re.IGNORECASE), _label, _mitre))
    else:
        _COMPILED_BAD.append((_ptype, _val.lower(), _label, _mitre))

# ── Sensitive registry key fragments ─────────────────────────────────────────
_SENSITIVE_REGISTRY_KEYS = [
    r"\sam",
    r"\security",
    r"\system\currentcontrolset\control\lsa",
    r"\system\currentcontrolset\services",
    r"\\sam\\sam",
]

# ── System processes that legitimately hold cross-process handles ─────────────
_LEGIT_CROSS_PROC = {
    "system", "svchost.exe", "services.exe", "wininit.exe",
    "csrss.exe", "lsass.exe", "winlogon.exe", "smss.exe",
    "antimalware service executable", "msmpeng.exe",
}


class MutexChecker(BaseIntelModule):
    name = "mutex_checker"

    def analyze(self, ctx: IntelContext) -> list[Finding]:
        if not ctx.handles:
            logger.info("MutexChecker: no handle data (windows.handles not run or returned empty)")
            return []

        findings: list[Finding] = []

        # ── 1. Known-bad mutex signatures ─────────────────────────────────────
        for h in ctx.handles:
            if h.handle_type.lower() not in ("mutant", "mutex"):
                continue
            if not h.name:
                continue

            name_lower = h.name.lower()
            for ptype, pattern, label, mitre_key in _COMPILED_BAD:
                matched = False
                if ptype == "regex":
                    matched = bool(pattern.search(h.name))
                else:
                    matched = pattern in name_lower

                if matched:
                    findings.append(Finding(
                        severity        = Severity.CRITICAL,
                        category        = FindingCategory.MALWARE,
                        title           = f"Known malware mutex: '{h.name}' — {label}",
                        description     = (
                            f"Process '{h.process_name}' (PID {h.pid}) holds a named mutex matching "
                            f"the signature of '{label}'. Named mutexes are used by malware to prevent "
                            "multiple instances of itself from running and are highly specific to malware "
                            "families. This is a strong indicator of active infection."
                        ),
                        evidence        = (
                            f"PID {h.pid} ({h.process_name})\n"
                            f"Handle type: {h.handle_type}\n"
                            f"Mutex name:  {h.name}\n"
                            f"Access mask: {h.granted_access}"
                        ),
                        mitre           = get_mitre(mitre_key),
                        source_module   = self.name,
                        source_plugin   = "windows.handles.Handles",
                        affected_pid    = h.pid,
                        affected_process= h.process_name,
                        iocs            = [f"mutex:{h.name}", f"pid:{h.pid}"],
                    ))
                    break  # one finding per handle

        # ── 2. Sensitive registry key handles ─────────────────────────────────
        for h in ctx.handles:
            if h.handle_type.lower() not in ("key", "regkey"):
                continue
            if not h.name:
                continue
            name_lower = h.name.lower()
            for key_frag in _SENSITIVE_REGISTRY_KEYS:
                if key_frag in name_lower:
                    proc_name_lower = h.process_name.lower()
                    # lsass, svchost, system legitimately hold SAM/SECURITY keys
                    if proc_name_lower in ("lsass.exe", "system", "svchost.exe", "services.exe"):
                        continue
                    findings.append(Finding(
                        severity        = Severity.HIGH,
                        category        = FindingCategory.CREDENTIAL,
                        title           = f"Sensitive registry key opened by '{h.process_name}': {h.name[:60]}",
                        description     = (
                            f"Process '{h.process_name}' (PID {h.pid}) holds an open handle to the "
                            f"registry key '{h.name}', which contains sensitive credential or security "
                            "data. Non-system processes accessing SAM, SECURITY, or LSA registry hives "
                            "is a strong indicator of credential dumping."
                        ),
                        evidence        = (
                            f"PID {h.pid} ({h.process_name})\n"
                            f"Registry key: {h.name}\n"
                            f"Access mask:  {h.granted_access}"
                        ),
                        mitre           = get_mitre("credential_dump"),
                        source_module   = self.name,
                        source_plugin   = "windows.handles.Handles",
                        affected_pid    = h.pid,
                        affected_process= h.process_name,
                        iocs            = [f"regkey:{h.name}", f"pid:{h.pid}"],
                    ))
                    break

        # ── 3. Cross-process handle (Process type) — injection indicator ──────
        # A non-system process holding a handle to another process's address space
        # is a classic injection setup (e.g. OpenProcess → WriteProcessMemory → CreateRemoteThread)
        pid_set = {p.pid for p in ctx.processes}
        for h in ctx.handles:
            if h.handle_type.lower() != "process":
                continue
            holder_lower = h.process_name.lower()
            if holder_lower in _LEGIT_CROSS_PROC:
                continue
            # Try to resolve the target PID from the handle name (vol3 sometimes shows it)
            # Even without resolution, a non-system process holding a Process handle is worth flagging
            findings.append(Finding(
                severity        = Severity.MEDIUM,
                category        = FindingCategory.INJECTION,
                title           = f"Cross-process handle held by '{h.process_name}' (PID {h.pid})",
                description     = (
                    f"'{h.process_name}' (PID {h.pid}) holds an open Process-type handle "
                    f"(value {h.handle_value}, access {h.granted_access}). "
                    "Non-system processes opening handles to other processes may be staging "
                    "process injection via OpenProcess → WriteProcessMemory → CreateRemoteThread."
                ),
                evidence        = (
                    f"Holder: {h.process_name} (PID {h.pid})\n"
                    f"Handle: type=Process, value={h.handle_value}, access={h.granted_access}\n"
                    f"Target name (if available): {h.name or 'N/A'}"
                ),
                mitre           = get_mitre("process_injection"),
                source_module   = self.name,
                source_plugin   = "windows.handles.Handles",
                affected_pid    = h.pid,
                affected_process= h.process_name,
                iocs            = [f"pid:{h.pid}"],
            ))

        logger.info("MutexChecker: %d findings from %d handles", len(findings), len(ctx.handles))
        return findings
