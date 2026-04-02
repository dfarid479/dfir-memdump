"""
Anomaly detector — pure logic, no network calls.

Detects:
  1. Parent-child process anomalies (Word spawning cmd.exe, etc.)
  2. Process masquerading (svchost.exe from wrong path)
  3. Hollow process indicators (PAGE_EXECUTE_READWRITE regions not backed by a loaded module)
  4. Suspicious process names (typosquatting known system processes)
"""

from __future__ import annotations
import logging
import re

from dfir_memdump.models import Finding, FindingCategory, Severity
from dfir_memdump.intelligence import BaseIntelModule, IntelContext
from dfir_memdump.intelligence.attck_mapper import get_mitre

logger = logging.getLogger(__name__)

# ─── Known-good parent → child relationships ────────────────────────────────
# Format: {child_name_lower: set_of_valid_parent_names_lower}
# Any parent NOT in the set is suspicious.
VALID_PARENTS: dict[str, set[str]] = {
    "smss.exe":         {"system", ""},
    "csrss.exe":        {"smss.exe", ""},
    "wininit.exe":      {"smss.exe"},
    "winlogon.exe":     {"smss.exe"},
    "services.exe":     {"wininit.exe"},
    "lsass.exe":        {"wininit.exe"},
    "svchost.exe":      {"services.exe", "msmpeng.exe"},
    "taskhost.exe":     {"services.exe"},
    "taskhostw.exe":    {"services.exe"},
    "spoolsv.exe":      {"services.exe"},
    "explorer.exe":     {"userinit.exe", "winlogon.exe"},
    "userinit.exe":     {"winlogon.exe"},
    "searchindexer.exe":{"services.exe"},
    "wermgr.exe":       {"wininit.exe", "svchost.exe"},
    "audiodg.exe":      {"svchost.exe"},
    "fontdrvhost.exe":  {"wininit.exe", "winlogon.exe"},
    "dwm.exe":          {"winlogon.exe"},
    "sihost.exe":       {"svchost.exe"},
    "runtimebroker.exe":{"svchost.exe"},
}

# Office → scripting engines spawns are high-confidence IOCs
OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe", "onenote.exe"}
SCRIPTING_ENGINES = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe"}

# Known system process paths (lower-case fragments that must appear in the path)
SYSTEM_PROC_PATHS: dict[str, str] = {
    "svchost.exe":       "system32",
    "lsass.exe":         "system32",
    "csrss.exe":         "system32",
    "services.exe":      "system32",
    "winlogon.exe":      "system32",
    "wininit.exe":       "system32",
    "explorer.exe":      "windows",
    "taskhost.exe":      "system32",
    "taskhostw.exe":     "system32",
    "smss.exe":          "system32",
    "spoolsv.exe":       "system32",
    "dwm.exe":           "system32",
}

# Common typosquatting targets
TYPOSQUATS: dict[str, list[str]] = {
    "svchost.exe":    ["svch0st.exe", "scvhost.exe", "svhost.exe", "svchos.exe", "svhost32.exe"],
    "lsass.exe":      ["lsas.exe", "lsass32.exe", "lssas.exe", "lsasss.exe"],
    "explorer.exe":   ["expl0rer.exe", "explor.exe", "iexplore.exe"],  # iexplore from odd paths
    "winlogon.exe":   ["winlogon32.exe", "winIogon.exe"],
    "csrss.exe":      ["csrs.exe", "cssrs.exe"],
    "services.exe":   ["service.exe", "services32.exe"],
}


class AnomalyDetector(BaseIntelModule):
    name = "anomaly_detector"

    def analyze(self, ctx: IntelContext) -> list[Finding]:
        findings: list[Finding] = []

        for proc in ctx.processes:
            name_lower = proc.name.lower()
            path_lower = (proc.image_path or "").lower()

            # 1. Office → scripting engine spawns
            parent = ctx.pid_to_process.get(proc.ppid)
            parent_name = (parent.name or "").lower() if parent else ""

            if name_lower in SCRIPTING_ENGINES and parent_name in OFFICE_PROCESSES:
                cmdline_entry = ctx.pid_to_cmdline.get(proc.pid)
                cmdline = cmdline_entry.cmdline if cmdline_entry else ""
                findings.append(Finding(
                    severity        = Severity.CRITICAL,
                    category        = FindingCategory.ANOMALY,
                    title           = f"Office application spawned scripting engine: {parent_name} → {name_lower}",
                    description     = (
                        f"PID {proc.pid} ({proc.name}) was spawned by {parent_name} (PID {proc.ppid}). "
                        "Office applications spawning cmd.exe, PowerShell, or script hosts is a primary "
                        "macro malware / phishing payload execution indicator."
                    ),
                    evidence        = f"Parent: {parent_name} (PID {proc.ppid}) → Child: {proc.name} (PID {proc.pid}) | cmdline: {cmdline or 'N/A'}",
                    mitre           = get_mitre("powershell") if "powershell" in name_lower else get_mitre("cmd_shell"),
                    source_module   = self.name,
                    source_plugin   = "windows.pslist.PsList",
                    affected_pid    = proc.pid,
                    affected_process= proc.name,
                    iocs            = [f"pid:{proc.pid}", f"parent_pid:{proc.ppid}"],
                ))

            # 2. Known parent-child violations
            if name_lower in VALID_PARENTS:
                valid_set = VALID_PARENTS[name_lower]
                if parent_name not in valid_set and parent_name:
                    findings.append(Finding(
                        severity        = Severity.HIGH,
                        category        = FindingCategory.ANOMALY,
                        title           = f"Unexpected parent: {parent_name} → {name_lower}",
                        description     = (
                            f"{proc.name} (PID {proc.pid}) should be spawned by "
                            f"{', '.join(valid_set) or 'System'}, but was spawned by "
                            f"{parent_name} (PID {proc.ppid}). This may indicate process injection "
                            "or a trojanized parent process."
                        ),
                        evidence        = f"Expected parent(s): {valid_set} | Actual parent: {parent_name} (PID {proc.ppid})",
                        mitre           = get_mitre("parent_child_anomaly"),
                        source_module   = self.name,
                        source_plugin   = "windows.pslist.PsList",
                        affected_pid    = proc.pid,
                        affected_process= proc.name,
                    ))

            # 3. Process masquerading — running from non-standard path
            if name_lower in SYSTEM_PROC_PATHS and path_lower:
                required_fragment = SYSTEM_PROC_PATHS[name_lower]
                if required_fragment not in path_lower:
                    findings.append(Finding(
                        severity        = Severity.CRITICAL,
                        category        = FindingCategory.ANOMALY,
                        title           = f"Process masquerading: {proc.name} running from non-standard path",
                        description     = (
                            f"{proc.name} (PID {proc.pid}) is running from '{proc.image_path}'. "
                            f"Legitimate {proc.name} should run from a path containing '{required_fragment}'. "
                            "This is a strong indicator of malware impersonating a system process."
                        ),
                        evidence        = f"Image path: {proc.image_path}",
                        mitre           = get_mitre("process_masquerading"),
                        source_module   = self.name,
                        source_plugin   = "windows.pslist.PsList",
                        affected_pid    = proc.pid,
                        affected_process= proc.name,
                        iocs            = [f"filepath:{proc.image_path}"],
                    ))

            # 4. Typosquatting
            for legit, fakes in TYPOSQUATS.items():
                if name_lower in fakes:
                    findings.append(Finding(
                        severity        = Severity.HIGH,
                        category        = FindingCategory.ANOMALY,
                        title           = f"Typosquatted system process: '{proc.name}' mimics '{legit}'",
                        description     = (
                            f"Process '{proc.name}' (PID {proc.pid}) appears to typosquat the "
                            f"legitimate system process '{legit}'. This is a common evasion technique."
                        ),
                        evidence        = f"Observed name: {proc.name} | Path: {proc.image_path or 'N/A'}",
                        mitre           = get_mitre("renamed_system_binary"),
                        source_module   = self.name,
                        source_plugin   = "windows.pslist.PsList",
                        affected_pid    = proc.pid,
                        affected_process= proc.name,
                    ))

        # 5. Hollow process detection — malfind entries not backed by a loaded DLL
        for entry in ctx.malfind:
            if "PAGE_EXECUTE_READWRITE" not in (entry.protection or ""):
                continue

            # Check if the VAD region is backed by a loaded module
            pid_dlls = ctx.pid_to_dlls.get(entry.pid, [])
            vad_start_int = int(entry.vad_start, 16) if entry.vad_start.startswith("0x") else 0

            backed_by_module = any(
                int(dll.base, 16) == vad_start_int
                for dll in pid_dlls
                if dll.base.startswith("0x")
            )

            if not backed_by_module:
                proc_name = ctx.pid_to_process.get(entry.pid, type("x", (), {"name": entry.process_name})()).name
                findings.append(Finding(
                    severity        = Severity.CRITICAL,
                    category        = FindingCategory.INJECTION,
                    title           = f"Hollow process / unbacked executable memory: PID {entry.pid} ({entry.process_name})",
                    description     = (
                        f"Process {entry.process_name} (PID {entry.pid}) has a VAD region at "
                        f"{entry.vad_start} marked {entry.protection} that is not backed by any "
                        "loaded module in DllList. This is a strong indicator of process hollowing "
                        "or reflective DLL injection."
                    ),
                    evidence        = (
                        f"VAD: {entry.vad_start}-{entry.vad_end} | Protection: {entry.protection} | "
                        f"No matching DLL base address found in {len(pid_dlls)} loaded modules"
                    ),
                    mitre           = get_mitre("process_hollowing"),
                    source_module   = self.name,
                    source_plugin   = "windows.malfind.Malfind",
                    affected_pid    = entry.pid,
                    affected_process= entry.process_name,
                    iocs            = [f"pid:{entry.pid}", f"vad:{entry.vad_start}"],
                ))

        logger.info("AnomalyDetector: %d findings", len(findings))
        return findings
