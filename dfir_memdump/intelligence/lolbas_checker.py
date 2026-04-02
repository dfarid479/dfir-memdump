"""
LOLBAS checker — detect Living Off the Land Binary and Script abuses.

Cross-references process command lines against known-malicious invocation
patterns for Windows system binaries (certutil, mshta, regsvr32, etc.).
"""

from __future__ import annotations
import re
import logging

from dfir_memdump.models import Finding, FindingCategory, Severity
from dfir_memdump.intelligence import BaseIntelModule, IntelContext
from dfir_memdump.intelligence.attck_mapper import get_mitre, ATTCK_MAP

logger = logging.getLogger(__name__)


# Each rule: (binary_name_lower, re_pattern_for_cmdline, severity, description, attck_key)
LOLBAS_RULES: list[tuple] = [
    # certutil — decode / download
    ("certutil.exe", r"-(?:url|URL)cache.*http",       Severity.CRITICAL, "certutil downloading payload from URL",               "certutil"),
    ("certutil.exe", r"-(?:decode|DECODE)",             Severity.HIGH,     "certutil decoding obfuscated file",                   "certutil"),
    ("certutil.exe", r"-(?:encode|ENCODE)",             Severity.MEDIUM,   "certutil encoding file (possible exfil staging)",     "certutil"),

    # mshta — execute VBScript/JScript from URL
    ("mshta.exe",    r"https?://",                      Severity.CRITICAL, "mshta loading script from remote URL",                "mshta"),
    ("mshta.exe",    r"vbscript:",                      Severity.CRITICAL, "mshta executing inline VBScript",                    "mshta"),
    ("mshta.exe",    r"javascript:",                    Severity.CRITICAL, "mshta executing inline JavaScript",                  "mshta"),

    # regsvr32 — squiblydoo
    ("regsvr32.exe", r"/[sS].*?/[nN].*?/[uU].*?/[iI]:https?://", Severity.CRITICAL, "regsvr32 squiblydoo (remote SCT file)", "regsvr32"),
    ("regsvr32.exe", r"https?://",                      Severity.HIGH,     "regsvr32 loading from remote URL",                   "regsvr32"),

    # rundll32 — proxy execute
    ("rundll32.exe", r"javascript:",                    Severity.CRITICAL, "rundll32 executing JavaScript",                      "rundll32"),
    ("rundll32.exe", r"shell32.*ShellExec",             Severity.HIGH,     "rundll32 proxy shell execution",                     "rundll32"),

    # PowerShell — encoded/hidden commands
    ("powershell.exe", r"(?:-e|-en|-enc|-EncodedCommand)\s+[A-Za-z0-9+/=]{20,}", Severity.CRITICAL, "PowerShell encoded command",                "powershell"),
    ("powershell.exe", r"-(?:w|win|window)\s+hid",     Severity.HIGH,     "PowerShell hidden window",                           "powershell"),
    ("powershell.exe", r"-(?:nop|NonInteractive).*?-(?:c|Command|ec)\s+", Severity.HIGH, "PowerShell non-interactive + command",   "powershell"),
    ("powershell.exe", r"(?:IEX|Invoke-Expression)\s*\(", Severity.CRITICAL, "PowerShell IEX (code injection vector)",          "powershell"),
    ("powershell.exe", r"(?:Net\.WebClient|Invoke-WebRequest|wget|curl).*?(?:Download|Get-Content)", Severity.CRITICAL, "PowerShell downloading content", "powershell"),
    ("powershell.exe", r"(?:bypass|Bypass)",            Severity.HIGH,     "PowerShell execution policy bypass",                 "powershell"),

    # wscript / cscript
    ("wscript.exe",  r"https?://",                      Severity.CRITICAL, "wscript executing remote script",                    "wscript_cscript"),
    ("cscript.exe",  r"https?://",                      Severity.CRITICAL, "cscript executing remote script",                    "wscript_cscript"),

    # bitsadmin — download
    ("bitsadmin.exe", r"/(?:transfer|download|upload)", Severity.HIGH,     "bitsadmin file transfer (download/upload)",          "bitsadmin"),
    ("bitsadmin.exe", r"https?://",                     Severity.HIGH,     "bitsadmin downloading from URL",                     "bitsadmin"),

    # wmic — spawn process / execute
    ("wmic.exe",     r"process\s+call\s+create",        Severity.CRITICAL, "wmic creating process (lateral movement vector)",    "wmic"),
    ("wmic.exe",     r"(?:/node:|/NODE:)",               Severity.HIGH,     "wmic connecting to remote node",                     "wmic"),

    # installutil — bypass application control
    ("installutil.exe", r"https?://",                   Severity.CRITICAL, "installutil loading from URL",                       "installutil"),
    ("installutil.exe", r"\.dll",                       Severity.HIGH,     "installutil executing DLL (AppLocker bypass)",       "installutil"),

    # msiexec
    ("msiexec.exe",  r"/[qQ]\s.*?https?://",            Severity.CRITICAL, "msiexec silent install from URL",                   "msiexec"),

    # cmd
    ("cmd.exe",      r"/[cC]\s+.*?(?:certutil|mshta|regsvr32|rundll32|powershell|bitsadmin)", Severity.HIGH, "cmd.exe chaining LOLBAS", "cmd_shell"),
]


class LolbasChecker(BaseIntelModule):
    name = "lolbas_checker"

    def analyze(self, ctx: IntelContext) -> list[Finding]:
        findings: list[Finding] = []

        for entry in ctx.cmdlines:
            if not entry.cmdline:
                continue

            cmdline_lower = entry.cmdline.lower()
            binary_lower  = entry.name.lower()

            for (binary, pattern, severity, description, attck_key) in LOLBAS_RULES:
                if binary_lower != binary:
                    continue

                if re.search(pattern, entry.cmdline, re.IGNORECASE):
                    proc = ctx.pid_to_process.get(entry.pid)
                    parent = ctx.pid_to_process.get(proc.ppid) if proc else None
                    parent_info = f" (spawned by {parent.name} PID {proc.ppid})" if parent and proc else ""

                    findings.append(Finding(
                        severity         = severity,
                        category         = FindingCategory.LOLBAS,
                        title            = f"LOLBAS: {description}",
                        description      = (
                            f"PID {entry.pid} ({entry.name}){parent_info} was invoked with a "
                            "pattern matching a known Living Off the Land technique."
                        ),
                        evidence         = entry.cmdline[:500],
                        mitre            = get_mitre(attck_key),
                        source_module    = self.name,
                        source_plugin    = "windows.cmdline.CmdLine",
                        affected_pid     = entry.pid,
                        affected_process = entry.name,
                        iocs             = [f"cmdline:{entry.cmdline[:200]}"],
                    ))
                    # One finding per binary per invocation is enough
                    break

        logger.info("LolbasChecker: %d findings", len(findings))
        return findings
