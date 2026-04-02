"""
Token Privilege Analyser (inspired by PrivHound).

Flags non-system processes holding high-value Windows privileges that,
if abused, grant near-SYSTEM access:

  SeDebugPrivilege         — read/write any process memory (token theft, injection)
  SeImpersonatePrivilege   — impersonate any logged-on user (potato attacks)
  SeAssignPrimaryToken     — swap process token → SYSTEM
  SeTcbPrivilege           — "act as part of the OS" — highest privilege possible
  SeLoadDriverPrivilege    — load/unload kernel modules → rootkit installation
  SeBackupPrivilege        — bypass DACL on any file (SAM dump, shadow copy)
  SeRestorePrivilege       — write any file / registry key regardless of ACL
  SeCreateTokenPrivilege   — synthesise access tokens from scratch
  SeTakeOwnershipPrivilege — take ownership of any object

Each enabled dangerous privilege on a non-system process generates a HIGH or
CRITICAL finding.  SeDebug + SeImpersonate together trigger CRITICAL because
this combination is sufficient for full domain compromise.
"""

from __future__ import annotations
import logging

from dfir_memdump.models import Finding, FindingCategory, Severity
from dfir_memdump.intelligence import BaseIntelModule, IntelContext
from dfir_memdump.intelligence.attck_mapper import get_mitre

logger = logging.getLogger(__name__)

# ── Privilege definitions ─────────────────────────────────────────────────────
# (priv_name_lower, severity, mitre_key, short_description)
_DANGEROUS_PRIVS: list[tuple[str, Severity, str, str]] = [
    ("sedebugprivilege",          Severity.CRITICAL, "se_debug",         "Full read/write access to any process memory"),
    ("seimpersonateprivilege",    Severity.HIGH,     "token_impersonate","Impersonate any user token (Potato attack surface)"),
    ("seassignprimarytokenprivilege", Severity.HIGH, "token_impersonate","Replace a process token — can elevate to SYSTEM"),
    ("setcbprivilege",            Severity.CRITICAL, "se_tcb_privilege", "Act as part of the OS — highest Windows privilege"),
    ("seloaddriverprivilege",     Severity.HIGH,     "se_load_driver",   "Load/unload kernel drivers — rootkit installation vector"),
    ("sebackupprivilege",         Severity.HIGH,     "credential_dump",  "Bypass file DACLs — enables SAM/NTDS.dit extraction"),
    ("serestoreprivilege",        Severity.HIGH,     "credential_dump",  "Write any file/registry key regardless of ACL"),
    ("secreatetokenprivilege",    Severity.CRITICAL, "dangerous_privilege","Create arbitrary access tokens from scratch"),
    ("setakeownershipprivilege",  Severity.HIGH,     "dangerous_privilege","Take ownership of any securable object"),
]

# Processes that legitimately hold these privileges
_SYSTEM_PROCS = {
    "system", "lsass.exe", "services.exe", "svchost.exe",
    "winlogon.exe", "wininit.exe", "csrss.exe", "smss.exe",
    "trustedinstaller.exe", "msiexec.exe",
}


class PrivilegeChecker(BaseIntelModule):
    name = "privilege_checker"

    def analyze(self, ctx: IntelContext) -> list[Finding]:
        if not ctx.privileges:
            logger.info("PrivilegeChecker: no privilege data (windows.privileges not run or returned empty)")
            return []

        findings: list[Finding] = []

        # Build map: pid → set of enabled privilege names (lower)
        pid_enabled: dict[int, set[str]] = {}
        for priv in ctx.privileges:
            if priv.enabled:
                pid_enabled.setdefault(priv.pid, set()).add(priv.privilege.lower())

        # Build pid → process_name from PrivilegeEntry directly (more complete than pid_to_process)
        pid_to_name: dict[int, str] = {}
        for priv in ctx.privileges:
            if priv.pid not in pid_to_name:
                pid_to_name[priv.pid] = priv.process_name

        for pid, priv_set in pid_enabled.items():
            proc = ctx.pid_to_process.get(pid)
            proc_name = proc.name if proc else pid_to_name.get(pid, f"PID {pid}")

            if proc_name.lower() in _SYSTEM_PROCS:
                continue

            # Check each dangerous privilege
            for priv_lower, sev, mitre_key, desc in _DANGEROUS_PRIVS:
                if priv_lower not in priv_set:
                    continue

                # Escalate to CRITICAL if process has both SeDebug + SeImpersonate
                combined = (
                    "sedebugprivilege" in priv_set and
                    "seimpersonateprivilege" in priv_set
                )
                final_sev = Severity.CRITICAL if combined else sev

                canonical = _to_canonical(priv_lower)
                findings.append(Finding(
                    severity         = final_sev,
                    category         = FindingCategory.CREDENTIAL,
                    title            = f"Dangerous privilege '{canonical}' enabled on '{proc_name}' (PID {pid})",
                    description      = (
                        f"'{proc_name}' (PID {pid}) has '{canonical}' enabled. "
                        f"{desc}. Non-system processes with this privilege represent "
                        "a significant privilege escalation risk and may indicate token "
                        "manipulation, credential theft, or an already-elevated implant."
                        + (
                            " Additionally, SeDebug + SeImpersonate are both present on this "
                            "process — this combination is sufficient for full domain compromise."
                            if combined else ""
                        )
                    ),
                    evidence         = (
                        f"PID {pid} ({proc_name})\n"
                        f"Privilege: {canonical}\n"
                        f"Enabled: True\n"
                        f"All dangerous privs on this PID: {', '.join(sorted(p for p in priv_set if any(p == dp[0] for dp in _DANGEROUS_PRIVS)))}"
                    ),
                    mitre            = get_mitre(mitre_key),
                    source_module    = self.name,
                    source_plugin    = "windows.privileges.Privs",
                    affected_pid     = pid,
                    affected_process = proc_name,
                    iocs             = [f"privilege:{canonical}", f"pid:{pid}"],
                ))

        logger.info("PrivilegeChecker: %d findings from %d privilege-holding PIDs",
                    len(findings), len(pid_enabled))
        return findings


def _to_canonical(priv_lower: str) -> str:
    """Return the canonical CamelCase privilege name from lowercase."""
    # Rebuild from the _DANGEROUS_PRIVS list
    _MAP = {
        "sedebugprivilege":               "SeDebugPrivilege",
        "seimpersonateprivilege":         "SeImpersonatePrivilege",
        "seassignprimarytokenprivilege":  "SeAssignPrimaryTokenPrivilege",
        "setcbprivilege":                 "SeTcbPrivilege",
        "seloaddriverprivilege":          "SeLoadDriverPrivilege",
        "sebackupprivilege":              "SeBackupPrivilege",
        "serestoreprivilege":             "SeRestorePrivilege",
        "secreatetokenprivilege":         "SeCreateTokenPrivilege",
        "setakeownershipprivilege":       "SeTakeOwnershipPrivilege",
    }
    return _MAP.get(priv_lower, priv_lower)
