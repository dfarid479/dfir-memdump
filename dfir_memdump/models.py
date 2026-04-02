"""
Pydantic models — the single source of truth for all data structures.

Every module exchanges these typed objects, not raw dicts.
"""

from __future__ import annotations

import enum
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


# ─── Enums ───────────────────────────────────────────────────────────────────

class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class FindingCategory(str, enum.Enum):
    MALWARE       = "MALWARE"
    C2            = "C2"
    ANOMALY       = "ANOMALY"
    LOLBAS        = "LOLBAS"
    CREDENTIAL    = "CREDENTIAL"
    PERSISTENCE   = "PERSISTENCE"
    INJECTION     = "INJECTION"
    NETWORK       = "NETWORK"


# ─── Volatility Plugin Output Models ─────────────────────────────────────────

class ProcessInfo(BaseModel):
    """Represents a single process from windows.pslist / pstree output."""
    pid:           int
    ppid:          int
    name:          str
    image_path:    Optional[str] = None
    cmdline:       Optional[str] = None
    create_time:   Optional[str] = None
    exit_time:     Optional[str] = None
    threads:       int = 0
    handles:       int = 0
    session_id:    Optional[int] = None
    wow64:         bool = False
    sha256:        Optional[str] = None
    children:      list[int] = Field(default_factory=list)


class NetworkConnection(BaseModel):
    """Represents a single row from windows.netscan output."""
    pid:            int
    proto:          str           # TCP, UDP, TCPv6, UDPv6
    local_addr:     str
    local_port:     int
    foreign_addr:   str
    foreign_port:   int
    state:          Optional[str] = None   # ESTABLISHED, LISTEN, CLOSE_WAIT, etc.
    process_name:   Optional[str] = None
    created_time:   Optional[str] = None


class DllInfo(BaseModel):
    """Represents a loaded DLL from windows.dlllist output."""
    pid:        int
    base:       str            # hex base address as string
    size:       int
    path:       Optional[str] = None
    name:       Optional[str] = None
    sha256:     Optional[str] = None    # computed lazily if path available


class MalfindEntry(BaseModel):
    """Represents a suspicious VAD region from windows.malfind output."""
    pid:           int
    process_name:  str
    vad_start:     str    # hex
    vad_end:       str    # hex
    tag:           str
    protection:    str    # e.g. PAGE_EXECUTE_READWRITE
    vad_type:      str
    file_path:     Optional[str] = None
    hex_dump:      Optional[str] = None
    disasm:        Optional[str] = None


class VadRegion(BaseModel):
    """VAD entry from windows.vadinfo output."""
    pid:         int
    vad_start:   str
    vad_end:     str
    protection:  str
    vad_type:    str
    file_path:   Optional[str] = None


class CmdlineEntry(BaseModel):
    """Command line from windows.cmdline output."""
    pid:     int
    name:    str
    cmdline: Optional[str] = None


# ─── Intelligence Finding ─────────────────────────────────────────────────────

class MitreRef(BaseModel):
    technique_id:   str             # e.g. T1055.012
    technique_name: str
    tactic:         str             # e.g. Defense Evasion
    url:            Optional[str] = None


class Finding(BaseModel):
    """A single intelligence finding attached to a process or network object."""
    severity:         Severity
    category:         FindingCategory
    title:            str
    description:      str
    evidence:         str           # What triggered this finding (cmdline, address, hash, etc.)
    mitre:            Optional[MitreRef] = None
    source_module:    str           # Which intelligence module generated this
    source_plugin:    str           # Which vol3 plugin supplied the raw data
    affected_pid:     Optional[int] = None
    affected_process: Optional[str] = None
    iocs:             list[str] = Field(default_factory=list)   # IPs, hashes, domain names
    raw_data:         Optional[dict[str, Any]] = None


# ─── Privilege Entry ──────────────────────────────────────────────────────────

class PrivilegeEntry(BaseModel):
    """A single privilege from windows.privileges.Privs output."""
    pid:              int
    process_name:     str
    privilege:        str    # e.g. SeDebugPrivilege
    enabled:          bool
    default_enabled:  bool = False


# ─── Attack Chain Step ────────────────────────────────────────────────────────

class ChainStep(BaseModel):
    """One stage in the reconstructed attack chain."""
    stage:       str        # Kill chain stage name (e.g. "Privilege Escalation")
    stage_order: int        # 0-based index for sorting
    findings:    list[str] = Field(default_factory=list)   # Finding titles
    mitre_ids:   list[str] = Field(default_factory=list)
    narrative:   str = ""


# ─── Handle / Mutex ───────────────────────────────────────────────────────────

class HandleEntry(BaseModel):
    """A single handle from windows.handles output."""
    pid:            int
    process_name:   str
    handle_value:   str            # hex string
    handle_type:    str            # Mutant, File, Key, Process, Thread, etc.
    granted_access: str            # hex string
    name:           Optional[str] = None   # meaningful for Mutant, Key, File


# ─── Process Risk Score ───────────────────────────────────────────────────────

class ProcessRiskScore(BaseModel):
    """Aggregated risk score for a single process across all findings."""
    pid:           int
    name:          str
    score:         int        # CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0
    finding_count: int
    top_severity:  Optional[str] = None
    finding_titles: list[str] = Field(default_factory=list)


# ─── IOC ─────────────────────────────────────────────────────────────────────

class IOC(BaseModel):
    """An Indicator of Compromise extracted from findings."""
    type:    str    # ip, hash_md5, hash_sha256, domain, process_name, cmdline, filepath
    value:   str
    context: str    # Human-readable description of where/why this was flagged
    pid:     Optional[int] = None


# ─── Triage Report ───────────────────────────────────────────────────────────

class TriageMetadata(BaseModel):
    image_path:     str
    image_size_mb:  float
    analysis_start: str
    analysis_end:   str
    vol3_version:   Optional[str] = None
    profile:        Optional[str] = None
    os_info:        Optional[str] = None
    tool_version:   str = "1.0.0"


class ProcessSummary(BaseModel):
    total:          int
    suspicious:     int
    injected:       int
    hollow:         int
    lolbas:         int


class NetworkSummary(BaseModel):
    total_connections:  int
    established:        int
    listening:          int
    c2_matches:         int
    feodo_matches:      int
    suspicious:         int


class TriageReport(BaseModel):
    """The complete output of a memory triage run."""
    metadata:            TriageMetadata
    process_summary:     ProcessSummary
    network_summary:     NetworkSummary
    findings:            list[Finding] = Field(default_factory=list)
    iocs:                list[IOC] = Field(default_factory=list)
    processes:           list[ProcessInfo] = Field(default_factory=list)
    connections:         list[NetworkConnection] = Field(default_factory=list)
    malfind_entries:     list[MalfindEntry] = Field(default_factory=list)
    handles:             list[HandleEntry] = Field(default_factory=list)
    privileges:          list[PrivilegeEntry] = Field(default_factory=list)
    process_risk_scores: list[ProcessRiskScore] = Field(default_factory=list)
    attack_chain:        list[ChainStep] = Field(default_factory=list)
    executive_summary:   Optional[str] = None

    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    def findings_by_severity(self) -> list[Finding]:
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        return sorted(self.findings, key=lambda f: order.get(f.severity, 99))

    def unique_mitre_techniques(self) -> list[str]:
        seen = set()
        out = []
        for f in self.findings:
            if f.mitre and f.mitre.technique_id not in seen:
                seen.add(f.mitre.technique_id)
                out.append(f.mitre.technique_id)
        return sorted(out)
