"""
Intelligence module registry.

Each module takes the full parsed context (processes, connections, cmdlines,
malfind output) and returns a list of Finding objects.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dfir_memdump.models import Finding, ProcessInfo, NetworkConnection, MalfindEntry, CmdlineEntry, DllInfo, HandleEntry, PrivilegeEntry


class IntelContext:
    """Snapshot of all vol3 plugin output, passed to every intel module."""

    def __init__(
        self,
        processes:   list[ProcessInfo]       = None,
        connections: list[NetworkConnection] = None,
        malfind:     list[MalfindEntry]      = None,
        cmdlines:    list[CmdlineEntry]      = None,
        dlls:        list[DllInfo]           = None,
        handles:     list[HandleEntry]       = None,
        privileges:  list[PrivilegeEntry]    = None,
    ):
        self.processes   = processes   or []
        self.connections = connections or []
        self.malfind     = malfind     or []
        self.cmdlines    = cmdlines    or []
        self.dlls        = dlls        or []
        self.handles     = handles     or []
        self.privileges  = privileges  or []

        # Build fast lookup tables
        self.pid_to_process:   dict[int, ProcessInfo]       = {p.pid: p for p in self.processes}
        self.pid_to_cmdline:   dict[int, CmdlineEntry]      = {c.pid: c for c in self.cmdlines}
        self.pid_to_dlls:      dict[int, list[DllInfo]]     = {}
        self.pid_to_handles:   dict[int, list[HandleEntry]] = {}
        self.pid_to_privileges:dict[int, list[PrivilegeEntry]] = {}
        for dll in self.dlls:
            self.pid_to_dlls.setdefault(dll.pid, []).append(dll)
        for h in self.handles:
            self.pid_to_handles.setdefault(h.pid, []).append(h)
        for priv in self.privileges:
            self.pid_to_privileges.setdefault(priv.pid, []).append(priv)


class BaseIntelModule(ABC):
    """Abstract base for all intelligence modules."""

    name: str

    @abstractmethod
    def analyze(self, ctx: IntelContext) -> list[Finding]:
        """Analyze the context and return findings."""
