"""
Main analysis runner — orchestrates all Volatility3 plugins and intelligence modules.

Usage:
    from dfir_memdump.runner import MemoryAnalyzer
    report = MemoryAnalyzer(image_path).run()
"""

from __future__ import annotations
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dfir_memdump.config import settings
from dfir_memdump.exceptions import ImageNotFoundError, Vol3NotFoundError
from dfir_memdump.models import (
    Finding, IOC, ProcessRiskScore, ProcessSummary, NetworkSummary,
    TriageMetadata, TriageReport, Severity, FindingCategory,
)

# Volatility plugins
from dfir_memdump.plugins.pslist      import PsListPlugin
from dfir_memdump.plugins.netscan     import NetScanPlugin
from dfir_memdump.plugins.malfind     import MalfindPlugin
from dfir_memdump.plugins.cmdline     import CmdLinePlugin
from dfir_memdump.plugins.dlllist     import DllListPlugin
from dfir_memdump.plugins.handles     import HandlesPlugin
from dfir_memdump.plugins.privileges  import PrivilegesPlugin

# Intelligence modules
from dfir_memdump.intelligence                        import IntelContext
from dfir_memdump.intelligence.anomaly_detector       import AnomalyDetector
from dfir_memdump.intelligence.lolbas_checker         import LolbasChecker
from dfir_memdump.intelligence.c2_detector            import C2Detector
from dfir_memdump.intelligence.yara_engine            import YaraEngine
from dfir_memdump.intelligence.vt_client              import VTClient
from dfir_memdump.intelligence.string_extractor       import StringExtractor
from dfir_memdump.intelligence.lateral_movement       import LateralMovementDetector
from dfir_memdump.intelligence.mutex_checker          import MutexChecker
from dfir_memdump.intelligence.privilege_checker      import PrivilegeChecker
from dfir_memdump.intelligence.chain_builder          import build_attack_chain

# Severity → numeric weight for risk scoring
_SEV_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH:     5,
    Severity.MEDIUM:   2,
    Severity.LOW:      1,
    Severity.INFO:     0,
}

logger = logging.getLogger(__name__)


class MemoryAnalyzer:
    """Runs all plugins and intel modules against a memory image."""

    def __init__(self, image_path: str | Path, profile: Optional[str] = None):
        self.image_path = Path(image_path)
        self.profile = profile

        if not self.image_path.exists():
            raise ImageNotFoundError(f"Memory image not found: {self.image_path}")

    def run(self) -> TriageReport:
        start_time = time.time()
        start_str  = datetime.now(timezone.utc).isoformat()

        logger.info("=== dfir-memdump analysis starting: %s ===", self.image_path.name)

        # ── Step 1: Run Volatility3 plugins ──────────────────────────────────
        processes   = self._run_plugin(PsListPlugin,    "PsList")
        connections = self._run_plugin(NetScanPlugin,   "NetScan")
        malfind     = self._run_plugin(MalfindPlugin,   "Malfind")
        cmdlines    = self._run_plugin(CmdLinePlugin,   "CmdLine")
        dlls        = self._run_plugin(DllListPlugin,   "DllList")
        handles     = self._run_plugin(HandlesPlugin,   "Handles")
        privileges  = self._run_plugin(PrivilegesPlugin,"Privileges")

        # ── Step 2: Build intelligence context ───────────────────────────────
        ctx = IntelContext(
            processes   = processes,
            connections = connections,
            malfind     = malfind,
            cmdlines    = cmdlines,
            dlls        = dlls,
            handles     = handles,
            privileges  = privileges,
        )

        # ── Step 3: Run intelligence modules ─────────────────────────────────
        all_findings: list[Finding] = []

        for module_cls in [
            AnomalyDetector,
            LolbasChecker,
            C2Detector,
            YaraEngine,
            VTClient,
            StringExtractor,
            LateralMovementDetector,
            MutexChecker,
            PrivilegeChecker,
        ]:
            module = module_cls()
            try:
                findings = module.analyze(ctx)
                all_findings.extend(findings)
                logger.info("%s: %d findings", module.name, len(findings))
            except Exception as exc:
                logger.error("Intel module %s failed: %s", module_cls.__name__, exc, exc_info=True)

        # ── Step 4: Build summaries ───────────────────────────────────────────
        process_summary = self._build_process_summary(processes, all_findings)
        network_summary = self._build_network_summary(connections, all_findings)

        # ── Step 5: Extract IOCs ──────────────────────────────────────────────
        iocs = self._extract_iocs(all_findings)

        # ── Step 6: Build per-process risk scores ─────────────────────────────
        risk_scores = self._build_risk_scores(processes, all_findings)

        # ── Step 6b: Reconstruct attack chain ─────────────────────────────────
        attack_chain = build_attack_chain(all_findings)

        # ── Step 7: Build metadata ────────────────────────────────────────────
        end_str = datetime.now(timezone.utc).isoformat()
        size_mb = self.image_path.stat().st_size / (1024 * 1024)

        metadata = TriageMetadata(
            image_path     = str(self.image_path),
            image_size_mb  = round(size_mb, 2),
            analysis_start = start_str,
            analysis_end   = end_str,
            profile        = self.profile,
        )

        # ── Step 8: Executive summary ─────────────────────────────────────────
        exec_summary = self._build_exec_summary(all_findings, process_summary, network_summary)

        elapsed = time.time() - start_time
        logger.info("=== Analysis complete in %.1fs — %d total findings ===", elapsed, len(all_findings))

        return TriageReport(
            metadata             = metadata,
            process_summary      = process_summary,
            network_summary      = network_summary,
            findings             = all_findings,
            iocs                 = iocs,
            processes            = processes,
            connections          = connections,
            malfind_entries      = malfind,
            handles              = handles,
            privileges           = privileges,
            process_risk_scores  = risk_scores,
            attack_chain         = attack_chain,
            executive_summary    = exec_summary,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _run_plugin(self, plugin_cls, label: str) -> list:
        plugin = plugin_cls(self.image_path, profile=self.profile)
        try:
            results = plugin.run()
            logger.info("%s: %d rows", label, len(results))
            return results
        except Exception as exc:
            logger.error("%s plugin failed: %s", label, exc)
            return []

    @staticmethod
    def _build_process_summary(processes, findings: list[Finding]) -> ProcessSummary:
        anomaly_pids  = {f.affected_pid for f in findings if f.category == FindingCategory.ANOMALY and f.affected_pid}
        injection_pids = {f.affected_pid for f in findings if f.category == FindingCategory.INJECTION and f.affected_pid}
        lolbas_pids   = {f.affected_pid for f in findings if f.category == FindingCategory.LOLBAS and f.affected_pid}
        hollow_pids   = {
            f.affected_pid for f in findings
            if f.affected_pid and "hollow" in f.title.lower()
        }
        suspicious_pids = anomaly_pids | injection_pids | lolbas_pids
        return ProcessSummary(
            total      = len(processes),
            suspicious = len(suspicious_pids),
            injected   = len(injection_pids),
            hollow     = len(hollow_pids),
            lolbas     = len(lolbas_pids),
        )

    @staticmethod
    def _build_network_summary(connections, findings: list[Finding]) -> NetworkSummary:
        c2_pids    = {f.affected_pid for f in findings if f.category == FindingCategory.C2}
        feodo_pids = {f.affected_pid for f in findings if f.affected_pid and "feodo" in f.title.lower()}
        return NetworkSummary(
            total_connections = len(connections),
            established       = sum(1 for c in connections if c.state == "ESTABLISHED"),
            listening         = sum(1 for c in connections if c.state == "LISTEN"),
            c2_matches        = len(c2_pids),
            feodo_matches     = len(feodo_pids),
            suspicious        = len(c2_pids),
        )

    @staticmethod
    def _extract_iocs(findings: list[Finding]) -> list[IOC]:
        seen: set[tuple[str, str]] = set()
        iocs: list[IOC] = []
        for f in findings:
            for raw in f.iocs:
                if ":" not in raw:
                    continue
                ioc_type, ioc_value = raw.split(":", 1)
                key = (ioc_type, ioc_value)
                if key in seen:
                    continue
                seen.add(key)
                iocs.append(IOC(
                    type    = ioc_type,
                    value   = ioc_value,
                    context = f.title,
                    pid     = f.affected_pid,
                ))
        return iocs

    @staticmethod
    def _build_risk_scores(processes, findings: list[Finding]) -> list[ProcessRiskScore]:
        """
        Aggregate all findings per PID into a weighted risk score.
        CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1, INFO=0.
        Returns list sorted by score descending.
        """
        from collections import defaultdict
        scores: dict[int, int]       = defaultdict(int)
        counts: dict[int, int]       = defaultdict(int)
        titles: dict[int, list[str]] = defaultdict(list)
        top_sev: dict[int, Severity] = {}

        sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

        for f in findings:
            if f.affected_pid is None:
                continue
            pid = f.affected_pid
            scores[pid] += _SEV_WEIGHT.get(f.severity, 0)
            counts[pid] += 1
            titles[pid].append(f.title[:80])
            current_top = top_sev.get(pid)
            if current_top is None or sev_order.index(f.severity) < sev_order.index(current_top):
                top_sev[pid] = f.severity

        pid_map = {p.pid: p for p in processes}
        result = []
        for pid, score in scores.items():
            proc = pid_map.get(pid)
            name = proc.name if proc else f"PID {pid}"
            result.append(ProcessRiskScore(
                pid           = pid,
                name          = name,
                score         = score,
                finding_count = counts[pid],
                top_severity  = top_sev[pid].value if pid in top_sev else None,
                finding_titles= titles[pid],
            ))

        return sorted(result, key=lambda r: r.score, reverse=True)

    @staticmethod
    def _build_exec_summary(findings: list[Finding], ps: ProcessSummary, ns: NetworkSummary) -> str:
        crit  = [f for f in findings if f.severity == Severity.CRITICAL]
        high  = [f for f in findings if f.severity == Severity.HIGH]
        cats  = {f.category.value for f in findings}

        lines = []
        if crit:
            lines.append(f"CRITICAL: {len(crit)} critical finding(s) detected — immediate investigation required.")
        if ns.feodo_matches:
            lines.append(f"ACTIVE C2: {ns.feodo_matches} connection(s) to known Feodo botnet C2 infrastructure.")
        if ps.hollow:
            lines.append(f"INJECTION: {ps.hollow} process(es) show hollow/unbacked executable memory regions.")
        if ps.injected:
            lines.append(f"INJECTION: {ps.injected} process(es) exhibit injection indicators.")
        if FindingCategory.CREDENTIAL.value in cats:
            lines.append("CREDENTIAL: Credential dumping tool signatures detected in memory.")
        if FindingCategory.LOLBAS.value in cats:
            lines.append(f"LOLBAS: {ps.lolbas} process(es) used Living-off-the-Land techniques.")
        if not crit and not high:
            lines.append("No critical or high-severity findings. Low/medium findings require review.")

        lines.append(
            f"Total: {len(findings)} findings | "
            f"Processes: {ps.total} ({ps.suspicious} suspicious) | "
            f"Connections: {ns.total_connections} ({ns.c2_matches} C2 matches)"
        )
        return "\n".join(lines)
