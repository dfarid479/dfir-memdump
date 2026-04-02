"""
YARA engine — scans malfind hex dumps and DLL/image paths against compiled rules.

Loads rules from settings.yara_rules_dir (*.yar), compiles once per run,
and returns findings with MITRE ATT&CK context from rule metadata.
"""

from __future__ import annotations
import binascii
import logging
from pathlib import Path
from typing import Optional

from dfir_memdump.config import settings
from dfir_memdump.models import Finding, FindingCategory, Severity
from dfir_memdump.intelligence import BaseIntelModule, IntelContext
from dfir_memdump.intelligence.attck_mapper import get_mitre, ATTCK_MAP

logger = logging.getLogger(__name__)

try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False
    logger.warning("yara-python not installed — YARA scanning disabled")


def _severity_from_str(s: str) -> Severity:
    return {
        "critical": Severity.CRITICAL,
        "high":     Severity.HIGH,
        "medium":   Severity.MEDIUM,
        "low":      Severity.LOW,
    }.get((s or "").lower(), Severity.MEDIUM)


class YaraEngine(BaseIntelModule):
    name = "yara_engine"

    def __init__(self):
        self._rules = None
        self._compiled = False

    # ─── Public ──────────────────────────────────────────────────────────────

    def analyze(self, ctx: IntelContext) -> list[Finding]:
        if not _YARA_AVAILABLE:
            return []

        self._compile_rules()
        if self._rules is None:
            return []

        findings: list[Finding] = []

        # 1. Scan malfind hex dumps (process memory snapshots)
        for entry in ctx.malfind:
            if not entry.hex_dump:
                continue
            raw = self._hex_to_bytes(entry.hex_dump)
            if not raw:
                continue

            matches = self._scan_bytes(raw)
            for match in matches:
                finding = self._make_finding(
                    match=match,
                    pid=entry.pid,
                    proc_name=entry.process_name,
                    source_plugin="windows.malfind.Malfind",
                    evidence=(
                        f"YARA match in PID {entry.pid} ({entry.process_name}) "
                        f"VAD {entry.vad_start}-{entry.vad_end} "
                        f"[{entry.protection}]"
                    ),
                    iocs=[f"pid:{entry.pid}", f"yara_rule:{match.rule}"],
                )
                if finding:
                    findings.append(finding)

        # 2. Scan loaded DLL paths on disk (best-effort — file must be accessible)
        scanned_paths: set[str] = set()
        for dll in ctx.dlls:
            if not dll.path or dll.path in scanned_paths:
                continue
            scanned_paths.add(dll.path)
            path = Path(dll.path)
            if not path.exists() or path.stat().st_size > 50 * 1024 * 1024:
                continue  # skip missing or >50 MB files
            try:
                matches = self._rules.match(str(path))
            except Exception as exc:
                logger.debug("YARA scan failed for %s: %s", path, exc)
                continue

            for match in matches:
                proc = ctx.pid_to_process.get(dll.pid)
                proc_name = proc.name if proc else "unknown"
                finding = self._make_finding(
                    match=match,
                    pid=dll.pid,
                    proc_name=proc_name,
                    source_plugin="windows.dlllist.DllList",
                    evidence=f"YARA match in loaded DLL: {dll.path}",
                    iocs=[f"filepath:{dll.path}", f"yara_rule:{match.rule}"],
                )
                if finding:
                    findings.append(finding)

        # Deduplicate: one finding per (rule, pid) pair
        seen: set[tuple[str, int]] = set()
        deduped: list[Finding] = []
        for f in findings:
            key = (f.title, f.affected_pid or 0)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        logger.info("YaraEngine: %d findings (%d raw)", len(deduped), len(findings))
        return deduped

    # ─── Private ─────────────────────────────────────────────────────────────

    def _compile_rules(self) -> None:
        if self._compiled:
            return
        self._compiled = True

        rules_dir: Path = settings.yara_rules_dir
        compiled_path: Path = settings.yara_compiled_path

        # Try pre-compiled first
        if compiled_path.exists():
            try:
                self._rules = yara.load(str(compiled_path))
                logger.info("YARA: loaded pre-compiled rules from %s", compiled_path)
                return
            except Exception as exc:
                logger.warning("YARA pre-compiled load failed: %s — recompiling", exc)

        # Compile from source files
        if not rules_dir.exists():
            logger.warning("YARA rules dir not found: %s", rules_dir)
            return

        yar_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
        if not yar_files:
            logger.warning("No .yar files found in %s", rules_dir)
            return

        filepaths = {f.stem: str(f) for f in yar_files}
        try:
            self._rules = yara.compile(filepaths=filepaths)
            logger.info("YARA: compiled %d rule files", len(yar_files))
            # Cache compiled rules
            compiled_path.parent.mkdir(parents=True, exist_ok=True)
            self._rules.save(str(compiled_path))
        except Exception as exc:
            logger.error("YARA compile failed: %s", exc)

    def _scan_bytes(self, data: bytes):
        try:
            return self._rules.match(data=data)
        except Exception as exc:
            logger.debug("YARA byte scan failed: %s", exc)
            return []

    @staticmethod
    def _hex_to_bytes(hex_dump: str) -> Optional[bytes]:
        """Convert a Volatility hex dump (space-separated or raw hex) to bytes."""
        cleaned = hex_dump.replace(" ", "").replace("\n", "").replace("\r", "")
        # Volatility dumps sometimes have address prefixes like "0x00000000: ab cd ef"
        # Strip address lines
        lines = []
        for line in hex_dump.splitlines():
            parts = line.split()
            if not parts:
                continue
            # Skip lines that are just address + ascii
            hex_parts = [p for p in parts if all(c in "0123456789abcdefABCDEF" for c in p) and len(p) == 2]
            lines.extend(hex_parts)

        if not lines:
            # fallback: treat entire string as contiguous hex
            try:
                return binascii.unhexlify(cleaned)
            except Exception:
                return None
        try:
            return binascii.unhexlify("".join(lines))
        except Exception:
            return None

    def _make_finding(
        self,
        match,
        pid: int,
        proc_name: str,
        source_plugin: str,
        evidence: str,
        iocs: list[str],
    ) -> Optional[Finding]:
        meta = match.meta or {}
        description = meta.get("description", f"YARA rule '{match.rule}' matched")
        severity = _severity_from_str(meta.get("severity", "high"))
        attck_key = meta.get("mitre_key", "yara_malware")
        category_str = meta.get("category", "MALWARE").upper()
        try:
            category = FindingCategory[category_str]
        except KeyError:
            category = FindingCategory.MALWARE

        # Include matched strings in evidence if available
        matched_strs = []
        for s in match.strings[:5]:  # cap at 5
            try:
                matched_strs.append(repr(s.instances[0].matched_data[:64]))
            except Exception:
                pass
        if matched_strs:
            evidence += f" | Matched: {', '.join(matched_strs)}"

        return Finding(
            severity         = severity,
            category         = category,
            title            = f"YARA: {match.rule} — {description[:80]}",
            description      = (
                f"YARA rule '{match.rule}' matched in PID {pid} ({proc_name}). "
                f"{description}"
            ),
            evidence         = evidence[:500],
            mitre            = get_mitre(attck_key),
            source_module    = self.name,
            source_plugin    = source_plugin,
            affected_pid     = pid,
            affected_process = proc_name,
            iocs             = iocs,
        )
