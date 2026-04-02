"""
VirusTotal intelligence module — hash reputation lookups with rate limiting and SQLite cache.

Looks up SHA256 hashes of:
  - Process image files (from ProcessInfo.sha256)
  - Loaded DLLs flagged by other modules

Rate-limited to settings.vt_rate_limit_per_minute (default: 4).
Results cached in data/vt_cache.db for the lifetime of the run (and across runs).
Skipped entirely if VT_API_KEY is not set.
"""

from __future__ import annotations
import logging
import sqlite3
import time
from pathlib import Path
from typing import Optional

import requests

from dfir_memdump.config import settings
from dfir_memdump.models import Finding, FindingCategory, Severity
from dfir_memdump.intelligence import BaseIntelModule, IntelContext
from dfir_memdump.intelligence.attck_mapper import get_mitre

logger = logging.getLogger(__name__)

VT_LOOKUP_URL  = "https://www.virustotal.com/api/v3/files/{hash}"
CACHE_DB_PATH  = Path.home() / ".cache" / "dfir-memdump" / "vt_cache.db"
CACHE_TTL_SECS = 30 * 86400   # 30 days
VT_MAX_RETRIES = 3

# A hit is considered malicious if at least this many AV engines flag it
MALICIOUS_THRESHOLD = 5


class VTClient(BaseIntelModule):
    name = "vt_client"

    def __init__(self):
        self._cache: dict[str, Optional[dict]] = {}   # sha256 → VT result or None
        self._db: Optional[sqlite3.Connection] = None
        self._request_times: list[float] = []

    def analyze(self, ctx: IntelContext) -> list[Finding]:
        if not settings.has_vt():
            logger.debug("VT_API_KEY not set — skipping VirusTotal lookups")
            return []

        self._open_db()
        findings: list[Finding] = []

        # Collect unique hashes: process images
        hashes: dict[str, tuple[int, str]] = {}  # sha256 → (pid, name)
        limit = settings.max_processes_to_hash

        for proc in ctx.processes[:limit]:
            if proc.sha256 and proc.sha256 not in hashes:
                hashes[proc.sha256] = (proc.pid, proc.name)

        # DLL hashes from DLLs loaded by processes that have malfind hits (RWX memory),
        # which are the most likely to be injected or malicious.
        flagged_pids = {m.pid for m in ctx.malfind}
        for dll in ctx.dlls:
            if dll.sha256 and dll.sha256 not in hashes and dll.pid in flagged_pids:
                proc = ctx.pid_to_process.get(dll.pid)
                hashes[dll.sha256] = (dll.pid, dll.name or "unknown.dll")

        logger.info("VTClient: %d unique hashes to check", len(hashes))

        for sha256, (pid, name) in hashes.items():
            result = self._lookup(sha256)
            if result is None:
                continue

            malicious = result.get("malicious", 0)
            suspicious = result.get("suspicious", 0)
            total = result.get("total", 0)
            vt_name = result.get("popular_threat_name", "")

            if malicious >= MALICIOUS_THRESHOLD:
                severity = Severity.CRITICAL if malicious >= 20 else Severity.HIGH
                findings.append(Finding(
                    severity         = severity,
                    category         = FindingCategory.MALWARE,
                    title            = f"VT malicious hash: {name} ({malicious}/{total} detections)",
                    description      = (
                        f"SHA256 of {name} (PID {pid}) is flagged by {malicious} of {total} "
                        f"AV engines on VirusTotal. "
                        + (f"Threat name: {vt_name}." if vt_name else "")
                    ),
                    evidence         = f"SHA256: {sha256} | Detections: {malicious}/{total}",
                    mitre            = get_mitre("yara_malware"),
                    source_module    = self.name,
                    source_plugin    = "windows.pslist.PsList",
                    affected_pid     = pid,
                    affected_process = name,
                    iocs             = [f"hash_sha256:{sha256}", f"pid:{pid}"],
                    raw_data         = result,
                ))
            elif suspicious >= 3:
                findings.append(Finding(
                    severity         = Severity.MEDIUM,
                    category         = FindingCategory.MALWARE,
                    title            = f"VT suspicious hash: {name} ({suspicious} suspicious detections)",
                    description      = (
                        f"SHA256 of {name} (PID {pid}) has {suspicious} suspicious detections "
                        f"on VirusTotal. May be a packer, dropper, or low-confidence malware hit."
                    ),
                    evidence         = f"SHA256: {sha256} | Suspicious: {suspicious}/{total}",
                    mitre            = get_mitre("yara_malware"),
                    source_module    = self.name,
                    source_plugin    = "windows.pslist.PsList",
                    affected_pid     = pid,
                    affected_process = name,
                    iocs             = [f"hash_sha256:{sha256}", f"pid:{pid}"],
                    raw_data         = result,
                ))

        logger.info("VTClient: %d findings", len(findings))
        return findings

    # ─── VT API ──────────────────────────────────────────────────────────────

    def _lookup(self, sha256: str, _attempt: int = 0) -> Optional[dict]:
        """Return condensed VT result dict or None (not found / error)."""
        # In-memory cache
        if sha256 in self._cache:
            return self._cache[sha256]

        # SQLite cache (respects TTL)
        cached = self._db_get(sha256)
        if cached is not None:
            self._cache[sha256] = cached
            return cached

        # Rate limit
        self._rate_limit()

        url = VT_LOOKUP_URL.format(hash=sha256)
        headers = {"x-apikey": settings.vt_api_key.get_secret_value()}
        try:
            resp = requests.get(url, headers=headers, timeout=15)
        except Exception as exc:
            logger.warning("VT request failed for %s: %s", sha256[:16], exc)
            self._cache[sha256] = None
            return None

        if resp.status_code == 404:
            self._cache[sha256] = None
            self._db_set(sha256, None)
            return None

        if resp.status_code == 429:
            if _attempt >= VT_MAX_RETRIES:
                logger.error(
                    "VT rate limit persists after %d retries — skipping %s",
                    VT_MAX_RETRIES, sha256[:16],
                )
                self._cache[sha256] = None
                return None
            wait = 60 * (2 ** _attempt)   # 60s, 120s, 240s
            logger.warning(
                "VT rate limit hit — sleeping %ds (attempt %d/%d)",
                wait, _attempt + 1, VT_MAX_RETRIES,
            )
            time.sleep(wait)
            return self._lookup(sha256, _attempt=_attempt + 1)

        if not resp.ok:
            logger.warning("VT error %d for %s", resp.status_code, sha256[:16])
            self._cache[sha256] = None
            return None

        try:
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result = {
                "malicious":           stats.get("malicious", 0),
                "suspicious":          stats.get("suspicious", 0),
                "undetected":          stats.get("undetected", 0),
                "total":               sum(stats.values()),
                "popular_threat_name": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
                "type_description":    attrs.get("type_description", ""),
                "first_submission":    attrs.get("first_submission_date", ""),
            }
        except Exception as exc:
            logger.warning("VT response parse error: %s", exc)
            self._cache[sha256] = None
            return None

        self._cache[sha256] = result
        self._db_set(sha256, result)
        return result

    def _rate_limit(self) -> None:
        """Enforce rate limiting: max N requests per 60 seconds."""
        now = time.time()
        window = 60.0
        self._request_times = [t for t in self._request_times if now - t < window]
        if len(self._request_times) >= settings.vt_rate_limit_per_minute:
            sleep_for = window - (now - self._request_times[0]) + 0.5
            if sleep_for > 0:
                logger.debug("VT rate limit: sleeping %.1fs", sleep_for)
                time.sleep(sleep_for)
        self._request_times.append(time.time())

    # ─── SQLite cache ─────────────────────────────────────────────────────────

    def _open_db(self) -> None:
        if self._db:
            return
        CACHE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(CACHE_DB_PATH))
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS vt_cache ("
            "  sha256 TEXT PRIMARY KEY,"
            "  malicious INTEGER,"
            "  suspicious INTEGER,"
            "  undetected INTEGER,"
            "  total INTEGER,"
            "  popular_threat_name TEXT,"
            "  type_description TEXT,"
            "  first_submission TEXT,"
            "  fetched_at REAL"
            ")"
        )
        self._db.commit()

    def _db_get(self, sha256: str) -> Optional[dict]:
        if not self._db:
            return None
        row = self._db.execute(
            "SELECT malicious, suspicious, undetected, total, popular_threat_name, "
            "type_description, first_submission, fetched_at FROM vt_cache WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
        if row is None:
            return None
        # Enforce TTL — expired entries are treated as cache misses
        fetched_at = row[7] or 0.0
        if time.time() - fetched_at > CACHE_TTL_SECS:
            return None
        if row[0] is None and row[1] is None:  # stored as "not found"
            return None
        return {
            "malicious":           row[0] or 0,
            "suspicious":          row[1] or 0,
            "undetected":          row[2] or 0,
            "total":               row[3] or 0,
            "popular_threat_name": row[4] or "",
            "type_description":    row[5] or "",
            "first_submission":    row[6] or "",
        }

    def _db_set(self, sha256: str, result: Optional[dict]) -> None:
        if not self._db:
            return
        if result is None:
            self._db.execute(
                "INSERT OR REPLACE INTO vt_cache (sha256, fetched_at) VALUES (?, ?)",
                (sha256, time.time()),
            )
        else:
            self._db.execute(
                "INSERT OR REPLACE INTO vt_cache "
                "(sha256, malicious, suspicious, undetected, total, "
                " popular_threat_name, type_description, first_submission, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    sha256,
                    result["malicious"],
                    result["suspicious"],
                    result["undetected"],
                    result["total"],
                    result["popular_threat_name"],
                    result["type_description"],
                    result["first_submission"],
                    time.time(),
                ),
            )
        self._db.commit()
