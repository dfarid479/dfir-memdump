"""
String Extractor — pulls printable ASCII and UTF-16LE strings from malfind
hex dumps and scans them for high-value patterns: URLs, IPs, base64 blobs,
Windows file paths, and known scripting/execution commands.

Every hit becomes a Finding with the extracted string as evidence, so the
analyst doesn't need to manually decode hex regions.
"""

from __future__ import annotations
import logging
import re

from dfir_memdump.models import Finding, FindingCategory, Severity
from dfir_memdump.intelligence import BaseIntelModule, IntelContext
from dfir_memdump.intelligence.attck_mapper import get_mitre

logger = logging.getLogger(__name__)

# ── Detection patterns ────────────────────────────────────────────────────────

_URL_RE   = re.compile(r'https?://[^\s"\'<>\x00]{8,}', re.IGNORECASE)
_IP_RE    = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d{2,5})?\b')
_B64_RE   = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/=])')
_WIN_PATH = re.compile(r'[A-Za-z]:\\(?:[\w\- .]+\\)*[\w\- .]+', re.IGNORECASE)
_CMD_RE   = re.compile(
    r'\b(?:cmd\.exe|powershell(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|'
    r'rundll32(?:\.exe)?|regsvr32(?:\.exe)?|mshta(?:\.exe)?|certutil(?:\.exe)?|'
    r'bitsadmin(?:\.exe)?|wmic(?:\.exe)?|msiexec(?:\.exe)?)\b',
    re.IGNORECASE,
)
_MIN_STR_LEN = 6

# Private IP ranges — exclude from IP findings to reduce noise
_PRIVATE_IP = re.compile(
    r'^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0|255\.255\.255\.255)'
)


class StringExtractor(BaseIntelModule):
    name = "string_extractor"

    def analyze(self, ctx: IntelContext) -> list[Finding]:
        findings: list[Finding] = []

        for entry in ctx.malfind:
            if not entry.hex_dump:
                continue

            raw_bytes = _hex_to_bytes(entry.hex_dump)
            if not raw_bytes:
                continue

            strings = _extract_strings(raw_bytes)
            if not strings:
                continue

            combined = "\n".join(strings)
            context_label = f"PID {entry.pid} ({entry.process_name}) VAD {entry.vad_start}"

            # URLs
            for m in _URL_RE.finditer(combined):
                url = m.group(0).rstrip(".,;)'\"")
                findings.append(Finding(
                    severity        = Severity.HIGH,
                    category        = FindingCategory.C2,
                    title           = f"URL found in executable memory: {url[:60]}",
                    description     = (
                        f"A URL was extracted from an executable memory region in {entry.process_name} "
                        f"(PID {entry.pid}). URLs in RWX/unbacked memory regions often indicate "
                        "embedded C2 addresses, payload download URLs, or injected shellcode configuration."
                    ),
                    evidence        = f"{context_label}\nExtracted URL: {url}",
                    mitre           = get_mitre("c2_http"),
                    source_module   = self.name,
                    source_plugin   = "windows.malfind.Malfind",
                    affected_pid    = entry.pid,
                    affected_process= entry.process_name,
                    iocs            = [f"url:{url}", f"pid:{entry.pid}"],
                ))

            # External IPs (skip RFC1918/loopback)
            seen_ips: set[str] = set()
            for m in _IP_RE.finditer(combined):
                ip_full = m.group(0)
                ip_only = ip_full.split(":")[0]
                if ip_only in seen_ips or _PRIVATE_IP.match(ip_only):
                    continue
                seen_ips.add(ip_only)
                findings.append(Finding(
                    severity        = Severity.MEDIUM,
                    category        = FindingCategory.C2,
                    title           = f"External IP in executable memory: {ip_full}",
                    description     = (
                        f"An external IP address ({ip_full}) was extracted from an executable memory "
                        f"region in {entry.process_name} (PID {entry.pid}). This may be a hardcoded "
                        "C2 server address embedded in shellcode or injected code."
                    ),
                    evidence        = f"{context_label}\nExtracted IP: {ip_full}",
                    mitre           = get_mitre("c2_http"),
                    source_module   = self.name,
                    source_plugin   = "windows.malfind.Malfind",
                    affected_pid    = entry.pid,
                    affected_process= entry.process_name,
                    iocs            = [f"ip:{ip_only}", f"pid:{entry.pid}"],
                ))

            # Execution commands in memory
            cmd_hits: list[str] = list({m.group(0).lower() for m in _CMD_RE.finditer(combined)})
            if cmd_hits:
                findings.append(Finding(
                    severity        = Severity.HIGH,
                    category        = FindingCategory.INJECTION,
                    title           = f"Execution command strings in memory: {', '.join(cmd_hits[:4])}",
                    description     = (
                        f"Execution-related command strings ({', '.join(cmd_hits)}) were found inside "
                        f"an executable memory region of {entry.process_name} (PID {entry.pid}). "
                        "This is characteristic of shellcode that spawns child processes, LOLBas-based "
                        "payloads, or injected code preparing to execute further stages."
                    ),
                    evidence        = f"{context_label}\nCommands found: {', '.join(cmd_hits)}",
                    mitre           = get_mitre("cmd_shell"),
                    source_module   = self.name,
                    source_plugin   = "windows.malfind.Malfind",
                    affected_pid    = entry.pid,
                    affected_process= entry.process_name,
                    iocs            = [f"cmdstring:{c}" for c in cmd_hits[:4]] + [f"pid:{entry.pid}"],
                ))

            # Suspicious Windows paths (AppData, Temp, ProgramData — common malware staging locations)
            suspicious_paths = [
                p for p in {m.group(0) for m in _WIN_PATH.finditer(combined)}
                if any(s in p.lower() for s in ("appdata", "temp", "tmp", "programdata", "public"))
            ]
            if suspicious_paths:
                findings.append(Finding(
                    severity        = Severity.MEDIUM,
                    category        = FindingCategory.MALWARE,
                    title           = f"Suspicious filesystem paths in memory ({len(suspicious_paths)} found)",
                    description     = (
                        f"{len(suspicious_paths)} Windows path(s) pointing to common malware staging "
                        f"locations were extracted from executable memory in {entry.process_name} "
                        f"(PID {entry.pid}). Paths in Temp, AppData, and ProgramData are frequently "
                        "used by malware for payload storage and persistence."
                    ),
                    evidence        = f"{context_label}\nPaths:\n" + "\n".join(suspicious_paths[:10]),
                    mitre           = get_mitre("persistence"),
                    source_module   = self.name,
                    source_plugin   = "windows.malfind.Malfind",
                    affected_pid    = entry.pid,
                    affected_process= entry.process_name,
                    iocs            = [f"filepath:{p}" for p in suspicious_paths[:5]] + [f"pid:{entry.pid}"],
                ))

            # Long base64 blobs (common for encoded payloads/commands)
            b64_hits = _B64_RE.findall(combined)
            if b64_hits:
                findings.append(Finding(
                    severity        = Severity.MEDIUM,
                    category        = FindingCategory.INJECTION,
                    title           = f"Base64-encoded blob(s) in executable memory ({len(b64_hits)} found)",
                    description     = (
                        f"{len(b64_hits)} base64-encoded string(s) of 48+ characters were extracted from "
                        f"executable memory in {entry.process_name} (PID {entry.pid}). Long base64 strings "
                        "in RWX memory are often encoded PowerShell commands, shellcode, or configuration "
                        "data for malware frameworks such as Cobalt Strike or Metasploit."
                    ),
                    evidence        = f"{context_label}\nFirst blob (truncated): {b64_hits[0][:80]}…",
                    mitre           = get_mitre("obfuscated_files"),
                    source_module   = self.name,
                    source_plugin   = "windows.malfind.Malfind",
                    affected_pid    = entry.pid,
                    affected_process= entry.process_name,
                    iocs            = [f"pid:{entry.pid}"],
                ))

        logger.info("StringExtractor: %d findings from %d malfind entries", len(findings), len(ctx.malfind))
        return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hex_to_bytes(hex_dump: str) -> bytes:
    """
    Parse a Volatility hex dump string into raw bytes.
    Format: '0xOFFSET  hh hh hh hh  hh hh hh hh  ...'
    """
    result = bytearray()
    for line in hex_dump.splitlines():
        parts = line.split()
        if not parts:
            continue
        # Skip the address field (first token)
        for p in parts[1:]:
            if len(p) == 2 and all(c in "0123456789abcdefABCDEF" for c in p):
                try:
                    result.append(int(p, 16))
                except ValueError:
                    pass
    return bytes(result)


def _extract_strings(data: bytes) -> list[str]:
    """Extract printable ASCII and UTF-16LE strings of at least MIN_STR_LEN chars."""
    results: list[str] = []

    # ASCII
    buf: list[str] = []
    for b in data:
        if 0x20 <= b < 0x7F:
            buf.append(chr(b))
        else:
            if len(buf) >= _MIN_STR_LEN:
                results.append("".join(buf))
            buf = []
    if len(buf) >= _MIN_STR_LEN:
        results.append("".join(buf))

    # UTF-16LE (Windows-native wide strings)
    try:
        wide = data.decode("utf-16-le", errors="ignore")
        buf = []
        for ch in wide:
            if 0x20 <= ord(ch) < 0x7F:
                buf.append(ch)
            else:
                if len(buf) >= _MIN_STR_LEN:
                    results.append("".join(buf))
                buf = []
        if len(buf) >= _MIN_STR_LEN:
            results.append("".join(buf))
    except Exception:
        pass

    return results
