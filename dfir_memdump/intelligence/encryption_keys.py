"""
Encryption Key Finder intelligence module.

Recovers encryption key material from memory using three approaches:
  1. BitLocker FVEKs   — already parsed by BitlockerPlugin, promoted to findings
  2. AES key schedules — aeskeyfind subprocess (Princeton CITP tool) if on PATH
  3. bulk_extractor    — -e aes scanner if on PATH (also catches VeraCrypt/TrueCrypt)
  4. VeraCrypt VAD     — checks for veracrypt.exe in process list + malfind hits

All recovered keys are appended to ctx.encryption_keys in addition to
being emitted as Finding objects so they appear in the attack chain.

Chain-of-custody note: key recovery is performed entirely against the
in-memory forensic copy. No writes to the original media.
"""

from __future__ import annotations
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from dfir_memdump.intelligence import BaseIntelModule, IntelContext
from dfir_memdump.models import (
    EncryptionKeyArtifact, Finding, FindingCategory, MitreRef, Severity,
)

logger = logging.getLogger(__name__)

# MITRE T1552.001 — Credentials in Files (closest mapping for key extraction)
_MITRE_CRED = MitreRef(
    technique_id   = "T1552.001",
    technique_name = "Credentials In Files",
    tactic         = "Credential Access",
    url            = "https://attack.mitre.org/techniques/T1552/001/",
)

# VeraCrypt process names (any capitalisation)
_VC_PROCS = {"veracrypt.exe", "veracrypt", "truecrypt.exe", "truecrypt"}

# aeskeyfind output line: "Key length: 128 bits"  then  "Key: <hex>"
_AES_KEY_RE = re.compile(
    r"Key\s+length:\s*(?P<bits>\d+)\s*bits.*?Key:\s*(?P<hex>[0-9a-fA-F]{32,64})",
    re.DOTALL | re.IGNORECASE,
)

# bulk_extractor aes_keys.txt line: "0x<offset>: <hex>"
_BE_KEY_RE = re.compile(r"0x[0-9a-fA-F]+:\s*(?P<hex>[0-9a-fA-F]{32,64})")


class EncryptionKeyFinder(BaseIntelModule):
    """Recovers encryption key material from a memory image."""

    name = "EncryptionKeyFinder"

    def analyze(self, ctx: IntelContext) -> list[Finding]:
        findings: list[Finding] = []

        # ── 1. BitLocker FVEKs (from BitlockerPlugin, already in ctx) ─────────
        for key in ctx.bitlocker_keys:
            findings.append(self._bitlocker_finding(key))

        # ── 2. aeskeyfind subprocess ──────────────────────────────────────────
        if ctx.image_path and shutil.which("aeskeyfind"):
            for key in self._run_aeskeyfind(ctx.image_path):
                ctx.encryption_keys.append(key)
                findings.append(self._aes_finding(key, "aeskeyfind"))
        elif ctx.image_path and not shutil.which("aeskeyfind"):
            logger.debug("aeskeyfind not on PATH — skipping AES key schedule scan")

        # ── 3. bulk_extractor -e aes ──────────────────────────────────────────
        if ctx.image_path and shutil.which("bulk_extractor"):
            for key in self._run_bulk_extractor(ctx.image_path):
                # Deduplicate against what aeskeyfind already found
                if key.key_hex not in {k.key_hex for k in ctx.encryption_keys}:
                    ctx.encryption_keys.append(key)
                    findings.append(self._aes_finding(key, "bulk_extractor"))
        elif ctx.image_path and not shutil.which("bulk_extractor"):
            logger.debug("bulk_extractor not on PATH — skipping bulk AES scan")

        # ── 4. VeraCrypt / TrueCrypt process presence ─────────────────────────
        for proc in ctx.processes:
            if proc.name.lower() in _VC_PROCS:
                key = EncryptionKeyArtifact(
                    key_type     = "VeraCrypt-candidate",
                    algorithm    = "AES-256-XTS",
                    key_hex      = "",
                    source       = "process-presence",
                    pid          = proc.pid,
                    process_name = proc.name,
                    notes        = (
                        f"{proc.name} (PID {proc.pid}) was running at collection time. "
                        "The master key is likely resident in its VAD regions. "
                        "Use aeskeyfind or bulk_extractor on the raw image to recover candidates."
                    ),
                )
                ctx.encryption_keys.append(key)
                findings.append(Finding(
                    severity         = Severity.HIGH,
                    category         = FindingCategory.ENCRYPTION,
                    title            = f"VeraCrypt/TrueCrypt process active at collection — key likely recoverable",
                    description      = (
                        f"{proc.name} was running when memory was captured. "
                        "The volume master key is typically held in the process VAD. "
                        "Run aeskeyfind or bulk_extractor against the image to recover AES candidates."
                    ),
                    evidence         = f"Process: {proc.name}  PID: {proc.pid}  PPID: {proc.ppid}",
                    source_module    = self.name,
                    source_plugin    = "windows.pslist",
                    affected_pid     = proc.pid,
                    affected_process = proc.name,
                    mitre            = _MITRE_CRED,
                    iocs             = [f"process_name:{proc.name}"],
                ))

        return findings

    # ── BitLocker finding builder ──────────────────────────────────────────────

    def _bitlocker_finding(self, key: EncryptionKeyArtifact) -> Finding:
        return Finding(
            severity         = Severity.CRITICAL,
            category         = FindingCategory.ENCRYPTION,
            title            = f"BitLocker FVEK recovered from memory ({key.algorithm})",
            description      = (
                "A BitLocker Full Volume Encryption Key (FVEK) was extracted directly from "
                "memory by windows.bitlocker.Bitlocker. This key can decrypt the target "
                "volume without the user password, PIN, or recovery key. "
                "Document tool version and command for chain-of-custody."
            ),
            evidence         = (
                f"Algorithm : {key.algorithm}\n"
                f"Key (hex) : {key.key_hex}\n"
                f"Mount cmd : {key.dislocker_cmd or 'see report'}"
            ),
            source_module    = self.name,
            source_plugin    = "windows.bitlocker.Bitlocker",
            mitre            = _MITRE_CRED,
            iocs             = [f"bitlocker_fvek:{key.key_hex}"],
        )

    # ── aeskeyfind ────────────────────────────────────────────────────────────

    def _run_aeskeyfind(self, image_path: Path) -> list[EncryptionKeyArtifact]:
        """Run aeskeyfind against the raw image and parse recovered key schedules."""
        results: list[EncryptionKeyArtifact] = []
        try:
            proc = subprocess.run(
                ["aeskeyfind", str(image_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )
            output = proc.stdout + proc.stderr
            for m in _AES_KEY_RE.finditer(output):
                bits    = int(m.group("bits"))
                key_hex = m.group("hex").lower()
                results.append(EncryptionKeyArtifact(
                    key_type  = f"AES-{bits}",
                    algorithm = f"AES-{bits}",
                    key_hex   = key_hex,
                    source    = "aeskeyfind",
                    notes     = (
                        f"AES-{bits} key schedule detected at statistical significance threshold. "
                        "May be BitLocker, VeraCrypt, TrueCrypt, or another AES-based cipher. "
                        "Attempt decryption against known encrypted volumes to confirm."
                    ),
                ))
                logger.info("aeskeyfind: recovered AES-%d key", bits)
        except subprocess.TimeoutExpired:
            logger.warning("aeskeyfind timed out on %s", image_path)
        except Exception as exc:
            logger.error("aeskeyfind failed: %s", exc)
        return results

    # ── bulk_extractor ────────────────────────────────────────────────────────

    def _run_bulk_extractor(self, image_path: Path) -> list[EncryptionKeyArtifact]:
        """Run bulk_extractor with -e aes and parse the aes_keys.txt output."""
        results: list[EncryptionKeyArtifact] = []
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                proc = subprocess.run(
                    ["bulk_extractor", "-e", "aes", "-o", tmpdir, str(image_path)],
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
                aes_file = Path(tmpdir) / "aes_keys.txt"
                if not aes_file.exists():
                    return results
                for line in aes_file.read_text(encoding="utf-8", errors="replace").splitlines():
                    m = _BE_KEY_RE.search(line)
                    if not m:
                        continue
                    key_hex = m.group("hex").lower()
                    bits    = len(key_hex) * 4  # 32 chars = 128 bits, 64 = 256 bits
                    # Extract offset from line prefix
                    offset = line.split(":")[0].strip() if ":" in line else None
                    results.append(EncryptionKeyArtifact(
                        key_type    = f"AES-{bits}",
                        algorithm   = f"AES-{bits}",
                        key_hex     = key_hex,
                        source      = "bulk_extractor",
                        file_offset = offset,
                        notes       = (
                            f"AES-{bits} key material found at offset {offset} by bulk_extractor. "
                            "Candidate for BitLocker, VeraCrypt, TrueCrypt, or LUKS volume decryption."
                        ),
                    ))
                    logger.info("bulk_extractor: recovered AES-%d key at %s", bits, offset)
        except subprocess.TimeoutExpired:
            logger.warning("bulk_extractor timed out on %s", image_path)
        except Exception as exc:
            logger.error("bulk_extractor failed: %s", exc)
        return results

    # ── AES finding builder ───────────────────────────────────────────────────

    def _aes_finding(self, key: EncryptionKeyArtifact, tool: str) -> Finding:
        offset_str = f" at offset {key.file_offset}" if key.file_offset else ""
        return Finding(
            severity      = Severity.HIGH,
            category      = FindingCategory.ENCRYPTION,
            title         = f"AES key schedule recovered by {tool} ({key.algorithm})",
            description   = (
                f"{tool} detected an AES key schedule{offset_str} in the memory image. "
                "Key schedules are the expanded form of AES encryption keys — their statistical "
                "properties distinguish them from random data with high confidence. "
                "Attempt to use this key against any encrypted volumes present on the device."
            ),
            evidence      = (
                f"Tool      : {tool}\n"
                f"Algorithm : {key.algorithm}\n"
                f"Key (hex) : {key.key_hex}"
                + (f"\nOffset    : {key.file_offset}" if key.file_offset else "")
            ),
            source_module = self.name,
            source_plugin = tool,
            mitre         = _MITRE_CRED,
            iocs          = [f"aes_key:{key.key_hex}"],
        )
