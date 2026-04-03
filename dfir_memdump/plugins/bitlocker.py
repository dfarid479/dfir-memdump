"""
Volatility3 windows.bitlocker.Bitlocker plugin wrapper.

Extracts BitLocker Full Volume Encryption Keys (FVEKs) from memory.
The recovered key can be passed directly to dislocker or bdemount to
mount the encrypted volume without the original password or recovery key.

Chain of custody note: key recovery is performed against the forensic
memory image; the original media is not touched.
"""

from __future__ import annotations
import logging

from dfir_memdump.models import EncryptionKeyArtifact
from dfir_memdump.plugins import BasePlugin

logger = logging.getLogger(__name__)

# Column name variants seen across Volatility3 versions / OS builds
_FVEK_COLS  = ("FVEK", "FVEKDecrypted", "Key", "FullVolumeEncryptionKey")
_CIPHER_COLS = ("Cipher", "Algorithm", "EncryptionType", "CipherAlgorithm")


class BitlockerPlugin(BasePlugin[EncryptionKeyArtifact]):
    """Extracts BitLocker FVEKs via windows.bitlocker.Bitlocker."""

    plugin_name  = "windows.bitlocker.Bitlocker"
    output_model = EncryptionKeyArtifact

    def _parse(self, raw: str) -> list[EncryptionKeyArtifact]:
        rows = self._parse_json_rows(raw)
        results: list[EncryptionKeyArtifact] = []

        for row in rows:
            fvek = None
            for col in _FVEK_COLS:
                val = row.get(col)
                if val and str(val).strip() not in ("N/A", "None", "-", ""):
                    fvek = str(val).strip()
                    break

            if not fvek:
                continue

            cipher = "AES-128-XTS"
            for col in _CIPHER_COLS:
                val = row.get(col)
                if val and str(val).strip() not in ("N/A", "None", "-", ""):
                    cipher = str(val).strip()
                    break

            # Normalise key hex: strip separators, prefix
            key_hex = fvek.replace("-", "").replace(" ", "").replace("0x", "").lower()

            if not key_hex or len(key_hex) < 32:
                logger.debug("Skipping short/empty FVEK: %s", fvek)
                continue

            dislocker_cmd = (
                f"dislocker -V /dev/sdX --fvek {key_hex} -- /mnt/dislocker\n"
                f"# OR: bdemount -k {key_hex} /dev/sdX /mnt/bde"
            )

            results.append(EncryptionKeyArtifact(
                key_type      = "BitLocker-FVEK",
                algorithm     = cipher,
                key_hex       = key_hex,
                source        = "windows.bitlocker.Bitlocker",
                dislocker_cmd = dislocker_cmd,
                notes         = "Replace /dev/sdX with the target BitLocker-encrypted partition device.",
            ))
            logger.info("BitLocker FVEK recovered (%s, %d bytes)", cipher, len(key_hex) // 2)

        return results
