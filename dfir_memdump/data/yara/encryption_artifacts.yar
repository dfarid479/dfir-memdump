/*
  encryption_artifacts.yar
  Signatures for encryption-related artifacts in memory images.

  Targets:
    - VeraCrypt volume header magic
    - TrueCrypt volume header signature
    - BitLocker VMK / metadata structures
    - Generic AES S-box presence (coarse indicator, high FP rate — INFO only)

  Note: These rules flag *presence* in memory, not key material itself.
  Recovered key candidates come from aeskeyfind / bulk_extractor / vol3 bitlocker.
*/

rule VeraCrypt_Volume_Header_Magic
{
    meta:
        description = "VeraCrypt volume header magic bytes present in memory"
        severity    = "HIGH"
        reference   = "https://veracrypt.fr/en/VeraCrypt%20Volume%20Format%20Specification.html"
    strings:
        $vera_sig   = "VeraCrypt" nocase
        $vera_magic = { 56 45 52 41 } /* "VERA" — volume header prefix */
    condition:
        $vera_sig or $vera_magic
}

rule TrueCrypt_Volume_Header
{
    meta:
        description = "TrueCrypt volume header signature in memory"
        severity    = "HIGH"
        reference   = "https://gitlab.com/cryptsetup/cryptsetup"
    strings:
        $tc_sig   = "TRUE" ascii
        $tc_sig2  = "TrueCrypt" nocase
    condition:
        $tc_sig or $tc_sig2
}

rule BitLocker_Metadata_Signature
{
    meta:
        description = "BitLocker FVE metadata structure signature in memory"
        severity    = "MEDIUM"
        reference   = "https://learn.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview"
    strings:
        /* BitLocker FVE metadata signature: "-FVE-FS-" */
        $fve_sig    = "-FVE-FS-" ascii
        /* BitLocker metadata block magic: 0x9A2A0000 (varies by version) */
        $fve_magic  = { 9A 2A 00 00 }
        /* "BITLOCKERVOLUMEBACKUPKEY" string sometimes present in WinPE/RE */
        $bl_str     = "BITLOCKER" nocase
    condition:
        $fve_sig or $fve_magic or $bl_str
}

rule LUKS_Header_In_Memory
{
    meta:
        description = "LUKS (Linux Unified Key Setup) partition header in memory — indicates encrypted Linux volume mounted or examined"
        severity    = "MEDIUM"
    strings:
        /* LUKS magic: 4C 55 4B 53 BA BE = "LUKS\xba\xbe" */
        $luks_magic = { 4C 55 4B 53 BA BE }
        $luks_str   = "LUKS" ascii
    condition:
        $luks_magic or $luks_str
}
