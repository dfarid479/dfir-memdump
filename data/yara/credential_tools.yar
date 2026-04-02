/*
   Credential dumping tool detection rules.
   Targets Mimikatz, ProcDump credential abuse, LSASS dumping tools, etc.
*/

rule Mimikatz_Strings
{
    meta:
        description = "Mimikatz credential dumping tool strings detected in memory"
        severity    = "critical"
        category    = "CREDENTIAL"
        mitre_key   = "lsass_access"
        author      = "dfir-memdump"

    strings:
        $s1 = "mimikatz" ascii wide nocase
        $s2 = "sekurlsa" ascii wide nocase
        $s3 = "lsadump" ascii wide nocase
        $s4 = "kerberos::ptt" ascii wide nocase
        $s5 = "privilege::debug" ascii wide nocase
        $s6 = "Pass-the-Hash" ascii wide nocase
        $s7 = "WDigest" ascii wide nocase
        $s8 = "NTLM hash" ascii wide nocase
        $s9 = "SamSs" ascii wide nocase

    condition:
        2 of them
}

rule Mimikatz_PE_Signature
{
    meta:
        description = "Mimikatz binary signature detected"
        severity    = "critical"
        category    = "CREDENTIAL"
        mitre_key   = "lsass_access"
        author      = "dfir-memdump"

    strings:
        $ver1 = "Benjamin DELPY" ascii wide
        $ver2 = "gentilkiwi" ascii wide
        $ver3 = "mimikatz" ascii wide nocase
        $mod1 = "kuhl_m_sekurlsa" ascii
        $mod2 = "kuhl_m_lsadump" ascii

    condition:
        ($ver1 or $ver2) and ($mod1 or $mod2 or $ver3)
}

rule LSASS_Dump_Strings
{
    meta:
        description = "LSASS credential dump attempt strings in process memory"
        severity    = "critical"
        category    = "CREDENTIAL"
        mitre_key   = "lsass_access"
        author      = "dfir-memdump"

    strings:
        $s1 = "lsass.exe" ascii wide nocase
        $s2 = "MiniDumpWriteDump" ascii wide
        $s3 = "dbghelp.dll" ascii wide nocase
        $s4 = "sekurlsa::logonpasswords" ascii wide nocase
        $s5 = "comsvcs.dll" ascii wide

    condition:
        2 of ($s1, $s2, $s3) or $s4
}

rule ProcDump_LSASS_Abuse
{
    meta:
        description = "ProcDump or similar tool targeting LSASS for credential extraction"
        severity    = "high"
        category    = "CREDENTIAL"
        mitre_key   = "credential_dumping"
        author      = "dfir-memdump"

    strings:
        $t1 = "procdump" ascii wide nocase
        $t2 = "-ma lsass" ascii wide nocase
        $t3 = "Task Manager" ascii wide
        $lsass = "lsass" ascii wide nocase

    condition:
        $lsass and ($t1 or $t2)
}

rule Impacket_Strings
{
    meta:
        description = "Impacket framework strings detected — credential/lateral movement tool"
        severity    = "high"
        category    = "CREDENTIAL"
        mitre_key   = "credential_dumping"
        author      = "dfir-memdump"

    strings:
        $s1 = "impacket" ascii wide nocase
        $s2 = "secretsdump" ascii wide nocase
        $s3 = "wmiexec" ascii wide nocase
        $s4 = "psexec" ascii wide nocase
        $s5 = "smbexec" ascii wide nocase
        $s6 = "DCSync" ascii wide nocase

    condition:
        2 of them
}

rule LaZagne_Password_Dumper
{
    meta:
        description = "LaZagne password recovery tool strings"
        severity    = "high"
        category    = "CREDENTIAL"
        mitre_key   = "credential_dumping"
        author      = "dfir-memdump"

    strings:
        $s1 = "lazagne" ascii wide nocase
        $s2 = "AESModeOfOperationCBC" ascii wide
        $s3 = "ChromePasswordManager" ascii wide
        $s4 = "hashdump" ascii wide nocase

    condition:
        $s1 or 2 of ($s2, $s3, $s4)
}
