/*
   C2 framework and RAT detection rules.
   Targets Cobalt Strike, Metasploit, Empire, Havoc, Sliver, etc.
*/

rule CobaltStrike_Beacon_Strings
{
    meta:
        description = "Cobalt Strike beacon strings detected in memory"
        severity    = "critical"
        category    = "C2"
        mitre_key   = "c2_connection"
        author      = "dfir-memdump"

    strings:
        $s1 = "beacon" ascii wide nocase
        $s2 = "CobaltStrike" ascii wide nocase
        $s3 = "%s (admin)" ascii wide
        $s4 = "could not spawn %s: %d" ascii
        $s5 = "BeaconJitter" ascii wide
        $s6 = "Malleable" ascii wide
        $s7 = "watermark" ascii wide
        $pe1 = "ReflectiveDll" ascii wide

    condition:
        3 of them
}

rule CobaltStrike_Beacon_Config
{
    meta:
        description = "Cobalt Strike beacon configuration block pattern"
        severity    = "critical"
        category    = "C2"
        mitre_key   = "c2_connection"
        author      = "dfir-memdump"

    strings:
        // Common beacon config XOR key pattern (0x69) at offset 0
        $xor_conf  = { 69 69 69 69 }
        // Checksum8 marker in beacon config
        $cfg_magic = { 00 01 00 01 00 02 }
        // Sleep mask default
        $sleep     = "sleep_mask" ascii wide

    condition:
        $xor_conf or ($cfg_magic and $sleep)
}

rule Metasploit_Meterpreter
{
    meta:
        description = "Metasploit Meterpreter payload strings detected in memory"
        severity    = "critical"
        category    = "C2"
        mitre_key   = "c2_connection"
        author      = "dfir-memdump"

    strings:
        $s1 = "meterpreter" ascii wide nocase
        $s2 = "Metasploit" ascii wide nocase
        $s3 = "METERPRETER_TRANSPORT" ascii wide
        $s4 = "TLV_TYPE" ascii wide
        $s5 = "ext_server_stdapi" ascii wide
        $s6 = "LoadLibraryA" ascii wide
        $s7 = "ReflectiveLoader" ascii wide

    condition:
        ($s1 or $s2) and 2 of ($s3, $s4, $s5, $s7)
}

rule Empire_PowerShell_Agent
{
    meta:
        description = "PowerShell Empire agent strings detected in memory"
        severity    = "critical"
        category    = "C2"
        mitre_key   = "c2_connection"
        author      = "dfir-memdump"

    strings:
        $s1 = "Empire" ascii wide
        $s2 = "PowerShell Empire" ascii wide
        $s3 = "staging key" ascii wide nocase
        $s4 = "Invoke-Empire" ascii wide
        $s5 = "EMLM" ascii wide

    condition:
        2 of them
}

rule Havoc_C2_Framework
{
    meta:
        description = "Havoc C2 framework demon agent strings"
        severity    = "critical"
        category    = "C2"
        mitre_key   = "c2_connection"
        author      = "dfir-memdump"

    strings:
        $s1 = "Havoc" ascii wide
        $s2 = "DemonID" ascii wide
        $s3 = "demon.x64" ascii wide nocase
        $s4 = "HavocTeamServer" ascii wide

    condition:
        2 of them
}

rule Sliver_C2
{
    meta:
        description = "Sliver C2 implant strings detected in memory"
        severity    = "critical"
        category    = "C2"
        mitre_key   = "c2_connection"
        author      = "dfir-memdump"

    strings:
        $s1 = "SliverC2" ascii wide
        $s2 = "sliver" ascii wide
        $s3 = "implant_config" ascii wide
        $s4 = "github.com/bishopfox/sliver" ascii wide

    condition:
        any of them
}

rule Generic_RAT_Strings
{
    meta:
        description = "Generic Remote Access Trojan behavioral strings"
        severity    = "high"
        category    = "C2"
        mitre_key   = "c2_connection"
        author      = "dfir-memdump"

    strings:
        $cmd1 = "cmd.exe /c " ascii wide nocase
        $cmd2 = "CreateRemoteThread" ascii wide
        $cmd3 = "VirtualAllocEx" ascii wide
        $cmd4 = "WriteProcessMemory" ascii wide
        $cmd5 = "OpenProcess" ascii wide
        $cmd6 = "keylogger" ascii wide nocase
        $cmd7 = "screenshot" ascii wide nocase
        $cmd8 = "reverse_shell" ascii wide nocase

    condition:
        4 of them
}

rule BruteRatel_C4
{
    meta:
        description = "Brute Ratel C4 badger implant strings"
        severity    = "critical"
        category    = "C2"
        mitre_key   = "c2_connection"
        author      = "dfir-memdump"

    strings:
        $s1 = "BruteRatel" ascii wide nocase
        $s2 = "brute_ratel" ascii wide nocase
        $s3 = "badger" ascii wide
        $s4 = "katana" ascii wide

    condition:
        2 of them
}
