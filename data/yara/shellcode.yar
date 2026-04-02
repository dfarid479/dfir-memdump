/*
   Shellcode and exploit pattern detection rules.
   These target common shellcode patterns seen in memory injection scenarios.
*/

rule Shellcode_MZ_Header_In_Memory
{
    meta:
        description = "Executable MZ header found in non-module-backed memory region"
        severity    = "critical"
        category    = "INJECTION"
        mitre_key   = "process_hollowing"
        author      = "dfir-memdump"

    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }

    condition:
        $mz at 0 and $pe
}

rule Shellcode_Common_Prologue
{
    meta:
        description = "Common shellcode function prologue patterns in executable memory"
        severity    = "high"
        category    = "INJECTION"
        mitre_key   = "process_injection"
        author      = "dfir-memdump"

    strings:
        // push ebp; mov ebp, esp; sub esp, N
        $prologue1 = { 55 8B EC 83 EC }
        // call $+5 (GetPC trick common in shellcode)
        $callnext  = { E8 00 00 00 00 }
        // NOP sled (16+ NOPs)
        $nop_sled  = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

    condition:
        2 of them
}

rule Shellcode_Win32_API_Hashing
{
    meta:
        description = "API hashing pattern — common technique in position-independent shellcode"
        severity    = "high"
        category    = "INJECTION"
        mitre_key   = "process_injection"
        author      = "dfir-memdump"

    strings:
        // ROR 13 hash loop pattern (Metasploit/CobaltStrike default)
        $ror13a = { C1 C? 0D }
        $ror13b = { D1 C? }
        // XOR hash loop
        $xorhash = { 31 C? 83 F? 00 }

    condition:
        2 of them
}

rule Shellcode_Reflective_DLL_Loader
{
    meta:
        description = "Reflective DLL injection loader stub pattern"
        severity    = "critical"
        category    = "INJECTION"
        mitre_key   = "reflective_dll"
        author      = "dfir-memdump"

    strings:
        // ReflectiveLoader export name
        $loader_name = "ReflectiveLoader" ascii wide
        // Common reflective loader magic
        $magic = { FC E8 ?? 00 00 00 }
        // VirtualAlloc call pattern
        $valloc = "VirtualAlloc" ascii wide

    condition:
        $loader_name or ($magic and $valloc)
}

rule Shellcode_Egg_Hunter
{
    meta:
        description = "Egg hunter shellcode pattern (SEH-based)"
        severity    = "medium"
        category    = "INJECTION"
        mitre_key   = "process_injection"
        author      = "dfir-memdump"

    strings:
        // w00tw00t egg (common in exploit dev)
        $egg1 = { 77 30 30 74 77 30 30 74 }
        // Common egg hunter stub
        $hunter = { 66 81 CA FF 0F 42 52 6A }

    condition:
        any of them
}
