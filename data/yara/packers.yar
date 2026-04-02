/*
   Packer and crypter detection rules.
   Packed executables are a strong evasion indicator.
*/

rule UPX_Packed
{
    meta:
        description = "UPX packer signature detected"
        severity    = "medium"
        category    = "MALWARE"
        mitre_key   = "yara_malware"
        author      = "dfir-memdump"

    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii

    condition:
        2 of them
}

rule Themida_Winlicense
{
    meta:
        description = "Themida/WinLicense commercial packer — often abused by malware"
        severity    = "medium"
        category    = "MALWARE"
        mitre_key   = "yara_malware"
        author      = "dfir-memdump"

    strings:
        $s1 = "Themida" ascii wide
        $s2 = "WinLicense" ascii wide
        $s3 = "OREANS" ascii wide

    condition:
        any of them
}

rule MPRESS_Packer
{
    meta:
        description = "MPRESS packer signature"
        severity    = "medium"
        category    = "MALWARE"
        mitre_key   = "yara_malware"
        author      = "dfir-memdump"

    strings:
        $s1 = ".MPRESS1" ascii
        $s2 = ".MPRESS2" ascii

    condition:
        any of them
}

rule ConfuserEx_Obfuscation
{
    meta:
        description = "ConfuserEx .NET obfuscator strings (.NET malware indicator)"
        severity    = "high"
        category    = "MALWARE"
        mitre_key   = "yara_malware"
        author      = "dfir-memdump"

    strings:
        $s1 = "ConfuserEx" ascii wide
        $s2 = "Confuser.Core" ascii wide
        $s3 = "ConfusedByAttribute" ascii wide

    condition:
        any of them
}

rule Suspicious_Section_Names
{
    meta:
        description = "Suspicious PE section names — common in packers and loaders"
        severity    = "medium"
        category    = "MALWARE"
        mitre_key   = "yara_malware"
        author      = "dfir-memdump"

    strings:
        $s1 = ".rmnet" ascii
        $s2 = "BitDefender" ascii
        $s3 = ".ndata" ascii
        $s4 = ".ccnet" ascii
        $s5 = "PECOMPACT" ascii

    condition:
        any of them
}
