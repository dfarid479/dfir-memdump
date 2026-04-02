"""
MITRE ATT&CK mapper — converts (category, subcategory) tuples to technique references.

Used by all other intelligence modules to attach ATT&CK context to findings.
"""

from dfir_memdump.models import MitreRef

# Inline mapping — no external file dependency, always available.
# Key: short mnemonic. Value: technique metadata.
ATTCK_MAP: dict[str, dict] = {
    # Process Injection
    "process_injection":        {"id": "T1055",     "name": "Process Injection",              "tactic": "Defense Evasion / Privilege Escalation"},
    "process_hollowing":        {"id": "T1055.012", "name": "Process Hollowing",              "tactic": "Defense Evasion"},
    "dll_injection":            {"id": "T1055.001", "name": "DLL Injection",                  "tactic": "Defense Evasion"},
    "reflective_dll":           {"id": "T1055.001", "name": "Reflective DLL Injection",       "tactic": "Defense Evasion"},
    "thread_hijacking":         {"id": "T1055.003", "name": "Thread Execution Hijacking",     "tactic": "Defense Evasion"},

    # Masquerading
    "process_masquerading":     {"id": "T1036",     "name": "Masquerading",                   "tactic": "Defense Evasion"},
    "renamed_system_binary":    {"id": "T1036.003", "name": "Rename System Utilities",        "tactic": "Defense Evasion"},

    # Command and Scripting
    "powershell":               {"id": "T1059.001", "name": "PowerShell",                     "tactic": "Execution"},
    "cmd_shell":                {"id": "T1059.003", "name": "Windows Command Shell",           "tactic": "Execution"},
    "wscript_cscript":          {"id": "T1059.005", "name": "Visual Basic",                   "tactic": "Execution"},
    "mshta":                    {"id": "T1218.005", "name": "Mshta",                          "tactic": "Defense Evasion"},
    "regsvr32":                 {"id": "T1218.010", "name": "Regsvr32",                       "tactic": "Defense Evasion"},
    "rundll32":                 {"id": "T1218.011", "name": "Rundll32",                       "tactic": "Defense Evasion"},
    "certutil":                 {"id": "T1140",     "name": "Deobfuscate/Decode via Certutil","tactic": "Defense Evasion"},
    "bitsadmin":                {"id": "T1197",     "name": "BITS Jobs",                      "tactic": "Defense Evasion / Persistence"},
    "wmic":                     {"id": "T1047",     "name": "Windows Management Instrumentation","tactic": "Execution"},
    "installutil":              {"id": "T1218.004", "name": "InstallUtil",                    "tactic": "Defense Evasion"},
    "msiexec":                  {"id": "T1218.007", "name": "Msiexec",                        "tactic": "Defense Evasion"},

    # Network
    "c2_connection":            {"id": "T1071",     "name": "Application Layer Protocol",     "tactic": "Command and Control"},
    "c2_known_port":            {"id": "T1571",     "name": "Non-Standard Port",              "tactic": "Command and Control"},
    "dns_over_https":           {"id": "T1071.004", "name": "DNS over HTTPS",                 "tactic": "Command and Control"},
    "feodo_c2":                 {"id": "T1071.001", "name": "Web Protocols (Feodo C2)",       "tactic": "Command and Control"},

    # Credential Access
    "lsass_access":             {"id": "T1003.001", "name": "LSASS Memory",                   "tactic": "Credential Access"},
    "credential_dumping":       {"id": "T1003",     "name": "OS Credential Dumping",          "tactic": "Credential Access"},

    # Persistence
    "scheduled_task":           {"id": "T1053.005", "name": "Scheduled Task",                 "tactic": "Persistence"},
    "run_key":                  {"id": "T1547.001", "name": "Registry Run Keys",              "tactic": "Persistence"},
    "service_creation":         {"id": "T1543.003", "name": "Windows Service",                "tactic": "Persistence"},

    # Discovery
    "system_info_discovery":    {"id": "T1082",     "name": "System Information Discovery",   "tactic": "Discovery"},
    "process_discovery":        {"id": "T1057",     "name": "Process Discovery",              "tactic": "Discovery"},
    "network_discovery":        {"id": "T1016",     "name": "System Network Configuration",  "tactic": "Discovery"},

    # Exfiltration
    "data_exfil_network":       {"id": "T1041",     "name": "Exfiltration Over C2 Channel",  "tactic": "Exfiltration"},

    # Malware (generic)
    "yara_malware":             {"id": "T1027",     "name": "Obfuscated Files or Information","tactic": "Defense Evasion"},

    # LOLBAS generic fallback
    "lolbas_generic":           {"id": "T1218",     "name": "System Binary Proxy Execution",  "tactic": "Defense Evasion"},

    # Parent-child anomaly generic
    "parent_child_anomaly":     {"id": "T1055",     "name": "Process Injection",              "tactic": "Defense Evasion"},

    # Token / Privilege Escalation
    "token_impersonate":        {"id": "T1134.001", "name": "Token Impersonation/Theft",       "tactic": "Privilege Escalation"},
    "se_debug":                 {"id": "T1134.001", "name": "Token Impersonation/Theft",       "tactic": "Privilege Escalation"},
    "dangerous_privilege":      {"id": "T1134",     "name": "Access Token Manipulation",       "tactic": "Privilege Escalation"},
    "se_load_driver":           {"id": "T1014",     "name": "Rootkit",                        "tactic": "Defense Evasion"},
    "se_tcb_privilege":         {"id": "T1134.002", "name": "Create Process with Token",       "tactic": "Privilege Escalation"},

    # Lateral Movement
    "smb_shares":               {"id": "T1021.002", "name": "SMB/Windows Admin Shares",        "tactic": "Lateral Movement"},
    "rdp":                      {"id": "T1021.001", "name": "Remote Desktop Protocol",         "tactic": "Lateral Movement"},
    "winrm":                    {"id": "T1021.006", "name": "Windows Remote Management",       "tactic": "Lateral Movement"},
    "dcom":                     {"id": "T1021.003", "name": "Distributed Component Object Model", "tactic": "Lateral Movement"},
    "psexec":                   {"id": "T1569.002", "name": "Service Execution (PsExec)",       "tactic": "Lateral Movement"},
    "pass_the_hash":            {"id": "T1550.002", "name": "Pass the Hash",                   "tactic": "Lateral Movement"},
    "lateral_tool":             {"id": "T1570",     "name": "Lateral Tool Transfer",            "tactic": "Lateral Movement"},

    # Credential Access (short aliases)
    "credential_dump":          {"id": "T1003",     "name": "OS Credential Dumping",           "tactic": "Credential Access"},

    # Discovery
    "ldap_enum":                {"id": "T1087.002", "name": "Domain Account Discovery (LDAP)",  "tactic": "Discovery"},
    "discovery":                {"id": "T1082",     "name": "System Information Discovery",     "tactic": "Discovery"},

    # C2 aliases
    "c2_http":                  {"id": "T1071.001", "name": "Web Protocols",                   "tactic": "Command and Control"},

    # Impact
    "impact_data":              {"id": "T1486",     "name": "Data Encrypted for Impact",        "tactic": "Impact"},

    # Persistence generic
    "persistence":              {"id": "T1547",     "name": "Boot/Logon Autostart Execution",   "tactic": "Persistence"},

    # Obfuscation
    "obfuscated_files":         {"id": "T1027",     "name": "Obfuscated Files or Information",  "tactic": "Defense Evasion"},
}

ATTCK_BASE_URL = "https://attack.mitre.org/techniques/"


def get_mitre(key: str) -> MitreRef | None:
    """Return a MitreRef for the given mapping key, or None if not found."""
    entry = ATTCK_MAP.get(key)
    if not entry:
        return None
    tech_id = entry["id"]
    url = ATTCK_BASE_URL + tech_id.replace(".", "/")
    return MitreRef(
        technique_id=tech_id,
        technique_name=entry["name"],
        tactic=entry["tactic"],
        url=url,
    )
