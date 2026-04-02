# dfir-memdump

**Windows memory forensics triage tool powered by Volatility3.**

Runs a curated stack of Volatility3 plugins against a memory image, passes the results through nine intelligence modules, and produces a structured triage report in JSON, Markdown, and self-contained HTML — ready to hand off to leadership, drop into a case folder, or import into a SIEM.

---

## What it does

| Stage | What happens |
|---|---|
| **Plugin execution** | Runs `windows.pslist`, `windows.netscan`, `windows.malfind`, `windows.cmdline`, `windows.dlllist`, `windows.handles`, `windows.privileges` via Volatility3 |
| **Intelligence analysis** | Nine modules analyse the output for behavioural indicators |
| **Report generation** | Outputs JSON (machine-readable), Markdown, and interactive HTML |

### Intelligence modules

| Module | Detects |
|---|---|
| `AnomalyDetector` | Parent-child spoofing, name/path masquerading, hollow process indicators, unusual session IDs |
| `LolbasChecker` | Living-off-the-Land binaries used for execution, bypass, or lateral movement |
| `C2Detector` | Connections to Feodo tracker C2 IPs, suspicious outbound ports, known malware callbacks |
| `YaraEngine` | Shellcode, credential tools, C2 frameworks (Cobalt Strike, Meterpreter, Sliver), and packers in VAD regions |
| `VTClient` | VirusTotal SHA-256 lookups on process images (4 req/min, SQLite-cached) |
| `StringExtractor` | URLs, external IPs, execution commands, suspicious paths, and base64 blobs from malfind hex dumps |
| `LateralMovementDetector` | SMB/RDP/WinRM/DCOM connections, 18 known lateral movement tool signatures, cmdline patterns (net use, wmiexec, Invoke-Command, etc.) |
| `MutexChecker` | 20+ known malware mutexes (Cobalt Strike, WannaCry, LockBit, NjRAT, Mimikatz…), sensitive registry key handles, cross-process handle abuse |
| `PrivilegeChecker` | Dangerous token privileges on non-system processes: `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeTcbPrivilege`, `SeLoadDriverPrivilege`, and five others |

### Report features

- **Executive Summary** — auto-generated priority narrative for leadership
- **Process Risk Leaderboard** — top processes by weighted finding score (CRITICAL=10 / HIGH=5 / MEDIUM=2 / LOW=1)
- **Process Tree** — parent→child hierarchy with `[!]` flags on suspicious PIDs and cmdline hints
- **Event Timeline** — chronological process creation + network events, flagged entries surfaced first
- **Attack Chain Reconstruction** — findings grouped by MITRE ATT&CK tactic, ordered along the kill chain (Initial Access → Execution → … → Impact), with plain-English narrative per stage
- **Findings** — colour-coded by severity, MITRE ATT&CK linked, evidence blocks, IOC chips (click to copy)
- **IOC Table** — deduplicated IPs, hashes, mutexes, registry keys, filepaths ready for SIEM import
- **MITRE ATT&CK Coverage** — badge grid linking to technique pages
- **Print / Save PDF** — one-click from the HTML report

---

## Requirements

- Python 3.10+
- [Volatility3](https://github.com/volatilityfoundation/volatility3) 2.7+  (`vol` must be on PATH, or set `VOL3_PATH` in `.env`)
- Windows memory image (`.raw`, `.mem`, `.vmem`, `.dmp`, etc.)
- *(Optional)* `yara-python` for YARA scanning
- *(Optional)* VirusTotal API key for hash lookups

---

## Installation

```bash
git clone https://github.com/yourusername/dfir-memdump.git
cd dfir-memdump

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -e .

# Volatility3 must be installed and on PATH
pip install volatility3

# Optional: copy and fill in the env template
cp .env.example .env
# then edit .env with your VT_API_KEY if you want VirusTotal lookups
```

---

## Quick start

```bash
# Full analysis — JSON + Markdown + HTML reports in ./reports/
dfir-memdump analyze /path/to/memory.raw

# HTML only, custom output folder
dfir-memdump analyze /path/to/memory.raw --format html --output ./case-001/

# Skip VirusTotal (offline / faster)
dfir-memdump analyze /path/to/memory.raw --no-vt

# Skip YARA (faster, no yara-python required)
dfir-memdump analyze /path/to/memory.raw --no-yara

# Specify a Volatility3 OS profile
dfir-memdump analyze /path/to/memory.raw --profile Win10x64_19041

# Custom report filename stem
dfir-memdump analyze /path/to/memory.raw --stem case-001-hostname

# Print version
dfir-memdump version
```

The HTML report opens in any browser — click **Print / Save PDF** to export a print-ready PDF.

---

## Options reference

```
dfir-memdump analyze IMAGE [OPTIONS]

Arguments:
  IMAGE           Path to the memory image file  [required]

Options:
  -p, --profile   Volatility3 profile override (e.g. Win10x64_19041)
  -o, --output    Output directory  [default: ./reports]
  -f, --format    Report format: json | markdown | html | all  [default: all]
  --no-vt         Skip VirusTotal hash lookups
  --no-yara       Skip YARA scanning
  --stem          Report filename stem  [default: <image>.triage]
  --debug         Enable debug logging
```

---

## Environment variables

Copy `.env.example` to `.env` and set as needed:

| Variable | Default | Description |
|---|---|---|
| `VT_API_KEY` | *(empty)* | VirusTotal API key. Free tier: 4 req/min. Omit to skip. |
| `VOL3_PATH` | `vol` | Path to the Volatility3 binary if not on `PATH` |

---

## Project layout

```
dfir_memdump/
  cli.py               # Click CLI entrypoint
  runner.py            # Orchestrator: plugins → intel → report
  models.py            # Pydantic models (single source of truth)
  config.py            # Pydantic-settings (reads .env)
  exceptions.py        # Custom exceptions
  plugins/
    pslist.py          # windows.pslist.PsList
    netscan.py         # windows.netscan.NetScan
    malfind.py         # windows.malfind.Malfind
    cmdline.py         # windows.cmdline.CmdLine
    dlllist.py         # windows.dlllist.DllList
    handles.py         # windows.handles.Handles
    privileges.py      # windows.privileges.Privs
  intelligence/
    anomaly_detector.py
    lolbas_checker.py
    c2_detector.py
    yara_engine.py
    vt_client.py
    string_extractor.py
    lateral_movement.py
    mutex_checker.py
    privilege_checker.py
    chain_builder.py   # Attack chain reconstruction
    attck_mapper.py    # MITRE ATT&CK technique registry
  report/
    builder.py         # Format dispatcher
    json_report.py
    markdown_report.py
    html_report.py     # Self-contained HTML (all CSS/JS inline)
data/
  yara/
    shellcode.yar
    credential_tools.yar
    c2_frameworks.yar
    packers.yar
templates/
  report.md.j2         # Jinja2 Markdown report template
```

---

## MITRE ATT&CK coverage

| Technique | Name | Module |
|---|---|---|
| T1055 / T1055.012 | Process Injection / Process Hollowing | AnomalyDetector |
| T1036 / T1036.003 | Masquerading / Rename System Utilities | AnomalyDetector |
| T1059.001 / T1059.003 | PowerShell / Windows Command Shell | LolbasChecker |
| T1218 | System Binary Proxy Execution (LOLBAS) | LolbasChecker |
| T1071 / T1571 | C2 Application Layer / Non-Standard Port | C2Detector |
| T1003 / T1003.001 | OS Credential Dumping / LSASS Memory | MutexChecker, PrivilegeChecker |
| T1027 | Obfuscated Files or Information | YaraEngine |
| T1021.001–T1021.006 | Remote Services (RDP, SMB, WinRM, DCOM) | LateralMovementDetector |
| T1550.002 | Pass the Hash | LateralMovementDetector |
| T1134 / T1134.001 | Access Token Manipulation / Token Theft | PrivilegeChecker |
| T1014 | Rootkit (SeLoadDriver abuse) | PrivilegeChecker |
| T1486 | Data Encrypted for Impact (ransomware) | MutexChecker |

---

## Extending the tool

**Add a YARA rule:** drop a `.yar` file into `data/yara/` — it's loaded automatically.

**Add an intelligence module:**
1. Create `dfir_memdump/intelligence/my_module.py`
2. Subclass `BaseIntelModule`, implement `analyze(ctx) -> list[Finding]`
3. Add it to the module list in `runner.py`

**Add a MITRE mapping:** add an entry to `intelligence/attck_mapper.py` and reference it with `get_mitre("your_key")`.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

This tool is intended for **authorized forensic investigation and security research only**. Always ensure you have legal authorization before acquiring or analysing memory images. The authors accept no liability for misuse.
