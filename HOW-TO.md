# dfir-memdump — How-To Guide

Step-by-step reference for common tasks.

---

## Table of Contents

1. [First-time setup](#1-first-time-setup)
2. [Running your first analysis](#2-running-your-first-analysis)
3. [Reading the HTML report](#3-reading-the-html-report)
4. [Working with the JSON report](#4-working-with-the-json-report)
5. [VirusTotal enrichment](#5-virustotal-enrichment)
6. [YARA rules — adding your own](#6-yara-rules--adding-your-own)
7. [Troubleshooting Volatility3 profiles](#7-troubleshooting-volatility3-profiles)
8. [Offline / air-gapped use](#8-offline--air-gapped-use)
9. [Understanding findings and severity](#9-understanding-findings-and-severity)
10. [Understanding the attack chain](#10-understanding-the-attack-chain)
11. [Exporting IOCs to a SIEM](#11-exporting-iocs-to-a-siem)
12. [Performance tips for large images](#12-performance-tips-for-large-images)

---

## 1. First-time setup

```bash
# 1. Clone the repo
git clone https://github.com/dfarid479/dfir-memdump.git
cd dfir-memdump

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate          # Linux/macOS
# venv\Scripts\activate           # Windows

# 3. Install dfir-memdump and all dependencies
pip install -e .

# 4. Install Volatility3 (required)
pip install volatility3

# 5. Verify vol is on PATH
vol --help

# If vol is not on PATH, set the path in .env:
cp .env.example .env
# Then edit .env:  VOL3_PATH=/path/to/vol.py  or  VOL3_PATH=python3 /path/to/vol.py

# 6. Verify the install
dfir-memdump version
# → dfir-memdump 1.0.0
```

---

## 2. Running your first analysis

```bash
# Basic — produces JSON + Markdown + HTML in ./reports/
dfir-memdump analyze /evidence/RAM.raw

# What you'll see:
#   dfir-memdump — analyzing RAM.raw
#   [spinner] Running Volatility3 plugins…
#
#   Executive Summary
#   ──────────────────────────────────────────────────────────
#   CRITICAL: 3 critical finding(s) detected — immediate investigation required.
#   ...
#
#   ╭─ Findings (14 total) ──────────────────────────────────╮
#   │ Sev       Category   PID    Process   Title             │
#   │ CRITICAL  MALWARE    1234   malware   Known malware...  │
#   ...
#   ╰────────────────────────────────────────────────────────╯
#
#   Reports written:
#     📋  ./reports/RAM.triage.json
#     📄  ./reports/RAM.triage.md
#     🌐  ./reports/RAM.triage.html
#
#   Open the HTML report in your browser to view the full interactive report.
#     file:///path/to/reports/RAM.triage.html
```

### Common flags

```bash
# HTML only (fastest — skip JSON + Markdown)
dfir-memdump analyze RAM.raw --format html

# Skip VirusTotal (no API key / offline)
dfir-memdump analyze RAM.raw --no-vt

# Skip YARA (if yara-python is not installed)
dfir-memdump analyze RAM.raw --no-yara

# Custom output folder + filename
dfir-memdump analyze RAM.raw --output ./case-2026-001/ --stem hostname-ram

# Override Volatility3 profile (skip auto-detection)
dfir-memdump analyze RAM.raw --profile Win10x64_19041

# Debug logging (shows every plugin invocation and row count)
dfir-memdump --debug analyze RAM.raw
```

---

## 3. Reading the HTML report

Open the `.html` file in any browser — it is fully self-contained (no internet required).

### Sections in order

| Section | What to look at first |
|---|---|
| **Executive Summary** | Read this first — it summarises critical findings in plain English |
| **Analysis Statistics** | Red stat boxes = something critical/high was found in that category |
| **Process Risk Leaderboard** | Top 15 highest-scoring processes — start your investigation here |
| **Process Tree** | Look for `[!]` flags and unexpected parent-child relationships (e.g. Word spawning cmd.exe) |
| **Event Timeline** | The ⚠ Flagged Events box at the top shows only suspicious events — easiest to read |
| **Attack Chain Reconstruction** | One-page kill-chain narrative — use this for briefings |
| **Intelligence Findings** | CRITICAL findings are auto-expanded. Click any finding to expand it. |
| **MITRE ATT&CK Coverage** | Click any badge to open the MITRE technique page |
| **IOC Summary** | Click any IOC value to copy it to clipboard |

### Saving as PDF

Click the **🖨 Print / Save PDF** button in the top-right corner. In the print dialog, select **Save as PDF**. The print stylesheet removes navigation elements and renders cleanly on A4/Letter.

---

## 4. Working with the JSON report

The JSON report is a full `TriageReport` model dump — useful for scripting and SIEM import.

```bash
# Pretty-print the executive summary
python3 -c "import json,sys; r=json.load(open('reports/RAM.triage.json')); print(r['executive_summary'])"

# Extract all critical findings
python3 -c "
import json
r = json.load(open('reports/RAM.triage.json'))
crits = [f for f in r['findings'] if f['severity'] == 'CRITICAL']
for f in crits:
    print(f['severity'], f['category'], f['title'])
"

# Extract all IOCs as newline-separated type:value pairs
python3 -c "
import json
r = json.load(open('reports/RAM.triage.json'))
for ioc in r['iocs']:
    print(f\"{ioc['type']}:{ioc['value']}\")
" > iocs.txt

# Get the attack chain stages
python3 -c "
import json
r = json.load(open('reports/RAM.triage.json'))
for step in r['attack_chain']:
    print(f\"{step['stage_order']+1}. {step['stage']}: {step['narrative']}\")
"
```

---

## 5. VirusTotal enrichment

dfir-memdump will look up SHA-256 hashes of process images against VirusTotal.

```bash
# 1. Get a free VirusTotal API key at https://www.virustotal.com
# 2. Add it to .env
echo "VT_API_KEY=your_64_char_key_here" >> .env

# 3. Run analysis normally — VT lookups happen automatically
dfir-memdump analyze RAM.raw

# Free tier is limited to 4 requests/minute — the tool respects this automatically.
# Results are cached in data/vt_cache.db so repeat runs on the same image are instant.

# To force-skip VT even if the key is set:
dfir-memdump analyze RAM.raw --no-vt
```

VT findings appear as `MALWARE` category findings with the detection ratio in the evidence field.

---

## 6. YARA rules — adding your own

Drop any `.yar` file into `data/yara/` — it is compiled and loaded automatically on next run.

```bash
# Example: add a custom rule
cat > data/yara/my_custom.yar << 'EOF'
rule SuspiciousString {
    meta:
        description = "Custom string pattern"
    strings:
        $s1 = "totally_legit_process" nocase
    condition:
        $s1
}
EOF

dfir-memdump analyze RAM.raw
# → YaraEngine will now include your rule
```

Rules are scanned against:
- All VAD regions flagged by `windows.malfind` (RWX memory)
- Process image paths resolved by `windows.dlllist`

Built-in rule sets:

| File | What it detects |
|---|---|
| `shellcode.yar` | MZ headers in non-mapped memory, API hash patterns, reflective DLL markers |
| `credential_tools.yar` | Mimikatz strings, LaZagne patterns, Impacket signatures |
| `c2_frameworks.yar` | Cobalt Strike beacon config patterns, Meterpreter, Empire, Sliver, Brute Ratel |
| `packers.yar` | UPX, Themida, ConfuserEx packing indicators |

---

## 7. Troubleshooting Volatility3 profiles

Volatility3 auto-detects the OS profile from the image. If it fails:

```bash
# List available profiles
vol windows.info

# Try with a specific profile
dfir-memdump analyze RAM.raw --profile Win10x64_19041

# Common profiles:
#   Win7SP1x64        Windows 7 SP1 x64
#   Win10x64_19041    Windows 10 2004 x64
#   Win10x64_22H2     Windows 10 22H2 x64
#   Win11x64_22621    Windows 11 22H2 x64
#   Win2019x64        Windows Server 2019 x64

# If vol is not on PATH:
echo "VOL3_PATH=/home/user/volatility3/vol.py" >> .env
# or
echo "VOL3_PATH=python3 /opt/volatility3/vol.py" >> .env

# Debug mode shows the exact command dfir-memdump runs for each plugin
dfir-memdump --debug analyze RAM.raw 2>&1 | grep "Running plugin"
```

If a plugin returns 0 rows, check the debug log — it will show the raw Volatility3 error.

---

## 8. Offline / air-gapped use

The HTML report is fully self-contained — no CDN, no external fonts, no network requests.

For the analysis itself:

```bash
# Skip VirusTotal (no network)
dfir-memdump analyze RAM.raw --no-vt

# Pre-cache the Feodo IP blocklist before going offline:
python3 -c "
from dfir_memdump.intelligence.c2_detector import C2Detector
from dfir_memdump.intelligence import IntelContext
C2Detector()._load_feodo()  # downloads and caches to data/feodo_cache.json
print('Feodo cache updated')
"

# The cache is valid for 6 hours by default (configurable in .env: FEODO_CACHE_TTL_HOURS=48)
```

---

## 9. Understanding findings and severity

| Severity | Meaning | Example |
|---|---|---|
| **CRITICAL** | Confirmed malicious indicator — act immediately | Known malware mutex, SeDebug+SeImpersonate on non-system process, known C2 IP |
| **HIGH** | Strong indicator requiring investigation | Suspicious cross-process handle, sensitive registry key access, SeLoadDriver on non-system process |
| **MEDIUM** | Suspicious — may be legitimate, requires context | Unusual parent-child, LOLBAS tool with suspicious flags, non-standard outbound port |
| **LOW** | Informational — low confidence or common technique | High-entropy cmdline token, external IP in strings |
| **INFO** | Context — not malicious, useful for timeline | Process without matching DLL path |

### Process Risk Score

Each process involved in findings gets a weighted score:

```
Score = (CRITICAL findings × 10) + (HIGH × 5) + (MEDIUM × 2) + (LOW × 1)
```

A score of 20+ means the process has multiple high-confidence indicators — investigate it first.

---

## 10. Understanding the attack chain

The Attack Chain section in the HTML and Markdown reports maps every finding to a MITRE ATT&CK tactic and orders them along the kill chain:

```
Initial Access → Execution → Persistence → Privilege Escalation →
Defense Evasion → Credential Access → Discovery → Lateral Movement →
Command and Control → Exfiltration → Impact
```

Only observed stages appear. Each stage shows:
- The stage name and order
- MITRE technique IDs that fired
- A plain-English narrative explaining what the attacker did at that stage
- A collapsible list of the specific finding titles

**Use this section to:**
- Brief a manager or legal team without referencing technical details
- Draft an incident timeline
- Fill in a kill-chain mapping for your threat intelligence report

---

## 11. Exporting IOCs to a SIEM

```bash
# Option 1: Extract from JSON report
python3 -c "
import json
r = json.load(open('reports/RAM.triage.json'))
for ioc in r['iocs']:
    print(f\"{ioc['type']}|{ioc['value']}|{ioc.get('context','')[:60]}\")
" > case_iocs.csv

# Option 2: jq (if installed)
jq -r '.iocs[] | [.type, .value, .context] | @csv' reports/RAM.triage.json > case_iocs.csv

# IOC types in the output:
#   ip           — external IP address
#   mutex        — malware named mutex
#   privilege    — abused Windows privilege
#   regkey       — sensitive registry key accessed
#   pid          — process ID involved in finding
#   url          — embedded URL extracted from memory strings
#   hash_sha256  — process image hash (if VT lookups enabled)
```

---

## 12. Performance tips for large images

Large images (16 GB+) can take 20–60 minutes depending on hardware.

```bash
# Run only the most critical plugins — skip DLL list and handles (slowest)
# (not a CLI flag yet — workaround: set plugin_timeout lower and accept partial output)

# Fastest useful invocation:
dfir-memdump analyze RAM.raw --no-vt --no-yara

# Or target HTML only (skips JSON serialisation of large datasets):
dfir-memdump analyze RAM.raw --no-vt --no-yara --format html

# Tune timeouts in .env:
echo "PLUGIN_TIMEOUT_SECONDS=600" >> .env   # default is 300s per plugin
```

The tool runs plugins sequentially (each Volatility3 invocation is separate). Plugin order is: PsList → NetScan → Malfind → CmdLine → DllList → Handles → Privileges.

The slowest plugins are typically `windows.handles` and `windows.dlllist` on images with many processes.
