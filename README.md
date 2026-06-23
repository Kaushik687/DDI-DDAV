<div align="center">
# 🛡️ DDI + DDAV
 
### Two standalone, fully offline Windows security tools, packaged together: **inspect what's running, then neutralize what's dangerous.**
 
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D6)](#system-requirements)
[![Offline](https://img.shields.io/badge/network-offline--only-2ea44f)](#privacy--offline-by-design)
[![Telemetry](https://img.shields.io/badge/telemetry-none-2ea44f)](#privacy--offline-by-design)
[![License](https://img.shields.io/badge/license-MIT-blue)](#license)
 
**[DDI — Deep Device Inspector](https://github.com/Kaushik687/DDI-Deep-Device-Inspector-)**  ·  **[DDAV — Deep Device Anti-Virus](https://github.com/Kaushik687/DDAV-Deep-Device-Anti-Virus-)**  ·  **[Releases](../../releases)**
 
</div>
---
 
## Table of Contents
 
- [What's Inside](#whats-inside)
- [🔍 DDI — Deep Device Inspector](#-ddi--deep-device-inspector)
- [🛡️ DDAV — Deep Device Anti-Virus](#️-ddav--deep-device-anti-virus)
- [Recommended Workflow](#recommended-workflow)
- [Download & Quick Start](#download--quick-start)
- [Privacy & Offline by Design](#privacy--offline-by-design)
- [System Requirements](#system-requirements)
- [Disclaimer](#disclaimer)
- [License](#license)
- [Author](#author)
---
 
 
## What's Inside
 
| Tool | Role | Touches your system? | Use it when you want to... |
|---|---|---|---|
| **DDI** — Deep Device Inspector | Read-only inspector | No — pure read-only, no edits | Understand what's running and why, before deciding anything |
| **DDAV** — Deep Device Anti-Virus | Active scanner | Yes — quarantine/block, fully reversible | Actually detect and neutralize a real threat |
 
Both ship as standalone `.exe` files. Neither requires installation, an internet connection, or any external runtime to set up separately.
 
---
 
## 🔍 DDI — Deep Device Inspector
 
A read-only, offline inspection tool that scans and displays everything your system is doing — with zero data storage and zero collection.
 
**Inspects:** processes · network connections · startup items · services · installed software · registry keys · drivers · scheduled tasks · files (including double-extension masquerades)
 
Every result carries a heuristic risk flag, and a final **Security Report** tab aggregates all suspicious findings into one summary. DDI never modifies, deletes, blocks, or phones home — it only looks and reports, and everything it finds disappears the moment you close it.
 
📂 Full tab-by-tab breakdown and usage instructions: **[DDI repository →](https://github.com/Kaushik687/DDI-Deep-Device-Inspector-)**
 
## 🛡️ DDAV — Deep Device Anti-Virus
 
A real, working antivirus scanner with a professional GUI and seven independent detection engines:
 
| Engine | What it catches |
|---|---|
| Signature Scanning | Hash + pattern matches against known malware |
| PE Analysis | Structural inspection of Windows executables |
| Heuristic Detection | NOP sleds, obfuscation, encoded payloads |
| AMSI Integration | Native Windows script/memory scanning |
| Registry Scan | Persistence mechanisms (Run keys, services, Winlogon hooks) |
| Process Scan | Masquerading processes, temp-folder execution |
| Startup Scan | Autoruns and scheduled-task abuse |
 
DDAV detects **25+ malware families** — ransomware, trojans, rootkits, spyware, cryptominers, worms, fileless malware, and AI-driven threats — and every block or quarantine action it takes is reversible. Like DDI, it collects nothing and runs entirely offline.
 
📂 Full detection details and setup: **[DDAV repository →](https://github.com/Kaushik687/DDAV-Deep-Device-Anti-Virus-)**
 
---
 
## Recommended Workflow
 
1. **Run DDI first.** Get a full read on what's running, what's new, and what looks off — at zero risk, since nothing is modified.
2. **Check the Security Report tab** for anything DDI flagged as suspicious.
3. **Run DDAV** for an active scan, especially on anything DDI surfaced. Review the findings before quarantining.
4. **Quarantine, not delete-on-sight** — DDAV's actions are reversible, so a false positive is never permanent.
## Download & Quick Start
 
1. Go to the [**Releases**](../../releases) page and download the zip files.
2. Extract it anywhere — no installer, no setup wizard.
3. Run `DDI.exe` first to inspect (Administrator recommended for full visibility).
4. Run `DDAV.exe` as Administrator if you want to scan and act on threats.
5. Read the on-screen disclaimer in each tool before your first scan.
Prefer the tools separately? Each one still has its own standalone repo and release — see the links at the top of this page.
 
## Privacy & Offline by Design
 
Both tools share the same non-negotiable baseline:
 
- **No telemetry, no analytics, no logging to disk.**
- **No network access** — neither tool ever connects to the internet.
- **No data leaves your machine**, ever, under any setting.
- DDI's results disappear the moment you close it; DDAV's quarantine is local and fully user-controlled.
## System Requirements
 
- Windows 10 or 11, 64-bit
- Administrator privileges (recommended for DDI, required for DDAV's full feature set)
- No installation, no external dependencies for either tool
## Disclaimer
 
DDI is an **inspector, not an antivirus** — it does not remove or clean anything. DDAV performs real detection and reversible blocking, but neither tool is a substitute for a properly maintained, actively-updated commercial security product on systems exposed to serious or evolving threats. Use both as a transparency and triage layer, alongside — not instead of — your primary security software.
 
## License
 
Both DDI and DDAV are released under the MIT License. See each repository's `LICENSE` file for details.
 
## Author
 
Built independently by **[Kaushik687](https://github.com/Kaushik687)**.
