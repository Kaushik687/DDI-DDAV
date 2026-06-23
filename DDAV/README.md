# DDAV - Deep Device Anti Virus

## Overview

DDAV (Deep Device Anti Virus) is a comprehensive, real-working antivirus scanner for Windows 64-bit systems. It uses multiple detection engines to identify malware, suspicious files, persistence mechanisms, and active threats on your device.

**Important:** DDAV requires Administrator privileges to access all areas of your system for thorough scanning. No data is collected. DDAV only works when you actively open and run it.

## Features

- **Multi-Engine Detection**: Uses 7 different scanning engines for comprehensive coverage
  - Signature Engine (hash + pattern matching)
  - PE Analyzer (Windows executable structural analysis)
  - Heuristic Engine (behavioral and pattern analysis)
  - AMSI Integration (Windows Antimalware Scan Interface)
  - Registry Scanner (persistence mechanism detection)
  - Process Scanner (active threat identification)
  - Startup Scanner (autorun and scheduled task detection)

- **Comprehensive Threat Categories Detected**:
  - Viruses (File Infectors, Boot Sector, Macro, Polymorphic, Metamorphic, etc.)
  - Worms (Network, Email, P2P/IM)
  - Trojans (RATs, Downloaders, Droppers, Bankers, DDoS, Proxy, Fake AV)
  - Rootkits & Bootkits (User-mode, Kernel-mode, Firmware, Hypervisor)
  - Ransomware (Crypto, Locker, Extortionware)
  - Spyware (Keyloggers, Screen Scrapers, Infostealers, Stalkerware)
  - Adware, Cryptominers, Logic Bombs, Formjackers
  - Fileless Malware, Web Shells, Exploit Kits, AI-Driven Malware

- **User Control**: All actions require YOUR explicit permission. DDAV never modifies or deletes anything automatically.

- **Block & Revert**: Block suspicious files/folders/code using Windows ACLs. All changes can be fully reverted from the Blocked Items tab.

- **Detailed Reports**: View threat details in both technical (for professionals) and simple (for general users) language. Copy or download reports as .txt files.

- **Code Inspection**: View extracted suspicious code blocks with syntax highlighting context.

## Quick Start — How to Run

There are **three ways** to run DDAV. Choose the one that fits your situation:

| Method | Recommended When | What You Need |
|--------|---------------|---------------|
| **`DDAV.exe`** | **Recommended for most users.** You just want to double-click and run. | No Python needed. Self-contained. |
| **`launcher.bat`** | **Recommended if you want to run from source.** You have Python installed and want to debug or customize. | Python 3.9+ on your system. |
| **`ddav_main.py`** | **Recommended for developers.** You want to run from command line or modify the code. | Python 3.9+ and a terminal. |

> **Note:** All methods require Administrator privileges for full scanning. Right-click the file and select **"Run as administrator"**.

### Option 1: DDAV.exe (Self-Contained, No Python Needed) — RECOMMENDED

**Best for:** Most users who just want to scan their computer without installing anything.

1. Copy the entire `DDAV` folder to your preferred location (e.g., Desktop, `C:\Tools\DDAV`, or a USB drive).
2. Right-click `DDAV.exe` and select **"Run as administrator"**.
3. The scanner opens in a dark-themed window. Click **"Full System Scan"** to begin.

> **Important:** The `.exe` is self-contained, but the `data/` folder and `reports/` folder must stay in the same directory as the `.exe`. Keep the entire folder together.

> **Portable:** You can copy the entire `DDAV` folder to a USB drive and run it from any Windows computer. The `DDAV-Portable.exe` file is identical to `DDAV.exe` — both are portable. Use whichever name you prefer.

### Option 2: launcher.bat (Source with Python) — RECOMMENDED for Developers

**Best for:** Users who have Python installed and want to run from source, or developers who want to modify the code.

1. Ensure Python 3.9+ is installed and in your PATH.
2. Copy the entire `DDAV` folder to your preferred location.
3. Right-click `launcher.bat` and select **"Run as administrator"**.
4. The batch file will find your Python installation and launch DDAV.

> The batch file auto-detects Python from common locations. If it cannot find Python, it will show a message with a download link.

### Option 3: ddav_main.py (Command Line) — RECOMMENDED for Power Users

**Best for:** Power users who want to run from a terminal or integrate DDAV into scripts.

```cmd
cd C:\DDAV
python ddav_main.py
```

> You must run from an **Administrator Command Prompt**. Right-click Command Prompt, select "Run as administrator", then run the commands above.

## Installation

### Requirements
- Windows 10/11 64-bit
- Python 3.9 or later (only if running from source; not needed for `.exe`)
- Administrator privileges

### File Checklist
After copying the `DDAV` folder, ensure all files are present:

```
DDAV/
├── DDAV.exe                    ← Self-contained app (recommended)
├── DDAV-Portable.exe           ← Same as above, portable copy
├── ddav_main.py                ← Source entry point
├── launcher.bat                ← Admin launcher for source
├── README.md                   ← This file
├── DDAV Icon.png               ← App icon
├── core/                       ← Scanner + GUI
├── engines/                    ← 7 detection engines
├── utils/                      ← Block manager, reporter, admin check
├── data/                       ← Threat signatures + block database
└── reports/                    ← Auto-generated reports
```

> **Note:** If `DDAV.exe` is missing, you can compile it yourself using PyInstaller: `pip install pyinstaller && pyinstaller --onefile --windowed ddav_main.py`

## How to Use

### Starting a Scan
1. Launch DDAV using any of the three methods above (as Administrator).
2. Click **"Full System Scan"** for a comprehensive scan of all user directories, temp folders, registry, processes, and startup items.
3. Or click **"Quick Scan"** to scan only Downloads, Desktop, and Documents.
4. Or click **"Custom Scan"** to select a specific folder.

### During the Scan
- The **Scan Progress** tab shows real-time progress and a detailed log.
- You can cancel the scan at any time using the **"Cancel Scan"** button.
- Scanning happens in a background thread — you can switch tabs while it runs.

### Reviewing Threats
1. After scanning completes, switch to the **Threats** tab.
2. Click any threat in the list to see full details.
3. Details include:
   - Exact file location (disk, folder, filename)
   - Threat type and name
   - Severity level (CRITICAL, HIGH, MEDIUM, LOW)
   - Technical analysis for professionals
   - Simple explanation for general users
   - Potential consequences
   - Device connections (registry, network, processes)
   - Suspicious code blocks (if extracted)

### Taking Action
For each threat, you have these options:
- **Copy Details**: Copy the full report to clipboard
- **Download Report**: Save the report as a `.txt` file
- **View Code Block**: See the suspicious code with context
- **Block Code [Careful]**: Restrict the file using Windows ACLs
- **Block File [Careful]**: Block the entire file
- **Block Folder [Careful]**: Block the entire folder
- **Leave As Is**: Do nothing and close the options

**Important:** All "Block" actions require **TWO confirmations** (permission + confirmation). This prevents accidental blocking.

### Reverting Blocked Items
1. Go to the **Blocked Items** tab.
2. Select any blocked item.
3. Click **"Revert Selected Item"** to restore original permissions.

**Note:** Reverting restores the original Windows ACL permissions. This is useful if you accidentally blocked a legitimate file.

### Saving Reports
- Full scan reports are automatically saved to the `reports/` folder inside DDAV.
- Individual threat reports can be downloaded to any location you choose.

## Safety & Privacy

- **No Data Collection**: DDAV does NOT send any data to external servers. All scanning is done locally on your machine.
- **No Automatic Actions**: DDAV will NEVER delete, modify, or block anything without your explicit permission.
- **Admin Required**: Administrator access is required only for thorough scanning and accurate detection. DDAV does not use admin privileges for anything beyond scanning and optional blocking (with your permission).
- **Reversible**: All blocking actions are fully reversible.
- **Offline Operation**: DDAV works entirely offline. No internet connection is required.

## Limitations

- DDAV is a Python-based scanner, not a kernel-mode driver. It cannot scan at the same level as commercial antivirus products that use kernel drivers.
- Deep memory scanning and boot sector scanning are limited compared to kernel-level antivirus solutions.
- Real-time protection is not available — DDAV is an **on-demand scanner only**.
- The signature database is built-in and does not auto-update. For best protection, use DDAV alongside a commercial antivirus with real-time protection.

## Technical Details

### Detection Methods
1. **Hash Signatures**: SHA-256 and MD5 hash matching against known malware
2. **String Patterns**: Detection of suspicious strings, API names, and network indicators
3. **PE Analysis**: Structural analysis of Windows executables (entropy, sections, imports)
4. **Heuristics**: Behavioral pattern detection (NOP sleds, shellcode, obfuscation, script patterns)
5. **AMSI**: Integration with Windows Antimalware Scan Interface for in-memory and script scanning
6. **Registry**: Detection of persistence mechanisms (Run keys, services, Winlogon hooks, IFEO)
7. **Process Scan**: Identification of suspicious running processes (masquerading, temp locations)
8. **Startup Scan**: Detection of suspicious startup items and scheduled tasks

### Blocking Mechanism
DDAV uses Windows ACL (Access Control List) modifications to block files and folders:
- Denies access to Everyone and Users groups
- Saves original ACLs before modification in a backups folder inside `data/`
- Reverting restores the saved ACLs
- No files are deleted or modified — only permissions are changed

## Troubleshooting

### "Administrator privileges required" warning
- Right-click the file you want to run (`DDAV.exe`, `launcher.bat`, or `ddav_main.py`) and select **"Run as administrator"**.
- Or right-click Command Prompt, select "Run as administrator", then run the application.

### The `.exe` won't open or shows an error
- Make sure the entire `DDAV` folder is intact (especially `core/`, `engines/`, `utils/`, `data/`).
- Do not move `DDAV.exe` out of the `DDAV` folder — the `data/` folder must be in the same directory.
- Try running `launcher.bat` instead if you have Python installed.

### "Python not found" error (when running from source)
- Install Python 3.9+ from https://www.python.org/downloads/
- During installation, check **"Add Python to PATH"**.
- Or use `DDAV.exe` instead — no Python is required.

### Scan is very slow
- Large files (>100MB) are skipped by default.
- Network drives and external storage may slow scanning.
- You can cancel and try a **Quick Scan** or **Custom Scan** on a smaller folder.

### False positives
- Some legitimate files may be flagged as suspicious (e.g., development tools, scripts, packed executables).
- Review the details carefully before blocking.
- Use **"Leave As Is"** if you are unsure.
- You can always revert a blocked item if you made a mistake.

### Reports folder not found
- The `reports/` folder is created automatically when you save a report.
- If it doesn't appear, ensure you have write permissions in the DDAV folder.

## License & Disclaimer

DDAV is provided as-is for educational and security research purposes. It is not a replacement for professional commercial antivirus software.

The authors are not responsible for any damage caused by the use or misuse of this software. Always verify detections before blocking. Keep regular backups of important data.

---
**DDAV v1.0.0** — Deep Device Anti Virus
