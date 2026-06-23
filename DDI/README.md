# DDI — Deep Device Inspector

> A standalone, offline system inspection tool for Windows 64-bit devices. DDI scans and displays detailed information about your computer's processes, network connections, startup items, services, installed software, files, drivers, scheduled tasks, and registry entries — all in real-time, with zero data collection or storage.

---

## 🔒 Privacy First

- **No data stored.** All inspection results disappear the moment you close the app.
- **No data collected.** No telemetry, no analytics, no logging to disk.
- **Offline only.** The app never connects to the internet. Everything runs locally.

---

## 🚀 How to Use

1. Download the latest `ddi.exe` from the [Releases](../../releases) page.
2. Double-click `ddi.exe` to run. **No installation required.**
3. On first launch, the app will ask for **Administrator privileges** — this is required for full system inspection.
4. Read the disclaimer and click **OK**.
5. Click **🔍 Start Deep Inspection** to begin scanning.
6. Browse the tabs to view detailed inspection results.

---

## 📋 Inspection Tabs

| Tab | What It Shows |
|-----|---------------|
| **Overview** | OS, CPU, RAM, disk usage, boot time, uptime, logged-in users |
| **Processes** | All running processes with CPU, memory, and **risk assessment** |
| **Network** | Active connections, interfaces, I/O stats, suspicious ports |
| **Startup** | Registry Run keys and startup folder items |
| **Services** | Windows services with status and start type |
| **Installed Software** | Full list of installed applications |
| **File Inspector** | Temp directory scan, executables, double-extension masquerades |
| **Registry** | System Policies, Winlogon, and other critical keys |
| **Drivers** | Loaded drivers with path-based suspicious checks |
| **Scheduled Tasks** | Windows scheduled tasks with action analysis |
| **Security Report** | Aggregated summary of all suspicious findings + recommendations |

---

## ⚠️ What DDI Is (And Isn't)

**DDI is:**
- A **read-only system inspector** — it does not modify, delete, or block anything.
- A **heuristic scanner** — it flags suspicious patterns based on file paths, resource usage, names, ports, and registry values.
- An **awareness tool** — it tells you what your system is doing, so you can make informed decisions.

**DDI is NOT:**
- An **antivirus** — it does not remove, quarantine, or clean threats. Use a proper antivirus for that.
- A **real-time monitor** — it only scans when you click "Start Deep Inspection."
- A **data collection tool** — it never uploads, stores, or logs anything.

---

## 🛡️ Security & Permissions

On launch, DDI requests **Administrator privileges** via the Windows UAC prompt. This is required to:
- Read all running processes and their executable paths
- Access system registry keys (HKLM, startup, services)
- Query driver information and scheduled tasks
- Inspect protected directories and files

If you decline admin access, DDI will run with limited capabilities.

---

## 📦 Requirements

- **OS:** Windows 10/11 (64-bit)
- **Privileges:** Administrator (recommended for full inspection)
- **No installation:** Runs as a standalone `.exe` file
- **No dependencies:** No Python, no .NET, no external libraries needed at runtime

---

## 🛠️ Build from Source

If you want to build the app yourself:

```bash
# Install dependencies (Python 3.10+)
pip install psutil pyinstaller

# Build the .exe
pyinstaller --windowed --onefile --icon="DDI Icon.ico" --uac-admin ddi.py
```

The built executable will be in the `dist/` folder.

---

## 📄 License

DDI is released under the [MIT License](LICENSE). You are free to use, modify, and distribute it.

Use it to inspect your own devices and understand your system better. Always pair it with a reputable antivirus solution for real-time protection.

---

*DDI v1.0 — Deep Device Inspector | Built for Windows 64-bit | Fully Offline*
