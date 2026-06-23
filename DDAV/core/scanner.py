"""
DDAV Main Scanner Orchestrator
Coordinates all scanning engines and produces unified threat reports.
"""

import os
import sys
import time
import threading
from pathlib import Path
from datetime import datetime, timedelta

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from engines.signature_engine import SignatureEngine
from engines.pe_analyzer import PEAnalyzer
from engines.heuristic_engine import HeuristicEngine
from engines.amsi_engine import AMSIEngine
from engines.registry_scanner import RegistryScanner
from engines.process_scanner import ProcessScanner
from engines.startup_scanner import StartupScanner
from utils.reporter import format_threat_details, save_full_report
from data.threat_signatures import (
    SUSPICIOUS_EXTENSIONS, SUSPICIOUS_STRING_PATTERNS,
    KNOWN_MALWARE_HASHES
)


class DDAVScanner:
    """Main scanning orchestrator for DDAV."""
    
    def __init__(self, progress_callback=None, log_callback=None):
        self.progress_callback = progress_callback
        self.log_callback = log_callback
        
        # Initialize all engines
        self.sig_engine = SignatureEngine()
        self.pe_analyzer = PEAnalyzer()
        self.heuristic_engine = HeuristicEngine()
        self.amsi_engine = AMSIEngine()
        self.registry_scanner = RegistryScanner()
        self.process_scanner = ProcessScanner()
        self.startup_scanner = StartupScanner()
        
        # Scan exclusions - empty by default for thorough scanning
        self.exclusions = []
        
        # Scan stats
        self.stats = {
            "total_files": 0,
            "files_scanned": 0,
            "threats_found": 0,
            "start_time": None,
            "end_time": None,
            "duration": "0s",
            "engines_used": [],
        }
        
        self.threats = []
        self.scanning = False
        self.cancelled = False
    
    def _log(self, message):
        """Log a message."""
        if self.log_callback:
            self.log_callback(message)
    
    def _progress(self, current, total, message=""):
        """Update progress."""
        if self.progress_callback:
            self.progress_callback(current, total, message)
    
    def _is_suspicious_extension(self, filepath):
        """Check if file has a suspicious extension."""
        ext = Path(filepath).suffix.lower()
        all_suspicious = set()
        for cat, exts in SUSPICIOUS_EXTENSIONS.items():
            all_suspicious.update(exts)
        return ext in all_suspicious
    
    def _extract_code_block(self, filepath, pattern):
        """Extract code block containing suspicious pattern."""
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            
            if isinstance(pattern, bytes):
                pattern_bytes = pattern
            else:
                pattern_bytes = str(pattern).encode('utf-8', errors='ignore')
            
            idx = data.find(pattern_bytes)
            if idx == -1:
                return None, 0, 0
            
            # Extract surrounding context (200 bytes before and after)
            start = max(0, idx - 200)
            end = min(len(data), idx + len(pattern_bytes) + 200)
            block = data[start:end]
            
            # Try to decode
            try:
                decoded = block.decode('utf-8')
            except:
                decoded = block.hex()
            
            return decoded, start, end
        except Exception:
            return None, 0, 0
    
    def _build_threat_report(self, filepath, detections, engine_name):
        """Build a comprehensive threat report from detections."""
        if not detections:
            return None
        
        # Aggregate threat info
        threat_types = set()
        threat_categories = set()
        max_confidence = 0
        all_indicators = []
        all_details = []
        
        for det in detections:
            threat_types.add(det.get("type", "unknown"))
            max_confidence = max(max_confidence, det.get("confidence", 0))
            all_indicators.append(det.get("details", ""))
            
            # Categorize
            if "hash_match" in det.get("type", ""):
                threat_categories.add("Known Malware")
            elif "amsi" in det.get("type", ""):
                threat_categories.add("AMSI-Detected Threat")
            elif "registry" in det.get("type", "") or "service" in det.get("type", "") or "winlogon" in det.get("type", "") or "appinit" in det.get("type", "") or "debugger" in det.get("type", ""):
                threat_categories.add("Persistence/Rootkit")
            elif "process" in det.get("type", ""):
                threat_categories.add("Active Threat (Process)")
            elif "startup" in det.get("type", "") or "scheduled_task" in det.get("type", ""):
                threat_categories.add("Persistence Mechanism")
            elif "suspicious_imports" in det.get("type", "") or "shellcode" in det.get("type", "") or "nop_sled" in det.get("type", ""):
                threat_categories.add("Code Injection/Exploit")
            elif "high_entropy" in det.get("type", "") or "packed" in det.get("type", "") or "suspicious_section" in det.get("type", ""):
                threat_categories.add("Packed/Obfuscated Code")
            elif "script" in det.get("type", ""):
                threat_categories.add("Script-Based Malware")
            elif "network" in det.get("type", "") or "url" in det.get("type", ""):
                threat_categories.add("Network Communication")
            elif "trojan" in det.get("type", "") or "rat" in det.get("type", "") or "banker" in det.get("type", ""):
                threat_categories.add("Trojan/RAT")
            elif "worm" in det.get("type", ""):
                threat_categories.add("Worm")
            elif "ransomware" in det.get("type", ""):
                threat_categories.add("Ransomware")
            elif "spyware" in det.get("type", "") or "keylogger" in det.get("type", "") or "infostealer" in det.get("type", ""):
                threat_categories.add("Spyware/InfoStealer")
            elif "cryptominer" in det.get("type", ""):
                threat_categories.add("Cryptominer")
            elif "adware" in det.get("type", ""):
                threat_categories.add("Adware")
            elif "rootkit" in det.get("type", "") or "bootkit" in det.get("type", ""):
                threat_categories.add("Rootkit/Bootkit")
            elif "fileless" in det.get("type", ""):
                threat_categories.add("Fileless Malware")
            elif "logic_bomb" in det.get("type", ""):
                threat_categories.add("Logic Bomb")
            elif "formjacking" in det.get("type", ""):
                threat_categories.add("Formjacking/Skimmer")
            elif "ddos" in det.get("type", ""):
                threat_categories.add("DDoS Bot")
            elif "dropper" in det.get("type", "") or "downloader" in det.get("type", ""):
                threat_categories.add("Dropper/Downloader")
            elif "fake_av" in det.get("type", ""):
                threat_categories.add("Fake AV/Scareware")
            elif "fleeceware" in det.get("type", ""):
                threat_categories.add("Fleeceware")
            elif "ai" in det.get("type", "") or "polymorphic" in det.get("type", ""):
                threat_categories.add("AI-Driven Malware")
            elif "macro" in det.get("type", ""):
                threat_categories.add("Macro Virus")
            elif "companion" in det.get("type", ""):
                threat_categories.add("Companion Virus")
            elif "multipartite" in det.get("type", ""):
                threat_categories.add("Multipartite Virus")
            elif "cavity" in det.get("type", ""):
                threat_categories.add("Cavity Virus")
            elif "encrypted" in det.get("type", "") or "polymorphic" in det.get("type", "") or "metamorphic" in det.get("type", ""):
                threat_categories.add("Polymorphic/Metamorphic Virus")
            elif "boot_sector" in det.get("type", ""):
                threat_categories.add("Boot Sector Virus")
            elif "file_infector" in det.get("type", ""):
                threat_categories.add("File Infector Virus")
            elif "exploit_kit" in det.get("type", "") or "shellcode" in det.get("type", ""):
                threat_categories.add("Exploit Kit/Shellcode")
            elif "web_shell" in det.get("type", ""):
                threat_categories.add("Web Shell")
            elif "suspicious" in det.get("type", "") or "obfuscated" in det.get("type", "") or "packed" in det.get("type", ""):
                threat_categories.add("Suspicious/Obfuscated Code")
            else:
                threat_categories.add("Unknown Threat")
        
        # Determine primary threat type and name (deterministic priority ordering)
        CATEGORY_PRIORITY = [
            "Known Malware", "Ransomware", "Trojan/RAT", "Rootkit/Bootkit",
            "Code Injection/Exploit", "Persistence/Rootkit", "Script-Based Malware",
            "Active Threat (Process)", "Suspicious/Obfuscated Code", "Packed/Obfuscated Code",
            "Spyware/InfoStealer", "Cryptominer", "Adware", "Worm", "DDoS Bot",
            "Dropper/Downloader", "Logic Bomb", "Formjacking/Skimmer", "AI-Driven Malware",
            "File Infector Virus", "Boot Sector Virus", "Macro Virus", "Multipartite Virus",
            "Cavity Virus", "Polymorphic/Metamorphic Virus", "Companion Virus",
            "Exploit Kit/Shellcode", "Web Shell", "Fileless Malware",
            "Unknown Threat"
        ]
        if threat_categories:
            primary_category = next(
                (c for c in CATEGORY_PRIORITY if c in threat_categories),
                sorted(threat_categories)[0]
            )
        else:
            primary_category = "Unknown"
        
        # Determine severity
        if max_confidence >= 90:
            severity = "CRITICAL"
        elif max_confidence >= 75:
            severity = "HIGH"
        elif max_confidence >= 55:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        # Extract code block if possible
        code_block = None
        code_start = 0
        code_end = 0
        for det in detections:
            if "pattern" in det and det.get("pattern"):
                block, start, end = self._extract_code_block(filepath, det["pattern"])
                if block:
                    code_block = block
                    code_start = start
                    code_end = end
                    break
        
        # Build descriptions
        technical_desc = self._build_technical_description(detections, primary_category)
        user_desc = self._build_user_description(detections, primary_category)
        consequences = self._build_consequences(detections, primary_category)
        connections = self._build_connections(detections, filepath)
        
        # Extract location info (handle non-file paths like registry keys, processes)
        if os.path.isfile(filepath):
            abs_path = os.path.abspath(filepath)
            drive = os.path.splitdrive(abs_path)[0] if os.path.splitdrive(abs_path)[0] else "Unknown"
            folder = os.path.dirname(abs_path)
            filename = os.path.basename(abs_path)
        else:
            abs_path = filepath
            drive = "N/A"
            folder = "N/A"
            filename = os.path.basename(filepath) if filepath else "N/A"
        
        threat_report = {
            "file_path": abs_path,
            "disk": drive,
            "folder": folder,
            "filename": filename,
            "threat_type": primary_category,
            "threat_name": self._get_threat_name(detections, primary_category),
            "severity": severity,
            "confidence": max_confidence,
            "engine": engine_name,
            "indicators_found": all_indicators,
            "technical_description": technical_desc,
            "user_description": user_desc,
            "consequences": consequences,
            "connections": connections,
            "code_block": code_block,
            "code_block_start": code_start,
            "code_block_end": code_end,
            "raw_detections": detections,
        }
        
        return threat_report
    
    def _get_threat_name(self, detections, category):
        """Generate a threat name from detections."""
        names = []
        for det in detections:
            if "threat_family" in det:
                names.append(det["threat_family"])
            elif "category" in det:
                names.append(det["category"])
            elif "type" in det:
                names.append(det["type"])
        
        if names:
            return f"{category} - {names[0]}"
        return category
    
    def _build_technical_description(self, detections, category):
        """Build technical description for professionals."""
        lines = [f"THREAT CLASSIFICATION: {category}", ""]
        
        for det in detections:
            det_type = det.get("type", "unknown")
            details = det.get("details", "")
            if details:
                lines.append(f"  [{det_type}] {details}")
        
        lines.append("")
        lines.append("TECHNICAL ANALYSIS:")
        
        if category == "Known Malware":
            lines.append("This file matches a known malware signature in the database. The hash or behavioral pattern corresponds to a previously identified threat family. This indicates a high-confidence detection of a known malicious sample.")
        elif category == "Packed/Obfuscated Code":
            lines.append("The file exhibits characteristics of executable packing or encryption. High entropy sections, unusual section names, and executable-writable memory regions indicate that the code is likely compressed or encrypted and will unpack at runtime. This is a common evasion technique used by malware to avoid static analysis.")
        elif category == "Persistence/Rootkit":
            lines.append("Registry modifications indicate a persistence mechanism or rootkit behavior. The malware has modified Windows startup hooks, service configurations, or execution options to maintain access across reboots. This may include AppInit DLL injection, Winlogon hooking, or IFEO debugger redirection.")
        elif category == "Script-Based Malware":
            lines.append("The script contains suspicious command patterns including obfuscated strings, encoded payloads, dynamic execution functions (eval, exec, Invoke-Expression), and network download operations. These patterns are characteristic of script-based malware, fileless attacks, and living-off-the-land techniques.")
        elif category == "Active Threat (Process)":
            lines.append("A running process exhibits suspicious characteristics including masquerading as a system process, executing from non-standard directories (temp, AppData), or missing an accessible executable path. This may indicate a running instance of malware, injected code, or a hollowed process.")
        elif category == "Code Injection/Exploit":
            lines.append("The binary contains patterns associated with code injection and exploitation techniques. Suspicious API imports (VirtualAllocEx, CreateRemoteThread, WriteProcessMemory), shellcode patterns, or NOP sleds indicate the file is designed to inject code into other processes or exploit vulnerabilities.")
        elif category == "Suspicious/Obfuscated Code":
            lines.append("Multiple heuristic indicators suggest this file is suspicious. Elevated entropy, obfuscated strings, suspicious network references, or unusual file characteristics warrant further investigation. While not definitively malicious, the file exhibits behavior patterns consistent with malware.")
        else:
            lines.append("The file exhibits multiple indicators of malicious behavior across different analysis engines. Combined heuristic, signature, and behavioral analysis suggest this file poses a security risk. Detailed investigation recommended.")
        
        return "\n".join(lines)
    
    def _build_user_description(self, detections, category):
        """Build simple description for general users."""
        descriptions = {
            "Known Malware": "This file has been identified as a known virus or malware. It matches a signature in our threat database, which means security researchers have already analyzed and confirmed this exact file is dangerous. You should remove it immediately.",
            "Packed/Obfuscated Code": "This file is hiding its true contents using compression or encryption. Think of it like a suspicious package wrapped in many layers. Malware does this to hide from antivirus scanners. When run, it unpacks itself and may reveal dangerous behavior.",
            "Persistence/Rootkit": "This file or registry setting is designed to stay on your computer even after reboots. It has modified Windows settings so it starts automatically every time you turn on your computer. This is how malware ensures it keeps running.",
            "Script-Based Malware": "This script file contains hidden commands that can harm your computer. Scripts are text files that can run programs, download files, or change system settings. This one contains suspicious commands that are commonly used by hackers.",
            "Active Threat (Process)": "A program is currently running on your computer that looks suspicious. It may be pretending to be a Windows system file, or it might be running from an unusual location where safe programs don't normally run.",
            "Code Injection/Exploit": "This file is designed to force its way into other programs that are already running. It can sneak into your web browser, email program, or other software to steal information or take control. This is a very dangerous technique.",
            "Trojan/RAT": "This file is a Trojan - it pretends to be something useful but is actually harmful. A RAT (Remote Access Trojan) gives hackers full control over your computer. They can see your screen, type on your keyboard, and steal your files without you knowing.",
            "Ransomware": "This is RANSOMWARE - the most dangerous type of malware. If you run this file, it will encrypt (lock) all your documents, photos, and videos. The hackers will then demand money to unlock them. DO NOT OPEN THIS FILE.",
            "Spyware/InfoStealer": "This file is designed to spy on you. It can record everything you type (passwords, credit cards), take screenshots of your screen, steal your browser saved passwords, and send all this information to hackers.",
            "Cryptominer": "This file will secretly use your computer's processor to make money for hackers. Your computer will become very slow, your electricity bill will increase, and your hardware may overheat and get damaged.",
            "Adware": "This file will flood your computer with unwanted advertisements. It may change your browser homepage, redirect your searches, and slow down your internet browsing.",
            "Worm": "This is a worm - it can copy itself to other computers on your network automatically. It can spread through USB drives, email, and shared folders without you doing anything.",
            "DDoS Bot": "This file turns your computer into a 'zombie' that helps hackers attack websites. Your internet connection will be used to flood websites with traffic, which is illegal and can get you in trouble.",
            "Dropper/Downloader": "This is a small file whose only job is to download and install MORE dangerous malware. It looks harmless but will secretly connect to the internet and download the real virus.",
            "Suspicious/Obfuscated Code": "This file looks suspicious but we cannot confirm it is definitely malware. It has unusual characteristics that are commonly seen in dangerous files. We recommend caution and further investigation.",
        }
        
        return descriptions.get(category, "This file has been flagged by our security analysis. Multiple detection engines identified suspicious characteristics. While we cannot explain the exact technical details simply, the file is not safe and should be treated with caution.")
    
    def _build_consequences(self, detections, category):
        """Build consequences description."""
        consequences = {
            "Known Malware": "Running this file will infect your computer. The malware may steal passwords, encrypt files, spy on your activities, or turn your computer into a bot for hackers.",
            "Packed/Obfuscated Code": "If executed, this file will unpack its hidden payload. The payload could be ransomware, a trojan, spyware, or any other malicious program. The hidden contents are specifically designed to evade detection.",
            "Persistence/Rootkit": "This threat will remain active even after restarting your computer. It may hide itself from antivirus software, making it very difficult to remove. Rootkits can intercept system calls and hide files, processes, and network connections.",
            "Script-Based Malware": "Executing this script may download additional malware, modify system settings, steal your data, or create backdoors for hackers to access your computer remotely.",
            "Active Threat (Process)": "This process is already running and may be actively stealing your data, monitoring your activities, or communicating with hacker-controlled servers. Your personal information could be at risk right now.",
            "Code Injection/Exploit": "This exploit can take control of legitimate programs, bypass security software, and execute malicious code with the same permissions as the target program. It can lead to full system compromise.",
            "Trojan/RAT": "A hacker may gain complete remote control of your computer. They can: see your screen, record your keystrokes, access your files, turn on your webcam and microphone, steal banking credentials, and use your computer for illegal activities.",
            "Ransomware": "ALL YOUR FILES WILL BE ENCRYPTED. You will lose access to documents, photos, videos, and any other important data. Hackers will demand payment (often in Bitcoin) to restore your files, and many victims never recover their data even after paying.",
            "Spyware/InfoStealer": "Your passwords, credit card numbers, banking information, personal messages, and browsing history will be stolen and sent to criminals. You may experience identity theft, financial loss, and privacy violations.",
            "Cryptominer": "Your computer will become extremely slow. Your CPU and GPU will be overworked, causing overheating, increased electricity costs, and potential hardware damage. The hackers make money while you pay the bills.",
            "Adware": "Your browser will be hijacked with unwanted ads. Your search results may be redirected. Your personal browsing data may be collected and sold. Your computer performance will degrade.",
            "Worm": "This will spread to other computers on your network, to your friends via email, and through removable drives. It can infect entire organizations and cause widespread damage.",
            "DDoS Bot": "Your internet connection will be used to commit crimes. Your IP address may be logged by law enforcement. Your bandwidth will be consumed. You may face legal consequences for participating in attacks.",
            "Dropper/Downloader": "This will install additional malware on your computer. The downloaded malware could be anything - ransomware, banking trojans, spyware. It's a gateway to more infections.",
            "Suspicious/Obfuscated Code": "The consequences depend on the hidden payload, but could include any of the above: data theft, system infection, ransomware, or remote access by hackers.",
        }
        
        return consequences.get(category, "Potential consequences include data theft, system compromise, financial loss, privacy violation, and identity theft. The exact impact depends on the specific malware variant.")
    
    def _build_connections(self, detections, filepath):
        """Build device connections description."""
        lines = []
        
        for det in detections:
            det_type = det.get("type", "")
            if "network" in det_type or "url" in det_type or "c2" in det_type:
                lines.append(f"Network reference detected: {det.get('details', '')}")
            if "registry" in det_type:
                lines.append(f"Registry modification: {det.get('details', '')}")
            if "process" in det_type:
                lines.append(f"Active process connection: {det.get('details', '')}")
            if "service" in det_type:
                lines.append(f"System service connection: {det.get('details', '')}")
        
        if not lines:
            lines.append("This file may attempt to connect to remote servers (Command & Control), modify the Windows registry, create or modify services, inject into other processes, or establish network connections for data exfiltration.")
        
        return "\n".join(lines)
    
    def scan_file(self, filepath):
        """Scan a single file with all file-based engines."""
        if not os.path.exists(filepath):
            return None
        
        all_detections = []
        
        # Signature engine
        sig_results = self.sig_engine.scan_file(filepath)
        all_detections.extend(sig_results)
        
        # PE analyzer (for executables)
        pe_results = self.pe_analyzer.analyze_file(filepath)
        all_detections.extend(pe_results)
        
        # Heuristic engine
        heur_results = self.heuristic_engine.scan_file(filepath)
        all_detections.extend(heur_results)
        
        # AMSI engine
        amsi_results = self.amsi_engine.scan_file(filepath)
        all_detections.extend(amsi_results)
        
        if all_detections:
            return self._build_threat_report(filepath, all_detections, "Multi-Engine")
        
        return None
    
    def scan_directory(self, directory, recursive=True, max_size_mb=100):
        """Scan a directory for threats."""
        threats = []
        files_to_scan = []
        
        # Build file list
        self._log(f"Building file list for: {directory}")
        
        if recursive:
            for root, dirs, files in os.walk(directory):
                # Skip system directories to avoid issues
                dirs[:] = [d for d in dirs if d.lower() not in [
                    'windows', 'programdata', 'program files', 'program files (x86)',
                    '$recycle.bin', 'system volume information', 'intel', 'amd'
                ]]
                
                for file in files:
                    filepath = os.path.join(root, file)
                    # Skip excluded paths (e.g., DDAV installation directory)
                    filepath_norm = os.path.normpath(filepath).lower()
                    if any(filepath_norm.startswith(excl) for excl in self.exclusions):
                        continue
                    try:
                        size = os.path.getsize(filepath)
                        if size > max_size_mb * 1024 * 1024:
                            continue
                        files_to_scan.append(filepath)
                    except Exception:
                        continue
        else:
            for item in os.listdir(directory):
                filepath = os.path.join(directory, item)
                # Skip excluded paths
                filepath_norm = os.path.normpath(filepath).lower()
                if any(filepath_norm.startswith(excl) for excl in self.exclusions):
                    continue
                if os.path.isfile(filepath):
                    try:
                        size = os.path.getsize(filepath)
                        if size > max_size_mb * 1024 * 1024:
                            continue
                        files_to_scan.append(filepath)
                    except Exception:
                        continue
        
        self.stats["total_files"] = len(files_to_scan)
        self._log(f"Found {len(files_to_scan)} files to scan")
        
        # Scan files
        for i, filepath in enumerate(files_to_scan):
            if self.cancelled:
                break
            
            self._progress(i + 1, len(files_to_scan), f"Scanning: {os.path.basename(filepath)}")
            
            try:
                threat = self.scan_file(filepath)
                if threat:
                    threats.append(threat)
                    self._log(f"THREAT DETECTED: {threat['threat_name']} - {filepath}")
            except Exception as e:
                self._log(f"Error scanning {filepath}: {e}")
            
            self.stats["files_scanned"] = i + 1
        
        return threats
    
    def full_system_scan(self, target_dirs=None):
        """Perform a full system scan."""
        self.scanning = True
        self.cancelled = False
        self.threats = []
        self.stats["start_time"] = time.time()
        self.stats["engines_used"] = [
            "Signature Engine (Hash + Pattern)",
            "PE Analyzer (Structural)",
            "Heuristic Engine (Behavioral)",
            "AMSI Engine (Windows Integrated)",
            "Registry Scanner (Persistence)",
            "Process Scanner (Active Threats)",
            "Startup Scanner (Autoruns)",
        ]
        
        self._log("=" * 60)
        self._log("DDAV FULL SYSTEM SCAN STARTED")
        self._log("=" * 60)
        
        try:
            # 1. Scan target directories
            if target_dirs is None:
                target_dirs = []
                # Add common user directories
                user_profile = os.environ.get("USERPROFILE", "")
                if user_profile:
                    target_dirs.extend([
                        user_profile,
                        os.path.join(user_profile, "Downloads"),
                        os.path.join(user_profile, "Desktop"),
                        os.path.join(user_profile, "Documents"),
                        os.path.join(user_profile, "AppData", "Local"),
                        os.path.join(user_profile, "AppData", "Roaming"),
                    ])
                
                # Add system temp
                target_dirs.append(os.environ.get("TEMP", "C:\\Windows\\Temp"))
                target_dirs.append(os.environ.get("TMP", "C:\\Windows\\Temp"))
                target_dirs.append(os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "Temp"))
            
            # Filter existing directories
            target_dirs = [d for d in target_dirs if os.path.exists(d)]
            target_dirs = list(set(target_dirs))
            
            for directory in target_dirs:
                if self.cancelled:
                    break
                self._log(f"\nScanning directory: {directory}")
                dir_threats = self.scan_directory(directory, recursive=True, max_size_mb=100)
                self.threats.extend(dir_threats)
            
            # 2. Scan registry
            if not self.cancelled:
                self._log("\nScanning Windows Registry...")
                self._progress(0, 100, "Scanning Registry...")
                registry_threats = self.registry_scanner.scan_all()
                for reg_threat in registry_threats:
                    # Create synthetic file path for registry threats
                    threat_report = self._build_threat_report(
                        reg_threat.get("key_path", "Registry"),
                        [reg_threat],
                        "Registry Scanner"
                    )
                    if threat_report:
                        self.threats.append(threat_report)
                self._log(f"Registry scan complete. Found {len(registry_threats)} suspicious entries.")
            
            # 3. Scan processes
            if not self.cancelled:
                self._log("\nScanning active processes...")
                self._progress(0, 100, "Scanning Processes...")
                process_threats = self.process_scanner.scan_all_processes()
                for proc_threat in process_threats:
                    threat_report = self._build_threat_report(
                        proc_threat.get("path", f"Process:{proc_threat.get('pid', 'unknown')}"),
                        [proc_threat],
                        "Process Scanner"
                    )
                    if threat_report:
                        self.threats.append(threat_report)
                self._log(f"Process scan complete. Found {len(process_threats)} suspicious processes.")
            
            # 4. Scan startup items
            if not self.cancelled:
                self._log("\nScanning startup items...")
                self._progress(0, 100, "Scanning Startup Items...")
                startup_threats = self.startup_scanner.scan_all()
                for startup_threat in startup_threats:
                    threat_report = self._build_threat_report(
                        startup_threat.get("item_path", startup_threat.get("location", "Startup")),
                        [startup_threat],
                        "Startup Scanner"
                    )
                    if threat_report:
                        self.threats.append(threat_report)
                self._log(f"Startup scan complete. Found {len(startup_threats)} suspicious items.")
            
            # Finalize stats
            self.stats["end_time"] = time.time()
            duration = self.stats["end_time"] - self.stats["start_time"]
            self.stats["duration"] = f"{int(duration // 60)}m {int(duration % 60)}s"
            self.stats["threats_found"] = len(self.threats)
            
            self._log("\n" + "=" * 60)
            self._log(f"SCAN COMPLETE")
            self._log(f"Total Files Scanned: {self.stats['total_files']}")
            self._log(f"Threats Detected: {self.stats['threats_found']}")
            self._log(f"Duration: {self.stats['duration']}")
            self._log("=" * 60)
            
        except Exception as e:
            self._log(f"SCAN ERROR: {e}")
        
        self.scanning = False
        return self.threats
    
    def cancel_scan(self):
        """Cancel the current scan."""
        self.cancelled = True
        self._log("Scan cancellation requested...")
