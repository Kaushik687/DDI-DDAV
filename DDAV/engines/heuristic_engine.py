"""
DDAV Heuristic Engine
Performs behavioral and structural heuristic analysis to detect
potentially malicious code patterns without relying on signatures.
"""

import os
import math
import re
import struct

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from data.threat_signatures import ENTROPY_SUSPICIOUS_THRESHOLD, ENTROPY_HIGH_THRESHOLD


class HeuristicEngine:
    """Heuristic analysis engine for malware detection."""
    
    def __init__(self):
        # Suspicious opcode patterns (x86)
        self.suspicious_opcodes = [
            b'\xEB\xFE',           # JMP $ (infinite loop, common in shellcode)
            b'\xE9\x00\x00\x00\x00',  # JMP near with 0 offset
            b'\xFF\xE4',           # JMP ESP (stack execution)
            b'\xFF\xD0',           # CALL EAX
            b'\xFF\xD1',           # CALL ECX
            b'\xFF\xD2',           # CALL EDX
            b'\xFF\xD3',           # CALL EBX
            b'\xFF\xD5',           # CALL EBP
            b'\xFF\xD6',           # CALL ESI
            b'\xFF\xD7',           # CALL EDI
            b'\x90\x90\x90\x90',   # NOP sled
        ]
        
        # Suspicious script patterns (regex)
        self.suspicious_script_patterns = [
            (r'eval\s*\(', 'eval() execution - common in obfuscated malware'),
            (r'exec\s*\(', 'exec() execution - arbitrary code execution'),
            (r'system\s*\(', 'system() call - OS command execution'),
            (r'subprocess\.call', 'subprocess call - OS command execution'),
            (r'os\.system', 'os.system() - OS command execution'),
            (r'CreateObject\s*\(', 'COM object creation - possible script injection'),
            (r'WScript\.Shell', 'WScript.Shell - script execution'),
            (r'ActiveXObject', 'ActiveXObject - potentially malicious COM'),
            (r'new\s+Function\s*\(', 'Dynamic function creation - possible obfuscation'),
            (r'fromCharCode', 'String.fromCharCode - common obfuscation technique'),
            (r'unescape\s*\(', 'unescape() - common in exploit kits'),
            (r'document\.write\s*\(', 'document.write - possible script injection'),
            (r'innerHTML\s*=', 'innerHTML assignment - possible XSS/malware'),
            (r'\\x[0-9a-fA-F]{2}', 'Hex-encoded strings - possible obfuscation'),
            (r'%[0-9a-fA-F]{2}', 'URL-encoded strings - possible obfuscation'),
            (r'base64\s*', 'Base64 operations - possible payload encoding'),
            (r'powershell', 'PowerShell invocation - common in fileless malware'),
            (r'cmd\.exe', 'cmd.exe invocation - OS command execution'),
            (r'netcat', 'netcat reference - network tool commonly abused'),
            (r'mimikatz', 'Mimikatz reference - credential theft tool'),
            (r'procdump', 'ProcDump reference - credential dumping tool'),
            (r'Invoke-Expression', 'Invoke-Expression - PowerShell code execution'),
            (r'IEX\(', 'IEX (Invoke-Expression) - PowerShell execution'),
            (r'DownloadString', 'DownloadString - downloads and executes code'),
            (r'DownloadFile', 'DownloadFile - downloads files from internet'),
            (r'FromBase64String', 'Base64 decode - payload obfuscation'),
            (r'Register-WmiEvent', 'WMI event registration - persistence'),
            (r'New-Object\s+Net\.WebClient', 'WebClient object - network download'),
            (r'Start-Process', 'Start-Process - launches programs'),
            (r'Get-WmiObject', 'WMI query - system information gathering'),
            (r'Get-Process', 'Process enumeration - reconnaissance'),
            (r'Get-ChildItem', 'Directory listing - reconnaissance'),
            (r'Add-Type', 'Add-Type - compiles C# code in memory'),
            (r'VirtualAlloc', 'VirtualAlloc - memory allocation for injection'),
            (r'CreateRemoteThread', 'CreateRemoteThread - process injection'),
            (r'WriteProcessMemory', 'WriteProcessMemory - process manipulation'),
            (r'NtMapViewOfSection', 'NtMapViewOfSection - process hollowing'),
            (r'RegCreateKeyEx', 'Registry creation - persistence'),
            (r'RegSetValueEx', 'Registry modification - persistence'),
            (r'CreateService', 'Service creation - persistence'),
            (r'SetWindowsHookEx', 'Windows hook - keylogging/monitoring'),
            (r'URLDownloadToFile', 'URLDownloadToFile - downloads payloads'),
        ]
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy."""
        if not data:
            return 0.0
        
        entropy = 0.0
        length = len(data)
        if length == 0:
            return 0.0
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def analyze_file_entropy(self, filepath):
        """Check file-level entropy."""
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            
            entropy = self.calculate_entropy(data)
            
            if entropy > ENTROPY_HIGH_THRESHOLD:
                return {
                    "type": "file_high_entropy",
                    "entropy": round(entropy, 2),
                    "confidence": 85,
                    "details": f"File has very high entropy ({entropy:.2f}/8.0). Likely packed, encrypted, or compressed."
                }
            elif entropy > ENTROPY_SUSPICIOUS_THRESHOLD:
                return {
                    "type": "file_suspicious_entropy",
                    "entropy": round(entropy, 2),
                    "confidence": 60,
                    "details": f"File has elevated entropy ({entropy:.2f}/8.0). Possibly compressed or encrypted."
                }
            
            return None
        except Exception:
            return None
    
    def detect_nop_sleds(self, filepath):
        """Detect NOP sleds (common in shellcode/exploit payloads)."""
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            
            # Count consecutive NOPs (0x90)
            nop_count = 0
            max_nop_run = 0
            for byte in data:
                if byte == 0x90:
                    nop_count += 1
                    max_nop_run = max(max_nop_run, nop_count)
                else:
                    nop_count = 0
            
            if max_nop_run > 20:
                return {
                    "type": "nop_sled",
                    "nop_count": max_nop_run,
                    "confidence": min(70, 50 + max_nop_run // 10),
                    "details": f"Detected {max_nop_run} consecutive NOP instructions. Common in shellcode and exploit payloads."
                }
            
            return None
        except Exception:
            return None
    
    def detect_shellcode_patterns(self, filepath):
        """Detect raw shellcode patterns."""
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            
            matches = []
            for opcode in self.suspicious_opcodes:
                if opcode in data:
                    matches.append(opcode.hex())
            
            if matches:
                return {
                    "type": "shellcode_indicator",
                    "patterns": matches,
                    "confidence": min(75, 50 + len(matches) * 5),
                    "details": f"Found {len(matches)} suspicious opcode pattern(s) typical of shellcode."
                }
            
            return None
        except Exception:
            return None
    
    def analyze_scripts(self, filepath):
        """Analyze script files for suspicious patterns."""
        ext = os.path.splitext(filepath)[1].lower()
        script_exts = ['.vbs', '.js', '.jse', '.wsf', '.wsh', '.hta', '.ps1', '.ps2', '.bat', '.cmd', '.py', '.rb', '.pl', '.php', '.asp', '.aspx', '.jsp', '.jspx']
        
        if ext not in script_exts:
            return []
        
        detections = []
        
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return detections
        
        content_lower = content.lower()
        
        for pattern, description in self.suspicious_script_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detections.append({
                    "type": "suspicious_script_pattern",
                    "pattern": pattern,
                    "description": description,
                    "confidence": 70,
                    "details": f"Pattern '{pattern}' detected: {description}"
                })
        
        # Check for very long lines (obfuscation)
        max_line_len = max(len(line) for line in content.split('\n')) if content else 0
        if max_line_len > 5000:
            detections.append({
                "type": "obfuscated_script",
                "max_line_length": max_line_len,
                "confidence": 65,
                "details": f"Extremely long line detected ({max_line_len} chars). Common in obfuscated scripts."
            })
        
        # Check for excessive string concatenation (obfuscation)
        concat_count = content.count('+') + content.count('&')
        if concat_count > 100:
            detections.append({
                "type": "string_concatenation",
                "concat_count": concat_count,
                "confidence": 55,
                "details": f"Excessive string concatenation ({concat_count} operators). Possible string obfuscation."
            })
        
        # Check for encoded/encrypted strings
        if content.count('\\x') > 50 or content.count('%') > 100:
            detections.append({
                "type": "encoded_strings",
                "confidence": 60,
                "details": "High concentration of encoded/hex strings detected. Possible payload obfuscation."
            })
        
        return detections
    
    def detect_fake_extensions(self, filepath):
        """Detect files with misleading double extensions."""
        filename = os.path.basename(filepath)
        
        # Check for spaces before extension to hide real extension
        if '.exe' in filename.lower() and not filename.lower().endswith('.exe'):
            # Something like "document.pdf .exe"
            return {
                "type": "fake_extension",
                "confidence": 90,
                "details": "Executable extension hidden in filename using spaces or special characters."
            }
        
        # Check for right-to-left override character (U+202E) used in spoofing
        if '\u202e' in filename:
            return {
                "type": "rtl_override_spoof",
                "confidence": 95,
                "details": "Right-to-left override character detected in filename. This is a known spoofing technique."
            }
        
        return None
    
    def detect_macro_indicators(self, filepath):
        """Detect suspicious macro indicators in Office documents."""
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in ['.docm', '.dotm', '.xlsm', '.xltm', '.pptm', '.potm', '.doc', '.xls', '.ppt']:
            return None
        
        # For macro-enabled files, just flag them as potentially suspicious
        # Real analysis would require OLE parsing, but we'll flag for user review
        if ext in ['.docm', '.dotm', '.xlsm', '.xltm', '.pptm', '.potm']:
            return {
                "type": "macro_enabled_document",
                "confidence": 45,
                "details": f"Macro-enabled Office document ({ext}). Macros can contain malicious code. Review required."
            }
        
        return None
    
    def detect_suspicious_urls(self, filepath):
        """Detect URLs/IP addresses that may be C2 servers."""
        try:
            with open(filepath, "rb") as f:
                data = f.read().decode('utf-8', errors='ignore')
        except Exception:
            return None
        
        # Regex for IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, data)
        
        # Regex for URLs
        url_pattern = r'https?://[^\s"\']+'
        urls = re.findall(url_pattern, data)
        
        # Check for suspicious TLDs or patterns
        suspicious_urls = []
        for url in urls:
            if any(x in url.lower() for x in ['.tk', '.ml', '.ga', '.cf', '.gq', 'pastebin', 'transfer.sh', '0x0.st']):
                suspicious_urls.append(url)
        
        if suspicious_urls or len(ips) > 5:
            details = []
            if suspicious_urls:
                details.append(f"Found {len(suspicious_urls)} suspicious URL(s): {suspicious_urls[0]}")
            if len(ips) > 5:
                details.append(f"Found {len(ips)} IP address references")
            
            return {
                "type": "suspicious_network_refs",
                "urls": suspicious_urls,
                "ip_count": len(ips),
                "confidence": 65,
                "details": "; ".join(details)
            }
        
        return None
    
    def scan_file(self, filepath):
        """Full heuristic scan on a single file."""
        results = []
        
        # File entropy
        entropy_result = self.analyze_file_entropy(filepath)
        if entropy_result:
            results.append(entropy_result)
        
        # NOP sled detection
        nop_result = self.detect_nop_sleds(filepath)
        if nop_result:
            results.append(nop_result)
        
        # Shellcode patterns
        shellcode_result = self.detect_shellcode_patterns(filepath)
        if shellcode_result:
            results.append(shellcode_result)
        
        # Script analysis
        script_results = self.analyze_scripts(filepath)
        results.extend(script_results)
        
        # Fake extensions
        fake_ext = self.detect_fake_extensions(filepath)
        if fake_ext:
            results.append(fake_ext)
        
        # Macro indicators
        macro = self.detect_macro_indicators(filepath)
        if macro:
            results.append(macro)
        
        # Suspicious URLs
        url_result = self.detect_suspicious_urls(filepath)
        if url_result:
            results.append(url_result)
        
        return results
