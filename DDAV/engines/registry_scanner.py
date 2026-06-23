"""
DDAV Registry Scanner
Scans Windows registry for persistence mechanisms, malicious keys,
and suspicious values commonly used by malware.
"""

import os
import sys
import winreg
import json
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from data.threat_signatures import SUSPICIOUS_REGISTRY_KEYS


class RegistryScanner:
    """Scans Windows registry for malware indicators."""
    
    # Registry hive mapping
    HIVE_MAP = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
    }
    
    def __init__(self):
        self.detections = []
    
    def parse_registry_path(self, reg_path):
        """Parse a registry path into hive and subpath."""
        parts = reg_path.split("\\", 1)
        if len(parts) < 2:
            return None, None
        
        hive_name = parts[0].upper()
        subpath = parts[1]
        
        hive = self.HIVE_MAP.get(hive_name)
        if hive is None:
            return None, None
        
        return hive, subpath
    
    def read_key_values(self, hive, subpath):
        """Read all values from a registry key."""
        values = {}
        try:
            with winreg.OpenKey(hive, subpath, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        values[name] = value
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except PermissionError:
            pass
        except Exception:
            pass
        
        return values
    
    def read_subkeys(self, hive, subpath):
        """Read all subkeys of a registry key."""
        subkeys = []
        try:
            with winreg.OpenKey(hive, subpath, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkeys.append(subkey_name)
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except PermissionError:
            pass
        except Exception:
            pass
        
        return subkeys
    
    def check_run_keys(self):
        """Check Run/RunOnce keys for suspicious entries."""
        detections = []
        
        for reg_path, category in SUSPICIOUS_REGISTRY_KEYS.get("Run_Keys", []):
            hive, subpath = self.parse_registry_path(reg_path)
            if hive is None:
                continue
            
            values = self.read_key_values(hive, subpath)
            
            for name, value in values.items():
                if not value:
                    continue
                
                value_str = str(value)
                value_lower = value_str.lower()
                
                # Check for suspicious patterns in values
                is_suspicious = False
                reasons = []
                
                # Points to temp directory
                if "\\temp\\" in value_lower or "\\tmp\\" in value_lower:
                    is_suspicious = True
                    reasons.append("Executable in temp directory")
                
                # Points to appdata/roaming (common for malware)
                if "\\appdata\\roaming\\" in value_lower:
                    is_suspicious = True
                    reasons.append("Executable in AppData\\Roaming")
                
                # Uses obfuscated command
                if "powershell" in value_lower or "cmd.exe" in value_lower or "wscript" in value_lower or "cscript" in value_lower:
                    is_suspicious = True
                    reasons.append("Uses script interpreter (PowerShell/CMD/VBS)")
                
                # Uses encoded commands
                if "-enc" in value_lower or "-encoded" in value_lower or "frombase64" in value_lower:
                    is_suspicious = True
                    reasons.append("Uses encoded commands (common obfuscation)")
                
                # Network download
                if "http" in value_lower or "ftp" in value_lower or "url" in value_lower:
                    is_suspicious = True
                    reasons.append("References network URLs")
                
                # Very long value (obfuscation)
                if len(value_str) > 500:
                    is_suspicious = True
                    reasons.append("Unusually long value (possible obfuscation)")
                
                # Points to system32 but has wrong name (spoofing)
                if "\\system32\\" in value_lower:
                    filename = os.path.basename(value_str).lower()
                    if filename not in ["ctfmon.exe", "msht.exe", "mobsync.exe"]:
                        # Check if it's a known system file with wrong path
                        is_suspicious = True
                        reasons.append("System directory reference with unusual filename")
                
                if is_suspicious:
                    detections.append({
                        "type": "registry_persistence",
                        "category": category,
                        "key_path": reg_path,
                        "value_name": name,
                        "value_data": value_str[:200] + "..." if len(value_str) > 200 else value_str,
                        "confidence": min(70, 40 + len(reasons) * 10),
                        "reasons": reasons,
                        "details": f"Suspicious Run key entry '{name}': {'; '.join(reasons)}"
                    })
        
        return detections
    
    def check_winlogon_hooks(self):
        """Check Winlogon hooks for malicious modifications."""
        detections = []
        
        for reg_path, value_name in SUSPICIOUS_REGISTRY_KEYS.get("Winlogon_Hooks", []):
            hive, subpath = self.parse_registry_path(reg_path)
            if hive is None:
                continue
            
            values = self.read_key_values(hive, subpath)
            
            if value_name in values:
                value = values[value_name]
                value_str = str(value) if value else ""
                
                # Default values (Userinit often has trailing comma: "userinit.exe,")
                defaults = {
                    "Shell": "explorer.exe",
                    "Userinit": "userinit.exe",
                }
                
                default_val = defaults.get(value_name, "")
                
                # For Userinit, allow "userinit.exe" or "userinit.exe," plus optional legitimate extras
                if value_name == "Userinit":
                    if not value_str.lower().startswith("userinit.exe") and value_str:
                        detections.append({
                            "type": "winlogon_hook",
                            "key_path": reg_path,
                            "value_name": value_name,
                            "value_data": value_str,
                            "confidence": 85,
                            "details": f"Winlogon '{value_name}' modified from default. Current: '{value_str}'. Expected to start with 'userinit.exe'. Possible bootkit/persistence."
                        })
                elif value_str.lower() != default_val.lower() and value_str:
                    # Modified from default
                    detections.append({
                        "type": "winlogon_hook",
                        "key_path": reg_path,
                        "value_name": value_name,
                        "value_data": value_str,
                        "confidence": 85,
                        "details": f"Winlogon '{value_name}' modified from default. Current: '{value_str}'. Expected: '{default_val}'. Possible bootkit/persistence."
                    })
        
        return detections
    
    def check_services(self):
        """Check services for suspicious entries."""
        detections = []
        
        for reg_path, value_name in SUSPICIOUS_REGISTRY_KEYS.get("Services", []):
            hive, subpath = self.parse_registry_path(reg_path)
            if hive is None:
                continue
            
            subkeys = self.read_subkeys(hive, subpath)
            
            for service_name in subkeys:
                service_path = f"{subpath}\\{service_name}"
                values = self.read_key_values(hive, service_path)
                
                image_path = values.get("ImagePath", "")
                if not image_path:
                    continue
                
                image_str = str(image_path)
                image_lower = image_str.lower()
                
                is_suspicious = False
                reasons = []
                
                # Service points to temp or appdata
                if "\\temp\\" in image_lower or "\\appdata\\" in image_lower:
                    is_suspicious = True
                    reasons.append("Service executable in temp/AppData")
                
                # Service uses script interpreter
                if exe_basename in ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"]:
                    is_suspicious = True
                    reasons.append("Service uses script interpreter")
                
                # Service points to non-standard location
                if "\\windows\\system32\\" not in exe_lower and "\\windows\\syswow64\\" not in exe_lower:
                    if not any(x in exe_lower for x in ["program files", "program files (x86)"]):
                        is_suspicious = True
                        reasons.append("Service in non-standard location")
                
                # Very short name (common for malware), but allow known short system services
                known_short = ["csrss", "lsass", "smss", "services", "svchost", "wininit", "winlogon"]
                if len(service_name) < 5 and service_name.lower() not in known_short:
                    is_suspicious = True
                    reasons.append("Unusually short service name")
                
                if is_suspicious:
                    detections.append({
                        "type": "suspicious_service",
                        "service_name": service_name,
                        "image_path": image_str,
                        "confidence": min(75, 40 + len(reasons) * 10),
                        "reasons": reasons,
                        "details": f"Suspicious service '{service_name}': {'; '.join(reasons)}"
                    })
        
        return detections
    
    def check_appinit_dlls(self):
        """Check AppInit_DLLs for malicious DLLs."""
        detections = []
        
        for reg_path, value_name in SUSPICIOUS_REGISTRY_KEYS.get("AppInit_DLLs", []):
            hive, subpath = self.parse_registry_path(reg_path)
            if hive is None:
                continue
            
            values = self.read_key_values(hive, subpath)
            
            if value_name in values:
                value = values[value_name]
                if value:
                    value_str = str(value)
                    detections.append({
                        "type": "appinit_dll",
                        "key_path": reg_path,
                        "value": value_str,
                        "confidence": 80,
                        "details": f"AppInit_DLLs is set to '{value_str}'. This loads DLLs into every process - common rootkit technique."
                    })
        
        return detections
    
    def check_image_file_execution(self):
        """Check Image File Execution Options for debugger hijacking."""
        detections = []
        
        for reg_path, value_name in SUSPICIOUS_REGISTRY_KEYS.get("Image_File_Execution_Options", []):
            hive, subpath = self.parse_registry_path(reg_path)
            if hive is None:
                continue
            
            subkeys = self.read_subkeys(hive, subpath)
            
            for subkey in subkeys:
                if subkey.lower() in ["your image file name without a path"]:
                    continue
                
                key_path = f"{subpath}\\{subkey}"
                values = self.read_key_values(hive, key_path)
                
                if "Debugger" in values:
                    debugger = str(values["Debugger"])
                    detections.append({
                        "type": "debugger_hijack",
                        "target_executable": subkey,
                        "debugger_path": debugger,
                        "confidence": 90,
                        "details": f"IFEO hijack: '{subkey}' is redirected to debugger '{debugger}'. When this program runs, the debugger executes instead."
                    })
        
        return detections
    
    def scan_all(self):
        """Run all registry scans."""
        all_detections = []
        
        all_detections.extend(self.check_run_keys())
        all_detections.extend(self.check_winlogon_hooks())
        all_detections.extend(self.check_services())
        all_detections.extend(self.check_appinit_dlls())
        all_detections.extend(self.check_image_file_execution())
        
        return all_detections
