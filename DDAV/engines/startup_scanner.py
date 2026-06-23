"""
DDAV Startup Scanner
Scans startup locations for persistence mechanisms.
"""

import os
import sys
import winreg
import glob
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from data.threat_signatures import SUSPICIOUS_FILENAMES, SUSPICIOUS_DIRECTORIES


class StartupScanner:
    """Scans startup folders and scheduled tasks for persistence."""
    
    def __init__(self):
        self.startup_locations = []
        self._build_startup_locations()
    
    def _build_startup_locations(self):
        """Build list of startup locations to check."""
        # Common startup folder paths
        user_profile = os.environ.get("USERPROFILE", "")
        program_data = os.environ.get("PROGRAMDATA", "")
        all_users_profile = os.environ.get("ALLUSERSPROFILE", "")
        
        startup_folders = []
        
        if user_profile:
            startup_folders.extend([
                os.path.join(user_profile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
                os.path.join(user_profile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
            ])
        
        if all_users_profile:
            startup_folders.append(os.path.join(all_users_profile, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
        
        if program_data:
            startup_folders.append(os.path.join(program_data, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
        
        # Also check for Windows Tasks folder
        if program_data:
            startup_folders.append(os.path.join(program_data, "Microsoft", "Windows", "Start Menu", "Programs"))
        
        self.startup_locations = list(set(startup_folders))
    
    def scan_startup_folders(self):
        """Scan startup folders for suspicious items."""
        detections = []
        
        for folder in self.startup_locations:
            if not os.path.exists(folder):
                continue
            
            try:
                for item in os.listdir(folder):
                    item_path = os.path.join(folder, item)
                    item_lower = item.lower()
                    
                    is_suspicious = False
                    reasons = []
                    
                    # Check for suspicious extensions
                    if item_lower.endswith(('.exe', '.com', '.scr', '.pif', '.bat', '.cmd', '.vbs', '.js', '.ps1')):
                        is_suspicious = True
                        reasons.append("Executable/script in startup folder")
                    
                    # Check for suspicious filenames
                    for susp_name in SUSPICIOUS_FILENAMES:
                        if susp_name.lower() in item_lower:
                            is_suspicious = True
                            reasons.append(f"Suspicious filename pattern: '{susp_name}'")
                            break
                    
                    # Check for double extensions
                    if item_lower.count('.') > 1:
                        if any(item_lower.endswith(ext) for ext in ['.exe', '.com', '.scr', '.pif']):
                            is_suspicious = True
                            reasons.append("Possible double extension trick")
                    
                    # Check if in suspicious subfolder
                    for susp_dir in SUSPICIOUS_DIRECTORIES:
                        if susp_dir.lower() in item_path.lower():
                            is_suspicious = True
                            reasons.append(f"Located in suspicious directory: {susp_dir}")
                            break
                    
                    if is_suspicious:
                        detections.append({
                            "type": "startup_persistence",
                            "location": folder,
                            "item_name": item,
                            "item_path": item_path,
                            "confidence": min(75, 40 + len(reasons) * 10),
                            "reasons": reasons,
                            "details": f"Suspicious startup item: '{item}' in '{folder}'. {'; '.join(reasons)}"
                        })
            
            except PermissionError:
                continue
            except Exception:
                continue
        
        return detections
    
    def scan_scheduled_tasks(self):
        """Scan for suspicious scheduled tasks by checking task folder."""
        detections = []
        
        # Windows Task Scheduler tasks are stored in XML files
        task_paths = [
            os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "System32", "Tasks"),
            os.path.join(os.environ.get("SYSTEMROOT", "C:\\Windows"), "SysWOW64", "Tasks"),
        ]
        
        for task_dir in task_paths:
            if not os.path.exists(task_dir):
                continue
            
            try:
                for root, dirs, files in os.walk(task_dir):
                    for file in files:
                        if file.endswith('.job') or file.endswith('.xml'):
                            file_path = os.path.join(root, file)
                            file_lower = file.lower()
                            
                            is_suspicious = False
                            reasons = []
                            
                            # Check for suspicious names
                            for susp_name in SUSPICIOUS_FILENAMES:
                                if susp_name.lower() in file_lower:
                                    is_suspicious = True
                                    reasons.append(f"Suspicious task name: '{susp_name}'")
                                    break
                            
                            if is_suspicious:
                                detections.append({
                                    "type": "scheduled_task",
                                    "task_path": file_path,
                                    "task_name": file,
                                    "confidence": 65,
                                    "reasons": reasons,
                                    "details": f"Suspicious scheduled task: '{file}'. {'; '.join(reasons)}"
                                })
            except PermissionError:
                continue
            except Exception:
                continue
        
        return detections
    
    def scan_wmi_persistence(self):
        """Check for WMI event subscriptions (fileless persistence)."""
        # WMI persistence checking requires WMI queries which need specific permissions
        # We'll add a detection noting that WMI should be checked manually
        detections = []
        
        # Note: Real WMI persistence checking would use:
        # wmic /namespace:\\root\subscription path __EventFilter get Name,Query
        # wmic /namespace:\\root\subscription path CommandLineEventConsumer get Name,CommandLineTemplate
        # wmic /namespace:\\root\subscription path __FilterToConsumerBinding get Filter,Consumer
        
        detections.append({
            "type": "wmi_persistence_check",
            "confidence": 30,
            "details": "WMI event subscription persistence cannot be fully scanned without WMI access. WMI-based persistence is a common fileless technique. Consider checking with: wmic /namespace:\\root\\subscription path __EventFilter get Name,Query"
        })
        
        return detections
    
    def scan_all(self):
        """Run all startup scans."""
        all_detections = []
        
        all_detections.extend(self.scan_startup_folders())
        all_detections.extend(self.scan_scheduled_tasks())
        all_detections.extend(self.scan_wmi_persistence())
        
        return all_detections
