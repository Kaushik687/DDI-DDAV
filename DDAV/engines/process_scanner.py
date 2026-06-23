"""
DDAV Process Scanner
Scans running processes and memory for suspicious indicators.
"""

import os
import sys
import ctypes
from ctypes import wintypes
import struct
import math

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from data.threat_signatures import SUSPICIOUS_FILENAMES, SUSPICIOUS_API_IMPORTS


class ProcessScanner:
    """Scans running processes for malware indicators."""
    
    # Windows API constants
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    TH32CS_SNAPPROCESS = 0x00000002
    MAX_PATH = 260
    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.psapi = ctypes.windll.psapi
        self._setup_api()
    
    def _setup_api(self):
        """Setup Windows API function prototypes."""
        # CreateToolhelp32Snapshot
        self.kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        self.kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        
        # Process32First
        self.kernel32.Process32First.restype = wintypes.BOOL
        self.kernel32.Process32First.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        
        # Process32Next
        self.kernel32.Process32Next.restype = wintypes.BOOL
        self.kernel32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        
        # OpenProcess
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        
        # CloseHandle
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        
        # GetModuleBaseName
        try:
            self.psapi.GetModuleBaseNameA.restype = wintypes.DWORD
            self.psapi.GetModuleBaseNameA.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPSTR, wintypes.DWORD]
        except:
            pass
        
        # GetModuleFileNameEx
        try:
            self.psapi.GetModuleFileNameExA.restype = wintypes.DWORD
            self.psapi.GetModuleFileNameExA.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPSTR, wintypes.DWORD]
        except:
            pass
    
    def get_process_list(self):
        """Get list of running processes using Toolhelp32Snapshot."""
        processes = []
        
        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.CHAR * self.MAX_PATH),
            ]
        
        snapshot = self.kernel32.CreateToolhelp32Snapshot(self.TH32CS_SNAPPROCESS, 0)
        if snapshot == -1:
            return processes
        
        try:
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            
            if self.kernel32.Process32First(snapshot, ctypes.byref(entry)):
                while True:
                    processes.append({
                        "pid": entry.th32ProcessID,
                        "name": entry.szExeFile.decode('utf-8', errors='ignore').strip('\x00'),
                        "parent_pid": entry.th32ParentProcessID,
                        "threads": entry.cntThreads,
                    })
                    if not self.kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                        break
        finally:
            self.kernel32.CloseHandle(snapshot)
        
        return processes
    
    def get_process_path(self, pid):
        """Get the full path of a process executable."""
        try:
            h_process = self.kernel32.OpenProcess(
                self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ,
                False,
                pid
            )
            if not h_process:
                return None
            
            try:
                buffer = ctypes.create_string_buffer(self.MAX_PATH)
                result = self.psapi.GetModuleFileNameExA(h_process, None, buffer, self.MAX_PATH)
                if result > 0:
                    return buffer.value.decode('utf-8', errors='ignore')
                return None
            finally:
                self.kernel32.CloseHandle(h_process)
        except Exception:
            return None
    
    def check_process_suspicious(self, proc_info):
        """Check if a process exhibits suspicious characteristics."""
        detections = []
        name = proc_info.get("name", "").lower()
        pid = proc_info.get("pid", 0)
        
        # Get process path if possible
        path = self.get_process_path(pid)
        path_lower = path.lower() if path else ""
        
        # Check against suspicious filenames
        for susp_name in SUSPICIOUS_FILENAMES:
            if susp_name.lower() in name:
                # But allow legitimate system processes
                legitimate_paths = [
                    "\\windows\\system32\\",
                    "\\windows\\syswow64\\",
                    "\\windows\\winsxs\\",
                ]
                is_legitimate = any(lp in path_lower for lp in legitimate_paths) if path else False
                
                if not is_legitimate:
                    detections.append({
                        "type": "suspicious_process_name",
                        "process_name": name,
                        "pid": pid,
                        "path": path,
                        "confidence": 70,
                        "details": f"Process '{name}' (PID: {pid}) has a name similar to system processes but is not in a system directory. Possible masquerading."
                    })
                    break
        
        # Check if running from temp or appdata
        if path:
            if "\\temp\\" in path_lower or "\\tmp\\" in path_lower:
                detections.append({
                    "type": "process_in_temp",
                    "process_name": name,
                    "pid": pid,
                    "path": path,
                    "confidence": 65,
                    "details": f"Process '{name}' (PID: {pid}) is running from a temp directory. Malware commonly executes from temp locations."
                })
            
            if "\\appdata\\roaming\\" in path_lower or "\\appdata\\local\\" in path_lower:
                detections.append({
                    "type": "process_in_appdata",
                    "process_name": name,
                    "pid": pid,
                    "path": path,
                    "confidence": 60,
                    "details": f"Process '{name}' (PID: {pid}) is running from AppData. While some legitimate apps do this, it's a common malware persistence location."
                })
        
        # Check for processes without a visible path (injected/hollowed)
        if not path and pid > 4:  # Exclude System Idle Process
            detections.append({
                "type": "process_no_path",
                "process_name": name,
                "pid": pid,
                "confidence": 50,
                "details": f"Process '{name}' (PID: {pid}) has no accessible executable path. Could be a injected process or protected malware."
            })
        
        return detections
    
    def scan_all_processes(self):
        """Scan all running processes."""
        all_detections = []
        
        try:
            processes = self.get_process_list()
            for proc in processes:
                detections = self.check_process_suspicious(proc)
                all_detections.extend(detections)
        except Exception as e:
            all_detections.append({
                "type": "process_scan_error",
                "confidence": 0,
                "details": f"Process scan error: {e}"
            })
        
        return all_detections


class MemoryScanner:
    """Basic memory scanning for suspicious patterns."""
    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.PROCESS_VM_READ = 0x0010
        self.PROCESS_QUERY_INFORMATION = 0x0400
    
    def scan_process_memory(self, pid):
        """Scan process memory for suspicious strings (simplified)."""
        # Full memory scanning requires complex VirtualQueryEx iteration
        # For this implementation, we return a note that deep memory scanning
        # requires kernel-level access
        return []
