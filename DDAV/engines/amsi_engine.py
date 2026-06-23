"""
DDAV AMSI Integration Engine
Uses Windows Antimalware Scan Interface (AMSI) to scan scripts and memory.
AMSI allows scanning of in-memory content before execution.
"""

import os
import sys
import ctypes
from ctypes import wintypes

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class AMSIEngine:
    """Windows AMSI integration for script and memory scanning."""
    
    AMSI_RESULT_CLEAN = 0
    AMSI_RESULT_NOT_DETECTED = 1
    AMSI_RESULT_DETECTED = 32768
    
    def __init__(self):
        self.amsi = None
        self.ctx = None
        self.session = None
        self.available = False
        self._init_amsi()
    
    def _init_amsi(self):
        """Initialize AMSI library."""
        try:
            # Load AMSI DLL
            self.amsi = ctypes.windll.amsi
            
            # Define function prototypes
            # AMSIInitialize
            self.amsi.AmsiInitialize.restype = wintypes.HRESULT
            self.amsi.AmsiInitialize.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.HANDLE)]
            
            # AmsiOpenSession
            self.amsi.AmsiOpenSession.restype = wintypes.HRESULT
            self.amsi.AmsiOpenSession.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE)]
            
            # AmsiScanString
            self.amsi.AmsiScanString.restype = wintypes.HRESULT
            self.amsi.AmsiScanString.argtypes = [
                wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
                wintypes.LPCWSTR, ctypes.POINTER(wintypes.INT)
            ]
            
            # AmsiScanBuffer
            self.amsi.AmsiScanBuffer.restype = wintypes.HRESULT
            self.amsi.AmsiScanBuffer.argtypes = [
                wintypes.HANDLE, ctypes.c_void_p, wintypes.ULONG,
                wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(wintypes.INT)
            ]
            
            # AmsiCloseSession
            self.amsi.AmsiCloseSession.restype = None
            self.amsi.AmsiCloseSession.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            
            # AmsiUninitialize
            self.amsi.AmsiUninitialize.restype = None
            self.amsi.AmsiUninitialize.argtypes = [wintypes.HANDLE]
            
            # Initialize AMSI context
            self.ctx = wintypes.HANDLE()
            result = self.amsi.AmsiInitialize("DDAV Deep Device AntiVirus", ctypes.byref(self.ctx))
            if result == 0:  # S_OK
                self.session = wintypes.HANDLE()
                result = self.amsi.AmsiOpenSession(self.ctx, ctypes.byref(self.session))
                if result == 0:
                    self.available = True
                    return
            
            self.available = False
            
        except Exception as e:
            self.available = False
    
    def is_available(self):
        """Check if AMSI is available and initialized."""
        return self.available
    
    def scan_string(self, content, content_name="unknown"):
        """
        Scan a string using AMSI.
        Returns (is_malicious, result_code, message)
        """
        if not self.available:
            return None, 0, "AMSI not available"
        
        try:
            result = wintypes.INT()
            hr = self.amsi.AmsiScanString(
                self.ctx,
                content,
                content_name,
                None,
                ctypes.byref(result)
            )
            
            if hr != 0:
                return None, hr, f"AMSI scan error (HRESULT: {hr})"
            
            result_val = result.value
            
            if result_val >= self.AMSI_RESULT_DETECTED:
                return True, result_val, f"AMSI detected threat (Result: {result_val})"
            elif result_val == self.AMSI_RESULT_NOT_DETECTED:
                return False, result_val, "AMSI could not determine - no threat detected"
            else:
                return False, result_val, "AMSI clean"
                
        except Exception as e:
            return None, 0, f"AMSI exception: {e}"
    
    def scan_buffer(self, data, content_name="unknown"):
        """
        Scan binary data using AMSI.
        Returns (is_malicious, result_code, message)
        """
        if not self.available:
            return None, 0, "AMSI not available"
        
        if not data:
            return False, 0, "Empty buffer"
        
        try:
            # Convert to bytes if string
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            result = wintypes.INT()
            buffer_size = len(data)
            buffer_ptr = ctypes.c_void_p()
            
            # Create ctypes buffer
            c_buffer = ctypes.create_string_buffer(data)
            buffer_ptr = ctypes.cast(c_buffer, ctypes.c_void_p)
            
            hr = self.amsi.AmsiScanBuffer(
                self.ctx,
                buffer_ptr,
                buffer_size,
                content_name,
                None,
                ctypes.byref(result)
            )
            
            if hr != 0:
                return None, hr, f"AMSI scan error (HRESULT: {hr})"
            
            result_val = result.value
            
            if result_val >= self.AMSI_RESULT_DETECTED:
                return True, result_val, f"AMSI detected threat (Result: {result_val})"
            elif result_val == self.AMSI_RESULT_NOT_DETECTED:
                return False, result_val, "AMSI could not determine - no threat detected"
            else:
                return False, result_val, "AMSI clean"
                
        except Exception as e:
            return None, 0, f"AMSI exception: {e}"
    
    def scan_file(self, filepath):
        """
        Scan a file using AMSI buffer scanning.
        Returns list of detection results.
        """
        results = []
        
        if not self.available:
            return results
        
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            
            if len(data) > 100 * 1024 * 1024:  # 100MB limit
                # Scan in chunks
                chunk_size = 10 * 1024 * 1024  # 10MB chunks
                for i in range(0, len(data), chunk_size):
                    chunk = data[i:i+chunk_size]
                    is_malicious, code, msg = self.scan_buffer(chunk, filepath)
                    if is_malicious:
                        results.append({
                            "type": "amsi_detection",
                            "chunk": i // chunk_size,
                            "confidence": 90,
                            "details": f"AMSI detected threat in chunk {i//chunk_size}: {msg}"
                        })
                        break  # One detection is enough for the file
            else:
                is_malicious, code, msg = self.scan_buffer(data, filepath)
                if is_malicious:
                    results.append({
                        "type": "amsi_detection",
                        "confidence": 90,
                        "details": f"AMSI detected threat: {msg}"
                    })
                elif is_malicious is None:
                    results.append({
                        "type": "amsi_error",
                        "confidence": 0,
                        "details": f"AMSI scan error: {msg}"
                    })
                    
        except Exception as e:
            results.append({
                "type": "amsi_error",
                "confidence": 0,
                "details": f"AMSI file scan error: {e}"
            })
        
        return results
    
    def scan_script_content(self, content, content_name="script"):
        """Scan script content (PowerShell, VBScript, JavaScript, etc.)."""
        results = []
        
        if not self.available:
            return results
        
        if not content:
            return results
        
        is_malicious, code, msg = self.scan_string(content, content_name)
        if is_malicious:
            results.append({
                "type": "amsi_script_detection",
                "confidence": 90,
                "details": f"AMSI detected malicious script content: {msg}"
            })
        
        return results
    
    def __del__(self):
        """Cleanup AMSI resources."""
        try:
            if self.available and self.amsi:
                if self.session:
                    self.amsi.AmsiCloseSession(self.ctx, self.session)
                if self.ctx:
                    self.amsi.AmsiUninitialize(self.ctx)
        except Exception:
            pass
