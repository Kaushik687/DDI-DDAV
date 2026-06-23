"""
DDAV Signature Engine
Performs hash-based and string-pattern-based detection on files.
"""

import os
import hashlib
import mmap
import struct
import time
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from data.threat_signatures import (
    KNOWN_MALWARE_HASHES, SUSPICIOUS_STRING_PATTERNS,
    SUSPICIOUS_EXTENSIONS, SUSPICIOUS_FILENAMES, SUSPICIOUS_DIRECTORIES
)


class SignatureEngine:
    """Hash and pattern-based signature detection engine."""
    
    def __init__(self):
        # Build flat hash lookup for fast checking
        self.hash_to_threat = {}
        for family, hashes in KNOWN_MALWARE_HASHES.items():
            for h in hashes:
                self.hash_to_threat[h.lower()] = family
        
        # Build flat pattern lookup
        self.pattern_to_category = {}
        for category, patterns in SUSPICIOUS_STRING_PATTERNS.items():
            for pattern in patterns:
                self.pattern_to_category[pattern] = category
        
        # Suspicious extensions
        self.suspicious_exts = set()
        for cat, exts in SUSPICIOUS_EXTENSIONS.items():
            self.suspicious_exts.update(exts)
    
    def calculate_hashes(self, filepath):
        """Calculate MD5, SHA-1, and SHA-256 hashes of a file."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        try:
            with open(filepath, "rb") as f:
                # Read in chunks for large files
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
        except Exception as e:
            return None, None, None
        
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    
    def check_hash_match(self, filepath):
        """Check if file hash matches known malware hashes."""
        md5, sha1, sha256 = self.calculate_hashes(filepath)
        if not sha256:
            return None
        
        # Check SHA-256
        threat_family = self.hash_to_threat.get(sha256.lower())
        if threat_family:
            return {
                "type": "hash_match",
                "threat_family": threat_family,
                "hash_type": "SHA-256",
                "hash_value": sha256,
                "confidence": 100
            }
        
        # Check MD5 (for shorter hashes)
        threat_family = self.hash_to_threat.get(md5.lower())
        if threat_family:
            return {
                "type": "hash_match",
                "threat_family": threat_family,
                "hash_type": "MD5",
                "hash_value": md5,
                "confidence": 100
            }
        
        return None
    
    def scan_strings(self, filepath):
        """Scan file for suspicious string patterns."""
        matches = []
        
        try:
            # Read file as binary
            with open(filepath, "rb") as f:
                data = f.read()
        except Exception:
            return matches
        
        # Scan each pattern
        for pattern, category in self.pattern_to_category.items():
            if pattern in data:
                matches.append({
                    "type": "string_pattern",
                    "category": category,
                    "pattern": pattern.decode('utf-8', errors='replace'),
                    "confidence": 85,
                    "details": f"Suspicious string pattern found: '{pattern.decode('utf-8', errors='replace')}' (Category: {category})"
                })
        
        return matches
    
    def check_suspicious_filename(self, filepath):
        """Check if filename matches known suspicious patterns."""
        filename = os.path.basename(filepath).lower()
        matches = []
        
        # Check against suspicious filenames
        for susp_name in SUSPICIOUS_FILENAMES:
            if susp_name.lower() in filename:
                matches.append({
                    "type": "suspicious_filename",
                    "pattern": susp_name,
                    "confidence": 60,
                    "details": f"Filename contains suspicious pattern: '{susp_name}'"
                })
        
        # Check for double extensions (e.g., document.pdf.exe)
        if filename.count('.') > 1:
            ext = Path(filepath).suffix.lower()
            if ext in ['.exe', '.com', '.scr', '.pif', '.bat', '.cmd']:
                # Check if it has a fake document extension before
                fake_exts = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                            '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.zip']
                for fe in fake_exts:
                    if fe in filename.lower() and filename.lower().endswith(ext):
                        matches.append({
                            "type": "double_extension",
                            "pattern": f"{fe}{ext}",
                            "confidence": 90,
                            "details": f"Double extension detected: '{fe}{ext}' - possible masquerading attack"
                        })
                        break
        
        return matches
    
    def check_suspicious_location(self, filepath):
        """Check if file is in a suspicious directory."""
        filepath_lower = filepath.lower()
        matches = []
        
        for susp_dir in SUSPICIOUS_DIRECTORIES:
            if susp_dir.lower() in filepath_lower:
                matches.append({
                    "type": "suspicious_location",
                    "location": susp_dir,
                    "confidence": 50,
                    "details": f"File located in suspicious directory: '{susp_dir}'"
                })
        
        return matches
    
    def check_extension(self, filepath):
        """Check file extension risk level."""
        ext = Path(filepath).suffix.lower()
        
        if ext in self.suspicious_exts:
            if ext in ['.exe', '.com', '.scr', '.pif', '.dll', '.sys']:
                return {"type": "executable_extension", "extension": ext, "confidence": 30, "details": f"Executable file extension: {ext}"}
            elif ext in ['.vbs', '.js', '.jse', '.wsf', '.wsh', '.hta', '.ps1', '.bat', '.cmd']:
                return {"type": "script_extension", "extension": ext, "confidence": 40, "details": f"Script file extension: {ext}"}
            elif ext in ['.docm', '.dotm', '.xlsm', '.xltm', '.pptm', '.potm']:
                return {"type": "macro_extension", "extension": ext, "confidence": 50, "details": f"Macro-enabled document: {ext}"}
        
        return None
    
    def scan_file(self, filepath):
        """
        Full signature scan on a single file.
        Returns list of detection results.
        """
        results = []
        
        # Hash check
        hash_match = self.check_hash_match(filepath)
        if hash_match:
            results.append(hash_match)
        
        # String pattern scan (for files < 100MB to avoid memory issues)
        try:
            size = os.path.getsize(filepath)
            if size < 100 * 1024 * 1024:
                string_matches = self.scan_strings(filepath)
                results.extend(string_matches)
        except Exception:
            pass
        
        # Filename check
        filename_matches = self.check_suspicious_filename(filepath)
        results.extend(filename_matches)
        
        # Location check
        location_matches = self.check_suspicious_location(filepath)
        results.extend(location_matches)
        
        # Extension check
        ext_match = self.check_extension(filepath)
        if ext_match:
            results.append(ext_match)
        
        return results
