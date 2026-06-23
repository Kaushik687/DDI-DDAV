"""
DDAV PE Analyzer
Analyzes Windows Portable Executable (PE) files for suspicious characteristics.
Detects packers, suspicious imports, section anomalies, and structural indicators.
"""

import os
import struct
import math
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from data.threat_signatures import (
    SUSPICIOUS_API_IMPORTS, SUSPICIOUS_PE_SECTIONS,
    ENTROPY_SUSPICIOUS_THRESHOLD, ENTROPY_HIGH_THRESHOLD
)


class PEAnalyzer:
    """Analyzes PE files for malware indicators."""
    
    # PE constants
    DOS_SIGNATURE = 0x5A4D  # 'MZ'
    PE_SIGNATURE = 0x00004550  # 'PE\0\0'
    
    def __init__(self):
        self.suspicious_imports = []
        for cat, apis in SUSPICIOUS_API_IMPORTS.items():
            for api in apis:
                self.suspicious_imports.append((cat, api))
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data. High = likely encrypted/packed."""
        if not data:
            return 0.0
        
        entropy = 0.0
        length = len(data)
        
        if length == 0:
            return 0.0
        
        # Count byte frequencies
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        # Calculate entropy
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def is_pe_file(self, filepath):
        """Check if file is a valid PE file."""
        try:
            with open(filepath, "rb") as f:
                # Check DOS signature
                dos_sig = struct.unpack("<H", f.read(2))[0]
                if dos_sig != self.DOS_SIGNATURE:
                    return False
                
                # Get PE header offset
                f.seek(0x3C)
                pe_offset_data = f.read(4)
                if len(pe_offset_data) < 4:
                    return False
                pe_offset = struct.unpack("<I", pe_offset_data)[0]
                
                # Check PE signature
                f.seek(pe_offset)
                pe_sig = struct.unpack("<I", f.read(4))[0]
                return pe_sig == self.PE_SIGNATURE
                
        except Exception:
            return False
    
    def parse_pe(self, filepath):
        """Parse basic PE structure and return analysis data."""
        results = {
            "is_pe": False,
            "is_dll": False,
            "is_64bit": False,
            "sections": [],
            "imports": [],
            "entry_point": 0,
            "image_base": 0,
            "suspicious_characteristics": []
        }
        
        if not self.is_pe_file(filepath):
            return results
        
        results["is_pe"] = True
        
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            
            # DOS Header
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
            
            # COFF Header (after PE signature)
            coff_offset = pe_offset + 4
            machine = struct.unpack("<H", data[coff_offset:coff_offset+2])[0]
            num_sections = struct.unpack("<H", data[coff_offset+2:coff_offset+4])[0]
            
            # Check machine type
            if machine == 0x8664:  # AMD64
                results["is_64bit"] = True
            elif machine == 0x14c:  # i386
                results["is_64bit"] = False
            
            # Check characteristics
            characteristics = struct.unpack("<H", data[coff_offset+16:coff_offset+18])[0]
            results["is_dll"] = bool(characteristics & 0x2000)
            
            # Optional Header offset
            opt_header_offset = coff_offset + 20
            
            # Magic number (PE32 vs PE32+)
            magic = struct.unpack("<H", data[opt_header_offset:opt_header_offset+2])[0]
            is_pe32_plus = (magic == 0x20b)
            
            # Entry point and image base
            if is_pe32_plus:
                results["entry_point"] = struct.unpack("<I", data[opt_header_offset+16:opt_header_offset+20])[0]
                results["image_base"] = struct.unpack("<Q", data[opt_header_offset+24:opt_header_offset+32])[0]
                section_table_offset = opt_header_offset + 240  # PE32+ optional header size
            else:
                results["entry_point"] = struct.unpack("<I", data[opt_header_offset+16:opt_header_offset+20])[0]
                results["image_base"] = struct.unpack("<I", data[opt_header_offset+28:opt_header_offset+32])[0]
                section_table_offset = opt_header_offset + 224
            
            # Parse sections
            for i in range(num_sections):
                sec_offset = section_table_offset + (i * 40)
                if sec_offset + 40 > len(data):
                    break
                
                name = data[sec_offset:sec_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
                virtual_size = struct.unpack("<I", data[sec_offset+8:sec_offset+12])[0]
                virtual_address = struct.unpack("<I", data[sec_offset+12:sec_offset+16])[0]
                raw_size = struct.unpack("<I", data[sec_offset+16:sec_offset+20])[0]
                raw_offset = struct.unpack("<I", data[sec_offset+20:sec_offset+24])[0]
                characteristics = struct.unpack("<I", data[sec_offset+36:sec_offset+40])[0]
                
                # Calculate entropy for this section
                section_data = data[raw_offset:raw_offset+raw_size] if raw_size > 0 else b""
                entropy = self.calculate_entropy(section_data)
                
                section_info = {
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_offset": raw_offset,
                    "entropy": round(entropy, 2),
                    "characteristics": characteristics,
                    "is_executable": bool(characteristics & 0x20000000),
                    "is_writable": bool(characteristics & 0x80000000),
                }
                results["sections"].append(section_info)
            
            # Parse imports (simplified - scan for import table strings)
            # This is a heuristic approach since full PE parsing is complex
            import_strings = self._extract_imports_heuristic(data)
            results["imports"] = import_strings
            
            return results
            
        except Exception as e:
            results["error"] = str(e)
            return results
    
    def _extract_imports_heuristic(self, data):
        """Extract potential API imports by scanning for known suspicious API names."""
        found = []
        for category, api_name in self.suspicious_imports:
            if api_name.encode().lower() in data.lower():
                found.append({"category": category, "api": api_name})
        return found
    
    def analyze_file(self, filepath):
        """Full PE analysis returning suspicious indicators."""
        detections = []
        
        if not self.is_pe_file(filepath):
            return detections
        
        pe_info = self.parse_pe(filepath)
        
        # Check section names
        for section in pe_info.get("sections", []):
            name = section["name"]
            
            # Suspicious section names
            if name in SUSPICIOUS_PE_SECTIONS:
                detections.append({
                    "type": "suspicious_section",
                    "section_name": name,
                    "confidence": 80,
                    "details": f"Section '{name}' is associated with known packers/protectors."
                })
            
            # High entropy sections
            entropy = section.get("entropy", 0)
            if entropy > ENTROPY_HIGH_THRESHOLD:
                detections.append({
                    "type": "high_entropy",
                    "section_name": name,
                    "entropy": entropy,
                    "confidence": 90,
                    "details": f"Section '{name}' has very high entropy ({entropy}), indicating packed/encrypted code."
                })
            elif entropy > ENTROPY_SUSPICIOUS_THRESHOLD:
                detections.append({
                    "type": "suspicious_entropy",
                    "section_name": name,
                    "entropy": entropy,
                    "confidence": 70,
                    "details": f"Section '{name}' has high entropy ({entropy}), possibly compressed/encrypted."
                })
            
            # Executable + Writable (common in injected code)
            if section.get("is_executable") and section.get("is_writable"):
                detections.append({
                    "type": "exec_writable_section",
                    "section_name": name,
                    "confidence": 75,
                    "details": f"Section '{name}' is both executable and writable - common in self-modifying/packed code."
                })
            
            # Raw size != Virtual size (packing indicator)
            if section.get("raw_size", 0) == 0 and section.get("virtual_size", 0) > 0:
                detections.append({
                    "type": "unpacked_section",
                    "section_name": name,
                    "confidence": 65,
                    "details": f"Section '{name}' has zero raw size but non-zero virtual size - unpacks at runtime."
                })
        
        # Check imports
        imports = pe_info.get("imports", [])
        if imports:
            # Group by category
            categories = {}
            for imp in imports:
                cat = imp["category"]
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(imp["api"])
            
            for cat, apis in categories.items():
                detections.append({
                    "type": "suspicious_imports",
                    "category": cat,
                    "apis": apis,
                    "confidence": min(60 + len(apis) * 5, 95),
                    "details": f"File imports {len(apis)} suspicious API(s) related to {cat}: {', '.join(apis[:5])}"
                })
        
        # Very small PE (dropper/stub)
        try:
            file_size = os.path.getsize(filepath)
            if file_size < 1024:
                detections.append({
                    "type": "tiny_pe",
                    "size": file_size,
                    "confidence": 60,
                    "details": f"PE file is extremely small ({file_size} bytes), possible dropper or stub."
                })
            elif file_size < 4096:
                detections.append({
                    "type": "small_pe",
                    "size": file_size,
                    "confidence": 40,
                    "details": f"PE file is unusually small ({file_size} bytes), may be a downloader or stub."
                })
        except Exception:
            pass
        
        return detections
