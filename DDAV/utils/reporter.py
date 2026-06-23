"""
DDAV Reporter
Handles report generation, copying details, and downloading to .txt files.
"""

import os
import sys
import time
from tkinter import filedialog

# Persistent data path (works for frozen .exe and source)
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REPORTS_DIR = os.path.join(BASE_DIR, "reports")


def ensure_reports_dir():
    """Ensure reports directory exists."""
    os.makedirs(REPORTS_DIR, exist_ok=True)


def format_threat_details(threat_data, mode="full"):
    """
    Format threat details into a readable string.
    mode: 'full', 'summary', 'code_only'
    """
    lines = []
    
    if mode in ("full", "summary"):
        lines.append("=" * 80)
        lines.append("DDAV THREAT DETECTION REPORT")
        lines.append("=" * 80)
        lines.append(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"File: {threat_data.get('file_path', 'N/A')}")
        lines.append(f"Threat Type: {threat_data.get('threat_type', 'Unknown')}")
        lines.append(f"Threat Name: {threat_data.get('threat_name', 'Unknown')}")
        lines.append(f"Severity: {threat_data.get('severity', 'Unknown')}")
        lines.append(f"Confidence: {threat_data.get('confidence', 0)}%")
        lines.append("")
        
        # Location details
        lines.append("-" * 40)
        lines.append("LOCATION DETAILS")
        lines.append("-" * 40)
        lines.append(f"Disk: {threat_data.get('disk', 'Unknown')}")
        lines.append(f"Folder: {threat_data.get('folder', 'Unknown')}")
        lines.append(f"File Name: {threat_data.get('filename', 'Unknown')}")
        lines.append(f"Full Path: {threat_data.get('file_path', 'Unknown')}")
        if threat_data.get('code_block'):
            lines.append(f"Code Block: Lines {threat_data.get('code_block_start', '?')} - {threat_data.get('code_block_end', '?')}")
        lines.append("")
        
        # Professional description
        lines.append("-" * 40)
        lines.append("TECHNICAL ANALYSIS (For Professionals)")
        lines.append("-" * 40)
        lines.append(threat_data.get('technical_description', 'No technical details available.'))
        lines.append("")
        
        # User-friendly description
        lines.append("-" * 40)
        lines.append("SIMPLE EXPLANATION (For General Users)")
        lines.append("-" * 40)
        lines.append(threat_data.get('user_description', 'No explanation available.'))
        lines.append("")
        
        # Consequences
        lines.append("-" * 40)
        lines.append("POTENTIAL CONSEQUENCES")
        lines.append("-" * 40)
        lines.append(threat_data.get('consequences', 'Unknown consequences.'))
        lines.append("")
        
        # Connections
        lines.append("-" * 40)
        lines.append("DEVICE CONNECTIONS")
        lines.append("-" * 40)
        lines.append(threat_data.get('connections', 'No connection data detected.'))
        lines.append("")
        
        # Indicators found
        if threat_data.get('indicators_found'):
            lines.append("-" * 40)
            lines.append("INDICATORS FOUND")
            lines.append("-" * 40)
            for indicator in threat_data.get('indicators_found', []):
                lines.append(f"  - {indicator}")
            lines.append("")
        
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
    
    if mode == "code_only":
        lines.append("=" * 80)
        lines.append("SUSPICIOUS CODE BLOCK")
        lines.append("=" * 80)
        lines.append(f"File: {threat_data.get('file_path', 'N/A')}")
        lines.append("")
        lines.append(threat_data.get('code_block', 'No code block available.'))
        lines.append("")
        lines.append("=" * 80)
    
    return "\n".join(lines)


def copy_to_clipboard(text, root_window=None):
    """Copy text to clipboard."""
    try:
        if root_window:
            root_window.clipboard_clear()
            root_window.clipboard_append(text)
            root_window.update()
        else:
            # Fallback using ctypes
            import ctypes
            # Open clipboard
            ctypes.windll.user32.OpenClipboard(0)
            ctypes.windll.user32.EmptyClipboard()
            # Allocate global memory
            hGlobal = ctypes.windll.kernel32.GlobalAlloc(0x2000, len(text) + 1)
            pGlobal = ctypes.windll.kernel32.GlobalLock(hGlobal)
            ctypes.memmove(pGlobal, text.encode('utf-8'), len(text) + 1)
            ctypes.windll.kernel32.GlobalUnlock(hGlobal)
            # Set clipboard data
            ctypes.windll.user32.SetClipboardData(1, hGlobal)
            ctypes.windll.user32.CloseClipboard()
        return True
    except Exception as e:
        return False


def download_as_txt(threat_data, default_filename=None, mode="full"):
    """
    Download threat report as a .txt file.
    Returns (success, file_path or error_message)
    """
    ensure_reports_dir()
    
    if default_filename is None:
        default_filename = f"DDAV_Report_{int(time.time())}.txt"
    
    # Use filedialog for save location
    try:
        from tkinter import Tk
        root = Tk()
        root.withdraw()
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile=default_filename,
            initialdir=REPORTS_DIR
        )
        root.destroy()
        
        if not file_path:
            return False, "Save cancelled by user"
        
        content = format_threat_details(threat_data, mode)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        
        return True, file_path
        
    except Exception as e:
        return False, f"Error saving file: {e}"


def download_code_block(threat_data, default_filename=None):
    """Download just the suspicious code block as .txt"""
    if not default_filename:
        default_filename = f"DDAV_CodeBlock_{int(time.time())}.txt"
    return download_as_txt(threat_data, default_filename, mode="code_only")


def generate_full_scan_report(all_threats, scan_stats):
    """Generate a comprehensive scan report for all threats found."""
    lines = []
    lines.append("=" * 80)
    lines.append("DDAV FULL SYSTEM SCAN REPORT")
    lines.append("=" * 80)
    lines.append(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Total Files Scanned: {scan_stats.get('total_files', 0)}")
    lines.append(f"Threats Detected: {scan_stats.get('threats_found', 0)}")
    lines.append(f"Scan Duration: {scan_stats.get('duration', 'Unknown')}")
    lines.append("")
    lines.append("-" * 80)
    lines.append("DETECTED THREATS SUMMARY")
    lines.append("-" * 80)
    lines.append("")
    
    for i, threat in enumerate(all_threats, 1):
        lines.append(f"[{i}] {threat.get('threat_name', 'Unknown')} ({threat.get('severity', 'Unknown')})")
        lines.append(f"    Path: {threat.get('file_path', 'Unknown')}")
        lines.append(f"    Type: {threat.get('threat_type', 'Unknown')}")
        lines.append("")
    
    lines.append("-" * 80)
    lines.append(f"Total: {len(all_threats)} threats detected")
    lines.append("=" * 80)
    
    return "\n".join(lines)


def save_full_report(all_threats, scan_stats):
    """Save full scan report to file."""
    ensure_reports_dir()
    filename = f"DDAV_FullScan_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = os.path.join(REPORTS_DIR, filename)
    
    content = generate_full_scan_report(all_threats, scan_stats)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    
    return filepath
