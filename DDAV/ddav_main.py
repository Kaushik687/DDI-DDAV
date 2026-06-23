"""
DDAV - Deep Device Anti Virus
Main Entry Point

Usage:
    python ddav_main.py
    Or use the launcher.bat file to run with administrator privileges.

This is a real working antivirus scanner that uses multiple detection engines:
- Signature-based detection (hash + pattern matching)
- PE structural analysis
- Heuristic behavioral analysis
- Windows AMSI integration
- Registry persistence scanning
- Process activity scanning
- Startup item scanning

All actions require explicit user permission.
DDAV does not collect any data and only works when actively opened.
"""

import os
import sys

# Ensure we're in the DDAV directory
current_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(current_dir)

# Add DDAV root and subdirectories to path for imports
sys.path.insert(0, current_dir)
sys.path.insert(0, os.path.join(current_dir, "core"))
sys.path.insert(0, os.path.join(current_dir, "engines"))
sys.path.insert(0, os.path.join(current_dir, "utils"))
sys.path.insert(0, os.path.join(current_dir, "data"))

def main():
    """Main entry point."""
    try:
        from core.gui import run_app
        run_app()
    except ImportError as e:
        print(f"[DDAV] Error loading application: {e}")
        print("[DDAV] Please ensure all files are present in the DDAV folder.")
        # Only block on input if we have a console; otherwise use a message box
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0,
                f"DDAV failed to load:\n{e}\n\nPlease ensure all files are present in the DDAV folder.",
                "DDAV - Error", 0x10)
        except:
            pass
        sys.exit(1)
    except Exception as e:
        print(f"[DDAV] Unexpected error: {e}")
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0,
                f"DDAV encountered an error:\n{e}",
                "DDAV - Error", 0x10)
        except:
            pass
        sys.exit(1)

if __name__ == "__main__":
    main()
