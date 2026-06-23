"""
DDAV Admin Privilege Checker
Ensures the app is running with Administrator privileges on Windows.
"""

import ctypes
import sys
import os


def is_admin():
    """Check if the current process has administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def require_admin(exit_on_fail=True):
    """
    Check for admin privileges. If not admin, exit with error message.
    Returns True if admin, False otherwise.
    """
    if not is_admin():
        if exit_on_fail:
            print("[DDAV] ERROR: Administrator privileges required.")
            print("[DDAV] Please run DDAV as Administrator.")
            print("[DDAV] Right-click the launcher and select 'Run as administrator'.")
            sys.exit(1)
        return False
    return True


def restart_as_admin():
    """Restart the current script with admin privileges using UAC elevation."""
    if not is_admin():
        script = sys.argv[0]
        params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        sys.exit(0)
