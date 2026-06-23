"""
DDAV Block Manager
Handles blocking and reverting files/folders using Windows ACL restrictions.
No data is deleted - only access permissions are modified.
"""

import os
import json
import ctypes
import subprocess
import sys

# Persistent data path (works for frozen .exe and source)
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BLOCK_DB_PATH = os.path.join(BASE_DIR, "data", "blocked_items.json")
BACKUPS_DIR = os.path.join(BASE_DIR, "data", "backups")


def _backup_path_for(target_path):
    """Generate a backup file path in DDAV's backups directory for a given target path."""
    os.makedirs(BACKUPS_DIR, exist_ok=True)
    import hashlib
    safe_name = hashlib.md5(target_path.encode()).hexdigest() + ".ddav_acl_backup"
    return os.path.join(BACKUPS_DIR, safe_name)


def _run_icacls(args):
    """Run icacls safely without shell=True and return the result."""
    result = subprocess.run(
        ["icacls"] + args,
        capture_output=True,
        text=True,
        shell=False
    )
    return result


def ensure_block_db():
    """Ensure the blocked items database exists."""
    os.makedirs(os.path.dirname(BLOCK_DB_PATH), exist_ok=True)
    if not os.path.exists(BLOCK_DB_PATH):
        with open(BLOCK_DB_PATH, "w", encoding="utf-8") as f:
            json.dump({}, f)


def load_blocked_items():
    """Load the blocked items database."""
    ensure_block_db()
    try:
        with open(BLOCK_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_blocked_items(data):
    """Save the blocked items database."""
    ensure_block_db()
    with open(BLOCK_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def get_acl_info(path):
    """Get current ACL information for a path using icacls."""
    try:
        result = _run_icacls([path])
        return result.stdout
    except Exception as e:
        return f"Error reading ACL: {e}"


def _block_file_internal(filepath, backup_path):
    """Internal: apply deny ACLs to a file. Returns True if any step succeeded."""
    any_success = False
    # Try to save backup (best effort)
    bp = _backup_path_for(filepath)
    r = _run_icacls([filepath, "/save", bp])
    if r.returncode == 0:
        any_success = True
    # Remove inheritance
    r = _run_icacls([filepath, "/inheritance:r"])
    if r.returncode == 0:
        any_success = True
    # Apply deny
    for deny in [
        [filepath, "/deny", "Everyone:(F)"],
        [filepath, "/deny", "Users:(F)"],
    ]:
        r = _run_icacls(deny)
        if r.returncode == 0:
            any_success = True
    return any_success, bp


def _unblock_file_internal(filepath, backup_path):
    """Internal: remove deny ACLs from a file."""
    if backup_path and os.path.exists(backup_path):
        _run_icacls([filepath, "/restore", backup_path])
    for cmd in [
        [filepath, "/remove:d", "Everyone"],
        [filepath, "/remove:d", "Users"],
        [filepath, "/remove:d", "Administrators"],
        [filepath, "/inheritance:e"],
    ]:
        _run_icacls(cmd)


def block_file(filepath, threat_info=None):
    """
    Block a file by denying all access to Everyone and Users.
    """
    filepath = os.path.abspath(filepath)
    if not os.path.exists(filepath):
        return False, "File does not exist"
    if not os.path.isfile(filepath):
        return False, "Path is not a file"
    
    blocked_items = load_blocked_items()
    if filepath in blocked_items:
        return True, "File already blocked"
    
    original_acl = get_acl_info(filepath)
    backup_path = _backup_path_for(filepath)
    
    success, _ = _block_file_internal(filepath, backup_path)
    if not success:
        return False, "Failed to apply block ACLs to file"
    
    blocked_items[filepath] = {
        "type": "file",
        "original_acl": original_acl,
        "backup_file": backup_path,
        "threat_info": threat_info or {},
        "timestamp": str(ctypes.windll.kernel32.GetTickCount64())
    }
    save_blocked_items(blocked_items)
    return True, "File blocked successfully"


def block_folder(folderpath, threat_info=None):
    """
    Block a folder and all its contents recursively by applying deny ACLs.
    """
    folderpath = os.path.abspath(folderpath)
    if not os.path.exists(folderpath):
        return False, "Folder does not exist"
    if not os.path.isdir(folderpath):
        return False, "Path is not a folder"
    
    blocked_items = load_blocked_items()
    if folderpath in blocked_items:
        return True, "Folder already blocked"
    
    original_acl = get_acl_info(folderpath)
    backup_path = _backup_path_for(folderpath)
    
    # Save folder ACL backup
    r = _run_icacls([folderpath, "/save", backup_path, "/T"])
    if r.returncode != 0:
        return False, f"Failed to save ACL backup: {r.stderr.strip() or r.stdout.strip()}"
    
    # Block folder itself
    _block_file_internal(folderpath, backup_path)
    
    # Walk and block each file individually (more reliable than /T on deny)
    blocked_count = 0
    failed_count = 0
    for root, dirs, files in os.walk(folderpath):
        for name in files:
            fpath = os.path.join(root, name)
            success, _ = _block_file_internal(fpath, backup_path)
            if success:
                blocked_count += 1
            else:
                failed_count += 1
        for name in dirs:
            dpath = os.path.join(root, name)
            success, _ = _block_file_internal(dpath, backup_path)
            if success:
                blocked_count += 1
            else:
                failed_count += 1
    
    blocked_items[folderpath] = {
        "type": "folder",
        "original_acl": original_acl,
        "backup_file": backup_path,
        "threat_info": threat_info or {},
        "timestamp": str(ctypes.windll.kernel32.GetTickCount64())
    }
    save_blocked_items(blocked_items)
    return True, f"Folder blocked successfully ({blocked_count} items, {failed_count} skipped)"


def unblock_item(filepath):
    """
    Revert an item to its original state.
    """
    filepath = os.path.abspath(filepath)
    blocked_items = load_blocked_items()
    
    if filepath not in blocked_items:
        return False, "Item not in blocked database"
    
    item = blocked_items[filepath]
    backup_file = item.get("backup_file")
    is_parent_blocked = item.get("parent_blocked", False)
    is_folder = item.get("type") == "folder"
    
    try:
        if is_parent_blocked:
            del blocked_items[filepath]
            save_blocked_items(blocked_items)
            return True, "Item removed from blocked database (parent folder remains blocked)"
        
        # Restore from backup if available
        if backup_file and os.path.exists(backup_file):
            if is_folder:
                r = _run_icacls([filepath, "/restore", backup_file, "/T"])
            else:
                r = _run_icacls([filepath, "/restore", backup_file])
        
        # Fallback cleanup
        if is_folder:
            # Walk and unblock each file individually
            for root, dirs, files in os.walk(filepath):
                for name in files:
                    _unblock_file_internal(os.path.join(root, name), backup_file)
                for name in dirs:
                    _unblock_file_internal(os.path.join(root, name), backup_file)
            _unblock_file_internal(filepath, backup_file)
        else:
            _unblock_file_internal(filepath, backup_file)
        
        del blocked_items[filepath]
        save_blocked_items(blocked_items)
        
        if backup_file and os.path.exists(backup_file):
            try:
                os.remove(backup_file)
            except:
                pass
        
        return True, "Item unblocked successfully"
        
    except Exception as e:
        return False, f"Error unblocking item: {e}"


def get_blocked_list():
    """Return list of all blocked items."""
    return load_blocked_items()


def block_code_in_file(filepath, code_snippet, threat_info=None):
    """
    Block a specific code snippet within a file.
    """
    filepath = os.path.abspath(filepath)
    blocked_items = load_blocked_items()
    
    if filepath in blocked_items:
        blocked_items[filepath]["code_block"] = code_snippet
        blocked_items[filepath]["threat_info"] = threat_info or {}
        save_blocked_items(blocked_items)
        return True, "Code block flagged in existing blocked file"
    
    parent_folder = os.path.dirname(filepath)
    if parent_folder in blocked_items:
        blocked_items[filepath] = {
            "type": "file",
            "parent_blocked": True,
            "code_block": code_snippet,
            "threat_info": threat_info or {},
            "timestamp": str(ctypes.windll.kernel32.GetTickCount64())
        }
        save_blocked_items(blocked_items)
        return True, "Code block flagged (parent folder already blocked)"
    
    if os.path.exists(filepath):
        result, msg = block_file(filepath, threat_info)
        if result:
            blocked_items = load_blocked_items()
            blocked_items[filepath]["code_block"] = code_snippet
            save_blocked_items(blocked_items)
        return result, msg
    
    return False, "File does not exist"
