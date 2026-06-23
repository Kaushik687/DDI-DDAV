"""
DDAV Threat Signatures & Indicators of Compromise (IoC) Database
Contains hashes, patterns, registry keys, and behavioral indicators
for real-world malware families and suspicious artifacts.
"""

import hashlib

# =============================================================================
# KNOWN MALWARE FILE HASHES (SHA-256) - Educational/Detection Database
# These are real or representative hashes of known malware families.
# =============================================================================
KNOWN_MALWARE_HASHES = {
    # Ransomware families
    "WannaCry": [
        "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
    ],
    # Remote Access Trojans (RATs)
    "DarkComet": [
        "c4b977da01051b0c1342d715d87d10e2a5f9b1e7f5b5e5c5d5f5e5a5b5c5d5e5f",
    ],
    # Trojans
    "Emotet": [
        "a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    ],
    # Worms
    "Conficker": [
        "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
    ],
    # Generic suspicious - these will match our test/demo files if we create them
    "Suspicious_EICAR": [
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "44d88612fea8a8f36de82e1278abb02f",
    ],
}

# =============================================================================
# MALICIOUS / SUSPICIOUS STRING PATTERNS (Signature-Based Detection)
# =============================================================================
SUSPICIOUS_STRING_PATTERNS = {
    "RAT_Indicators": [
        b"DarkComet", b"RemoteShell", b"ReverseShell", b"BackConnect",
        b"RAT_SERVER", b"KEYLOGGER", b"SCREEN_CAPTURE", b"WEBCAM_CAPTURE",
        b"recv_shell", b"send_shell", b"cmd.exe /c", b"powershell -enc",
        b"WSAConnect", b"WSASocket", b"CreateRemoteThread", b"VirtualAllocEx",
    ],
    "Ransomware_Indicators": [
        b".encrypted", b".locked", b".crypto", b"YOUR_FILES_HAVE_BEEN_ENCRYPTED",
        b"RSA PRIVATE KEY", b"AES-256", b"decrypt_instructions", b"TOR_PAYMENT",
        b"bitcoin", b"monero", b"pay_ransom", b"restore_files", b"READ_ME",
    ],
    "Spyware_Indicators": [
        b"steal_passwords", b"harvest_cookies", b"browser_history",
        b"credit_card", b"CVV", b"clipboard_monitor", b"screenshot_grab",
        b"webcam_snap", b"microphone_record", b"keylog_buffer", b"form_grab",
    ],
    "Cryptominer_Indicators": [
        b"stratum+tcp", b"stratum+ssl", b"mining_pool", b"xmrig", b"minerd",
        b"cryptonight", b"hashrate", b"wallet_address", b"cpu_miner",
        b"monero_address", b"bitcoin_mine", b"pool_url", b"worker_name",
    ],
    "Banking_Trojan_Indicators": [
        b"bank_login", b"credential_harvest", b"phish_page", b"mimikatz",
        b"lsass_dump", b"sam_dump", b"ntds_dump", b"web_inject",
        b"banking_fraud", b"card_number", b"pin_code", b"2fa_bypass",
    ],
    "Rootkit_Indicators": [
        b"SSDT_hook", b"DKOM", b"DirectKernelObjectManipulation",
        b"NtEnumerateKey", b"NtQuerySystemInformation", b"hide_process",
        b"hide_file", b"hide_registry", b"IRP_MJ_DEVICE_CONTROL",
        b"sysenter_hook", b"KiServiceTable", b"ZwQueryDirectoryFile",
    ],
    "Worm_Indicators": [
        b"autorun.inf", b"spread_network", b"worm_replicate", b"copy_to_share",
        b"net_share", b"WNetEnum", b"EnumNetworkDrives", b"mass_mail",
        b"outlook_address_book", b"smtp_server", b"self_replicate",
    ],
    "DDoS_Indicators": [
        b"HTTP_FLOOD", b"SYN_FLOOD", b"UDP_FLOOD", b"DNS_AMP",
        b"botnet_command", b"C2_SERVER", b"flood_target", b"attack_start",
        b"stress_test", b"booter", b"mirai", b"qbot",
    ],
    "Dropper_Downloader_Indicators": [
        b"URLDownloadToFile", b"WinExec", b"ShellExecute", b"CreateProcess",
        b"download_payload", b"execute_payload", b"drop_file", b"write_file",
        b"regsvr32", b"rundll32", b"msiexec", b"certutil", b"bitsadmin",
    ],
    "Packer_Encryption_Indicators": [
        b"UPX", b"ASPack", b"PECompact", b"FSG", b"MPRESS", b"Themida",
        b"VMProtect", b"Enigma", b"Armadillo", b"EXECryptor", b"Obsidium",
    ],
    "Script_Based_Malware": [
        b"IEX(New-Object Net.WebClient).downloadString",
        b"Invoke-Expression", b"Invoke-Shellcode", b"Metasploit",
        b"powercat", b"nishang", b"empire", b" cobalt_strike",
        b"Beacon", b"Stager", b"Payload_delivery", b"obfuscate",
    ],
    "Fileless_Malware_Indicators": [
        b"WScript.Shell", b"Scripting.FileSystemObject", b"Shell.Application",
        b"Win32_Process", b"Win32_ProcessStartup", b"GetObject",
        b"CreateInstance", b"WMI.ExecQuery", b"WMI.ExecMethod",
        b"mshta", b"cscript", b"wscript", b"regsvr32 /s /u /i",
    ],
    "Logic_Bomb_Indicators": [
        b"trigger_date", b"trigger_time", b"countdown_timer",
        b"if user_deleted:", b"payload_armed", b"time_check",
        b"specific_date", b"dormant_payload", b"activate_on",
    ],
    "Formjacking_Skimming": [
        b"checkout_form", b"payment_form", b"credit_card_input",
        b"cvv_input", b"skimmer_script", b"magecart", b"card_data_exfil",
        b"form_submit_intercept", b"checkout_intercept",
    ],
}

# =============================================================================
# SUSPICIOUS FILE EXTENSIONS (Often used for malware delivery)
# =============================================================================
SUSPICIOUS_EXTENSIONS = {
    "executable_dangerous": [
        ".exe", ".com", ".scr", ".pif", ".bat", ".cmd", ".sh", ".msi",
        ".vbs", ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".ps2",
        ".psc1", ".psc2", ".msp", ".mst", ".sct", ".inf", ".reg",
        ".dll", ".sys", ".drv", ".cpl", ".ocx", ".ax", ".bpl",
    ],
    "script_dangerous": [
        ".vbs", ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".ps2",
        ".bat", ".cmd", ".sh", ".py", ".rb", ".pl", ".php", ".asp",
        ".aspx", ".jsp", ".jspx", ".war", ".jar", ".ws", ".sct",
    ],
    "macro_dangerous": [
        ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm",
        ".doc", ".dot", ".xls", ".ppt", ".rtf", ".mdb", ".accdb",
    ],
    "compressed_dangerous": [
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ],
    "double_extension_trick": [
        ".pdf.exe", ".doc.exe", ".jpg.exe", ".png.exe", ".txt.exe",
        ".zip.exe", ".mp3.exe", ".mp4.exe", ".avi.exe", ".docx.exe",
    ],
}

# =============================================================================
# MALICIOUS / SUSPICIOUS REGISTRY KEYS (Persistence Mechanisms)
# =============================================================================
SUSPICIOUS_REGISTRY_KEYS = {
    "Run_Keys": [
        ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Run"),
        ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce"),
        ("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "Run"),
        ("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "RunOnce"),
        ("HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "Run WOW64"),
        ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", "RunOnceEx"),
    ],
    "Winlogon_Hooks": [
        ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Shell"),
        ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Userinit"),
        ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "Notify"),
    ],
    "Services": [
        ("HKLM\\SYSTEM\\CurrentControlSet\\Services", "ImagePath"),
    ],
    "Explorer_Hooks": [
        ("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", "Common Startup"),
        ("HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", "Startup"),
    ],
    "AppInit_DLLs": [
        ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "AppInit_DLLs"),
    ],
    "Boot_Execute": [
        ("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager", "BootExecute"),
    ],
    "Image_File_Execution_Options": [
        ("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "Debugger"),
    ],
    "File_Associations": [
        ("HKLM\\SOFTWARE\\Classes\\exefile\\shell\\open\\command", ""),
    ],
}

# =============================================================================
# SUSPICIOUS PROCESS BEHAVIORS / API CALLS
# =============================================================================
SUSPICIOUS_API_IMPORTS = {
    "Process_Manipulation": [
        "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
        "NtUnmapViewOfSection", "SetThreadContext", "ResumeThread",
        "QueueUserAPC", "NtCreateThreadEx", "RtlCreateUserThread",
    ],
    "Memory_Injection": [
        "VirtualAlloc", "VirtualProtect", "HeapAlloc", "MapViewOfFile",
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory",
    ],
    "Persistence": [
        "RegSetValueEx", "RegCreateKeyEx", "CreateService", "OpenService",
        "StartService", "WritePrivateProfileString", "WriteProfileString",
    ],
    "Network": [
        "WSASocket", "WSAConnect", "InternetOpen", "InternetConnect",
        "HttpSendRequest", "URLDownloadToFile", "WinHttpConnect",
        "socket", "connect", "send", "recv",
    ],
    "Evasion": [
        "NtSetInformationThread", "NtQueryInformationProcess", "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent", "OutputDebugString", "NtUnmapViewOfSection",
        "NtSetContextThread", "GetTickCount", "QueryPerformanceCounter",
    ],
    "Credential_Theft": [
        "LsaLogonUser", "NtLmSspLogonUser", "CredEnumerate", "CredRead",
        "CryptUnprotectData", "Decrypt", "mimikatz", "sekurlsa",
    ],
    "Keylogging": [
        "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "MapVirtualKey",
        "RegisterRawInputDevices", "GetRawInputData",
    ],
    "Screenshot": [
        "BitBlt", "GetDC", "CreateCompatibleBitmap", "GetDesktopWindow",
    ],
    "Disk_Raw_Access": [
        "CreateFile", "DeviceIoControl", "WriteFile", "SetFilePointer",
        "NtReadFile", "NtWriteFile", "\\.\\PhysicalDrive", "\\.\\Harddisk",
    ],
    "COM_Hijacking": [
        "DllRegisterServer", "DllGetClassObject", "CoCreateInstance",
        "ProgID", "CLSID",
    ],
}

# =============================================================================
# SUSPICIOUS SECTION NAMES IN PE FILES
# =============================================================================
SUSPICIOUS_PE_SECTIONS = [
    "UPX", "UPX0", "UPX1", "UPX2", "UPX!",
    "ASPack", "Aspack", ".aspack", ".adata",
    "PECompact", "PEC", ".pec", ".pec1", ".pec2",
    "FSG", ".fsg", ".fsg1", ".fsg2",
    "MPRESS", ".mpress", ".mpress1", ".mpress2",
    "Themida", ".themida", ".themida1", ".tmd",
    "VMProtect", ".vmp", ".vmp0", ".vmp1", ".vmp2",
    "Enigma", ".enigma", ".enigma1",
    "Armadillo", ".armadillo", ".arma",
    "Obsidium", ".obsidium", ".obs",
    "PACKED", ".packed", ".pack", ".pck",
    "CODE", ".code", "DATA", ".data",  # Can be suspicious if entropy is high
]

# =============================================================================
# SUSPICIOUS ENTROPES (High entropy indicates packed/encrypted data)
# =============================================================================
ENTROPY_SUSPICIOUS_THRESHOLD = 7.0  # Shannon entropy above this is suspicious
ENTROPY_HIGH_THRESHOLD = 7.5       # Very high - likely encrypted/packed

# =============================================================================
# SUSPICIOUS FILE SIZE PATTERNS
# =============================================================================
SUSPICIOUS_SIZE_PATTERNS = {
    "tiny_executable": (0, 1024),           # Very small executables
    "huge_script": (1024*1024, None),      # Scripts > 1MB
    "empty_macro": (0, 100),                # Empty macro documents
}

# =============================================================================
# KNOWN C2 DOMAINS / IP PATTERNS (Representative)
# =============================================================================
SUSPICIOUS_NETWORK_INDICATORS = [
    b"pastie.", b"pastebin.", b"gist.github.", b"raw.githubusercontent.",
    b"transfer.sh", b"file.io", b"0x0.st", b"catbox.moe",
    b"ngrok.", b"serveo.", b"localtunnel.", b"pagekite.",
    b"duckdns.", b"noip.", b"dyndns.", b"changeip.",
    b"tor2web.", b"onion.", b".onion", b"darkweb.",
    b"booter.", b"stresser.", b"ddos.", b"botnet.",
]

# =============================================================================
# SUSPICIOUS DIRECTORY LOCATIONS
# =============================================================================
SUSPICIOUS_DIRECTORIES = [
    "\\temp\\", "\\tmp\\", "\\cache\\", "\\logs\\",
    "\\appdata\\local\\temp\\", "\\windows\\temp\\",
    "\\programdata\\", "\\recycler\\", "\\system volume information\\",
    "\\startup\\", "\\start menu\\programs\\startup\\",
    "\\windows\\system32\\", "\\windows\\syswow64\\",
    "\\inetpub\\wwwroot\\", "\\xampp\\htdocs\\", "\\wamp\\www\\",
    "\\users\\public\\", "\\users\\default\\",
]

# =============================================================================
# SUSPICIOUS FILE NAME PATTERNS
# =============================================================================
SUSPICIOUS_FILENAMES = [
    "svchost", "csrss", "lsass", "services", "winlogon", "smss",
    "crss", "crss.exe", "svch0st", "scvhost", "csrsss", "lssas",
    "taskmgr", "notepad", "cmd", "powershell", "explorer",
    "update", "patch", "install", "setup", "crack", "keygen",
    "patch", "serial", "license", "activator", "loader",
    "document", "invoice", "shipping", "order", "payment",
    "scan", "copy", "important", "urgent", "notice", "alert",
]


def get_all_signatures():
    """Return all signature databases as a dictionary."""
    return {
        "malware_hashes": KNOWN_MALWARE_HASHES,
        "string_patterns": SUSPICIOUS_STRING_PATTERNS,
        "extensions": SUSPICIOUS_EXTENSIONS,
        "registry_keys": SUSPICIOUS_REGISTRY_KEYS,
        "api_imports": SUSPICIOUS_API_IMPORTS,
        "pe_sections": SUSPICIOUS_PE_SECTIONS,
        "network_indicators": SUSPICIOUS_NETWORK_INDICATORS,
        "directories": SUSPICIOUS_DIRECTORIES,
        "filenames": SUSPICIOUS_FILENAMES,
        "entropy_threshold": ENTROPY_SUSPICIOUS_THRESHOLD,
        "size_patterns": SUSPICIOUS_SIZE_PATTERNS,
    }
