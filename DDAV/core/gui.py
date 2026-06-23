"""
DDAV Main GUI Application
Professional tkinter interface for the DDAV antivirus scanner.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from pathlib import Path
import threading
import time

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from utils.admin_check import is_admin, require_admin
from utils.block_manager import (
    block_file, block_folder, block_code_in_file, unblock_item, get_blocked_list
)
from utils.reporter import (
    format_threat_details, copy_to_clipboard, download_as_txt,
    download_code_block, save_full_report
)
from core.scanner import DDAVScanner


class DDAVApp:
    """Main DDAV Application GUI."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("DDAV - Deep Device Anti Virus")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Set icon if available
        icon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "DDAV Icon.png")
        if os.path.exists(icon_path):
            try:
                self.icon = tk.PhotoImage(file=icon_path)
                self.root.iconphoto(True, self.icon)
            except Exception:
                pass
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self._configure_styles()
        
        # State variables
        self.scanner = None
        self.threats = []
        self.selected_threat = None
        self.blocked_items = {}
        
        # Build UI
        self._build_ui()
        
        # Check admin on startup
        self.root.after(100, self._check_admin)
    
    def _configure_styles(self):
        """Configure custom styles."""
        # Colors
        bg_dark = "#1a1a2e"
        bg_card = "#16213e"
        accent = "#0f3460"
        accent_light = "#e94560"
        text_light = "#eaeaea"
        text_dim = "#a0a0a0"
        
        self.style.configure("DDAV.TFrame", background=bg_dark)
        self.style.configure("Card.TFrame", background=bg_card)
        self.style.configure("DDAV.TLabel", background=bg_dark, foreground=text_light, font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", background=bg_dark, foreground=text_light, font=("Segoe UI", 18, "bold"))
        self.style.configure("Subheader.TLabel", background=bg_dark, foreground=text_dim, font=("Segoe UI", 12))
        
        self.style.configure("DDAV.TButton", font=("Segoe UI", 10, "bold"), padding=8)
        self.style.configure("Danger.TButton", background=accent_light, foreground="white", font=("Segoe UI", 10, "bold"), padding=8)
        self.style.configure("Action.TButton", background=accent, foreground="white", font=("Segoe UI", 9), padding=5)
        
        self.style.configure("DDAV.TNotebook", background=bg_dark, tabmargins=[2, 5, 2, 0])
        self.style.configure("DDAV.TNotebook.Tab", font=("Segoe UI", 10), padding=[15, 5], background=bg_card, foreground=text_dim)
        self.style.map("DDAV.TNotebook.Tab", background=[("selected", accent)], foreground=[("selected", text_light)])
        
        self.style.configure("DDAV.Horizontal.TProgressbar", background=accent_light, troughcolor=bg_card)
        
        self.bg_dark = bg_dark
        self.bg_card = bg_card
        self.accent = accent
        self.accent_light = accent_light
        self.text_light = text_light
        self.text_dim = text_dim
    
    def _build_ui(self):
        """Build the main user interface."""
        # Main container
        self.main_frame = ttk.Frame(self.root, style="DDAV.TFrame")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        self._build_header()
        
        # Content area with notebook
        self.notebook = ttk.Notebook(self.main_frame, style="DDAV.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tabs
        self._build_dashboard_tab()
        self._build_scan_tab()
        self._build_threats_tab()
        self._build_blocked_tab()
        
        # Status bar
        self._build_status_bar()
    
    def _build_header(self):
        """Build the application header."""
        header = ttk.Frame(self.main_frame, style="DDAV.TFrame")
        header.pack(fill=tk.X, padx=10, pady=10)
        
        # Logo/Title
        title_frame = ttk.Frame(header, style="DDAV.TFrame")
        title_frame.pack(side=tk.LEFT)
        
        ttk.Label(title_frame, text="DDAV", style="Header.TLabel").pack(anchor=tk.W)
        ttk.Label(title_frame, text="Deep Device Anti Virus", style="Subheader.TLabel").pack(anchor=tk.W)
        
        # Admin badge
        self.admin_badge = ttk.Label(header, text="ADMIN: CHECKING...", 
                                       font=("Segoe UI", 9, "bold"),
                                       background="#333", foreground="#999",
                                       padding=(10, 5))
        self.admin_badge.pack(side=tk.RIGHT, padx=10)
        
        # Version
        ttk.Label(header, text="v1.0.0", font=("Segoe UI", 9), 
                  background=self.bg_dark, foreground=self.text_dim).pack(side=tk.RIGHT)
    
    def _build_dashboard_tab(self):
        """Build the dashboard/overview tab."""
        self.dashboard_frame = ttk.Frame(self.notebook, style="DDAV.TFrame")
        self.notebook.add(self.dashboard_frame, text=" Dashboard ")
        
        # Welcome message
        welcome = ttk.Frame(self.dashboard_frame, style="Card.TFrame")
        welcome.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Label(welcome, text="Welcome to DDAV", 
                  font=("Segoe UI", 16, "bold"),
                  background=self.bg_card, foreground=self.text_light).pack(padx=20, pady=10, anchor=tk.W)
        
        welcome_text = (
            "DDAV provides comprehensive device security scanning using multiple detection engines:\n\n"
            "  • Signature Engine - Hash and pattern-based detection of known malware\n"
            "  • PE Analyzer - Structural analysis of Windows executables\n"
            "  • Heuristic Engine - Behavioral and pattern analysis\n"
            "  • AMSI Integration - Windows Antimalware Scan Interface\n"
            "  • Registry Scanner - Persistence mechanism detection\n"
            "  • Process Scanner - Active threat identification\n"
            "  • Startup Scanner - Autorun and persistence detection\n\n"
            "All actions require your explicit permission. DDAV does not modify or delete files without your approval.\n"
            "Use the Block feature carefully - blocked items can be reverted from the Blocked Items tab."
        )
        
        ttk.Label(welcome, text=welcome_text, 
                  font=("Segoe UI", 10),
                  background=self.bg_card, foreground=self.text_dim,
                  wraplength=800, justify=tk.LEFT).pack(padx=20, pady=10, anchor=tk.W)
        
        # Quick scan buttons
        buttons_frame = ttk.Frame(self.dashboard_frame, style="DDAV.TFrame")
        buttons_frame.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Button(buttons_frame, text="Full System Scan", 
                   command=self._start_full_scan, style="Danger.TButton").pack(side=tk.LEFT, padx=5)
        
        ttk.Button(buttons_frame, text="Quick Scan (Downloads + Desktop)", 
                   command=self._start_quick_scan, style="DDAV.TButton").pack(side=tk.LEFT, padx=5)
        
        ttk.Button(buttons_frame, text="Custom Scan", 
                   command=self._start_custom_scan, style="DDAV.TButton").pack(side=tk.LEFT, padx=5)
        
        # Stats cards
        stats_frame = ttk.Frame(self.dashboard_frame, style="DDAV.TFrame")
        stats_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.stat_total_files = self._create_stat_card(stats_frame, "Files Scanned", "0")
        self.stat_threats = self._create_stat_card(stats_frame, "Threats Found", "0")
        self.stat_blocked = self._create_stat_card(stats_frame, "Blocked Items", "0")
        self.stat_last_scan = self._create_stat_card(stats_frame, "Last Scan", "Never")
        
        self.stat_total_files.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.stat_threats.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.stat_blocked.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.stat_last_scan.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
    
    def _create_stat_card(self, parent, label, value):
        """Create a statistics card. Returns the value label for updates."""
        card = tk.Frame(parent, bg=self.bg_card, padx=20, pady=15)
        
        tk.Label(card, text=label, bg=self.bg_card, fg=self.text_dim,
                 font=("Segoe UI", 10)).pack(anchor=tk.W)
        value_label = tk.Label(card, text=value, bg=self.bg_card, fg=self.text_light,
                 font=("Segoe UI", 20, "bold"))
        value_label.pack(anchor=tk.W, pady=5)
        
        return value_label
    
    def _build_scan_tab(self):
        """Build the scan progress tab."""
        self.scan_frame = ttk.Frame(self.notebook, style="DDAV.TFrame")
        self.notebook.add(self.scan_frame, text=" Scan Progress ")
        
        # Progress section
        progress_frame = ttk.Frame(self.scan_frame, style="Card.TFrame")
        progress_frame.pack(fill=tk.X, padx=20, pady=20)
        
        self.scan_status_label = tk.Label(progress_frame, text="Ready to scan",
                                           bg=self.bg_card, fg=self.text_light,
                                           font=("Segoe UI", 12, "bold"))
        self.scan_status_label.pack(padx=20, pady=10, anchor=tk.W)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate',
                                             length=800, style="DDAV.Horizontal.TProgressbar")
        self.progress_bar.pack(padx=20, pady=5, fill=tk.X)
        
        self.progress_text = tk.Label(progress_frame, text="0 / 0 files",
                                      bg=self.bg_card, fg=self.text_dim,
                                      font=("Segoe UI", 9))
        self.progress_text.pack(padx=20, pady=5, anchor=tk.W)
        
        # Buttons
        btn_frame = ttk.Frame(self.scan_frame, style="DDAV.TFrame")
        btn_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.btn_start_scan = ttk.Button(btn_frame, text="Start Scan", 
                                          command=self._start_full_scan, style="Danger.TButton")
        self.btn_start_scan.pack(side=tk.LEFT, padx=5)
        
        self.btn_cancel_scan = ttk.Button(btn_frame, text="Cancel Scan", 
                                           command=self._cancel_scan, state=tk.DISABLED)
        self.btn_cancel_scan.pack(side=tk.LEFT, padx=5)
        
        # Log output
        log_frame = ttk.Frame(self.scan_frame, style="Card.TFrame")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(log_frame, text="Scan Log", bg=self.bg_card, fg=self.text_light,
                 font=("Segoe UI", 11, "bold")).pack(padx=10, pady=5, anchor=tk.W)
        
        self.scan_log = scrolledtext.ScrolledText(log_frame, bg="#0d1117", fg="#c9d1d9",
                                                   font=("Consolas", 9), wrap=tk.WORD,
                                                   padx=10, pady=10)
        self.scan_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.scan_log.insert(tk.END, "DDAV initialized. Ready to scan.\n")
        self.scan_log.config(state=tk.DISABLED)
    
    def _build_threats_tab(self):
        """Build the threats list and details tab."""
        self.threats_frame = ttk.Frame(self.notebook, style="DDAV.TFrame")
        self.notebook.add(self.threats_frame, text=" Threats ")
        
        # Paned window for split view
        paned = tk.PanedWindow(self.threats_frame, orient=tk.HORIZONTAL, 
                               bg=self.bg_dark, sashwidth=4, sashpad=2)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left: Threat list
        left_frame = tk.Frame(paned, bg=self.bg_dark)
        paned.add(left_frame, minsize=350)
        
        tk.Label(left_frame, text="Detected Threats", bg=self.bg_dark, fg=self.text_light,
                 font=("Segoe UI", 12, "bold")).pack(padx=5, pady=5, anchor=tk.W)
        
        # Threat listbox with scrollbar
        list_frame = tk.Frame(left_frame, bg=self.bg_dark)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.threat_listbox = tk.Listbox(list_frame, bg=self.bg_card, fg=self.text_light,
                                          font=("Segoe UI", 10), selectmode=tk.SINGLE,
                                          yscrollcommand=scrollbar.set, activestyle="none",
                                          selectbackground=self.accent_light, selectforeground="white")
        self.threat_listbox.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.threat_listbox.yview)
        
        self.threat_listbox.bind("<<ListboxSelect>>", self._on_threat_select)
        
        # Right: Threat details
        right_frame = tk.Frame(paned, bg=self.bg_dark)
        paned.add(right_frame, minsize=500)
        
        # Threat details text
        tk.Label(right_frame, text="Threat Details", bg=self.bg_dark, fg=self.text_light,
                 font=("Segoe UI", 12, "bold")).pack(padx=5, pady=5, anchor=tk.W)
        
        self.threat_details = scrolledtext.ScrolledText(right_frame, bg=self.bg_card, fg=self.text_light,
                                                         font=("Segoe UI", 9), wrap=tk.WORD,
                                                         padx=10, pady=10)
        self.threat_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.threat_details.insert(tk.END, "Select a threat from the list to view details.")
        self.threat_details.config(state=tk.DISABLED)
        
        # Action buttons
        action_frame = tk.Frame(right_frame, bg=self.bg_dark)
        action_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.btn_copy = tk.Button(action_frame, text="Copy Details", bg=self.accent, fg="white",
                                   font=("Segoe UI", 9), command=self._copy_threat_details,
                                   state=tk.DISABLED)
        self.btn_copy.pack(side=tk.LEFT, padx=2)
        
        self.btn_download = tk.Button(action_frame, text="Download Report", bg=self.accent, fg="white",
                                         font=("Segoe UI", 9), command=self._download_threat_report,
                                         state=tk.DISABLED)
        self.btn_download.pack(side=tk.LEFT, padx=2)
        
        self.btn_view_code = tk.Button(action_frame, text="View Code Block", bg=self.accent, fg="white",
                                        font=("Segoe UI", 9), command=self._view_code_block,
                                        state=tk.DISABLED)
        self.btn_view_code.pack(side=tk.LEFT, padx=2)
        
        self.btn_block_code = tk.Button(action_frame, text="Block Code [Careful]", bg="#8B0000", fg="white",
                                           font=("Segoe UI", 9, "bold"), command=self._block_code,
                                           state=tk.DISABLED)
        self.btn_block_code.pack(side=tk.LEFT, padx=2)
        
        self.btn_block_file = tk.Button(action_frame, text="Block File [Careful]", bg="#8B0000", fg="white",
                                           font=("Segoe UI", 9, "bold"), command=self._block_file,
                                           state=tk.DISABLED)
        self.btn_block_file.pack(side=tk.LEFT, padx=2)
        
        self.btn_block_folder = tk.Button(action_frame, text="Block Folder [Careful]", bg="#8B0000", fg="white",
                                             font=("Segoe UI", 9, "bold"), command=self._block_folder,
                                             state=tk.DISABLED)
        self.btn_block_folder.pack(side=tk.LEFT, padx=2)
        
        self.btn_leave = tk.Button(action_frame, text="Leave As Is", bg="#555", fg="white",
                                    font=("Segoe UI", 9), command=self._leave_as_is,
                                    state=tk.DISABLED)
        self.btn_leave.pack(side=tk.LEFT, padx=2)
    
    def _build_blocked_tab(self):
        """Build the blocked items management tab."""
        self.blocked_frame = ttk.Frame(self.notebook, style="DDAV.TFrame")
        self.notebook.add(self.blocked_frame, text=" Blocked Items ")
        
        # Info label
        tk.Label(self.blocked_frame, 
                 text="Blocked items have been restricted using Windows permissions. You can revert them to their original state.",
                 bg=self.bg_dark, fg=self.text_dim, font=("Segoe UI", 10), wraplength=800,
                 justify=tk.LEFT).pack(padx=20, pady=10, anchor=tk.W)
        
        # Blocked list
        list_frame = tk.Frame(self.blocked_frame, bg=self.bg_dark)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.blocked_listbox = tk.Listbox(list_frame, bg=self.bg_card, fg=self.text_light,
                                           font=("Segoe UI", 10), selectmode=tk.SINGLE,
                                           yscrollcommand=scrollbar.set, activestyle="none",
                                           selectbackground=self.accent_light, selectforeground="white")
        self.blocked_listbox.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.blocked_listbox.yview)
        
        # Buttons
        btn_frame = tk.Frame(self.blocked_frame, bg=self.bg_dark)
        btn_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.btn_unblock = tk.Button(btn_frame, text="Revert Selected Item", bg=self.accent, fg="white",
                                      font=("Segoe UI", 10, "bold"), command=self._unblock_selected)
        self.btn_unblock.pack(side=tk.LEFT, padx=5)
        
        self.btn_refresh_blocked = tk.Button(btn_frame, text="Refresh List", bg=self.accent, fg="white",
                                              font=("Segoe UI", 10), command=self._refresh_blocked_list)
        self.btn_refresh_blocked.pack(side=tk.LEFT, padx=5)
        
        # Details
        self.blocked_details = scrolledtext.ScrolledText(self.blocked_frame, bg=self.bg_card, fg=self.text_light,
                                                        font=("Segoe UI", 9), wrap=tk.WORD,
                                                        padx=10, pady=10, height=8)
        self.blocked_details.pack(fill=tk.X, padx=20, pady=10)
        self.blocked_details.insert(tk.END, "Select a blocked item to view details. Reverting restores original permissions.")
        self.blocked_details.config(state=tk.DISABLED)
    
    def _build_status_bar(self):
        """Build the status bar at the bottom."""
        self.status_bar = tk.Label(self.main_frame, text="Ready",
                                    bg=self.bg_card, fg=self.text_dim,
                                    font=("Segoe UI", 9), anchor=tk.W, padx=10, pady=5)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
    
    # ==================== ACTIONS ====================
    
    def _check_admin(self):
        """Check admin privileges and update badge."""
        if is_admin():
            self.admin_badge.config(text="ADMIN: GRANTED", background="#2d5a27", foreground="#90EE90")
            self._log("Administrator privileges confirmed.")
        else:
            self.admin_badge.config(text="ADMIN: REQUIRED", background="#5a2727", foreground="#FF6B6B")
            self._log("WARNING: Administrator privileges not detected. Some features may not work.")
            messagebox.showwarning("DDAV - Permission Required",
                                    "Please run DDAV as Administrator for full functionality.\n\n"
                                    "Right-click the launcher and select 'Run as administrator'.")
    
    def _log(self, message):
        """Add a message to the scan log (thread-safe)."""
        def _do_log():
            if hasattr(self, 'scan_log'):
                self.scan_log.config(state=tk.NORMAL)
                self.scan_log.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
                self.scan_log.see(tk.END)
                self.scan_log.config(state=tk.DISABLED)
        if self.root:
            self.root.after(0, _do_log)
        else:
            _do_log()
    
    def _update_progress(self, current, total, message=""):
        """Update progress bar from scanner callback (thread-safe)."""
        def _do_update():
            if self.root and self.progress_bar:
                pct = (current / total * 100) if total > 0 else 0
                self.progress_bar.config(value=pct)
                self.progress_text.config(text=f"{current} / {total} files - {message}")
                self.root.update_idletasks()
        if self.root:
            self.root.after(0, _do_update)
        else:
            _do_update()
    
    def _start_full_scan(self):
        """Start a full system scan."""
        if self.scanner and self.scanner.scanning:
            messagebox.showinfo("Scan in Progress", "A scan is already running.")
            return
        
        self.notebook.select(self.scan_frame)
        self._clear_scan_log()
        self._log("Starting Full System Scan...")
        
        self.progress_bar.config(value=0)
        self.btn_start_scan.config(state=tk.DISABLED)
        self.btn_cancel_scan.config(state=tk.NORMAL)
        self.scan_status_label.config(text="Scanning in progress...")
        
        self.scanner = DDAVScanner(
            progress_callback=self._update_progress,
            log_callback=self._log
        )
        
        # Run scan in thread
        thread = threading.Thread(target=self._run_scan, args=(None,))
        thread.daemon = True
        thread.start()
    
    def _start_quick_scan(self):
        """Start a quick scan of common directories."""
        user_profile = os.environ.get("USERPROFILE", "")
        target_dirs = []
        if user_profile:
            target_dirs.extend([
                os.path.join(user_profile, "Downloads"),
                os.path.join(user_profile, "Desktop"),
                os.path.join(user_profile, "Documents"),
            ])
        
        self._start_scan_with_dirs(target_dirs, "Quick Scan")
    
    def _start_custom_scan(self):
        """Start a custom scan of user-selected directory."""
        directory = filedialog.askdirectory(title="Select Directory to Scan")
        if directory:
            self._start_scan_with_dirs([directory], "Custom Scan")
    
    def _start_scan_with_dirs(self, dirs, scan_name):
        """Start scan with specific directories."""
        if self.scanner and self.scanner.scanning:
            messagebox.showinfo("Scan in Progress", "A scan is already running.")
            return
        
        dirs = [d for d in dirs if os.path.exists(d)]
        if not dirs:
            messagebox.showwarning("No Valid Directories", "No valid directories selected for scanning.")
            return
        
        self.notebook.select(self.scan_frame)
        self._clear_scan_log()
        self._log(f"Starting {scan_name}...")
        
        self.progress_bar.config(value=0)
        self.btn_start_scan.config(state=tk.DISABLED)
        self.btn_cancel_scan.config(state=tk.NORMAL)
        self.scan_status_label.config(text=f"{scan_name} in progress...")
        
        self.scanner = DDAVScanner(
            progress_callback=self._update_progress,
            log_callback=self._log
        )
        
        thread = threading.Thread(target=self._run_scan, args=(dirs,))
        thread.daemon = True
        thread.start()
    
    def _run_scan(self, target_dirs):
        """Run the scan in a thread."""
        try:
            threats = self.scanner.full_system_scan(target_dirs)
            
            # Update UI after scan
            self.root.after(0, self._scan_complete, threats)
        except Exception as e:
            self.root.after(0, self._scan_error, str(e))
    
    def _scan_complete(self, threats):
        """Handle scan completion."""
        self.threats = threats
        
        self.btn_start_scan.config(state=tk.NORMAL)
        self.btn_cancel_scan.config(state=tk.DISABLED)
        self.scan_status_label.config(text=f"Scan Complete - {len(threats)} threats found")
        self.progress_bar.config(value=100)
        
        self._log(f"Scan complete. {len(threats)} threats detected.")
        
        # Update stats
        if self.scanner:
            self.stat_total_files.config(text=str(self.scanner.stats.get("total_files", 0)))
            self.stat_threats.config(text=str(len(threats)))
            self.stat_last_scan.config(text=time.strftime("%Y-%m-%d %H:%M"))
        
        # Update threat list
        self._update_threat_list()
        
        # Save full report
        if self.scanner and threats:
            try:
                report_path = save_full_report(threats, self.scanner.stats)
                self._log(f"Full report saved to: {report_path}")
            except Exception as e:
                self._log(f"Could not save full report: {e}")
        
        if threats:
            self.notebook.select(self.threats_frame)
            messagebox.showwarning("DDAV - Threats Detected",
                                    f"Scan complete. {len(threats)} potential threat(s) detected.\n\n"
                                    f"Please review the Threats tab for details.")
        else:
            messagebox.showinfo("DDAV - Scan Complete",
                                 "Scan complete. No threats were detected.\n\n"
                                 "Your system appears clean.")
    
    def _scan_error(self, error):
        """Handle scan error."""
        self.btn_start_scan.config(state=tk.NORMAL)
        self.btn_cancel_scan.config(state=tk.DISABLED)
        self.scan_status_label.config(text="Scan Error")
        self._log(f"SCAN ERROR: {error}")
        messagebox.showerror("DDAV - Scan Error", f"An error occurred during scanning:\n{error}")
    
    def _cancel_scan(self):
        """Cancel the current scan."""
        if self.scanner:
            self.scanner.cancel_scan()
            self._log("Scan cancellation requested...")
            self.btn_cancel_scan.config(state=tk.DISABLED)
    
    def _clear_scan_log(self):
        """Clear the scan log."""
        self.scan_log.config(state=tk.NORMAL)
        self.scan_log.delete(1.0, tk.END)
        self.scan_log.config(state=tk.DISABLED)
    
    def _update_threat_list(self):
        """Update the threat listbox."""
        self.threat_listbox.delete(0, tk.END)
        
        for i, threat in enumerate(self.threats):
            severity = threat.get("severity", "UNKNOWN")
            name = threat.get("threat_name", "Unknown")
            filename = threat.get("filename", "Unknown")
            display = f"[{severity}] {filename} - {name[:50]}"
            self.threat_listbox.insert(tk.END, display)
            
            # Color code based on severity
            if severity == "CRITICAL":
                self.threat_listbox.itemconfig(i, {"fg": "#ff4444"})
            elif severity == "HIGH":
                self.threat_listbox.itemconfig(i, {"fg": "#ff8844"})
            elif severity == "MEDIUM":
                self.threat_listbox.itemconfig(i, {"fg": "#ffaa44"})
            else:
                self.threat_listbox.itemconfig(i, {"fg": "#ffdd44"})
    
    def _on_threat_select(self, event):
        """Handle threat selection."""
        selection = self.threat_listbox.curselection()
        if not selection:
            return
        
        index = selection[0]
        if index < len(self.threats):
            self.selected_threat = self.threats[index]
            self._display_threat_details(self.selected_threat)
            self._enable_action_buttons(True)
    
    def _display_threat_details(self, threat):
        """Display threat details in the text widget."""
        self.threat_details.config(state=tk.NORMAL)
        self.threat_details.delete(1.0, tk.END)
        
        text = format_threat_details(threat, mode="full")
        self.threat_details.insert(tk.END, text)
        self.threat_details.config(state=tk.DISABLED)
    
    def _enable_action_buttons(self, enabled):
        """Enable or disable action buttons."""
        state = tk.NORMAL if enabled else tk.DISABLED
        for btn in [self.btn_copy, self.btn_download, self.btn_view_code,
                     self.btn_block_code, self.btn_block_file, self.btn_block_folder, self.btn_leave]:
            btn.config(state=state)
    
    def _copy_threat_details(self):
        """Copy threat details to clipboard."""
        if not self.selected_threat:
            return
        
        text = format_threat_details(self.selected_threat, mode="full")
        if copy_to_clipboard(text, self.root):
            messagebox.showinfo("Copied", "Threat details copied to clipboard.")
        else:
            messagebox.showwarning("Copy Failed", "Could not copy to clipboard.")
    
    def _download_threat_report(self):
        """Download threat report as .txt."""
        if not self.selected_threat:
            return
        
        success, result = download_as_txt(self.selected_threat, mode="full")
        if success:
            messagebox.showinfo("Report Saved", f"Report saved to:\n{result}")
        else:
            messagebox.showwarning("Save Failed", f"Could not save report: {result}")
    
    def _view_code_block(self):
        """View the suspicious code block."""
        if not self.selected_threat:
            return
        
        code = self.selected_threat.get("code_block")
        if not code:
            messagebox.showinfo("No Code Block", "No suspicious code block was extracted for this threat.")
            return
        
        # Open new window with code
        window = tk.Toplevel(self.root)
        window.title(f"Code Block - {self.selected_threat.get('filename', 'Unknown')}")
        window.geometry("800x600")
        window.configure(bg=self.bg_dark)
        
        text = scrolledtext.ScrolledText(window, bg=self.bg_card, fg="#e94560",
                                          font=("Consolas", 10), wrap=tk.WORD,
                                          padx=10, pady=10)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, code)
        text.config(state=tk.DISABLED)
        
        btn_frame = tk.Frame(window, bg=self.bg_dark)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(btn_frame, text="Copy Code", bg=self.accent, fg="white",
                  command=lambda: copy_to_clipboard(code, window)).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Download Code", bg=self.accent, fg="white",
                  command=lambda: download_code_block(self.selected_threat)).pack(side=tk.LEFT, padx=5)
    
    def _confirm_careful_action(self, action_name):
        """Double confirmation for careful actions."""
        # First permission
        result1 = messagebox.askyesno("Permission Required",
                                      f"You are about to {action_name}.\n\n"
                                      f"This will modify file permissions on your system.\n\n"
                                      f"Do you want to proceed?",
                                      icon="warning")
        if not result1:
            return False
        
        # Second confirmation
        result2 = messagebox.askyesno("Confirm Action",
                                      f"FINAL CONFIRMATION:\n\n"
                                      f"Are you ABSOLUTELY SURE you want to {action_name}?\n\n"
                                      f"This action can be reverted from the Blocked Items tab.",
                                      icon="warning")
        return result2
    
    def _block_code(self):
        """Block the dangerous code in the selected file."""
        if not self.selected_threat:
            return
        
        filepath = self.selected_threat.get("file_path", "")
        code_block = self.selected_threat.get("code_block", "")
        
        if not self._confirm_careful_action("BLOCK the suspicious code in this file"):
            return
        
        success, msg = block_code_in_file(filepath, code_block, self.selected_threat)
        if success:
            messagebox.showinfo("Code Blocked", msg)
            self._refresh_blocked_list()
        else:
            messagebox.showerror("Block Failed", msg)
    
    def _block_file(self):
        """Block the entire file."""
        if not self.selected_threat:
            return
        
        filepath = self.selected_threat.get("file_path", "")
        
        if not self._confirm_careful_action("BLOCK the entire file"):
            return
        
        success, msg = block_file(filepath, self.selected_threat)
        if success:
            messagebox.showinfo("File Blocked", msg)
            self._refresh_blocked_list()
        else:
            messagebox.showerror("Block Failed", msg)
    
    def _block_folder(self):
        """Block the entire folder."""
        if not self.selected_threat:
            return
        
        folder = self.selected_threat.get("folder", "")
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning("No Folder", "Could not determine the folder path for this threat.")
            return
        
        if not self._confirm_careful_action("BLOCK the entire folder"):
            return
        
        success, msg = block_folder(folder, self.selected_threat)
        if success:
            messagebox.showinfo("Folder Blocked", msg)
            self._refresh_blocked_list()
        else:
            messagebox.showerror("Block Failed", msg)
    
    def _leave_as_is(self):
        """Close options without action."""
        self._enable_action_buttons(False)
        self.threat_listbox.selection_clear(0, tk.END)
        self.threat_details.config(state=tk.NORMAL)
        self.threat_details.delete(1.0, tk.END)
        self.threat_details.insert(tk.END, "Select a threat from the list to view details.")
        self.threat_details.config(state=tk.DISABLED)
    
    def _refresh_blocked_list(self):
        """Refresh the blocked items list."""
        self.blocked_listbox.delete(0, tk.END)
        
        blocked = get_blocked_list()
        self.blocked_items = blocked
        
        self.stat_blocked.config(text=str(len(blocked)))
        
        for path, info in blocked.items():
            item_type = info.get("type", "unknown")
            display = f"[{item_type.upper()}] {os.path.basename(path)}"
            self.blocked_listbox.insert(tk.END, display)
        
        self.blocked_details.config(state=tk.NORMAL)
        self.blocked_details.delete(1.0, tk.END)
        if blocked:
            self.blocked_details.insert(tk.END, f"{len(blocked)} item(s) currently blocked. Select an item to revert.")
        else:
            self.blocked_details.insert(tk.END, "No items are currently blocked. Blocked items will appear here.")
        self.blocked_details.config(state=tk.DISABLED)
    
    def _unblock_selected(self):
        """Revert the selected blocked item."""
        selection = self.blocked_listbox.curselection()
        if not selection:
            messagebox.showinfo("Select Item", "Please select a blocked item to revert.")
            return
        
        index = selection[0]
        paths = list(self.blocked_items.keys())
        if index >= len(paths):
            return
        
        filepath = paths[index]
        
        result = messagebox.askyesno("Confirm Revert",
                                      f"Are you sure you want to revert permissions for:\n\n"
                                      f"{filepath}\n\n"
                                      f"This will restore the original access permissions.",
                                      icon="question")
        if not result:
            return
        
        success, msg = unblock_item(filepath)
        if success:
            messagebox.showinfo("Reverted", msg)
            self._refresh_blocked_list()
        else:
            messagebox.showerror("Revert Failed", msg)


def run_app():
    """Entry point to run the DDAV GUI application."""
    root = tk.Tk()
    app = DDAVApp(root)
    root.mainloop()
