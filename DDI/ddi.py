import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import os
import sys
import platform
import subprocess
import threading
import time
import json
import ctypes
from datetime import datetime, timedelta
from pathlib import Path

# System inspection modules
import psutil
import winreg

# Admin check
IS_ADMIN = ctypes.windll.shell32.IsUserAnAdmin() != 0

class DDIApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DDI - Deep Device Inspector")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Set icon - PyInstaller embeds it in the exe, so manual loading is optional
        try:
            if hasattr(sys, '_MEIPASS'):
                icon_path = os.path.join(sys._MEIPASS, "DDI Icon.ico")
            else:
                icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "DDI Icon.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass
        
        self.scanning = False
        self.suspicious_items = []
        
        self.setup_ui()
        self.show_disclaimer()
    
    def setup_ui(self):
        # Top frame with warning and status
        top_frame = tk.Frame(self.root, bg="#1a1a2e")
        top_frame.pack(fill=tk.X, padx=0, pady=0)
        
        self.warning_label = tk.Label(
            top_frame, 
            text="⚠️ Some inspections require Administrator privileges. Run as Admin for full scan.",
            bg="#1a1a2e", fg="#ffcc00", font=("Segoe UI", 10, "bold")
        )
        self.warning_label.pack(pady=5)
        if IS_ADMIN:
            self.warning_label.config(text="✅ Administrator privileges granted. Full inspection enabled.", fg="#00ff88")
        
        # Toolbar
        toolbar = tk.Frame(self.root, bg="#16213e")
        toolbar.pack(fill=tk.X, padx=0, pady=0)
        
        self.scan_btn = tk.Button(
            toolbar, text="🔍 Start Deep Inspection", command=self.start_scan,
            bg="#0f3460", fg="white", font=("Segoe UI", 11, "bold"),
            padx=20, pady=5, cursor="hand2"
        )
        self.scan_btn.pack(side=tk.LEFT, padx=10, pady=5)
        
        self.progress = ttk.Progressbar(toolbar, mode="indeterminate", length=200)
        self.progress.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.status_label = tk.Label(
            toolbar, text="Ready", bg="#16213e", fg="#e94560",
            font=("Segoe UI", 10)
        )
        self.status_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Threat count badge
        self.threat_frame = tk.Frame(toolbar, bg="#16213e")
        self.threat_frame.pack(side=tk.RIGHT, padx=10)
        self.threat_label = tk.Label(
            self.threat_frame, text="Suspicious: 0", bg="#16213e", fg="#ff4444",
            font=("Segoe UI", 10, "bold")
        )
        self.threat_label.pack()
        
        # Notebook (tabs)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background="#0f3460")
        style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[10, 5])
        style.map("TNotebook.Tab", background=[("selected", "#e94560")], foreground=[("selected", "white")])
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.overview_tab = self.create_tab("Overview")
        self.processes_tab = self.create_tab("Processes")
        self.network_tab = self.create_tab("Network")
        self.startup_tab = self.create_tab("Startup")
        self.services_tab = self.create_tab("Services")
        self.installed_tab = self.create_tab("Installed Software")
        self.files_tab = self.create_tab("File Inspector")
        self.registry_tab = self.create_tab("Registry")
        self.drivers_tab = self.create_tab("Drivers")
        self.scheduled_tab = self.create_tab("Scheduled Tasks")
        self.security_tab = self.create_tab("Security Report")
        
        # Setup each tab's content
        self.setup_overview_tab()
        self.setup_processes_tab()
        self.setup_network_tab()
        self.setup_startup_tab()
        self.setup_services_tab()
        self.setup_installed_tab()
        self.setup_files_tab()
        self.setup_registry_tab()
        self.setup_drivers_tab()
        self.setup_scheduled_tab()
        self.setup_security_tab()
        
        # Footer
        footer = tk.Frame(self.root, bg="#1a1a2e", height=25)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        footer_label = tk.Label(
            footer, text="DDI v1.0 | Deep Device Inspector | Offline Mode | No Data Stored",
            bg="#1a1a2e", fg="#888888", font=("Segoe UI", 8)
        )
        footer_label.pack(side=tk.RIGHT, padx=10)
    
    def create_tab(self, title):
        frame = tk.Frame(self.notebook, bg="#1a1a2e")
        self.notebook.add(frame, text=title)
        return frame
    
    def show_disclaimer(self):
        disclaimer = (
            "DDI - Deep Device Inspector\n\n"
            "This application does NOT store, collect, or transmit any data.\n"
            "All inspections are performed locally and in real-time.\n"
            "Data is displayed only while the app is running.\n\n"
            "Provide permission to inspect device.\n"
            "Administrator privileges are recommended for full inspection.\n\n"
            "Click OK to proceed."
        )
        messagebox.showinfo("DDI Disclaimer", disclaimer)
    
    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.scan_btn.config(state=tk.DISABLED, text="Scanning...")
        self.progress.start()
        self.suspicious_items = []
        self.update_threat_count()
        self.clear_all_displays()
        
        thread = threading.Thread(target=self.run_scan, daemon=True)
        thread.start()
    
    def clear_all_displays(self):
        for widget in [self.overview_text, self.network_text, self.files_text, 
                       self.registry_text, self.drivers_text, self.scheduled_text, self.security_text]:
            widget.config(state=tk.NORMAL)
            widget.delete(1.0, tk.END)
            widget.insert(tk.END, "Scanning...")
            widget.config(state=tk.DISABLED)
        for tree in [self.processes_tree, self.startup_tree, self.services_tree, self.installed_tree]:
            for row in tree.get_children():
                tree.delete(row)
    
    def run_scan(self):
        try:
            self.update_status("Scanning system overview...")
            self.scan_overview()
            
            self.update_status("Inspecting processes...")
            self.scan_processes()
            
            self.update_status("Analyzing network connections...")
            self.scan_network()
            
            self.update_status("Checking startup items...")
            self.scan_startup()
            
            self.update_status("Inspecting services...")
            self.scan_services()
            
            self.update_status("Listing installed software...")
            self.scan_installed()
            
            self.update_status("Scanning files...")
            self.scan_files()
            
            self.update_status("Reading registry...")
            self.scan_registry()
            
            self.update_status("Inspecting drivers...")
            self.scan_drivers()
            
            self.update_status("Checking scheduled tasks...")
            self.scan_scheduled()
            
            self.update_status("Generating security report...")
            self.generate_security_report()
            
            self.update_status("Inspection complete!")
        except Exception as e:
            self.update_status(f"Error: {str(e)}")
        finally:
            self.scanning = False
            self.root.after(0, self.scan_complete)
    
    def scan_complete(self):
        self.scan_btn.config(state=tk.NORMAL, text="🔍 Start Deep Inspection")
        self.progress.stop()
        self.update_threat_count()
        messagebox.showinfo("DDI", "Deep Inspection Complete! Check the Security Report tab.")
    
    def update_status(self, text):
        self.root.after(0, lambda: self.status_label.config(text=text))
    
    def update_threat_count(self):
        count = len(self.suspicious_items)
        self.root.after(0, lambda: self.threat_label.config(text=f"Suspicious: {count}"))
    
    def add_suspicious(self, category, name, reason, details=""):
        self.suspicious_items.append({
            "category": category,
            "name": name,
            "reason": reason,
            "details": details,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    
    def setup_copyable_text(self, parent):
        frame = tk.Frame(parent, bg="#1a1a2e")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        text = scrolledtext.ScrolledText(
            frame, wrap=tk.WORD, font=("Consolas", 10),
            bg="#1a1a2e", fg="#eeeeee", insertbackground="white"
        )
        text.pack(fill=tk.BOTH, expand=True)
        btn = tk.Button(frame, text="📋 Copy", command=lambda t=text: self.copy_text(t),
                        bg="#0f3460", fg="white", font=("Segoe UI", 9))
        btn.pack(anchor=tk.NE, padx=2, pady=2)
        return text
    
    def copy_text(self, text_widget):
        try:
            content = text_widget.get(1.0, tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            messagebox.showinfo("DDI", "Content copied to clipboard!")
        except Exception as e:
            messagebox.showerror("DDI", f"Failed to copy: {e}")
    
    # ============== OVERVIEW TAB ==============
    def setup_overview_tab(self):
        self.overview_text = self.setup_copyable_text(self.overview_tab)
        self.scan_overview()
    
    def scan_overview(self):
        info = []
        info.append("=" * 60)
        info.append("  DDI - SYSTEM OVERVIEW")
        info.append("=" * 60)
        info.append("")
        info.append(f"  Operating System: {platform.system()} {platform.release()}")
        info.append(f"  Version: {platform.version()}")
        info.append(f"  Machine: {platform.machine()}")
        info.append(f"  Processor: {platform.processor()}")
        info.append(f"  Computer Name: {platform.node()}")
        info.append(f"  Admin Privileges: {'Yes' if IS_ADMIN else 'No'}")
        info.append("")
        info.append("-" * 60)
        info.append("  CPU Information")
        info.append("-" * 60)
        info.append(f"  Physical Cores: {psutil.cpu_count(logical=False)}")
        info.append(f"  Logical Cores: {psutil.cpu_count(logical=True)}")
        cpu_freq = psutil.cpu_freq()
        info.append(f"  Current Frequency: {cpu_freq.current:.2f} MHz" if cpu_freq else "  Current Frequency: N/A")
        info.append(f"  CPU Usage: {psutil.cpu_percent()}%")
        info.append("")
        info.append("-" * 60)
        info.append("  Memory Information")
        info.append("-" * 60)
        mem = psutil.virtual_memory()
        info.append(f"  Total: {self.format_bytes(mem.total)}")
        info.append(f"  Available: {self.format_bytes(mem.available)}")
        info.append(f"  Used: {self.format_bytes(mem.used)}")
        info.append(f"  Usage: {mem.percent}%")
        info.append("")
        info.append("-" * 60)
        info.append("  Disk Information")
        info.append("-" * 60)
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                info.append(f"  {part.device} ({part.mountpoint})")
                info.append(f"    Total: {self.format_bytes(usage.total)}")
                info.append(f"    Used: {self.format_bytes(usage.used)}")
                info.append(f"    Free: {self.format_bytes(usage.free)}")
                info.append(f"    Usage: {usage.percent}%")
            except Exception:
                pass
        info.append("")
        info.append("-" * 60)
        info.append("  Boot Time")
        info.append("-" * 60)
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        info.append(f"  Boot Time: {boot_time.strftime('%Y-%m-%d %H:%M:%S')}")
        info.append(f"  Uptime: {str(uptime).split('.')[0]}")
        info.append("")
        info.append("-" * 60)
        info.append("  Users")
        info.append("-" * 60)
        for user in psutil.users():
            info.append(f"  {user.name} - Terminal: {user.terminal} - Host: {user.host}")
        info.append("")
        info.append("=" * 60)
        
        self.root.after(0, lambda: self.update_text(self.overview_text, "\n".join(info)))
    
    # ============== PROCESSES TAB ==============
    def setup_processes_tab(self):
        cols = ("PID", "Name", "User", "CPU%", "Memory", "Status", "Path", "Risk")
        tree = ttk.Treeview(self.processes_tab, columns=cols, show="headings")
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=100 if col not in ("Name", "Path", "Risk") else 200)
        tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(self.processes_tab, orient="vertical", command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)
        
        self.processes_tree = tree
    
    def scan_processes(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info', 'status', 'exe']):
            try:
                p = proc.info
                risk = "Safe"
                reasons = []
                
                # Heuristic checks
                if p['exe']:
                    exe_lower = p['exe'].lower()
                    if any(x in exe_lower for x in ['temp', 'tmp', 'appdata\\local\\temp']):
                        risk = "High"
                        reasons.append("Running from temp directory")
                    if not os.path.exists(p['exe']):
                        risk = "High"
                        reasons.append("Executable path invalid")
                
                if p['cpu_percent'] and p['cpu_percent'] > 80:
                    risk = "Medium" if risk == "Safe" else risk
                    reasons.append(f"High CPU: {p['cpu_percent']:.1f}%")
                
                if p['memory_info'] and p['memory_info'].rss > 500 * 1024 * 1024:
                    risk = "Medium" if risk == "Safe" else risk
                    reasons.append(f"High Memory: {self.format_bytes(p['memory_info'].rss)}")
                
                suspicious_names = ['keylogger', 'spy', 'stealer', 'logger', 'monitor', 'capture', 'sniff']
                if p['name'] and any(s in p['name'].lower() for s in suspicious_names):
                    risk = "High"
                    reasons.append("Suspicious name pattern")
                
                if risk != "Safe":
                    self.add_suspicious("Process", p['name'], "; ".join(reasons), p['exe'] or "")
                
                processes.append((
                    p['pid'], p['name'], p['username'] or "N/A",
                    f"{p['cpu_percent'] or 0:.1f}",
                    self.format_bytes(p['memory_info'].rss) if p['memory_info'] else "N/A",
                    p['status'], p['exe'] or "N/A", risk
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        self.root.after(0, lambda: self.update_tree(self.processes_tree, processes))
    
    # ============== NETWORK TAB ==============
    def setup_network_tab(self):
        self.network_text = self.setup_copyable_text(self.network_tab)
    
    def scan_network(self):
        info = []
        info.append("=" * 60)
        info.append("  NETWORK CONNECTIONS")
        info.append("=" * 60)
        info.append("")
        
        connections = psutil.net_connections()
        info.append(f"  Total Connections: {len(connections)}")
        info.append("")
        
        for conn in connections:
            try:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                status = conn.status
                pid = conn.pid or "N/A"
                
                risk = ""
                if conn.raddr:
                    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 12345, 31337]
                    if conn.raddr.port in suspicious_ports:
                        risk = " [SUSPICIOUS PORT]"
                        self.add_suspicious("Network", f"PID {pid}", f"Connection to suspicious port {conn.raddr.port}", laddr)
                    
                    # Check for external connections
                    if not conn.raddr.ip.startswith(('127.', '10.', '192.168.', '172.')):
                        risk = " [EXTERNAL]"
                
                info.append(f"  {conn.type} | {laddr} -> {raddr} | {status} | PID: {pid}{risk}")
            except Exception:
                pass
        
        info.append("")
        info.append("-" * 60)
        info.append("  Network Interfaces")
        info.append("-" * 60)
        
        for name, addrs in psutil.net_if_addrs().items():
            info.append(f"  {name}:")
            for addr in addrs:
                info.append(f"    {addr.family.name}: {addr.address}")
        
        info.append("")
        info.append("-" * 60)
        info.append("  Network I/O Statistics")
        info.append("-" * 60)
        io = psutil.net_io_counters()
        info.append(f"  Bytes Sent: {self.format_bytes(io.bytes_sent)}")
        info.append(f"  Bytes Received: {self.format_bytes(io.bytes_recv)}")
        info.append(f"  Packets Sent: {io.packets_sent}")
        info.append(f"  Packets Received: {io.packets_recv}")
        info.append("")
        info.append("=" * 60)
        
        self.root.after(0, lambda: self.update_text(self.network_text, "\n".join(info)))
    
    # ============== STARTUP TAB ==============
    def setup_startup_tab(self):
        frame = tk.Frame(self.startup_tab, bg="#1a1a2e")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        cols = ("Name", "Command", "Location", "Risk")
        tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=200 if col in ("Name", "Command") else 150)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)
        self.startup_tree = tree
    
    def scan_startup(self):
        items = []
        startup_locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        for hkey, path in startup_locations:
            try:
                with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            i += 1
                            risk = "Safe"
                            reasons = []
                            
                            val_lower = str(value).lower()
                            if any(x in val_lower for x in ['temp', 'tmp', 'appdata']):
                                risk = "High"
                                reasons.append("Startup from temp/AppData")
                            if not os.path.exists(str(value).split(' ')[0].strip('"')):
                                risk = "Medium"
                                reasons.append("Path may not exist")
                            
                            if risk != "Safe":
                                self.add_suspicious("Startup", name, "; ".join(reasons), str(value))
                            
                            items.append((name, str(value), path, risk))
                        except OSError:
                            break
            except Exception:
                pass
        
        # Startup folder
        startup_paths = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]
        for spath in startup_paths:
            if os.path.exists(spath):
                for f in os.listdir(spath):
                    fpath = os.path.join(spath, f)
                    risk = "Safe"
                    if f.endswith(('.exe', '.bat', '.cmd', '.vbs', '.js', '.ps1')):
                        risk = "Medium"
                        self.add_suspicious("Startup", f, "Executable/script in startup folder", fpath)
                    items.append((f, fpath, "Startup Folder", risk))
        
        self.root.after(0, lambda: self.update_tree(self.startup_tree, items))
    
    # ============== SERVICES TAB ==============
    def setup_services_tab(self):
        frame = tk.Frame(self.services_tab, bg="#1a1a2e")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        cols = ("Name", "Display Name", "Status", "Start Type", "Risk")
        tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=150)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)
        self.services_tree = tree
    
    def scan_services(self):
        services = []
        for svc in psutil.win_service_iter():
            try:
                s = svc.as_dict()
                risk = "Safe"
                
                suspicious_services = ['spy', 'keylog', 'steal', 'monitor', 'remote', 'backdoor']
                if any(x in s['name'].lower() or x in s['display_name'].lower() for x in suspicious_services):
                    risk = "High"
                    self.add_suspicious("Service", s['display_name'], "Suspicious service name", s['name'])
                
                if s['start_type'] == 'auto' and s['status'] == 'running':
                    if s['binpath'] and any(x in s['binpath'].lower() for x in ['temp', 'appdata']):
                        risk = "High"
                        self.add_suspicious("Service", s['display_name'], "Auto-running from temp", s['binpath'])
                
                services.append((s['name'], s['display_name'], s['status'], s['start_type'], risk))
            except Exception:
                pass
        
        self.root.after(0, lambda: self.update_tree(self.services_tree, services))
    
    # ============== INSTALLED SOFTWARE TAB ==============
    def setup_installed_tab(self):
        frame = tk.Frame(self.installed_tab, bg="#1a1a2e")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        cols = ("Name", "Version", "Publisher", "Install Date", "Path")
        tree = ttk.Treeview(frame, columns=cols, show="headings")
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=150 if col != "Path" else 300)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)
        self.installed_tree = tree
    
    def scan_installed(self):
        software = []
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        
        for hkey, path in registry_paths:
            try:
                with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            i += 1
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                try:
                                    name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                except:
                                    continue
                                try:
                                    version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                except:
                                    version = "N/A"
                                try:
                                    publisher = winreg.QueryValueEx(subkey, "Publisher")[0]
                                except:
                                    publisher = "N/A"
                                try:
                                    date = winreg.QueryValueEx(subkey, "InstallDate")[0]
                                except:
                                    date = "N/A"
                                try:
                                    install_path = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                                except:
                                    install_path = "N/A"
                                
                                software.append((name, version, publisher, date, install_path))
                        except OSError:
                            break
            except Exception:
                pass
        
        software = list(set(software))
        software.sort(key=lambda x: x[0])
        self.root.after(0, lambda: self.update_tree(self.installed_tree, software))
    
    # ============== FILES TAB ==============
    def setup_files_tab(self):
        self.files_text = self.setup_copyable_text(self.files_tab)
    
    def scan_files(self):
        info = []
        info.append("=" * 60)
        info.append("  FILE SYSTEM INSPECTOR")
        info.append("=" * 60)
        info.append("")
        
        # Scan temp directories
        temp_dirs = [
            os.path.expandvars("%TEMP%"),
            os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
            os.path.expandvars(r"%WINDIR%\Temp"),
        ]
        
        info.append("-" * 60)
        info.append("  TEMP DIRECTORY SCAN")
        info.append("-" * 60)
        
        suspicious_exts = ['.exe', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.scr', '.com']
        
        for temp_dir in temp_dirs:
            if os.path.exists(temp_dir):
                info.append(f"  Scanning: {temp_dir}")
                try:
                    files = os.listdir(temp_dir)
                    exe_count = sum(1 for f in files if os.path.splitext(f)[1].lower() in suspicious_exts)
                    info.append(f"    Total items: {len(files)}")
                    info.append(f"    Executables/Scripts: {exe_count}")
                    
                    for f in files[:50]:  # Limit output
                        try:
                            fpath = os.path.join(temp_dir, f)
                            ext = os.path.splitext(f)[1].lower()
                            if ext in suspicious_exts:
                                info.append(f"    ⚠️  {f}")
                                self.add_suspicious("File", f, "Executable in temp directory", fpath)
                            elif os.path.isfile(fpath) and os.path.getsize(fpath) > 10 * 1024 * 1024:
                                info.append(f"    [Large] {f} ({self.format_bytes(os.path.getsize(fpath))})")
                        except (OSError, PermissionError):
                            continue
                except Exception as e:
                    info.append(f"    Error: {e}")
                info.append("")
        
        # Scan Downloads for double extensions
        downloads = os.path.expandvars(r"%USERPROFILE%\Downloads")
        if os.path.exists(downloads):
            info.append("-" * 60)
            info.append("  DOWNLOADS SCAN (Double Extensions)")
            info.append("-" * 60)
            try:
                for f in os.listdir(downloads):
                    if f.count('.') > 1 and not f.endswith(('.tar.gz', '.tar.bz2')):
                        info.append(f"  ⚠️  {f}")
                        self.add_suspicious("File", f, "Double extension - possible masquerade", os.path.join(downloads, f))
            except (OSError, PermissionError) as e:
                info.append(f"  Access denied: {e}")
            info.append("")
        
        # Check Windows System32 for recent modifications (heuristic)
        info.append("-" * 60)
        info.append("  SYSTEM DIRECTORIES")
        info.append("-" * 60)
        sys_paths = [os.path.expandvars(r"%WINDIR%\System32")]
        for sp in sys_paths:
            if os.path.exists(sp):
                info.append(f"  {sp} - exists and accessible")
        info.append("")
        info.append("=" * 60)
        
        self.root.after(0, lambda: self.update_text(self.files_text, "\n".join(info)))
    
    # ============== REGISTRY TAB ==============
    def setup_registry_tab(self):
        self.registry_text = self.setup_copyable_text(self.registry_tab)
    
    def scan_registry(self):
        info = []
        info.append("=" * 60)
        info.append("  REGISTRY INSPECTOR")
        info.append("=" * 60)
        info.append("")
        
        # Check common suspicious keys
        suspicious_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "System Policies"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", "System Policies (LM)"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon (LM)"),
        ]
        
        for hkey, path, label in suspicious_keys:
            info.append(f"-" * 60)
            info.append(f"  {label}")
            info.append(f"-" * 60)
            try:
                with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            i += 1
                            info.append(f"    {name}: {value}")
                            
                            suspicious_vals = ['shell', 'userinit', 'notify', 'run', 'load']
                            if any(s in name.lower() for s in suspicious_vals):
                                self.add_suspicious("Registry", name, f"Suspicious registry value in {label}", f"{path}\\{name}")
                        except OSError:
                            break
            except Exception as e:
                info.append(f"    Access denied or not found: {e}")
            info.append("")
        
        info.append("=" * 60)
        self.root.after(0, lambda: self.update_text(self.registry_text, "\n".join(info)))
    
    # ============== DRIVERS TAB ==============
    def setup_drivers_tab(self):
        self.drivers_text = self.setup_copyable_text(self.drivers_tab)
    
    def scan_drivers(self):
        info = []
        info.append("=" * 60)
        info.append("  DRIVER INSPECTOR")
        info.append("=" * 60)
        info.append("")
        
        try:
            result = subprocess.run(['driverquery', '/v', '/fo', 'csv'], capture_output=True, text=True, errors='ignore', timeout=30)
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                info.append(f"  Total drivers listed: {len(lines) - 1}")
                info.append("")
                for line in lines[1:]:
                    parts = [p.strip('"') for p in line.split(',')]
                    if len(parts) >= 5:
                        name = parts[0] if parts[0] else "Unknown"
                        display_name = parts[1] if len(parts) > 1 and parts[1] else name
                        status = parts[6] if len(parts) > 6 else "Unknown"
                        state = parts[7] if len(parts) > 7 else "Unknown"
                        path = parts[8] if len(parts) > 8 else "Unknown"
                        
                        risk = ""
                        if status.lower() == 'running' and path and any(x in path.lower() for x in ['temp', 'appdata']):
                            risk = " [SUSPICIOUS PATH]"
                            self.add_suspicious("Driver", name, "Driver running from temp/user directory", path)
                        
                        info.append(f"  {display_name} ({name})")
                        info.append(f"    Status: {status} | State: {state}{risk}")
                        if path != "Unknown":
                            info.append(f"    Path: {path}")
                        info.append("")
        except subprocess.TimeoutExpired:
            info.append("  Driver query timed out (30s).")
        except Exception as e:
            info.append(f"  Error querying drivers: {e}")
        
        info.append("=" * 60)
        self.root.after(0, lambda: self.update_text(self.drivers_text, "\n".join(info)))
    
    # ============== SCHEDULED TASKS TAB ==============
    def setup_scheduled_tab(self):
        self.scheduled_text = self.setup_copyable_text(self.scheduled_tab)
    
    def scan_scheduled(self):
        info = []
        info.append("=" * 60)
        info.append("  SCHEDULED TASKS INSPECTOR")
        info.append("=" * 60)
        info.append("")
        
        try:
            result = subprocess.run(['schtasks', '/query', '/fo', 'csv', '/v'], capture_output=True, text=True, errors='ignore', timeout=30)
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                info.append(f"  Total tasks listed: {len(lines) - 1}")
                info.append("")
                for line in lines[1:]:
                    parts = [p.strip('"') for p in line.split(',')]
                    if len(parts) >= 8:
                        task_name = parts[1] if len(parts) > 1 else "Unknown"
                        task_to_run = parts[8] if len(parts) > 8 else "N/A"
                        run_as = parts[18] if len(parts) > 18 else "N/A"
                        next_run = parts[3] if len(parts) > 3 else "N/A"
                        status = parts[2] if len(parts) > 2 else "N/A"
                        
                        risk = ""
                        if task_to_run and any(x in task_to_run.lower() for x in ['temp', 'appdata', 'powershell', 'cmd.exe', 'vbs', 'js']):
                            risk = " [SUSPICIOUS]"
                            self.add_suspicious("Scheduled Task", task_name, f"Suspicious task action: {task_to_run}", task_to_run)
                        
                        if task_name != "Unknown" and task_name != "TaskName":
                            info.append(f"  {task_name}")
                            info.append(f"    Action: {task_to_run}{risk}")
                            info.append(f"    Run As: {run_as}")
                            info.append(f"    Status: {status}")
                            info.append("")
        except subprocess.TimeoutExpired:
            info.append("  Scheduled tasks query timed out (30s).")
        except Exception as e:
            info.append(f"  Error querying scheduled tasks: {e}")
        
        info.append("=" * 60)
        self.root.after(0, lambda: self.update_text(self.scheduled_text, "\n".join(info)))
    
    # ============== SECURITY REPORT TAB ==============
    def setup_security_tab(self):
        self.security_text = self.setup_copyable_text(self.security_tab)
    
    def generate_security_report(self):
        info = []
        info.append("=" * 70)
        info.append("  DDI SECURITY REPORT")
        info.append("=" * 70)
        info.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        info.append(f"  Total Suspicious Items Found: {len(self.suspicious_items)}")
        info.append("")
        
        if not self.suspicious_items:
            info.append("  ✅ No suspicious items detected during this inspection.")
            info.append("  Note: This is a heuristic scan. Always use dedicated antivirus software.")
        else:
            info.append("  ⚠️  SUSPICIOUS ITEMS DETECTED:")
            info.append("-" * 70)
            
            categories = {}
            for item in self.suspicious_items:
                cat = item['category']
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(item)
            
            for cat, items in categories.items():
                info.append(f"\n  [{cat.upper()}] - {len(items)} item(s)")
                info.append("  " + "-" * 50)
                for item in items:
                    info.append(f"    Name: {item['name']}")
                    info.append(f"    Reason: {item['reason']}")
                    if item['details']:
                        info.append(f"    Details: {item['details']}")
                    info.append("")
        
        info.append("")
        info.append("=" * 70)
        info.append("  RECOMMENDATIONS")
        info.append("=" * 70)
        info.append("  1. Review all suspicious items listed above.")
        info.append("  2. Research unknown processes online before taking action.")
        info.append("  3. Keep your operating system and applications updated.")
        info.append("  4. Use a reputable antivirus solution for real-time protection.")
        info.append("  5. DDI is an inspector, not a remover. It does not clean threats.")
        info.append("=" * 70)
        
        self.root.after(0, lambda: self.update_text(self.security_text, "\n".join(info)))
    
    # ============== HELPERS ==============
    def format_bytes(self, bytes_val):
        if bytes_val is None:
            return "N/A"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.2f} PB"
    
    def update_text(self, widget, text):
        widget.config(state=tk.NORMAL)
        widget.delete(1.0, tk.END)
        widget.insert(tk.END, text)
        widget.config(state=tk.DISABLED)
    
    def update_tree(self, tree, items):
        for row in tree.get_children():
            tree.delete(row)
        for item in items:
            tree.insert("", tk.END, values=item)


def main():
    root = tk.Tk()
    app = DDIApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
