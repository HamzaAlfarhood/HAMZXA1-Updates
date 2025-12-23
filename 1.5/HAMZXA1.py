import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox, font
from pathlib import Path
from datetime import datetime
import psutil
import sys
import time
import ctypes
import shutil
import urllib.request
import webbrowser
import winreg

# =============================================================================
#                           HAMZXA1 Security Tool
#               Version 1.5 (The Stable Build) - By Hamza Alfarhood
# =============================================================================

# =============================
#      Global Settings & Update Info
# =============================
CURRENT_VERSION = "1.5"
VERSION_URL = "https://raw.githubusercontent.com/alzyood95/HAMZXA1-Updates/main/version.txt"
UPDATE_PAGE_URL = "https://github.com/alzyood95/HAMZXA1-Updates"

LOG_FILE = Path("HAMZXA1_log.txt"  )
WSVCZ_TARGET_DIR = Path(r"C:\Windows\System32\wsvcz")
SYSTEM32_DIR = Path(r"C:\Windows\System32")
MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004

# --- GUI Colors ---
COLOR_BG="#0f172a"; COLOR_CARD="#1e293b"; COLOR_TEXT="#cbd5f5"; COLOR_TEXT_BRIGHT="#f1f5f9"
COLOR_ACCENT="#38bdf8"; COLOR_SUCCESS="#22c55e"; COLOR_WARNING="#f59e0b"; COLOR_ERROR="#ef4444"; COLOR_GRAY="#64748b"

# =============================
#      Logging & Update Functions
# =============================
def log_message(msg: str, widget: tk.Text | None = None):
    ts = datetime.now().strftime("%H:%M:%S"); line = f"[{ts}] {msg}\n"; print(line.strip())
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f: f.write(line)
    except Exception as e: print(f"Log Error: {e}")
    if widget: widget.insert(tk.END, line); widget.see(tk.END); widget.update_idletasks()

def check_for_updates(log_widget: tk.Text):
    log_message("Checking for updates...", log_widget)
    try:
        with urllib.request.urlopen(VERSION_URL, timeout=5) as response:
            latest_version = response.read().decode('utf-8').strip()
        log_message(f"Current: {CURRENT_VERSION}, Latest: {latest_version}", log_widget)
        if latest_version > CURRENT_VERSION:
            if messagebox.askyesno("Update Available", f"New version ({latest_version}) available!\nGo to download page?"):
                webbrowser.open(UPDATE_PAGE_URL)
        else: messagebox.showinfo("No Updates", "You are running the latest version.")
    except Exception as e:
        log_message(f"Update check failed: {e}", log_widget); messagebox.showerror("Update Check Failed", "Could not connect to update server.")

# =============================
#      Core Aggressive Functions (FINAL FORM)
# =============================
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def take_ownership(path: Path, log_widget: tk.Text):
    log_message(f"Taking ownership of {path.name}...", log_widget)
    os.system(f'takeown /F "{path}" /A /R /D Y > nul 2>&1')
    os.system(f'icacls "{path}" /grant Administrators:F /T /C /L /Q > nul 2>&1')

def remove_protection(path: Path):
    os.system(f'attrib -h -s -r "{path}" /S /D')

def kill_processes_using(file_path: Path, log_widget: tk.Text):
    killed = 0; f_str = str(file_path).lower()
    log_message(f"Searching for processes using '{file_path.name}'...", log_widget)
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            p_info = proc.info
            if (p_info['exe'] and p_info['exe'].lower() == f_str) or \
               (p_info['cmdline'] and any(f_str in str(c).lower() for c in p_info['cmdline'])):
                proc.kill(); killed += 1; log_message(f"KILLED: {p_info['name']} (PID: {p_info['pid']})", log_widget)
        except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        except Exception as e: log_message(f"Kill Error: {e}", log_widget)
    if killed > 0: log_message(f"Killed {killed} process(es).", log_widget)

def try_immediate_delete(path: Path, log_widget: tk.Text):
    log_message(f"Starting AGGRESSIVE delete for: {path.name}", log_widget)
    try:
        if not path.exists(): log_message("File already deleted.", log_widget); return
        take_ownership(path, log_widget); remove_protection(path)
        kill_processes_using(path, log_widget); time.sleep(0.2)
        try: os.remove(path)
        except Exception as e:
            log_message(f"os.remove failed: {e}. Trying 'del'.", log_widget); os.system(f'del /f /q "{path}"')
        if not path.exists(): log_message("SUCCESS: File deleted.", log_widget)
        else: log_message("FAILED: File still exists. Use 'Ultimate Delete'.", log_widget)
    except Exception as e: log_message(f"FATAL ERROR during delete: {e}", log_widget)

def find_and_destroy_malicious_service(threat_path: Path, log_widget: tk.Text):
    log_message(f"Hunting for service responsible for {threat_path.name}...", log_widget)
    services_key = r"SYSTEM\CurrentControlSet\Services"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_key) as hkey:
            for i in range(winreg.QueryInfoKey(hkey)[0]):
                service_name = winreg.EnumKey(hkey, i)
                try:
                    with winreg.OpenKey(hkey, service_name) as service_key:
                        image_path, _ = winreg.QueryValueEx(service_key, "ImagePath")
                        if threat_path.name in image_path:
                            log_message(f"FOUND MALICIOUS SERVICE: {service_name}", log_widget)
                            log_message(f"Service Path: {image_path}", log_widget)
                            log_message(f"Stopping service '{service_name}'...", log_widget)
                            os.system(f'sc.exe stop "{service_name}" > nul 2>&1')
                            time.sleep(1)
                            log_message(f"Deleting service '{service_name}'...", log_widget)
                            os.system(f'sc.exe delete "{service_name}" > nul 2>&1')
                            log_message(f"SUCCESS: Service '{service_name}' has been destroyed.", log_widget)
                            return
                except (FileNotFoundError, OSError): continue
    except Exception as e:
        log_message(f"Service hunt error: {e}", log_widget)
    log_message("No responsible service found. The malware might use another persistence method.", log_widget)

def clean_run_keys(threat_path: Path, log_widget: tk.Text):
    log_message(f"Searching Run keys for {threat_path.name}...", log_widget)
    run_keys = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"]
    hives = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
    for hive in hives:
        for key_path in run_keys:
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                    i = 0
                    while True:
                        try:
                            name, data, _ = winreg.EnumValue(key, i)
                            if threat_path.name in data:
                                log_message(f"FOUND Run key entry: '{name}'", log_widget)
                                winreg.DeleteValue(key, name)
                                log_message("SUCCESS: Removed Run key entry.", log_widget)
                            i += 1
                        except OSError: break
            except FileNotFoundError: continue

def schedule_ultimate_delete(path: Path, log_widget: tk.Text):
    log_message(f"Scheduling ULTIMATE delete for: {path.name}", log_widget)
    try:
        log_message("--- Stage 1: Destroying Service ---", log_widget)
        find_and_destroy_malicious_service(path, log_widget)
        log_message("--- Stage 2: Cleaning Run Keys ---", log_widget)
        clean_run_keys(path, log_widget)
        log_message("--- Stage 3: Scheduling Final Deletion ---", log_widget)
        take_ownership(path, log_widget); remove_protection(path)
        key = r"SYSTEM\CurrentControlSet\Control\Session Manager"; val = "PendingFileRenameOperations"
        formatted_path = f"\\??\\{path}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_ALL_ACCESS) as hkey:
            try: existing, _ = winreg.QueryValueEx(hkey, val)
            except FileNotFoundError: existing = []
            new_val = existing + [formatted_path, ""]
            winreg.SetValueEx(hkey, val, 0, winreg.REG_MULTI_SZ, new_val)
        log_message("SUCCESS: Final deletion scheduled for next boot via Registry.", log_widget)
    except PermissionError:
        log_message("FATAL: Permission denied. MUST run as Administrator.", log_widget)
    except Exception as e:
        log_message(f"EXCEPTION during ultimate delete: {e}", log_widget)

# =============================
#      Scanner & Cleaner Logic
# =============================
def find_wsvcz_threats():
    if not WSVCZ_TARGET_DIR.exists(): return []
    return [f for f in WSVCZ_TARGET_DIR.iterdir() if f.is_file()]

def find_system32_u_dll_threats():
    threats = [];
    if not SYSTEM32_DIR.exists(): return threats
    for f in SYSTEM32_DIR.iterdir():
        name = f.name.lower()
        if f.is_file() and name.startswith("u") and name.endswith(".dll") and name[1:-4].isdigit():
            threats.append(f)
    return threats

def list_usb_drives() -> list[Path]:
    drives = [];
    try:
        for p in psutil.disk_partitions(all=False):
            if 'removable' in p.opts.lower() and p.fstype != "":
                drives.append(Path(p.device))
    except: pass
    return drives

def clean_usb_drive(root: Path, log_widget: tk.Text):
    log_message(f"--- Cleaning USB Drive: {root} ---", log_widget)
    try:
        sysvolume_dir = next((i for i in root.iterdir() if i.is_dir() and i.name.lower() == "sysvolume"), None)
        shortcut_files = [i for i in root.iterdir() if i.is_file() and i.suffix.lower() == ".lnk"]
        data_dir = next((i for i in root.iterdir() if i.is_dir() and i.name.lower() not in ["system volume information", "sysvolume"]), None)
        if not any([sysvolume_dir, shortcut_files, data_dir]):
            log_message(f"No known patterns on {root}.", log_widget); return
        for sh in shortcut_files:
            try: remove_protection(sh); sh.unlink(); log_message(f"Deleted shortcut: {sh.name}", log_widget)
            except Exception as e: log_message(f"Failed to delete {sh.name}: {e}", log_widget)
        if sysvolume_dir:
            try: remove_protection(sysvolume_dir); shutil.rmtree(sysvolume_dir, ignore_errors=True); log_message(f"Removed folder: {sysvolume_dir.name}", log_widget)
            except Exception as e: log_message(f"Error removing {sysvolume_dir.name}: {e}", log_widget)
        if data_dir:
            log_message(f"Restoring from: {data_dir.name}", log_widget)
            for item in data_dir.iterdir():
                try: shutil.move(str(item), str(root / item.name)); remove_protection(root / item.name); log_message(f"Restored: {item.name}", log_widget)
                except Exception as e: log_message(f"Failed to restore {item.name}: {e}", log_widget)
            try: data_dir.rmdir()
            except: pass
        for item in root.iterdir():
            if item.name.lower() != "system volume information": remove_protection(item)
        log_message(f"--- Finished cleaning {root} ---", log_widget)
    except Exception as e:
        log_message(f"CRITICAL ERROR cleaning {root}: {e}", log_widget)

# =============================
#      Main GUI Application
# =============================
class HAMZXA1_App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"HAMZXA1 Security Tool v{CURRENT_VERSION}")
        self.geometry("1000x700"); self.minsize(900, 650); self.configure(bg=COLOR_BG)
        def resource_path(relative_path):
            try: base_path = sys._MEIPASS
            except Exception: base_path = os.path.abspath(".")
            return os.path.join(base_path, relative_path)
        try: self.iconbitmap(resource_path("icon.ico"))
        except Exception as e: print(f"Icon Error: {e}")
        log_message("Application started.", None)
        if not is_admin():
            self.after(100, lambda: messagebox.showerror("Admin Rights Required", "This tool MUST be run as Administrator. Please restart as Administrator."))
        self.create_main_layout()

    def create_main_layout(self):
        self.clear_window()
        self.grid_rowconfigure(0, weight=0); self.grid_rowconfigure(1, weight=1); self.grid_rowconfigure(2, weight=0); self.grid_columnconfigure(0, weight=1)
        header_frame = tk.Frame(self, bg=COLOR_BG); header_frame.grid(row=0, column=0, sticky="ew", padx=30, pady=(20, 10))
        tk.Label(header_frame, text="🛡️ HAMZXA1 Security", font=("Segoe UI Semibold", 28), fg=COLOR_ACCENT, bg=COLOR_BG).pack(side="left")
        tk.Label(header_frame, text=f"v{CURRENT_VERSION} by Hamza Alfarhood", font=("Segoe UI", 10), fg=COLOR_GRAY, bg=COLOR_BG).pack(side="left", padx=10, pady=(10,0))
        update_button = tk.Button(header_frame, text="Check for Updates", font=("Segoe UI", 9), bg=COLOR_GRAY, fg="white", relief="flat", command=lambda: check_for_updates(self.log_widget)); update_button.pack(side="right", pady=(10,0))
        
        main_frame = tk.Frame(self, bg=COLOR_BG)
        main_frame.grid(row=1, column=0, sticky="nsew", padx=30, pady=10)
        # *** THE FIX IS HERE ***
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)
        
        system_card = tk.Frame(main_frame, bg=COLOR_CARD, highlightbackground="#334155", highlightthickness=1); system_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.create_action_card(system_card, "System Scanner", "Targets 'wsvcz' and malicious System32 DLLs.", "PC", self.start_system_scan)
        usb_card = tk.Frame(main_frame, bg=COLOR_CARD, highlightbackground="#334155", highlightthickness=1); usb_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.create_action_card(usb_card, "USB Cleaner", "Cleans shortcut viruses and restores files.", "USB", self.show_usb_selection)
        log_frame = tk.Frame(self, bg=COLOR_CARD, height=200); log_frame.grid(row=2, column=0, sticky="ew", padx=30, pady=(10, 20)); log_frame.pack_propagate(False)
        tk.Label(log_frame, text="Activity Log", font=("Segoe UI Semibold", 12), fg=COLOR_TEXT, bg=COLOR_CARD).pack(anchor="nw", padx=15, pady=(10,5))
        self.log_widget = tk.Text(log_frame, bg=COLOR_CARD, fg=COLOR_GRAY, font=("Consolas", 9), relief="flat", height=1); self.log_widget.pack(fill="both", expand=True, padx=15, pady=(0,10))
        log_message(f"HAMZXA1 v{CURRENT_VERSION} initialized. Admin: {is_admin()}", self.log_widget)

    def create_action_card(self, parent, title, desc, icon_text, command):
        parent.grid_rowconfigure(0, weight=1); parent.grid_columnconfigure(0, weight=1)
        content = tk.Frame(parent, bg=COLOR_CARD); content.grid(sticky="nsew", padx=25, pady=25)
        tk.Label(content, text=icon_text, font=("Segoe UI Symbol", 48), fg=COLOR_ACCENT, bg=COLOR_CARD).pack(pady=(0,10))
        tk.Label(content, text=title, font=("Segoe UI Semibold", 18), fg=COLOR_TEXT_BRIGHT, bg=COLOR_CARD).pack()
        tk.Label(content, text=desc, font=("Segoe UI", 10), fg=COLOR_TEXT, bg=COLOR_CARD, wraplength=300).pack(pady=5)
        tk.Button(content, text=f"Launch {title}", font=("Segoe UI Semibold", 11), bg=COLOR_ACCENT, fg="black", relief="flat", padx=20, pady=8, command=command).pack(pady=(20,0))

    def clear_window(self):
        for widget in self.winfo_children(): widget.destroy()

    def show_popup_window(self, title):
        popup = tk.Toplevel(self); popup.title(title); popup.geometry("700x500"); popup.configure(bg=COLOR_BG); popup.transient(self); popup.grab_set()
        header = tk.Frame(popup, bg=COLOR_BG); header.pack(fill="x", padx=10, pady=10)
        tk.Button(header, text="← Back to Main", font=("Segoe UI", 10), bg=COLOR_GRAY, fg="white", relief="flat", command=popup.destroy).pack(side="left")
        content_frame = tk.Frame(popup, bg=COLOR_BG); content_frame.pack(fill="both", expand=True, padx=20, pady=10)
        return popup, content_frame

    def start_system_scan(self):
        log_message("--- Starting System Scan ---", self.log_widget)
        threats = find_wsvcz_threats() + find_system32_u_dll_threats()
        popup, frame = self.show_popup_window("System Scanner")
        if not threats:
            log_message("System scan complete. No threats found.", self.log_widget)
            tk.Label(frame, text="✅ System Clean", font=("Segoe UI Semibold", 24), fg=COLOR_SUCCESS, bg=COLOR_BG).pack(pady=50)
            tk.Label(frame, text="No threats found.", font=("Segoe UI", 11), fg=COLOR_TEXT, bg=COLOR_BG).pack()
            return
        log_message(f"Found {len(threats)} threat(s). Awaiting action.", self.log_widget)
        tk.Label(frame, text="⚠️ System Threats Detected", font=("Segoe UI Semibold", 22), fg=COLOR_WARNING, bg=COLOR_BG).pack(anchor="w")
        list_frame = tk.Frame(frame, bg=COLOR_CARD); list_frame.pack(fill="both", expand=True, pady=5)
        check_vars = []
        for f in threats:
            v = tk.BooleanVar(value=True); row = tk.Frame(list_frame, bg=COLOR_CARD); row.pack(fill="x", padx=10, pady=4)
            tk.Checkbutton(row, variable=v, bg=COLOR_CARD, activebackground=COLOR_CARD, selectcolor="#334155").pack(side="left")
            tk.Label(row, text=str(f), font=("Consolas", 10), fg=COLOR_TEXT_BRIGHT, bg=COLOR_CARD).pack(side="left", padx=6)
            check_vars.append((v, f))
        def on_delete_now():
            targets = [p for var, p in check_vars if var.get()]
            if not targets or not messagebox.askyesno("Confirm Deletion", f"Attempt to delete {len(targets)} file(s)? This may not work for locked files."): return
            for p in targets: try_immediate_delete(p, self.log_widget)
            popup.destroy(); messagebox.showinfo("Complete", "Deletion process finished. Check log for details.")
        def on_ultimate_delete():
            targets = [p for var, p in check_vars if var.get()]
            if not targets or not messagebox.askyesno("Confirm Ultimate Delete", f"This will perform a TRIPLE ATTACK:\n\n1. Find and DESTROY the malware's service.\n2. Clean malware's startup entries.\n3. Schedule final deletion for next boot.\n\nThis is the most powerful option. Proceed?"): return
            for p in targets: schedule_ultimate_delete(p, self.log_widget)
            popup.destroy(); messagebox.showinfo("Reboot Required", "Ultimate Delete process scheduled. Please RESTART your computer now to complete the removal.")
        buttons = tk.Frame(frame, bg=COLOR_BG); buttons.pack(fill="x", pady=(15, 0))
        tk.Button(buttons, text="🗑️ Delete Now", font=("Segoe UI Semibold", 11), bg=COLOR_ERROR, fg="white", relief="flat", padx=16, pady=6, command=on_delete_now).pack(side="left", padx=(0, 10))
        tk.Button(buttons, text="💥 Ultimate Delete (Reboot)", font=("Segoe UI Semibold", 11), bg=COLOR_ACCENT, fg="black", relief="flat", padx=16, pady=6, command=on_ultimate_delete).pack(side="left")

    def show_usb_selection(self):
        log_message("--- Starting USB Scan ---", self.log_widget)
        drives = list_usb_drives()
        popup, frame = self.show_popup_window("USB Drive Cleaner")
        if not drives:
            log_message("USB scan complete. No removable drives found.", self.log_widget)
            tk.Label(frame, text="✅ No USB Drives Found", font=("Segoe UI Semibold", 24), fg=COLOR_SUCCESS, bg=COLOR_BG).pack(pady=50)
            return
        log_message(f"Found {len(drives)} USB drive(s). Awaiting selection.", self.log_widget)
        tk.Label(frame, text="Select Drives to Clean", font=("Segoe UI Semibold", 22), fg=COLOR_ACCENT, bg=COLOR_BG).pack(anchor="w")
        check_vars = []
        for drive in drives:
            v = tk.BooleanVar(value=True)
            tk.Checkbutton(frame, text=str(drive), variable=v, font=("Segoe UI", 11), bg=COLOR_BG, fg=COLOR_TEXT, selectcolor=COLOR_CARD, activebackground=COLOR_BG, activeforeground=COLOR_TEXT_BRIGHT).pack(anchor="w", padx=10, pady=5)
            check_vars.append((v, drive))
        def on_clean():
            targets = [d for var, d in check_vars if var.get()]
            if not targets or not messagebox.askyesno("Confirm Clean", f"Proceed with cleaning {len(targets)} selected drive(s)?"): return
            clean_button.config(state="disabled", text="Cleaning...")
            def worker():
                for d in targets: clean_usb_drive(d, self.log_widget)
                self.after(100, lambda: (popup.destroy(), messagebox.showinfo("Complete", "USB cleaning finished. Check log for details.")))
            threading.Thread(target=worker, daemon=True).start()
        clean_button = tk.Button(frame, text="Clean Selected Drives", font=("Segoe UI Semibold", 11), bg=COLOR_SUCCESS, fg="white", relief="flat", padx=16, pady=6, command=on_clean)
        clean_button.pack(pady=20)

# =============================
#           MAIN
# =============================
if __name__ == "__main__":
    if not sys.platform.startswith("win"):
        print("This tool is designed for Windows only."); sys.exit(1)
    app = HAMZXA1_App()
    app.mainloop()
