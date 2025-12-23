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
#           Version 2.0 (The Unified & Complete Edition) - By Hamza Alfarhood
# =============================================================================

# =============================
#      Global Settings & Update Info
# =============================
CURRENT_VERSION = "2.0"
VERSION_URL = "https://pastebin.com/raw/H1GHRfLX"
UPDATE_PAGE_URL = "https://github.com/alzyood95/HAMZXA1-Updates"

LOG_FILE = Path("HAMZXA1_log.txt" )
SYSTEM32_DIR = Path(r"C:\Windows\System32")

# --- GUI Colors ---
COLOR_BG="#0f172a"; COLOR_CARD="#1e293b"; COLOR_CARD_LIGHT="#334155"; COLOR_TEXT="#cbd5f5"
COLOR_TEXT_BRIGHT="#f1f5f9"; COLOR_ACCENT="#38bdf8"; COLOR_SUCCESS="#22c55e"
COLOR_WARNING="#f59e0b"; COLOR_ERROR="#ef4444"; COLOR_GRAY="#64748b"

# =============================
#      .icon
# =============================


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS   # لما يكون EXE
    except Exception:
        base_path = os.path.abspath(".")  # لما يكون .py
    return os.path.join(base_path, relative_path)

# =============================
#      Logging & Core Functions
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
        log_message(f"Current: {CURRENT_VERSION}, Latest from server: {latest_version}", log_widget)
        if latest_version > CURRENT_VERSION:
            if messagebox.askyesno("Update Available", f"A new version ({latest_version}) is available!\n\nWould you like to go to the download page now?"):
                webbrowser.open(UPDATE_PAGE_URL)
        else:
            messagebox.showinfo("No Updates", "You are currently running the latest version.")
    except Exception as e:
        log_message(f"Update check failed: {e}", log_widget)
        messagebox.showerror("Update Check Failed", "Could not connect to the update server.")

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def take_ownership(path: Path, log_widget: tk.Text):
    log_message(f"Taking ownership of {path.name}...", log_widget)
    os.system(f'takeown /F "{path}" /A /R /D Y > nul 2>&1')
    os.system(f'icacls "{path}" /grant Administrators:F /T /C /L /Q > nul 2>&1')

def remove_protection(path: Path, log_widget: tk.Text):
    """Strips a file of its 'hidden', 'system', and 'read-only' attributes."""
    log_message(f"Stripping protection attributes from {path.name}...", log_widget)
    os.system(f'attrib -h -s -r "{path}" /S /D')

def kill_processes_holding_file(file_path: Path, log_widget: tk.Text):
    """
    Terminates processes that are either the target executable or have the target
    file (e.g., a DLL) loaded into their memory space. This is CRITICAL for DLL removal.
    """
    killed_count = 0
    target_path_str = str(file_path.resolve()).lower()
    log_message(f"Executing multi-wave hunt for processes holding file: '{file_path.name}'...", log_widget)
    
    for attempt in range(3): # Multi-wave kill for resilience
        killed_in_wave = 0
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                # 1. Check if the process is the target executable itself
                if proc.info['exe'] and str(Path(proc.info['exe']).resolve()).lower() == target_path_str:
                    proc.kill()
                    killed_in_wave += 1
                    log_message(f"WAVE {attempt+1}: KILLED target EXE process {proc.info['name']} (PID: {proc.info['pid']})", log_widget)
                    continue
                
                # 2. Check if the process has the file loaded (for DLLs)
                # Note: memory_maps requires admin privileges, which we assume we have.
                for item in proc.memory_maps(grouped=True):
                    if item.path and str(Path(item.path).resolve()).lower() == target_path_str:
                        proc.kill()
                        killed_in_wave += 1
                        log_message(f"WAVE {attempt+1}: KILLED process {proc.info['name']} holding DLL (PID: {proc.info['pid']})", log_widget)
                        break # Move to the next process after killing
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                # Log other exceptions but continue the hunt
                log_message(f"Error during process check for PID {proc.info['pid']}: {e}", log_widget)
                continue
                
        if killed_in_wave > 0:
            killed_count += killed_in_wave
            log_message(f"Wave {attempt+1} complete. Eliminated {killed_in_wave} process(es).", log_widget)
            time.sleep(0.5) # Pause to see if it respawns
        else:
            log_message(f"Wave {attempt+1}: No active processes found holding the file.", log_widget)
            break # No need for more attempts if none were found
            
    if killed_count > 0: log_message(f"Total eliminated processes: {killed_count}.", log_widget)

# =============================
#      The Instant Annihilator Toolkit
# =============================
def find_and_destroy_malicious_service(threat_name: str, log_widget: tk.Text):
    log_message(f"Hunting for service responsible for {threat_name}...", log_widget)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") as hkey:
            for i in range(winreg.QueryInfoKey(hkey)[0]):
                service_name = winreg.EnumKey(hkey, i)
                try:
                    with winreg.OpenKey(hkey, service_name) as service_key:
                        image_path, _ = winreg.QueryValueEx(service_key, "ImagePath")
                        if threat_name in image_path:
                            log_message(f"FOUND MALICIOUS SERVICE: {service_name}", log_widget)
                            os.system(f'sc.exe stop "{service_name}" > nul 2>&1'); time.sleep(1)
                            os.system(f'sc.exe delete "{service_name}" > nul 2>&1')
                            log_message(f"SUCCESS: Service '{service_name}' destroyed.", log_widget)
                except (FileNotFoundError, OSError): continue
    except Exception as e: log_message(f"Service hunt error: {e}", log_widget)

def destroy_malicious_scheduled_tasks(threat_name: str, log_widget: tk.Text):
    log_message(f"Hunting for scheduled tasks for {threat_name}...", log_widget)
    task_file = SYSTEM32_DIR / "Tasks" / threat_name.replace('.exe', '')
    if task_file.exists():
        log_message(f"Found malicious task definition file: {task_file}", log_widget)
        take_ownership(task_file, log_widget); remove_protection(task_file, log_widget)
        try:
            os.remove(task_file); log_message("SUCCESS: Deleted task definition file.", log_widget)
        except Exception as e: log_message(f"Failed to delete task file: {e}", log_widget)
    try:
        task_query_name = threat_name.replace('.exe', '')
        result = os.popen(f'schtasks /query /tn "{task_query_name}"').read()
        if "ERROR:" not in result:
            log_message(f"FOUND active scheduled task: {task_query_name}", log_widget)
            os.system(f'schtasks /delete /tn "{task_query_name}" /f > nul 2>&1')
            log_message(f"SUCCESS: Task '{task_query_name}' has been destroyed.", log_widget)
        else: log_message("No active scheduled task found with that name.", log_widget)
    except Exception as e: log_message(f"Scheduled task hunt error: {e}", log_widget)

def clean_all_persistence(threat_name: str, log_widget: tk.Text):
    log_message(f"Starting full persistence cleanup for '{threat_name}'...", log_widget)
    persistence_keys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        # Advanced Persistence Locations (Autoruns equivalent)
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", # IFEO
        r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", # IFEO 32-bit
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", # BHOs
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", # BHOs 32-bit
    ]
    hives = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
    for hive in hives:
        for key_path in persistence_keys:
            try:
                with winreg.OpenKey(hive, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                    i = 0
                    while True:
                        try:
                            value_name, value_data, _ = winreg.EnumValue(key, i)
                            # Check for direct value match (Run keys, Winlogon)
                            if isinstance(value_data, str) and threat_name in value_data:
                                log_message(f"FOUND persistence: '{value_name}' in '{key_path}'", log_widget)
                                winreg.DeleteValue(key, value_name)
                                log_message("SUCCESS: Removed persistence entry.", log_widget)
                            i += 1
                        except OSError: break
                
                # Special handling for IFEO (Image File Execution Options)
                if "Image File Execution Options" in key_path:
                    try:
                        j = 0
                        while True:
                            sub_key_name = winreg.EnumKey(key, j)
                            with winreg.OpenKey(key, sub_key_name, 0, winreg.KEY_ALL_ACCESS) as sub_key:
                                # Check for the 'Debugger' value
                                try:
                                    debugger_path, _ = winreg.QueryValueEx(sub_key, "Debugger")
                                    if isinstance(debugger_path, str) and threat_name in debugger_path:
                                        log_message(f"FOUND IFEO persistence: '{sub_key_name}' -> '{debugger_path}'", log_widget)
                                        winreg.DeleteValue(sub_key, "Debugger")
                                        log_message("SUCCESS: Removed IFEO Debugger entry.", log_widget)
                                except FileNotFoundError:
                                    pass # No Debugger value
                                except Exception as e:
                                    log_message(f"Error checking IFEO subkey '{sub_key_name}': {e}", log_widget)
                            j += 1
                    except OSError:
                        pass # No more subkeys
                
                # Special handling for BHOs (Browser Helper Objects) - checks the default value of the CLSID subkey
                elif "Browser Helper Objects" in key_path:
                    try:
                        j = 0
                        while True:
                            clsid_key_name = winreg.EnumKey(key, j)
                            with winreg.OpenKey(key, clsid_key_name, 0, winreg.KEY_ALL_ACCESS) as clsid_key:
                                # BHOs use the default value of the CLSID key to point to the DLL path
                                try:
                                    dll_path, _ = winreg.QueryValueEx(clsid_key, None) # None for default value
                                    if isinstance(dll_path, str) and threat_name in dll_path:
                                        log_message(f"FOUND BHO persistence: CLSID '{clsid_key_name}' -> '{dll_path}'", log_widget)
                                        # To remove a BHO, we delete the CLSID subkey itself
                                        winreg.DeleteKey(key, clsid_key_name)
                                        log_message("SUCCESS: Removed BHO CLSID key.", log_widget)
                                except FileNotFoundError:
                                    pass # No default value
                                except Exception as e:
                                    log_message(f"Error checking BHO subkey '{clsid_key_name}': {e}", log_widget)
                            j += 1
                    except OSError:
                        pass # No more subkeys
                        
            except FileNotFoundError: continue

def annihilate_now(path: Path, log_widget: tk.Text):
    log_message(f"--- Initiating INSTANT ANNIHILATION for: {path.name} ---", log_widget)
    try:
        log_message("--- Stage 1: Hunting Scheduled Tasks ---", log_widget)
        destroy_malicious_scheduled_tasks(path.name, log_widget)
        log_message("--- Stage 2: Hunting Service ---", log_widget)
        find_and_destroy_malicious_service(path.name, log_widget)
        log_message("--- Stage 3: Deep Cleaning Registry ---", log_widget)
        clean_all_persistence(path.name, log_widget)
        log_message("--- Stage 4: Killing Live Process and Loaded Modules ---", log_widget)
        kill_processes_holding_file(path, log_widget)
        log_message("--- Stage 5: Final Deletion ---", log_widget)
        take_ownership(path, log_widget); remove_protection(path, log_widget)
        time.sleep(0.5)
        try:
            os.remove(path)
        except Exception as e:
            log_message(f"os.remove failed: {e}. Trying final 'del' command.", log_widget)
            os.system(f'del /f /q "{path}"')
        if not path.exists():
            log_message(f"SUCCESS: {path.name} has been annihilated.", log_widget)
        else:
            log_message(f"FAILURE: {path.name} could not be deleted.", log_widget)
    except Exception as e:
        log_message(f"EXCEPTION during annihilation: {e}", log_widget)

# =============================
#      Scanner & Cleaner Logic
# =============================
def find_system_threats():
    threats = []
    if not SYSTEM32_DIR.exists(): return threats
    threat_patterns = ["svctrl64.exe", "winring0x64.sys", "wlogz.dat"]
    for f in SYSTEM32_DIR.iterdir():
        name = f.name.lower()
        if f.is_file() and (
            (name.startswith("u") and (name.endswith(".dll") or name.endswith(".exe") or name.endswith(".dat")) and name[1:-4].isdigit()) or
            name in threat_patterns
        ):
            threats.append(f)
    return threats

def list_usb_drives():
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
        # 1. Identify components of the USB virus
        sysvolume_dir = next((i for i in root.iterdir() if i.is_dir() and i.name.lower() == "sysvolume"), None)
        shortcut_files = [i for i in root.iterdir() if i.is_file() and i.suffix.lower() == ".lnk"]
        # Assuming the data is in a hidden folder that is not System Volume Information or SysVolume
        data_dir = next((i for i in root.iterdir() if i.is_dir() and i.name.lower() not in ["system volume information", "sysvolume", "$recycle.bin"]), None)
        
        if not any([sysvolume_dir, shortcut_files, data_dir]):
            log_message(f"No known USB virus patterns found on {root}.", log_widget); return
            
        # 2. Clean up shortcuts
        for sh in shortcut_files:
            try: 
                take_ownership(sh, log_widget)
                remove_protection(sh, log_widget)
                sh.unlink()
                log_message(f"Deleted shortcut: {sh.name}", log_widget)
            except Exception as e: 
                log_message(f"Failed to delete shortcut {sh.name}: {e}", log_widget)
                
        # 3. Remove virus folder
        if sysvolume_dir:
            try: 
                take_ownership(sysvolume_dir, log_widget)
                remove_protection(sysvolume_dir, log_widget)
                shutil.rmtree(sysvolume_dir, ignore_errors=True)
                log_message(f"Removed virus folder: {sysvolume_dir.name}", log_widget)
            except Exception as e: 
                log_message(f"Error removing {sysvolume_dir.name}: {e}", log_widget)
                
        # 4. Restore user data
        if data_dir:
            log_message(f"Restoring user files from hidden folder: {data_dir.name}", log_widget)
            for item in data_dir.iterdir():
                try:
                    # Move and then strip attributes
                    shutil.move(str(item), str(root / item.name))
                    remove_protection(root / item.name, log_widget)
                    log_message(f"Restored: {item.name}", log_widget)
                except Exception as e:
                    log_message(f"Failed to restore {item.name}: {e}", log_widget)
            try:
                data_dir.rmdir() # Try to remove the now-empty container
            except:
                pass
                
        # 5. Final attribute cleanup on the root
        for item in root.iterdir():
            if item.name.lower() not in ["system volume information", "$recycle.bin"]:
                remove_protection(item, log_widget)
                
        log_message(f"--- USB Clean for {root} finished. ---", log_widget)
    except Exception as e:
        log_message(f"CRITICAL ERROR during USB clean of {root}: {e}", log_widget)

# =============================
#      Main GUI Application
# =============================
class HAMZXA1_App(tk.Tk):
    def __init__(self):
        super().__init__()
        
        # --- NEW ICONPHOTO FIX (Required for Taskbar/Alt+Tab on Windows) ---
        try:
            # iconphoto requires a PhotoImage object, which supports PNG/GIF, not ICO.
            # We assume 'icon.png' exists alongside 'icon.ico' for this fix to work reliably.
            icon_path_png = resource_path("icon.png")
            if os.path.exists(icon_path_png):
                photo = tk.PhotoImage(file=icon_path_png)
                self.iconphoto(True, photo)
            else:
                print("IconPhoto PNG not found:", icon_path_png)
        except Exception as e:
            print("IconPhoto error:", e)
        # ------------------------------------------------------------------

        self.title(f"HAMZXA1 Security Tool v{CURRENT_VERSION}")

        # ===== ICON FIX =====
        try:
            icon_path = resource_path("icon.ico")
            if os.path.exists(icon_path):
                self.iconbitmap(icon_path)
            else:
                print("Icon not found:", icon_path)
        except Exception as e:
            print("Icon error:", e)
        # ====================

        self.geometry("1000x700")
        self.minsize(900, 650)
        self.configure(bg=COLOR_BG)
        # --- Admin Check ---
        if not is_admin():
            # Use self.after to ensure the messagebox appears before the window is destroyed
            self.after(100, lambda: messagebox.showerror("Permission Denied", "This application requires Administrator privileges to function correctly. Please run as Administrator."))
            self.after(200, self.destroy)
            return
        
        self.create_main_layout()

    def create_main_layout(self):
        for widget in self.winfo_children(): widget.destroy()
        self.grid_rowconfigure(1, weight=1); self.grid_columnconfigure(0, weight=1)
        
        header_frame = tk.Frame(self, bg=COLOR_BG); header_frame.grid(row=0, column=0, sticky="ew", padx=30, pady=(20, 10))
        tk.Label(header_frame, text="🛡️ HAMZXA1 Security", font=("Segoe UI Semibold", 28), fg=COLOR_ACCENT, bg=COLOR_BG).pack(side="left")
        tk.Label(header_frame, text=f"v{CURRENT_VERSION} by Hamza Alfarhood", font=("Segoe UI", 10), fg=COLOR_GRAY, bg=COLOR_BG).pack(side="left", padx=10, pady=(10,0))
        update_button = tk.Button(header_frame, text="Check for Updates", font=("Segoe UI", 9), bg=COLOR_GRAY, fg="white", relief="flat", command=lambda: check_for_updates(self.log_widget))
        update_button.pack(side="right", pady=(10,0))
        
        main_frame = tk.Frame(self, bg=COLOR_BG); main_frame.grid(row=1, column=0, sticky="nsew", padx=30, pady=10)
        main_frame.grid_columnconfigure(0, weight=1); main_frame.grid_columnconfigure(1, weight=1); main_frame.grid_rowconfigure(0, weight=1)
        
        system_card = tk.Frame(main_frame, bg=COLOR_CARD, highlightbackground=COLOR_CARD_LIGHT, highlightthickness=1); system_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.create_action_card(system_card, "System Scanner", "Finds and destroys polymorphic rootkits and their persistence mechanisms instantly.", "💻", self.start_system_scan)
        usb_card = tk.Frame(main_frame, bg=COLOR_CARD, highlightbackground=COLOR_CARD_LIGHT, highlightthickness=1); usb_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.create_action_card(usb_card, "USB Cleaner", "Cleans shortcut viruses and restores files on removable drives.", "💾", self.show_usb_selection)
        
        log_frame = tk.Frame(self, bg=COLOR_CARD, height=250); log_frame.grid(row=2, column=0, sticky="ew", padx=30, pady=(10, 20)); log_frame.pack_propagate(False)
        tk.Label(log_frame, text="Activity Log", font=("Segoe UI Semibold", 12), fg=COLOR_TEXT, bg=COLOR_CARD).pack(anchor="nw", padx=15, pady=(10,5))
        self.log_widget = tk.Text(log_frame, bg=COLOR_CARD, fg=COLOR_GRAY, font=("Consolas", 9), relief="flat", height=1); self.log_widget.pack(fill="both", expand=True, padx=15, pady=(0,10))
        log_message(f"HAMZXA1 v{CURRENT_VERSION} initialized. Admin: {is_admin()}", self.log_widget)

    def create_action_card(self, parent, title, desc, icon_text, command):
        parent.grid_rowconfigure(0, weight=1); parent.grid_columnconfigure(0, weight=1)
        content = tk.Frame(parent, bg=COLOR_CARD); content.grid(sticky="nsew", padx=25, pady=25)
        tk.Label(content, text=icon_text, font=("Segoe UI Symbol", 48), fg=COLOR_ACCENT, bg=COLOR_CARD).pack(pady=(0,10))
        tk.Label(content, text=title, font=("Segoe UI Semibold", 18), fg=COLOR_TEXT_BRIGHT, bg=COLOR_CARD).pack()
        tk.Label(content, text=desc, font=("Segoe UI", 10), fg=COLOR_TEXT, bg=COLOR_CARD, wraplength=300, justify="center").pack(pady=5)
        tk.Button(content, text=f"Launch {title}", font=("Segoe UI Semibold", 11), bg=COLOR_ACCENT, fg="black", relief="flat", padx=20, pady=8, command=command).pack(pady=(20,0))

    def show_popup_window(self, title):
        popup = tk.Toplevel(self); popup.title(title); popup.geometry("700x500"); popup.configure(bg=COLOR_BG); popup.transient(self); popup.grab_set()
        header = tk.Frame(popup, bg=COLOR_BG); header.pack(fill="x", padx=10, pady=10)
        tk.Button(header, text="← Back to Main", font=("Segoe UI", 10), bg=COLOR_GRAY, fg="white", relief="flat", command=popup.destroy).pack(side="left")
        content_frame = tk.Frame(popup, bg=COLOR_BG); content_frame.pack(fill="both", expand=True, padx=20, pady=10)
        return popup, content_frame

    def start_system_scan(self):
        log_message("--- Starting System Scan ---", self.log_widget)
        threats = find_system_threats()
        popup, frame = self.show_popup_window("System Scanner")
        if not threats:
            log_message("System scan complete. No threats found.", self.log_widget)
            tk.Label(frame, text="✅ System Clean", font=("Segoe UI Semibold", 24), fg=COLOR_SUCCESS, bg=COLOR_BG).pack(pady=50)
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
        
        def on_annihilate_now():
            targets = [p for var, p in check_vars if var.get()]
            if not targets or not messagebox.askyesno("Confirm Instant Annihilation", f"This will perform a 5-STAGE ATTACK to destroy the rootkit's entire infrastructure and delete {len(targets)} file(s) INSTANTLY.\n\nThis is the final, most powerful action. Proceed?"): return
            annihilate_button.config(state="disabled", text="Annihilating...")
            def worker():
                for target in targets:
                    annihilate_now(target, self.log_widget)
                self.after(100, lambda: (
                    popup.destroy(),
                    messagebox.showinfo("Complete", "Annihilation Protocol finished. Please check the log for details and restart your computer as a precaution.")
                ))
            threading.Thread(target=worker, daemon=True).start()

        buttons = tk.Frame(frame, bg=COLOR_BG); buttons.pack(fill="x", pady=(15, 0))
        annihilate_button = tk.Button(buttons, text="💥 Annihilate Now", font=("Segoe UI Semibold", 12), bg=COLOR_ERROR, fg="white", relief="flat", padx=20, pady=8, command=on_annihilate_now)
        annihilate_button.pack(side="left")

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

if __name__ == "__main__":
    if not sys.platform.startswith("win"):
        print("This tool is designed for Windows only."); sys.exit(1)
    app = HAMZXA1_App()
    app.mainloop()
