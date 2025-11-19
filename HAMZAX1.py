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

# =============================================================================
#                           HAMZXA1 Security Tool
#                     Version 1.1 - By Hamza Alfarhood
# =============================================================================

# =============================
#      Global Settings & Update Info
# =============================
CURRENT_VERSION = "1.1"  # Version updated to reflect aggressive improvements
VERSION_URL = "https://raw.githubusercontent.com/alzyood95/HAMZXA1-Updates/main/version.txt"
UPDATE_PAGE_URL = "https://github.com/alzyood95/HAMZXA1-Updates"

LOG_FILE = Path("HAMZXA1_log.txt"  )
WSVCZ_TARGET_DIR = Path(r"C:\Windows\System32\wsvcz")
SYSTEM32_DIR = Path(r"C:\Windows\System32")
MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004

# --- GUI Colors ---
COLOR_BG = "#0f172a"
COLOR_CARD = "#1e293b"
COLOR_CARD_LIGHT = "#334155"
COLOR_TEXT = "#cbd5f5"
COLOR_TEXT_BRIGHT = "#f1f5f9"
COLOR_ACCENT = "#38bdf8"
COLOR_SUCCESS = "#22c55e"
COLOR_WARNING = "#f59e0b"
COLOR_ERROR = "#ef4444"
COLOR_GRAY = "#64748b"

# =============================
#      Logging Function
# =============================
def log_message(msg: str, widget: tk.Text | None = None):
    """Logs a message to console, file, and an optional GUI widget."""
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}\n"
    print(line.strip())
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:
        print(f"Failed to write to log file: {e}")
    if widget:
        widget.insert(tk.END, line)
        widget.see(tk.END)
        widget.update_idletasks()

# =============================
#      Update Checker
# =============================
def check_for_updates(log_widget: tk.Text):
    """Connects to GitHub to check for a new version."""
    log_message("Checking for updates...", log_widget)
    try:
        with urllib.request.urlopen(VERSION_URL, timeout=5) as response:
            latest_version = response.read().decode('utf-8').strip()
        
        log_message(f"Current version: {CURRENT_VERSION}, Latest version from server: {latest_version}", log_widget)

        if latest_version > CURRENT_VERSION:
            if messagebox.askyesno("Update Available", f"A new version ({latest_version}) is available!\n\nThis update may contain important security patches and new features.\n\nWould you like to go to the download page now?"):
                webbrowser.open(UPDATE_PAGE_URL)
        else:
            messagebox.showinfo("No Updates", "You are currently running the latest version of HAMZXA1 Security Tool.")
            
    except Exception as e:
        log_message(f"Update check failed: {e}", log_widget)
        messagebox.showerror("Update Check Failed", "Could not connect to the update server. Please check your internet connection and try again.")

# =============================
#      Core Aggressive Functions (WITH OWNERSHIP-TAKING)
# =============================
def is_admin():
    """Check for administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def take_ownership(path: Path, log_widget: tk.Text):
    """NEW: Takes ownership of a file/folder to bypass permissions."""
    log_message(f"Attempting to take ownership of {path.name}...", log_widget)
    # These commands are piped to nul to prevent command prompt windows from flashing.
    os.system(f'takeown /F "{path}" /A /R /D Y > nul 2>&1')
    os.system(f'icacls "{path}" /grant Administrators:F /T /C /L /Q > nul 2>&1')

def remove_protection(path: Path):
    """Aggressively removes read-only, system, and hidden attributes."""
    os.system(f'attrib -h -s -r "{path}" /S /D')

def kill_processes_using(file_path: Path, log_widget: tk.Text) -> int:
    """Kills any process that has a lock on the specified file or path."""
    killed = 0
    f_str = str(file_path).lower()
    log_message(f"Searching for processes using '{file_path.name}'...", log_widget)
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            p_info = proc.info
            exe = p_info['exe']
            cmdline = p_info['cmdline']
            
            should_kill = False
            if exe and exe.lower() == f_str:
                should_kill = True
            elif cmdline and any(f_str in str(c).lower() for c in cmdline):
                should_kill = True

            if should_kill:
                proc.kill()
                killed += 1
                log_message(f"KILLED process: {p_info['name']} (PID: {p_info['pid']})", log_widget)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue # Process already gone or protected
        except Exception as e:
            log_message(f"Error killing process: {e}", log_widget)
    if killed > 0:
        log_message(f"Killed {killed} process(es).", log_widget)
    return killed

def try_immediate_delete(path: Path, log_widget: tk.Text) -> bool:
    """The full, aggressive immediate deletion logic with ownership-taking."""
    log_message(f"Starting AGGRESSIVE delete for: {path.name}", log_widget)
    try:
        if not path.exists():
            log_message("File not found (already deleted).", log_widget)
            return True

        # STEP 1: Take ownership (Most Aggressive Step)
        take_ownership(path, log_widget)

        # STEP 2: Remove attributes
        remove_protection(path)
        log_message("Removed file protection attributes.", log_widget)

        # STEP 3: Kill locking processes
        kill_processes_using(path, log_widget)
        time.sleep(0.2) # Give OS a moment to release handles

        # STEP 4: Attempt deletion (multiple methods)
        try:
            os.remove(path)
            log_message("os.remove() succeeded.", log_widget)
        except Exception as e:
            log_message(f"os.remove() failed: {e}. Trying 'del' command.", log_widget)
            os.system(f'del /f /q "{path}"')

        if not path.exists():
            log_message("SUCCESS: File has been deleted.", log_widget)
            return True

        log_message("FAILED: File still exists after all attempts. Try 'Delete on Reboot'.", log_widget)
        return False
    except Exception as e:
        log_message(f"FATAL ERROR during immediate delete: {e}", log_widget)
        return False

def schedule_delete_on_reboot(path: Path, log_widget: tk.Text) -> bool:
    """Schedules a file for deletion on the next system reboot, with ownership-taking."""
    log_message(f"Scheduling for reboot deletion: {path.name}", log_widget)
    try:
        if not path.exists():
            log_message("File already gone, no need to schedule.", log_widget)
            return True
        
        # Take ownership and remove protection before scheduling
        take_ownership(path, log_widget)
        remove_protection(path)
        
        res = ctypes.windll.kernel32.MoveFileExW(str(path), None, MOVEFILE_DELAY_UNTIL_REBOOT)
        if res == 0:
            err = ctypes.GetLastError()
            log_message(f"FAILED to schedule. MoveFileExW error code: {err}", log_widget)
            return False

        log_message("SUCCESS: File will be deleted on next reboot.", log_widget)
        return True
    except Exception as e:
        log_message(f"EXCEPTION during scheduling: {e}", log_widget)
        return False

# =============================
#      Scanner Logic
# =============================
def find_wsvcz_threats():
    if not WSVCZ_TARGET_DIR.exists(): return []
    return [f for f in WSVCZ_TARGET_DIR.iterdir() if f.is_file()]

def find_system32_u_dll_threats():
    """Finds malware DLLs in System32 like u#####.dll"""
    threats = []
    if not SYSTEM32_DIR.exists(): return threats
    for f in SYSTEM32_DIR.iterdir():
        name = f.name.lower()
        if f.is_file() and name.startswith("u") and name.endswith(".dll") and name[1:-4].isdigit():
            threats.append(f)
    return threats

def list_usb_drives() -> list[Path]:
    drives = []
    try:
        for p in psutil.disk_partitions(all=False):
            if 'removable' in p.opts.lower() and p.fstype != "":
                drives.append(Path(p.device))
    except: pass
    return drives

def clean_usb_drive(root: Path, log_widget: tk.Text):
    log_message(f"--- Cleaning USB Drive: {root} ---", log_widget)
    try:
        # Identification
        sysvolume_dir = next((item for item in root.iterdir() if item.is_dir() and item.name.lower() == "sysvolume"), None)
        shortcut_files = [item for item in root.iterdir() if item.is_file() and item.suffix.lower() == ".lnk"]
        data_dir_candidate = next((item for item in root.iterdir() if item.is_dir() and item.name.lower() not in ["system volume information", "sysvolume"]), None)

        if not any([sysvolume_dir, shortcut_files, data_dir_candidate]):
            log_message(f"No known virus patterns found on {root}.", log_widget)
            return

        # Deletion
        for sh in shortcut_files:
            try: remove_protection(sh); sh.unlink(); log_message(f"Deleted shortcut: {sh.name}", log_widget)
            except Exception as e: log_message(f"Failed to delete {sh.name}: {e}", log_widget)
        if sysvolume_dir:
            try: remove_protection(sysvolume_dir); shutil.rmtree(sysvolume_dir, ignore_errors=True); log_message(f"Removed virus folder: {sysvolume_dir.name}", log_widget)
            except Exception as e: log_message(f"Error removing {sysvolume_dir.name}: {e}", log_widget)

        # Restoration
        if data_dir_candidate:
            log_message(f"Restoring files from hidden folder: {data_dir_candidate.name}", log_widget)
            for item in data_dir_candidate.iterdir():
                target = root / item.name
                try: shutil.move(str(item), str(target)); remove_protection(target); log_message(f"Restored: {item.name}", log_widget)
                except Exception as e: log_message(f"Failed to restore {item.name}: {e}", log_widget)
            try: data_dir_candidate.rmdir()
            except: pass
        
        # Final attribute cleanup
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
        self.geometry("1000x700")
        self.minsize(900, 650)
        self.configure(bg=COLOR_BG)
        
        def resource_path(relative_path):
            """Get absolute path to resource inside EXE or script folder."""
            try:
                base_path = sys._MEIPASS  # PyInstaller EXE
            except Exception:
                base_path = os.path.abspath(".")  # Script mode
            return os.path.join(base_path, relative_path)

        icon_file = resource_path("icon.ico")

        try:
            self.iconbitmap(icon_file)
        except Exception as e:
            print("Icon load failed:", e)
        
        log_message("Application started.", None) 
        if not is_admin():
            self.after(100, lambda: messagebox.showwarning("Admin Rights Required", "For best results, please run this tool as an Administrator."))
        
        self.create_main_layout()

    def create_main_layout(self):
        self.clear_window()
        
        # --- Main Grid ---
        self.grid_rowconfigure(0, weight=0) # Header
        self.grid_rowconfigure(1, weight=1) # Main content
        self.grid_rowconfigure(2, weight=0) # Log area
        self.grid_columnconfigure(0, weight=1)

        # --- Header ---
        header_frame = tk.Frame(self, bg=COLOR_BG)
        header_frame.grid(row=0, column=0, sticky="ew", padx=30, pady=(20, 10))
        tk.Label(header_frame, text="🛡️ HAMZXA1 Security", font=("Segoe UI Semibold", 28), fg=COLOR_ACCENT, bg=COLOR_BG).pack(side="left")
        tk.Label(header_frame, text=f"v{CURRENT_VERSION} by Hamza Alfarhood", font=("Segoe UI", 10), fg=COLOR_GRAY, bg=COLOR_BG).pack(side="left", padx=10, pady=(10,0))
        
        # --- Update Button ---
        update_button = tk.Button(header_frame, text="Check for Updates", font=("Segoe UI", 9), bg=COLOR_GRAY, fg="white", relief="flat", command=lambda: check_for_updates(self.log_widget))
        update_button.pack(side="right", pady=(10,0))

        # --- Main Content (Action Cards) ---
        main_frame = tk.Frame(self, bg=COLOR_BG)
        main_frame.grid(row=1, column=0, sticky="nsew", padx=30, pady=10)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)

        # --- System Scan Card ---
        system_card = tk.Frame(main_frame, bg=COLOR_CARD, highlightbackground=COLOR_CARD_LIGHT, highlightthickness=1)
        system_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.create_action_card(system_card, "System Scanner", "Targets threats in 'wsvcz' and malicious System32 DLLs.", "PC", self.start_system_scan)

        # --- USB Scan Card ---
        usb_card = tk.Frame(main_frame, bg=COLOR_CARD, highlightbackground=COLOR_CARD_LIGHT, highlightthickness=1)
        usb_card.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.create_action_card(usb_card, "USB Cleaner", "Cleans shortcut viruses and restores files on removable drives.", "USB", self.show_usb_selection)

        # --- Log Viewer ---
        log_frame = tk.Frame(self, bg=COLOR_CARD, height=200)
        log_frame.grid(row=2, column=0, sticky="ew", padx=30, pady=(10, 20))
        log_frame.pack_propagate(False)
        tk.Label(log_frame, text="Activity Log", font=("Segoe UI Semibold", 12), fg=COLOR_TEXT, bg=COLOR_CARD).pack(anchor="nw", padx=15, pady=(10,5))
        self.log_widget = tk.Text(log_frame, bg=COLOR_CARD, fg=COLOR_GRAY, font=("Consolas", 9), relief="flat", height=1)
        self.log_widget.pack(fill="both", expand=True, padx=15, pady=(0,10))
        log_message(f"HAMZXA1 v{CURRENT_VERSION} initialized. Admin: {is_admin()}", self.log_widget)

    def create_action_card(self, parent, title, desc, icon_text, command):
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        
        content = tk.Frame(parent, bg=COLOR_CARD)
        content.grid(sticky="nsew", padx=25, pady=25)

        tk.Label(content, text=icon_text, font=("Segoe UI Symbol", 48), fg=COLOR_ACCENT, bg=COLOR_CARD).pack(pady=(0,10))
        tk.Label(content, text=title, font=("Segoe UI Semibold", 18), fg=COLOR_TEXT_BRIGHT, bg=COLOR_CARD).pack()
        tk.Label(content, text=desc, font=("Segoe UI", 10), fg=COLOR_TEXT, bg=COLOR_CARD, wraplength=300).pack(pady=5)
        
        button = tk.Button(content, text=f"Launch {title}", font=("Segoe UI Semibold", 11), bg=COLOR_ACCENT, fg="black", relief="flat", padx=20, pady=8, command=command)
        button.pack(pady=(20,0))

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_popup_window(self, title):
        popup = tk.Toplevel(self)
        popup.title(title)
        popup.geometry("700x500")
        popup.configure(bg=COLOR_BG)
        popup.transient(self)
        popup.grab_set()
        
        header = tk.Frame(popup, bg=COLOR_BG)
        header.pack(fill="x", padx=10, pady=10)
        tk.Button(header, text="← Back to Main", font=("Segoe UI", 10), bg=COLOR_GRAY, fg="white", relief="flat", command=popup.destroy).pack(side="left")
        
        content_frame = tk.Frame(popup, bg=COLOR_BG)
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)
        return popup, content_frame

    # --- System Scan Workflow ---
    def start_system_scan(self):
        log_message("--- Starting System Scan ---", self.log_widget)
        threats = find_wsvcz_threats() + find_system32_u_dll_threats()
        
        popup, frame = self.show_popup_window("System Scanner")

        if not threats:
            log_message("System scan complete. No threats found.", self.log_widget)
            tk.Label(frame, text="✅ System Clean", font=("Segoe UI Semibold", 24), fg=COLOR_SUCCESS, bg=COLOR_BG).pack(pady=50)
            tk.Label(frame, text="No threats found in 'wsvcz' or malicious DLLs in System32.", font=("Segoe UI", 11), fg=COLOR_TEXT, bg=COLOR_BG).pack()
            return

        log_message(f"Found {len(threats)} system threat(s). Awaiting user action.", self.log_widget)
        tk.Label(frame, text="⚠️ System Threats Detected", font=("Segoe UI Semibold", 22), fg=COLOR_WARNING, bg=COLOR_BG).pack(anchor="w")
        tk.Label(frame, text="Select files below to apply an action.", font=("Segoe UI", 11), fg=COLOR_TEXT, bg=COLOR_BG).pack(anchor="w", pady=(4, 15))

        list_frame = tk.Frame(frame, bg=COLOR_CARD)
        list_frame.pack(fill="both", expand=True, pady=5)
        
        check_vars = []
        for f in threats:
            v = tk.BooleanVar(value=True)
            row = tk.Frame(list_frame, bg=COLOR_CARD)
            row.pack(fill="x", padx=10, pady=4)
            tk.Checkbutton(row, variable=v, bg=COLOR_CARD, activebackground=COLOR_CARD, selectcolor=COLOR_CARD_LIGHT).pack(side="left")
            tk.Label(row, text=str(f), font=("Consolas", 10), fg=COLOR_TEXT_BRIGHT, bg=COLOR_CARD).pack(side="left", padx=6)
            check_vars.append((v, f))

        def on_delete_now():
            targets = [p for var, p in check_vars if var.get()]
            if not targets or not messagebox.askyesno("Confirm Deletion", f"Attempt to aggressively delete {len(targets)} file(s)?\nThis action is irreversible."): return
            for p in targets: try_immediate_delete(p, self.log_widget)
            popup.destroy()
            messagebox.showinfo("Complete", "Deletion process finished. Check the log for details.")

        def on_schedule_delete():
            targets = [p for var, p in check_vars if var.get()]
            if not targets or not messagebox.askyesno("Confirm Schedule", f"Schedule {len(targets)} file(s) for deletion on next reboot?"): return
            for p in targets: schedule_delete_on_reboot(p, self.log_widget)
            popup.destroy()
            messagebox.showinfo("Complete", "Scheduling process finished. Check the log for details.")

        buttons = tk.Frame(frame, bg=COLOR_BG)
        buttons.pack(fill="x", pady=(15, 0))
        tk.Button(buttons, text="🗑️ Delete Now", font=("Segoe UI Semibold", 11), bg=COLOR_ERROR, fg="white", relief="flat", padx=16, pady=6, command=on_delete_now).pack(side="left", padx=(0, 10))
        tk.Button(buttons, text="⏱️ Delete on Reboot", font=("Segoe UI Semibold", 11), bg=COLOR_ACCENT, fg="black", relief="flat", padx=16, pady=6, command=on_schedule_delete).pack(side="left")

    # --- USB Scan Workflow ---
    def show_usb_selection(self):
        log_message("--- Starting USB Scan ---", self.log_widget)
        drives = list_usb_drives()
        
        popup, frame = self.show_popup_window("USB Drive Cleaner")

        if not drives:
            log_message("USB scan complete. No removable drives found.", self.log_widget)
            tk.Label(frame, text="✅ No USB Drives Found", font=("Segoe UI Semibold", 24), fg=COLOR_SUCCESS, bg=COLOR_BG).pack(pady=50)
            return

        log_message(f"Found {len(drives)} USB drive(s). Awaiting user selection.", self.log_widget)
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
                for d in targets:
                    clean_usb_drive(d, self.log_widget)
                self.after(100, lambda: (
                    popup.destroy(),
                    messagebox.showinfo("Complete", "USB cleaning process finished. Check the log for details.")
                ))
            
            threading.Thread(target=worker, daemon=True).start()

        clean_button = tk.Button(frame, text="Clean Selected Drives", font=("Segoe UI Semibold", 11), bg=COLOR_SUCCESS, fg="white", relief="flat", padx=16, pady=6, command=on_clean)
        clean_button.pack(pady=20)

# =============================
#           MAIN
# =============================
if __name__ == "__main__":
    if not sys.platform.startswith("win"):
        print("This tool is designed for Windows only.")
        sys.exit(1)
    
    app = HAMZXA1_App()
    app.mainloop()
