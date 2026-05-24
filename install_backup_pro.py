import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import sys
import socket
import os
import threading
import time
import urllib.request
import ssl
import glob
import re
import json
import zipfile
import shutil
import platform
import importlib

# --- Konfiguration & Design (Commander Pro Theme) ---
COLORS = {
    "bg": "#0a0b10",       # Deep Space Black
    "card": "#11141d",     # Dark Panel
    "text": "#c0c8d6",     # Soft Blue-Grey Text
    "accent": "#0084ff",   # Electric Blue (Primary)
    "accent_hover": "#006bbd",
    "border": "#1f2430",   # Subtle Border
    "success": "#10b981",  # Emerald Green
    "error": "#ef4444",    # Red
    "warning": "#f59e0b",  # Amber
    "header": "#e2e8f0",   # Muted White Header
    "console": "#0d0f16",  # Black Console Background
    "disabled": "#4b5563"  # Gray for disabled
}

REQUIRED_PACKAGES = [
    "flask", 
    "waitress", 
    "gevent", 
    "requests", 
    "pycryptodomex", 
    "paramiko", 
    "boto3", 
    "dropbox"
]

# Windows specific
if sys.platform == "win32":
    REQUIRED_PACKAGES.extend(["pywin32", "winshell"])

APP_PORT = 5000
GITHUB_ZIP_URL = "https://github.com/Exulizer/Backup_Pro/archive/refs/heads/main.zip"
APP_NAME = "Backup Pro v8"

class ComponentRow:
    def __init__(self, parent, title, on_install, app):
        self.app = app
        self.on_install = on_install
        
        self.frame = tk.Frame(parent, bg=COLORS["card"], pady=5)
        self.frame.pack(fill="x", pady=2)
        
        # Icon/Status
        self.status_lbl = tk.Label(self.frame, text="•", bg=COLORS["card"], fg=COLORS["text"], width=3, font=("Segoe UI", 12))
        self.status_lbl.pack(side="left")
        
        # Title
        self.title_lbl = tk.Label(self.frame, text=title, bg=COLORS["card"], fg=COLORS["text"], font=("Segoe UI", 10), anchor="w")
        self.title_lbl.pack(side="left", fill="x", expand=True, padx=10)
        
        # Button
        self.btn = tk.Button(self.frame, text="Installieren", command=self.run_install, 
                           bg=COLORS["card"], fg=COLORS["accent"], 
                           font=("Segoe UI", 9), relief="flat", 
                           activebackground=COLORS["card"], activeforeground=COLORS["accent_hover"],
                           bd=1, highlightthickness=0)
        self.btn.pack(side="right", padx=10)
        
        # Hover Effect
        self.app.add_hover(self.btn, COLORS["card"], COLORS["border"], COLORS["accent"], COLORS["accent_hover"])

    def run_install(self):
        if self.app.is_installing:
            return
        threading.Thread(target=self._thread_run, daemon=True).start()

    def _thread_run(self):
        self.app.set_installing(True)
        self.set_status("running")
        try:
            success = self.on_install()
            self.set_status("success" if success else "error")
        except Exception as e:
            self.app.log(f"Fehler: {e}", "error")
            self.set_status("error")
        finally:
            self.app.set_installing(False)

    def set_status(self, status):
        def _update():
            if status == "pending":
                self.status_lbl.config(text="•", fg=COLORS["text"])
                self.btn.config(state="normal", text="Installieren")
            elif status == "running":
                self.status_lbl.config(text="↻", fg=COLORS["warning"])
                self.btn.config(state="disabled", text="Läuft...")
            elif status == "success":
                self.status_lbl.config(text="✓", fg=COLORS["success"])
                self.btn.config(state="disabled", text="Fertig")
            elif status == "error":
                self.status_lbl.config(text="✗", fg=COLORS["error"])
                self.btn.config(state="normal", text="Wiederholen")
        self.app.root.after(0, _update)

class InstallerApp:
    def __init__(self, root):
        self.root = root
        self.is_installing = False
        self.stop_requested = False
        
        self.root.title(f"{APP_NAME} - Setup Assistant")
        self.root.geometry("900x700")
        self.root.configure(bg=COLORS["bg"])
        
        try:
            icon_path = os.path.join(os.path.dirname(__file__), "resources", "app_icon.ico")
            if not os.path.exists(icon_path):
                 icon_path = os.path.join(os.path.dirname(__file__), "static", "app_icon.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except: pass

        self.setup_styles()
        self.setup_ui()
        self.check_pre_requirements()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TFrame", background=COLORS["bg"])
        self.style.configure("Card.TFrame", background=COLORS["card"], relief="flat")
        self.style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", background=COLORS["bg"], foreground=COLORS["header"], font=("Inter", 24, "bold"))
        self.style.configure("Horizontal.TProgressbar", background=COLORS["accent"], troughcolor=COLORS["card"], borderwidth=0, thickness=6)

    def check_pre_requirements(self):
        if sys.platform == "win32":
            threading.Thread(target=self._install_prerequisites, daemon=True).start()

    def _fix_pywin32_path(self):
        """Manually add pywin32_system32 to PATH and sys.path, and load DLLs directly."""
        try:
            import site
            import ctypes
            
            # Determine if we are in a venv
            is_venv = (sys.prefix != getattr(sys, "base_prefix", sys.prefix))
            
            # 1. Identify Candidates with Priority
            candidates = []
            
            # Priority 1: Local Venv (strict isolation)
            if is_venv:
                venv_site = os.path.join(sys.prefix, "Lib", "site-packages")
                candidates.append(venv_site)
                # Also check standard venv layout on Windows
                candidates.append(os.path.join(sys.prefix, "site-packages"))
            
            # Priority 2: Standard Site Packages (only if not found in venv or not in venv)
            # If we are in venv, we might want to skip user site packages to avoid version conflicts
            # unless the venv doesn't have pywin32.
            
            # We will search candidates strictly in order.
            if not is_venv:
                 candidates.extend(site.getsitepackages())
                 candidates.append(site.getusersitepackages())
            else:
                 # In venv, only fall back if absolutely necessary?
                 # Let's add them as low priority fallback
                 candidates.extend(site.getsitepackages())
                 candidates.append(site.getusersitepackages())

            # Find the FIRST valid pywin32_system32
            target_dll_path = None
            
            for p in candidates:
                dll_path = os.path.join(p, "pywin32_system32")
                if os.path.exists(dll_path):
                    target_dll_path = dll_path
                    self.log(f"Verwende pywin32 aus: {target_dll_path}", "info")
                    break # STOP after finding the highest priority match
            
            if not target_dll_path:
                self.log("Warnung: pywin32_system32 nicht gefunden.", "warn")
                return

            # 2. Clean PATH (Remove conflicting pywin32 entries)
            # This prevents Windows from loading a wrong DLL from PATH if we append ours
            current_path = os.environ["PATH"]
            new_path_parts = []
            for part in current_path.split(os.pathsep):
                if "pywin32_system32" not in part.lower():
                    new_path_parts.append(part)
            
            # Prepend our target path
            new_path_parts.insert(0, target_dll_path)
            os.environ["PATH"] = os.pathsep.join(new_path_parts)
            self.log("PATH bereinigt und aktualisiert.", "info")

            # 2. Add site-packages subdirectories explicitly (simulating .pth behavior)
            # Many pywin32 installations require 'win32', 'win32/lib', and 'Pythonwin' in sys.path
            site_packages = os.path.dirname(target_dll_path)
            extra_paths = [
                os.path.join(site_packages, "win32"),
                os.path.join(site_packages, "win32", "lib"),
                os.path.join(site_packages, "Pythonwin")
            ]
            
            for p in extra_paths:
                if os.path.exists(p) and p not in sys.path:
                    sys.path.append(p)
                    self.log(f"Added to sys.path: {os.path.basename(p)}", "info")

            # 3. Add DLL directory specifically for Python 3.8+
            if hasattr(os, "add_dll_directory"):
                try:
                    os.add_dll_directory(target_dll_path)
                    self.log(f"add_dll_directory: {target_dll_path}", "info")
                except Exception as e:
                    self.log(f"add_dll_directory failed: {e}", "warn")

            # 4. CRITICAL: Explicitly load DLLs via ctypes to bypass import resolution issues
            try:
                # Load pythoncomXX.dll and pywintypesXX.dll
                dll_files = glob.glob(os.path.join(target_dll_path, "*.dll"))
                # Sort: pywintypes first
                dll_files.sort(key=lambda x: "pythoncom" in os.path.basename(x).lower()) 
                
                for dll_file in dll_files:
                    filename = os.path.basename(dll_file).lower()
                    if "pythoncom" in filename or "pywintypes" in filename:
                        try:
                            # Use LoadLibraryEx with LOAD_WITH_ALTERED_SEARCH_PATH (0x00000008)
                            # This forces dependencies to be resolved from the DLL's directory
                            ctypes.windll.kernel32.LoadLibraryExW(dll_file, 0, 0x00000008)
                            self.log(f"DLL geladen (Altered Search): {filename}", "info")
                        except Exception as ex:
                            self.log(f"DLL Ladefehler {filename}: {ex}", "warn")
            except Exception as e:
                self.log(f"DLL Scan Fehler: {e}", "warn")

            # Force reload attempt
            try:
                if "pywintypes" in sys.modules:
                    importlib.reload(sys.modules["pywintypes"])
                else:
                    import pywintypes
            except:
                pass

        except Exception as e:
            self.log(f"Path Fix Fehler: {e}", "warn")

    def _install_prerequisites(self):
        try:
            import win32com.client
        except ImportError:
            self.log("Initialisiere Setup-Umgebung (pywin32)...", "warn")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "pywin32", "winshell", "--no-warn-script-location"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                self._fix_pywin32_path()
                self.log("Setup-Umgebung bereit.", "success")
            except:
                self.log("Konnte Setup-Tools nicht automatisch installieren.", "error")

    def setup_ui(self):
        main_frame = tk.Frame(self.root, bg=COLORS["bg"], padx=40, pady=30)
        main_frame.pack(fill="both", expand=True)

        # Header
        header_frame = tk.Frame(main_frame, bg=COLORS["bg"])
        header_frame.pack(side="top", fill="x", pady=(0, 20))
        
        tk.Label(header_frame, text="🛡️", bg=COLORS["bg"], fg=COLORS["accent"], font=("Segoe UI", 32)).pack(side="left", padx=(0, 15))
        
        title_frame = tk.Frame(header_frame, bg=COLORS["bg"])
        title_frame.pack(side="left")
        ttk.Label(title_frame, text="BACKUP PRO", style="Header.TLabel").pack(anchor="w")
        tk.Label(title_frame, text="V8 MODULAR EDITION INSTALLER", bg=COLORS["bg"], fg=COLORS["accent"], font=("Segoe UI", 9, "bold")).pack(anchor="w")

        # Main Layout: Left (Components) - Right (Log)
        content_frame = tk.Frame(main_frame, bg=COLORS["bg"])
        content_frame.pack(fill="both", expand=True)
        
        # Left Panel
        left_panel = tk.Frame(content_frame, bg=COLORS["card"], padx=15, pady=15)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        tk.Label(left_panel, text="KOMPONENTEN", bg=COLORS["card"], fg=COLORS["header"], font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 10))
        
        self.components_frame = tk.Frame(left_panel, bg=COLORS["card"])
        self.components_frame.pack(fill="x")
        
        self.comp_download = ComponentRow(self.components_frame, "1. System-Dateien (Download & Patch)", self.step_download, self)
        self.comp_deps = ComponentRow(self.components_frame, "2. Abhängigkeiten (Python Packages)", self.step_dependencies, self)
        self.comp_launcher = ComponentRow(self.components_frame, "3. Launcher & Bootloader", self.step_launcher, self)
        self.comp_shortcut = ComponentRow(self.components_frame, "4. Desktop Verknüpfung", self.step_shortcut, self)

        # Right Panel (Log)
        right_panel = tk.Frame(content_frame, bg=COLORS["console"], padx=2, pady=2)
        right_panel.pack(side="right", fill="both", expand=True)
        
        tk.Label(right_panel, text=" >_ SYSTEM LOG", bg=COLORS["console"], fg=COLORS["text"], font=("Consolas", 9, "bold"), anchor="w").pack(fill="x", padx=5, pady=5)
        
        self.log_text = tk.Text(right_panel, bg=COLORS["console"], fg=COLORS["text"], font=("Consolas", 9), relief="flat", bd=5, state="disabled")
        self.log_text.pack(fill="both", expand=True)

        # Bottom Section
        bottom_frame = tk.Frame(main_frame, bg=COLORS["bg"])
        bottom_frame.pack(side="bottom", fill="x", pady=(20, 0))
        
        # Progress
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(bottom_frame, orient="horizontal", mode="determinate", variable=self.progress_var, style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(0, 15))
        
        # Buttons
        btn_bar = tk.Frame(bottom_frame, bg=COLORS["bg"])
        btn_bar.pack(fill="x")
        
        self.btn_exit = self.create_button(btn_bar, "Beenden", self.root.quit, False)
        self.btn_exit.pack(side="left")

        self.btn_install_all = self.create_button(btn_bar, "ALLE INSTALLIEREN", self.run_full_installation, True)
        self.btn_install_all.pack(side="right")
        
        self.btn_cancel = tk.Button(btn_bar, text="Abbrechen", command=self.cancel_install, 
                                  bg=COLORS["bg"], fg=COLORS["error"], font=("Segoe UI", 10), 
                                  relief="flat", cursor="hand2", bd=0)
        self.btn_cancel.pack(side="right", padx=15)
        self.btn_cancel.pack_forget() # Initially hidden

    def create_button(self, parent, text, command, primary=False):
        bg = COLORS["accent"] if primary else COLORS["card"]
        fg = "#ffffff" if primary else COLORS["text"]
        bg_hover = COLORS["accent_hover"] if primary else COLORS["border"]
        
        btn = tk.Button(parent, text=text, command=command, bg=bg, fg=fg, 
                       font=("Segoe UI", 10, "bold"), relief="flat", padx=30, pady=10, 
                       cursor="hand2", borderwidth=0)
        
        self.add_hover(btn, bg, bg_hover, fg, fg)
        return btn

    def add_hover(self, btn, bg_normal, bg_hover, fg_normal, fg_hover):
        def on_enter(e):
            btn.config(bg=bg_hover, fg=fg_hover)
        def on_leave(e):
            btn.config(bg=bg_normal, fg=fg_normal)
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)

    def set_installing(self, state):
        self.is_installing = state
        self.stop_requested = False
        
        def _ui():
            if state:
                self.btn_install_all.config(state="disabled", bg=COLORS["disabled"])
                self.btn_exit.config(state="disabled")
                self.btn_cancel.pack(side="right", padx=15)
                # Disable individual buttons
                for c in [self.comp_download, self.comp_deps, self.comp_launcher, self.comp_shortcut]:
                    c.btn.config(state="disabled")
            else:
                self.btn_install_all.config(state="normal", bg=COLORS["accent"])
                self.btn_exit.config(state="normal")
                self.btn_cancel.pack_forget()
                # Re-enable pending buttons
                for c in [self.comp_download, self.comp_deps, self.comp_launcher, self.comp_shortcut]:
                    if c.status_lbl.cget("text") != "✓":
                        c.btn.config(state="normal")
        
        self.root.after(0, _ui)

    def cancel_install(self):
        if self.is_installing:
            self.stop_requested = True
            self.log("Abbruch angefordert...", "warn")

    def log(self, message, level="info"):
        def _log():
            self.log_text.configure(state="normal")
            prefix = "• "
            color = COLORS["text"]
            if level == "success": 
                prefix = "✓ "
                color = COLORS["success"]
            elif level == "error": 
                prefix = "✗ "
                color = COLORS["error"]
            elif level == "warn": 
                prefix = "! "
                color = COLORS["warning"]
            
            self.log_text.insert("end", f"{prefix}{message}\n")
            self.log_text.tag_add(level, "end-2l", "end-1c")
            self.log_text.tag_config(level, foreground=color)
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        self.root.after(0, _log)

    def update_progress(self, val):
        self.root.after(0, lambda: self.progress_var.set(val))

    # --- STEPS ---

    def step_download(self):
        self.log("Starte Download...", "info")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            url = GITHUB_ZIP_URL
            zip_name = "update.zip"
            
            # Download with progress manually implemented to support SSL context
            with urllib.request.urlopen(url, context=ctx) as response, open(zip_name, 'wb') as out_file:
                total_size = int(response.info().get('Content-Length', -1))
                block_size = 8192
                downloaded = 0
                
                while True:
                    if self.stop_requested: raise Exception("Vom Benutzer abgebrochen")
                    buffer = response.read(block_size)
                    if not buffer:
                        break
                    downloaded += len(buffer)
                    out_file.write(buffer)
                    
                    if total_size > 0:
                        pct = (downloaded * 100) / total_size
                        # Map 0-100 download to 0-50 total step progress
                        self.update_progress(pct * 0.5)
            
            self.log("Entpacke Dateien...", "info")
            if self.stop_requested: return False

            with zipfile.ZipFile(zip_name, 'r') as zip_ref:
                root_dir = zip_ref.namelist()[0].split('/')[0]
                zip_ref.extractall("temp_update")
            
            source_dir = os.path.join("temp_update", root_dir)
            
            # File Move with progress
            files = os.listdir(source_dir)
            total_files = len(files)
            for i, item in enumerate(files):
                if self.stop_requested: return False
                s = os.path.join(source_dir, item)
                d = os.path.join(os.getcwd(), item)
                if os.path.exists(d):
                    if os.path.isdir(d): shutil.rmtree(d)
                    else: os.remove(d)
                shutil.move(s, d)
                self.update_progress(50 + ((i / total_files) * 30))

            shutil.rmtree("temp_update")
            if os.path.exists(zip_name): os.remove(zip_name)
            
            self.patch_application()
            self.update_progress(100)
            self.log("Dateien erfolgreich aktualisiert.", "success")
            return True
        except Exception as e:
            self.log(f"Download Fehler: {e}", "error")
            return False

    def step_dependencies(self):
        self.log("Installiere Abhängigkeiten (optimiert)...", "info")
        
        # Optimize: Single Batch Install with Retries & Parallel Downloads (via pip)
        base_cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "--prefer-binary", "--no-warn-script-location"]
        packages = REQUIRED_PACKAGES
        
        max_retries = 3
        for attempt in range(max_retries):
            if self.stop_requested: return False
            try:
                # Use --user flag for fallback attempts to handle permission issues
                current_cmd = base_cmd + packages
                if attempt > 0:
                    # In a venv, --user is not allowed. We just retry normally.
                    self.log(f"Wiederhole Installation...", "warn")

                self.log(f"Starte Pip Installation (Versuch {attempt+1}/{max_retries})...")
                
                # Start process
                process = subprocess.Popen(current_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                
                # Read output for progress
                while True:
                    if self.stop_requested: 
                        process.terminate()
                        return False
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break
                    if line:
                        clean_line = line.strip()
                        if clean_line:
                            # Log only important info to avoid clutter
                            if any(x in clean_line for x in ["Collecting", "Installing", "Successfully", "Requirement", "WARNING"]):
                                self.log(f" > {clean_line[:80]}...")
                
                if process.returncode == 0:
                    self.log("Alle Pakete installiert.", "success")
                    self.update_progress(100)
                    self._fix_pywin32_path() # Ensure path is correct after potential upgrades
                    return True
                else:
                    self.log(f"Pip Fehler Code: {process.returncode}", "warn")
                    
            except Exception as e:
                self.log(f"Fehler: {e}", "error")
            
            # Backoff before retry
            if attempt < max_retries - 1:
                wait_time = 2 * (attempt + 1)
                self.log(f"Warte {wait_time}s vor Retry...", "warn")
                time.sleep(wait_time)
            
        self.log("Installation fehlgeschlagen nach Retries.", "error")
        return False

    def step_launcher(self):
        try:
            self.log("Erstelle Launcher Scripts...", "info")
            
            # Python Script
            py_content = """import os
import sys
import subprocess
import time
import shutil

def get_python_executable():
    pypy = shutil.which("pypy3") or shutil.which("pypy")
    if pypy: return pypy
    return sys.executable

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    script = "main.py"
    if os.path.exists(script):
        try:
            cmd = [get_python_executable(), script] + sys.argv[1:]
            subprocess.run(cmd, check=False)
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(10)
    else:
        print("main.py not found!")
        time.sleep(10)
"""
            with open("launcher.py", "w") as f: f.write(py_content)
            
            # Platform specific scripts
            if sys.platform == "win32":
                bat_content = f"""@echo off
title {APP_NAME}
cd /d "%~dp0"
if exist ".venv\\Scripts\\python.exe" (
    ".venv\\Scripts\\python.exe" "main.py"
) else (
    python "main.py"
)
if %errorlevel% neq 0 pause
"""
                with open("start_backup_pro.bat", "w") as f: f.write(bat_content)
                shutil.copy("start_backup_pro.bat", "startapp.bat")
            else:
                sh_content = f"""#!/bin/bash
cd "$(dirname "$0")"
if [ -f ".venv/bin/python" ]; then
    .venv/bin/python main.py
else
    python3 main.py
fi
"""
                with open("start_backup_pro.sh", "w") as f: f.write(sh_content)
                os.chmod("start_backup_pro.sh", 0o755)

            self.update_progress(100)
            self.log("Launcher erstellt.", "success")
            return True
        except Exception as e:
            self.log(f"Launcher Fehler: {e}", "error")
            return False

    def step_shortcut(self):
        if sys.platform != "win32":
            self.log("Desktop Shortcut nur unter Windows verfügbar.", "warn")
            return True # Not an error
            
        try:
            self.log("Erstelle Desktop Verknüpfung...", "info")
            
            # 1. Sicherstellen, dass win32com verfügbar ist
            try:
                # Proactive Path Fix before import attempt
                self._fix_pywin32_path()
                import win32com.client
                from win32com.client import Dispatch
            except ImportError:
                self.log("Installiere fehlende Windows-Module (pywin32)...", "warn")
                try:
                    subprocess.check_call(
                        [sys.executable, "-m", "pip", "install", "pywin32", "winshell", "--no-warn-script-location"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                except:
                    try:
                        self.log("System-Install fehlgeschlagen, versuche User-Install...", "warn")
                        subprocess.check_call(
                            [sys.executable, "-m", "pip", "install", "pywin32", "winshell", "--user", "--no-warn-script-location"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                        )
                    except Exception as e:
                        self.log(f"Konnte pywin32 nicht installieren: {e}", "error")
                        return False

                # FIX: Patch Path again after installation
                self._fix_pywin32_path()
                try:
                    import pywintypes
                    import win32api
                    import win32con
                    import win32com.client
                    from win32com.client import Dispatch
                    self.log("pywin32 Module erfolgreich importiert.", "success")
                except ImportError as e:
                    self.log(f"CRITICAL: pywin32 Import fehlgeschlagen trotz Installation. Details: {e}", "error")
                    self.log(f"sys.path: {sys.path}", "warn")
                    return False
            
            # 2. Desktop Pfad ermitteln
            desktop = ""
            try:
                import winshell
                desktop = winshell.desktop()
            except:
                # Fallback via Registry oder Environment
                desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')
            
            if not desktop or not os.path.exists(desktop):
                self.log("Desktop-Pfad konnte nicht ermittelt werden.", "error")
                return False

            path = os.path.join(desktop, f"{APP_NAME}.lnk")
            
            # 3. Ziel definieren
            # Bevorzuge die .bat Datei, falls erstellt, sonst Python script
            target = os.path.join(os.getcwd(), "start_backup_pro.bat")
            if not os.path.exists(target):
                 target = os.path.join(os.getcwd(), "launcher.py") # Fallback
            
            working_dir = os.getcwd()
            icon_path = os.path.join(os.getcwd(), "resources", "app_icon.ico")
            
            # 4. Shortcut erstellen
            import pythoncom
            pythoncom.CoInitialize()
            try:
                shell = Dispatch('WScript.Shell')
                shortcut = shell.CreateShortCut(path)
                shortcut.TargetPath = target
                shortcut.WorkingDirectory = working_dir
                shortcut.Description = "Startet Backup Pro v8"
                
                if os.path.exists(icon_path):
                    shortcut.IconLocation = icon_path
                else:
                    self.log("Icon nicht gefunden (optional), verwende Standard.", "warn")
                
                shortcut.save()
            finally:
                pythoncom.CoUninitialize()
            self.update_progress(100)
            self.log(f"Verknüpfung erstellt auf Desktop.", "success")
            return True
        except Exception as e:
            self.log(f"Shortcut Fehler: {e}", "error")
            return False

    def patch_application(self):
        self.log("Wende Patches an...", "info")
        # Reuse existing patch logic...
        try:
            if os.path.exists("requirements.txt"):
                with open("requirements.txt", "r") as f: c = f.read()
                c = c.replace("dropbox==11.36.0", "dropbox>=11.36.0").replace("gevent==25.9.1", "gevent")
                with open("requirements.txt", "w") as f: f.write(c)
            
            ws_path = os.path.join("gui", "web_server.py")
            if os.path.exists(ws_path):
                with open(ws_path, "r", encoding="utf-8") as f: code = f.read()
                if "def find_available_port" not in code:
                    import_socket = "import socket\n\n"
                    func_code = """def find_available_port(start_port=5000, max_tries=50):
    for port in range(start_port, start_port + max_tries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                return port
        except OSError:
            continue
    return start_port
\n"""
                    code = code.replace("def start_server", import_socket + func_code + "def start_server")
                    with open(ws_path, "w", encoding="utf-8") as f: f.write(code)

            main_path = "main.py"
            if os.path.exists(main_path):
                with open(main_path, "r", encoding="utf-8") as f: code = f.read()
                if "find_available_port" not in code:
                    code = code.replace("from gui.web_server import create_app, start_server", "from gui.web_server import create_app, start_server, find_available_port")
                    if "app = create_app" in code:
                        insert = 'app = create_app(config_manager, db_manager, backup_engine, scheduler)\n'
                        new = """    port = find_available_port(5000)\n"""
                        code = code.replace(insert, insert + new)
                        code = code.replace('webbrowser.open("http://127.0.0.1:5000")', 'webbrowser.open(f"http://127.0.0.1:{port}")')
                        code = code.replace('logger.info("Starting Web Server on port 5000...")', 'logger.info(f"Starting Web Server on port {port}...")')
                        code = code.replace('start_server(app)', 'start_server(app, port=port)')
                        with open(main_path, "w", encoding="utf-8") as f: f.write(code)
            self.log("Patches OK.", "success")
        except Exception as e:
            self.log(f"Patch Fehler: {e}", "warn")

    def run_full_installation(self):
        threading.Thread(target=self._full_install_thread, daemon=True).start()

    def _full_install_thread(self):
        self.set_installing(True)
        self.update_progress(0)
        
        steps = [
            (self.comp_download, self.step_download),
            (self.comp_deps, self.step_dependencies),
            (self.comp_launcher, self.step_launcher),
            (self.comp_shortcut, self.step_shortcut)
        ]
        
        step_weight = 100 / len(steps)
        
        all_ok = True
        for i, (comp, func) in enumerate(steps):
            if self.stop_requested: break
            
            comp.set_status("running")
            try:
                # Reset progress for visual clarity per step? 
                # Or keep global? Let's do global accumulation.
                # Since func updates progress 0-100, we need to map it.
                # But func is hardcoded to update self.progress_var. 
                # We should override update_progress locally or change logic.
                # For simplicity, let the individual funcs just run and we show global progress here.
                # Actually, individual funcs calling self.update_progress(0-100) will make the bar jump.
                # I should patch update_progress.
                
                base_progress = i * step_weight
                
                def scoped_update(val):
                    # val is 0-100 for current step
                    global_val = base_progress + (val * (step_weight / 100))
                    self.root.after(0, lambda: self.progress_var.set(global_val))
                
                # Monkey patch for this thread context (tricky) or pass callback
                # Since I didn't change signatures, I'll temporarily override the method
                original_update = self.update_progress
                self.update_progress = scoped_update
                
                success = func()
                
                self.update_progress = original_update # Restore
                
                comp.set_status("success" if success else "error")
                if not success: 
                    all_ok = False
                    break
            except Exception as e:
                self.log(f"Critical Error: {e}", "error")
                comp.set_status("error")
                all_ok = False
                break
        
        self.set_installing(False)
        if all_ok and not self.stop_requested:
            self.progress_var.set(100)
            self.log("GESAMT-INSTALLATION ERFOLGREICH!", "success")
            self.root.after(0, lambda: messagebox.showinfo("Fertig", "Installation abgeschlossen."))
        elif self.stop_requested:
            self.log("Installation abgebrochen.", "warn")

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = InstallerApp(root)
        root.mainloop()
    except Exception as e:
        import ctypes
        try: ctypes.windll.user32.MessageBoxW(0, str(e), "Fataler Fehler", 0x10)
        except: print(e)
