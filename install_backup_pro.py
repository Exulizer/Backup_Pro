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

# Lazy Imports für optionale Module (verhindert Crash beim Start)
# import winshell
# from win32com.client import Dispatch

# --- Konfiguration & Design ---
COLORS = {
    "bg": "#1e1e2f",       # Dunkler Hintergrund
    "card": "#2d2b55",     # Card Hintergrund
    "text": "#ffffff",     # Weißer Text
    "accent": "#4a90e2",   # Blau (Buttons)
    "success": "#2ecc71",  # Grün
    "error": "#e74c3c",    # Rot
    "warning": "#f1c40f",  # Gelb
    "btn_text": "#ffffff"
}

REQUIRED_PACKAGES = ["flask", "pyzipper", "paramiko", "pywin32", "winshell"]
APP_PORT = 5000
GITHUB_RAW_URL = "https://raw.githubusercontent.com/Exulizer/Backup_Pro/main/backup_app.py"
APP_NAME = "Backup Pro"
# APP_SCRIPT wird dynamisch ermittelt

class InstallerApp:
    def __init__(self, root):
        self.root = root
        self.app_script = self.find_latest_app_script()
        
        self.root.title(f"{APP_NAME} - Installation")
        self.root.geometry("700x550")
        self.root.configure(bg=COLORS["bg"])
        
        # Styles für Labels
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TFrame", background=COLORS["bg"])
        self.style.configure("Card.TFrame", background=COLORS["card"])
        self.style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", background=COLORS["bg"], foreground=COLORS["accent"], font=("Segoe UI", 18, "bold"))
        
        self.setup_ui()
        
        # Prüfe auf pywin32 für Shortcuts vorab
        self.check_pre_requirements()

    def find_latest_app_script(self):
        """Sucht automatisch nach der neuesten backup_app_vX_Y.py Version."""
        pattern = "backup_app_v*.py"
        files = glob.glob(pattern)
        
        if not files:
            return "backup_app_v7_1.py" # Fallback
            
        # Sortiere nach Versionen im Dateinamen
        def version_key(filename):
            # Extrahiere alle Zahlen aus dem Dateinamen
            numbers = re.findall(r'\d+', filename)
            if not numbers:
                return 0
            # Mache daraus eine Versionsnummer (z.B. [7, 1] -> 701) oder Tuple
            return tuple(map(int, numbers))
            
        try:
            latest_file = max(files, key=version_key)
            return latest_file
        except:
            return files[0] # Fallback auf irgendeine gefundene

    def check_pre_requirements(self):
        # Versuche pywin32 leise zu installieren, falls für Installer-Logik benötigt
        try:
            import win32com.client
        except ImportError:
            self.log("Installiere Installer-Abhängigkeiten (pywin32)...", "warn")
            subprocess.call([sys.executable, "-m", "pip", "install", "pywin32", "winshell"])

    def setup_ui(self):
        # Main Container mit Padding
        main_frame = tk.Frame(self.root, bg=COLORS["bg"], padx=20, pady=20)
        main_frame.pack(fill="both", expand=True)

        # Header
        lbl_title = ttk.Label(main_frame, text=f"{APP_NAME} Installer", style="Header.TLabel")
        lbl_title.pack(anchor="w", pady=(0, 20))
        
        # Info Bereich
        info_text = (
            "Dieser Assistent richtet Backup Pro vollständig für Sie ein.\n\n"
            "Schritte:\n"
            "1. Prüfung der Systemumgebung und Ports\n"
            "2. Download der neuesten Version (optional)\n"
            "3. Installation aller benötigten Python-Bibliotheken\n"
            "4. Erstellung einer Start-Datei (Launcher)\n"
            "5. Erstellung einer Desktop-Verknüpfung"
        )
        lbl_info = tk.Label(main_frame, text=info_text, bg=COLORS["bg"], fg=COLORS["text"], 
                           justify="left", font=("Segoe UI", 11), anchor="w")
        lbl_info.pack(fill="x", pady=(0, 20))
        
        # Log Console
        self.log_text = tk.Text(main_frame, bg=COLORS["card"], fg=COLORS["text"], 
                                font=("Consolas", 9), relief="flat", height=12, bd=5)
        self.log_text.pack(fill="both", expand=True, pady=(0, 20))
        
        # Progress Bar
        self.progress = ttk.Progressbar(main_frame, orient="horizontal", mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 20))
        
        # Button Area (unten)
        btn_frame = tk.Frame(main_frame, bg=COLORS["bg"])
        btn_frame.pack(fill="x")
        
        # Standard TK Buttons für volle Kontrolle über Farben/Sichtbarkeit
        self.btn_install = tk.Button(btn_frame, text="Installation Starten", 
                                   command=self.start_installation,
                                   bg=COLORS["accent"], fg=COLORS["btn_text"],
                                   font=("Segoe UI", 11, "bold"), relief="flat",
                                   padx=20, pady=8, cursor="hand2")
        self.btn_install.pack(side="right")
        
        self.btn_download = tk.Button(btn_frame, text="Download App", 
                                   command=self.download_from_github,
                                   bg=COLORS["warning"], fg="#000000",
                                   font=("Segoe UI", 11), relief="flat",
                                   padx=20, pady=8, cursor="hand2",
                                   state="disabled") # Initial disabled
        self.btn_download.pack(side="right", padx=10)
        
        self.btn_exit = tk.Button(btn_frame, text="Abbrechen",  
                                command=self.root.quit,
                                bg="#555555", fg=COLORS["btn_text"],
                                font=("Segoe UI", 11), relief="flat",
                                padx=20, pady=8, cursor="hand2")
        self.btn_exit.pack(side="right", padx=10)

    def log(self, message, level="info"):
        self.log_text.configure(state="normal")
        prefix = "• "
        tag = "info"
        if level == "success": 
            prefix = "✓ "
            tag = "success"
        elif level == "error": 
            prefix = "✗ "
            tag = "error"
        elif level == "warn": 
            prefix = "! "
            tag = "warn"
        
        self.log_text.insert("end", f"{prefix}{message}\n", tag)
        
        # Farben für Tags
        self.log_text.tag_config("success", foreground=COLORS["success"])
        self.log_text.tag_config("error", foreground=COLORS["error"])
        self.log_text.tag_config("warn", foreground=COLORS["warning"])
        
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def check_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result != 0 

    def install_package(self, package):
        try:
            # --user flag oft sicherer ohne Admin-Rechte
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            return True
        except subprocess.CalledProcessError:
            try:
                # Fallback ohne user flag
                subprocess.check_call([sys.executable, "-m", "pip", "install", package, "--user"])
                return True
            except:
                return False

    def create_python_launcher(self):
        try:
            content = """import glob
import os
import sys
import re
import subprocess
import time

def find_latest_app_script():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(base_dir)
    pattern = "backup_app_v*.py"
    files = glob.glob(pattern)
    if not files: return None
    def version_key(filename):
        numbers = re.findall(r'\\d+', filename)
        if not numbers: return 0
        return tuple(map(int, numbers))
    try: return max(files, key=version_key)
    except: return files[0]

if __name__ == "__main__":
    print("Suche nach neuester Version...")
    script = find_latest_app_script()
    if script:
        print(f"Starte {script}...")
        try:
            cmd = [sys.executable, script] + sys.argv[1:]
            subprocess.run(cmd, check=False)
        except Exception as e:
            print(f"Fehler beim Starten: {e}")
            time.sleep(5)
    else:
        print("FEHLER: Keine App gefunden!")
        time.sleep(10)
"""
            with open("launcher.py", "w") as f:
                f.write(content)
            return True
        except Exception as e:
            self.log(f"Launcher.py Fehler: {e}", "error")
            return False

    def create_launcher(self):
        try:
            # Der Launcher startet nun das intelligente launcher.py Skript
            # Dieses sucht bei JEDEM Start dynamisch nach der neuesten Version.
            bat_content = f"""@echo off
title Backup Pro Launcher
echo Starte Backup Pro...
cd /d "%~dp0"
if exist ".venv\\Scripts\\python.exe" (
    ".venv\\Scripts\\python.exe" "launcher.py"
) else (
    "{sys.executable}" "launcher.py"
)
if %errorlevel% neq 0 pause
"""
            with open("start_backup_pro.bat", "w") as f:
                f.write(bat_content)
            return True
        except Exception as e:
            self.log(f"Launcher Fehler: {e}", "error")
            return False

    def create_shortcut(self):
        # Versuche zuerst die COM Methode
        try:
            import winshell
            from win32com.client import Dispatch
            import pythoncom
            
            # Initialisiere COM für diesen Thread
            try:
                pythoncom.CoInitialize()
            except:
                pass
            
            desktop = winshell.desktop()
            path = os.path.join(desktop, f"{APP_NAME}.lnk")
            target = os.path.join(os.getcwd(), "start_backup_pro.bat")
            
            shell = Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(path)
            shortcut.TargetPath = target
            shortcut.WorkingDirectory = os.getcwd()
            shortcut.IconLocation = sys.executable
            shortcut.save()
            return True
        except Exception as e:
            self.log(f"COM Shortcut Fehler: {e}. Versuche VBS Fallback...", "warn")
            return self.create_shortcut_vbs()

    def create_shortcut_vbs(self):
        """Fallback Methode mittels VBScript, falls pywin32/COM fehlschlägt"""
        try:
            vbs_script = "create_shortcut.vbs"
            target = os.path.join(os.getcwd(), "start_backup_pro.bat")
            # Desktop Pfad via VBS ermitteln ist sicherer als Annahmen
            
            vbs_content = f"""
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = oWS.SpecialFolders("Desktop") & "\\{APP_NAME}.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "{target}"
oLink.WorkingDirectory = "{os.getcwd()}"
oLink.IconLocation = "{sys.executable}"
oLink.Save
"""
            with open(vbs_script, "w") as f:
                f.write(vbs_content)
                
            # Ausführen
            subprocess.run(["cscript", "//Nologo", vbs_script], check=True)
            
            # Aufräumen
            if os.path.exists(vbs_script):
                os.remove(vbs_script)
                
            return True
        except Exception as e:
            self.log(f"VBS Shortcut Fehler: {e}", "error")
            return False

    def download_from_github(self):
        self.log(f"Starte Download von GitHub...", "info")
        
        # Liste von (URL, Ziel-Dateiname)
        # Priorisiere v7_1 und behalte den Dateinamen bei
        base_url = "https://raw.githubusercontent.com/Exulizer/Backup_Pro"
        candidates = [
            (f"{base_url}/main/backup_app_v7_1.py", "backup_app_v7_1.py"),
            (f"{base_url}/master/backup_app_v7_1.py", "backup_app_v7_1.py"),
            # Fallback: Falls v7_1 nicht da ist, versuche backup_app.py, aber nenne es backup_app_fallback.py oder ähnlich?
            # User sagt "geht ab v7_1 los", also sollten wir v7_1 erwarten.
            # Wenn wir backup_app.py laden, nennen wir es auch so.
            (f"{base_url}/main/backup_app.py", "backup_app.py"),
            (f"{base_url}/master/backup_app.py", "backup_app.py")
        ]
        
        self.btn_download.config(state="disabled")
        self.progress.start(10)
        
        def _download():
            success = False
            last_error = None
            downloaded_file = None
            
            # SSL Context
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            for url, filename in candidates:
                try:
                    self.root.after(0, lambda u=url: self.log(f"Versuche: {u}...", "info"))
                    with urllib.request.urlopen(url, context=ctx) as response:
                        if response.getcode() == 200:
                            total_size = int(response.info().get('Content-Length', 0))
                            downloaded = 0
                            chunk_size = 8192
                            
                            with open(filename, 'wb') as out_file:
                                while True:
                                    chunk = response.read(chunk_size)
                                    if not chunk:
                                        break
                                    out_file.write(chunk)
                                    downloaded += len(chunk)
                                    
                                    if total_size > 0:
                                        percent = (downloaded / total_size) * 100
                                        self.root.after(0, lambda p=percent: self.progress.configure(value=p))
                                        
                            success = True
                            downloaded_file = filename
                            break
                except Exception as e:
                    last_error = e
            
            if success:
                self.root.after(0, lambda: self.log(f"Download erfolgreich: {downloaded_file}", "success"))
                self.root.after(0, lambda: messagebox.showinfo("Download", f"Die App ({downloaded_file}) wurde erfolgreich heruntergeladen!"))
            else:
                self.root.after(0, lambda: self.log(f"Download fehlgeschlagen.", "error"))
                self.root.after(0, lambda: messagebox.showerror("Fehler", f"Konnte keine gültige App-Datei finden.\nLetzter Fehler: {last_error}"))

            self.root.after(0, lambda: self.btn_download.config(state="normal"))
            self.root.after(0, self.progress.stop)
                
        threading.Thread(target=_download, daemon=True).start()

    def start_installation(self):
        self.btn_install.config(state="disabled", bg="#333333")
        self.btn_exit.config(state="disabled")
        self.progress.start(10)
        
        threading.Thread(target=self.run_install_process, daemon=True).start()

    def run_install_process(self):
        self.log("Starte Installation...", "info")
        time.sleep(1)
        
        # 1. Port Check
        if self.check_port(APP_PORT):
            self.log(f"Standard-Port {APP_PORT} ist frei.", "success")
        else:
            self.log(f"Info: Port {APP_PORT} ist belegt.", "warn")
            self.log("Backup Pro wird beim Start einen alternativen Port suchen.", "info")
        
        # 2. Dependencies
        self.log("Installiere Python-Bibliotheken...", "info")
        all_success = True
        total_pkgs = len(REQUIRED_PACKAGES)
        
        for i, pkg in enumerate(REQUIRED_PACKAGES, 1):
            self.log(f"Installiere {pkg} ({i}/{total_pkgs})...")
            # Update Progress bar smooth (0-100% relative to package count)
            # Wir nutzen hier den Bereich 0-80% des Gesamtfortschritts für Packages
            progress_val = int((i / total_pkgs) * 80)
            self.root.after(0, lambda v=progress_val: self.progress.configure(mode="determinate", value=v))
            
            if self.install_package(pkg):
                self.log(f"{pkg} erfolgreich installiert.", "success")
            else:
                self.log(f"Fehler bei {pkg}!", "error")
                all_success = False
        
        # 3. Launcher
        self.log("Erstelle Start-Skript...", "info")
        self.root.after(0, lambda: self.progress.configure(value=90))
        
        # Erstelle launcher.py
        if self.create_python_launcher():
            self.log("launcher.py erstellt.", "success")
        else:
            self.log("Fehler beim Erstellen von launcher.py", "error")
            all_success = False

        if self.create_launcher():
            self.log("start_backup_pro.bat erstellt.", "success")
        
        # 4. Shortcut
        self.log("Erstelle Desktop-Verknüpfung...", "info")
        self.root.after(0, lambda: self.progress.configure(value=100))
        if self.create_shortcut():
            self.log("Desktop-Icon erstellt.", "success")
        else:
            self.log("Konnte Desktop-Icon nicht erstellen.", "warn")

        self.progress.stop()
        self.progress.configure(mode="determinate", value=100)
        
        if all_success:
            self.log("Installation vollständig abgeschlossen!", "success")
            # Button aktivieren
            self.root.after(0, lambda: self.btn_download.config(state="normal", bg=COLORS["warning"]))
            self.root.after(1000, self.show_success_dialog)
        else:
            self.log("Installation mit Warnungen beendet.", "warn")
            self.btn_exit.config(state="normal", text="Schließen")

    def show_success_dialog(self):
        msg = (
            "Die Installation war erfolgreich!\n\n"
            "Auf Ihrem Desktop wurde eine Verknüpfung 'Backup Pro' erstellt.\n"
            "Sie können das Programm auch über 'start_backup_pro.bat' starten.\n\n"
            "Soll dieser Installer nun gelöscht werden?"
        )
        response = messagebox.askyesno("Installation Fertig", msg)
        
        if response:
            self.create_cleanup_script()
            self.root.destroy()
            subprocess.Popen(["cleanup_installer.bat"], shell=True)
        else:
            self.btn_exit.config(state="normal", text="Beenden")
            self.btn_install.config(text="Fertig")

    def create_cleanup_script(self):
        script_name = os.path.basename(__file__)
        bat_content = f"""
@echo off
timeout /t 2 /nobreak >nul
del "{script_name}"
del "cleanup_installer.bat"
"""
        with open("cleanup_installer.bat", "w") as f:
            f.write(bat_content)

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = InstallerApp(root)
        root.mainloop()
    except Exception as e:
        # Fallback Fehleranzeige falls GUI komplett failt
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, str(e), "Fataler Fehler", 0x10)
