import os
import shutil
import hashlib
import webbrowser
import json
import time
import zipfile
import pyzipper
import fnmatch
import subprocess
import threading
import logging
import errno
import paramiko
import socket
import sys
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template_string, jsonify, request
import tkinter as tk
from tkinter import filedialog, messagebox

# --- Konfiguration & Logging ---

# Logging initialisieren für bessere Fehlerbehebung
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Globaler Status für Async-Jobs
current_job_status = {
    "active": False,
    "progress": 0,
    "step": "idle",
    "message": "",
    "result": None
}
backup_lock = threading.Lock()

# Re-Indexing Status
reindexing_lock = threading.Lock()
reindexing_active = False

app = Flask(__name__)

# Pfade definieren
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(BASE_DIR, "backup_history.json")
CONFIG_FILE = os.path.join(BASE_DIR, "backup_config.json")

# --- Hilfsfunktionen für Robustheit ---

def ensure_files_exist():
    """Initialisierung der Systemdateien beim ersten Start mit Fehlerprüfung."""
    try:
        if not os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump([], f)
            logger.info("Historie-Datei erstellt.")
            
        if not os.path.exists(CONFIG_FILE):
            default_conf = {
                "default_source": "", 
                "default_dest": "", 
                "retention_count": 10,
                "exclusions": "node_modules, .git, .tmp, *.log, __pycache__",
                "safety_snapshots": True,
                "auto_interval": 0, # In Minuten, 0 = Aus
                "auto_backup_enabled": False,
                "encryption_enabled": False,
                "encryption_password": "",
                "cloud_sync_enabled": False,
                "cloud_provider": "SFTP",
                "cloud_user": "",
                "cloud_password": "",
                "cloud_api_key": "",
                "cloud_target_path": "/backups"
            }
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(default_conf, f, indent=4)
            logger.info("Konfigurations-Datei erstellt.")
    except IOError as e:
        logger.error(f"Fehler bei der Initialisierung der Dateien: {e}")

def safe_write_json(file_path, data):
    """
    Robustes Schreiben zur Vermeidung von Windows-Dateisperren.
    Implementiert einen Retry-Mechanismus und spezifische Fehlerbehandlung.
    """
    temp_path = file_path + ".tmp"
    for i in range(15):
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
                f.flush()
                # Erzwingt das Schreiben auf die Festplatte
                os.fsync(f.fileno())
            
            # Atomares Ersetzen der Datei
            if os.path.exists(file_path):
                os.replace(temp_path, file_path)
            else:
                os.rename(temp_path, file_path)
            return True
        except OSError as e:
            if e.errno == errno.EACCES:  # Datei wird von anderem Prozess verwendet
                logger.warning(f"Datei gesperrt, versuche erneut... ({i+1}/15)")
                time.sleep(0.3)
            else:
                logger.error(f"Betriebssystem-Fehler beim Schreiben: {e}")
                break
        except Exception as e:
            logger.error(f"Unerwarteter Fehler beim safe_write_json: {e}")
            break
            
    # Cleanup falls temp Datei noch existiert
    if os.path.exists(temp_path):
        try: os.remove(temp_path)
        except: pass
    return False

def calculate_sha256(file_path, salt=""):
    """
    Berechnet einen SHA256-Hash mit optionalem Salt.
    Optimiert für große Dateien durch Block-Reading (64KB Blöcke).
    """
    sha256_hash = hashlib.sha256()
    if salt:
        sha256_hash.update(salt.encode('utf-8'))
    try:
        if not os.path.exists(file_path):
            return "FILE_NOT_FOUND"
        with open(file_path, "rb") as f:
            # Erhöhte Blockgröße (1MB) für bessere Performance beim Hashing moderner SSDs
            for byte_block in iter(lambda: f.read(1024 * 1024), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Fehler beim Berechnen des Hashes für {file_path}: {e}")
        return "HASH_ERROR"

def is_excluded(item_name, exclusions):
    """Prüft, ob eine Datei oder ein Ordner von der Sicherung ausgeschlossen werden soll."""
    for pattern in exclusions:
        if fnmatch.fnmatch(item_name, pattern) or pattern in item_name:
            return True
    return False

def apply_retention(dest_path, limit):
    """
    Entfernt alte Backups basierend auf dem Namen (enthält Zeitstempel).
    Nutzt lexikographische Sortierung, da Zeitstempel im Format YYYY-MM-DD sind.
    """
    try:
        if not os.path.exists(dest_path):
            return []
        # Nur ZIP Dateien erfassen, die dem Backup-Schema entsprechen
        backups = [f for f in os.listdir(dest_path) if f.startswith("backup_") and f.endswith(".zip")]
        # Sortierung nach Name ist bei diesem Zeitstempelformat chronologisch korrekt
        backups.sort()
        
        deleted = []
        while len(backups) > limit:
            oldest_filename = backups.pop(0)
            full_path = os.path.join(dest_path, oldest_filename)
            if os.path.exists(full_path):
                try:
                    os.remove(full_path)
                    deleted.append(oldest_filename)
                    logger.info(f"Retention: Altes Backup entfernt: {oldest_filename}")
                except OSError as e:
                    logger.error(f"Konnte altes Backup nicht löschen: {e}")
        return deleted
    except Exception as e:
        logger.error(f"Fehler in der Retention-Logik: {e}")
        return []

# --- Daten-Management ---

def load_history():
    """Lädt die Backup-Historie mit Fehlerprüfung."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Fehler beim Laden der Historie: {e}")
        return []

def sync_history_with_disk(dest_path):
    """
    Synchronisiert die JSON-Historie mit den tatsächlichen Dateien auf der Festplatte.
    Fügt fehlende ZIPs hinzu (Re-Indexing) und entfernt Einträge von gelöschten Dateien.
    """
    if not dest_path or not os.path.exists(dest_path):
        return
    
    history = load_history()
    disk_files = set()
    
    # 1. Scanne Disk nach validen Backups
    try:
        for f in os.listdir(dest_path):
            if f.startswith("backup_") and f.endswith(".zip"):
                disk_files.add(f)
    except OSError:
        return

    history_map = {entry['filename']: entry for entry in history}
    changed = False

    # 2. Entferne Einträge aus History, die nicht mehr auf Disk sind
    to_remove = []
    for filename in history_map:
        if filename not in disk_files:
            to_remove.append(filename)
    
    if to_remove:
        history = [h for h in history if h['filename'] not in to_remove]
        changed = True
        logger.info(f"Sync: {len(to_remove)} verwaiste Einträge entfernt.")

    # 3. Füge neue Dateien von Disk zur History hinzu
    for filename in disk_files:
        if filename not in history_map:
            # Versuche Metadaten zu rekonstruieren
            full_path = os.path.join(dest_path, filename)
            try:
                # Timestamp aus Dateinamen parsen: backup_YYYY-MM-DD_HH-MM-SS.zip
                # Format: backup_2025-01-03_19-55-12.zip
                ts_part = filename.replace("backup_", "").replace(".zip", "")
                # Versuche Format zu parsen
                try:
                    dt = datetime.strptime(ts_part, "%Y-%m-%d_%H-%M-%S")
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    # Fallback auf File Mtime
                    timestamp = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime("%Y-%m-%d %H:%M:%S")
                
                size = os.path.getsize(full_path)
                
                # Hash berechnen (kann dauern, aber wichtig für Integrität)
                # Um UI nicht zu blockieren bei vielen Files, könnten wir hier optimieren.
                # Aber User will Telemetrie. Wir berechnen Hash.
                sha256 = calculate_sha256(full_path)
                
                new_entry = {
                    "filename": filename,
                    "timestamp": timestamp,
                    "size": size,
                    "sha256": sha256,
                    "comment": "Re-Indexed / Extern erkannt"
                }
                history.append(new_entry)
                changed = True
                logger.info(f"Sync: Datei {filename} indexiert.")
            except Exception as e:
                logger.error(f"Fehler beim Indexieren von {filename}: {e}")

    # 4. Speichern wenn Änderungen
    if changed:
        # Sortieren nach Timestamp
        try:
            history.sort(key=lambda x: x['timestamp'])
        except: pass
        safe_write_json(HISTORY_FILE, history)

def load_config():
    """Lädt die Konfiguration mit Fehlerprüfung."""
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Fehler beim Laden der Konfiguration: {e}")
        return {}

@app.route("/api/cancel_backup", methods=["GET"])
def cancel_backup():
    """Setzt das Abbruch-Flag für den laufenden Job."""
    global current_job_status
    if current_job_status.get("active"):
        current_job_status["abort_requested"] = True
        return jsonify({"status": "success", "message": "Abbruch angefordert..."})
    return jsonify({"status": "error", "message": "Kein aktiver Job."})

# --- Kern-Backup Logik ---

def run_backup_logic(source, dest, comment="Automatisches Backup"):
    """
    Zentrale Engine für den Backup-Vorgang.
    Aufgeteilt in Validierung, Archivierung und Post-Processing.
    """
    global current_job_status
    
    # Versuche Lock zu bekommen
    if not backup_lock.acquire(blocking=False):
        logger.warning("Backup läuft bereits. Abgelehnt.")
        return {"status": "error", "message": "Backup läuft bereits."}

    try:
        # Status Initialisierung
        current_job_status.update({
            "active": True, "progress": 0, "step": "init", "message": "Initialisiere Backup...", 
            "result": None, "abort_requested": False
        })
        
        # 1. Validierung
        is_multi_file = "|" in source
        
        if not is_multi_file and not os.path.exists(source):
            return {"status": "error", "message": f"Quellpfad existiert nicht: {source}"}
            
        if is_multi_file:
             # Kurzer Check, ob überhaupt was gültiges dabei ist
             parts = [p.strip() for p in source.split("|") if p.strip()]
             if not any(os.path.exists(p) for p in parts):
                 return {"status": "error", "message": "Keine der ausgewählten Dateien existiert."}

        if not os.path.exists(dest):
            try: os.makedirs(dest)
            except: return {"status": "error", "message": "Zielpfad konnte nicht erstellt werden."}

        # Pre-Flight Check: Speicherplatz
        try:
            _, _, free_space = shutil.disk_usage(dest)
            if free_space < (500 * 1024 * 1024): # Warnung unter 500MB
                logger.warning("Kritischer Speicherplatzmangel auf Zielmedium!")
                current_job_status["message"] = "WARNUNG: Wenig Speicherplatz!"
                # Wir brechen hier nicht hart ab, aber warnen
        except: pass

        config = load_config()
        limit = config.get("retention_count", 10)
        exclusions_raw = config.get("exclusions", "")
        exclusions = [x.strip() for x in exclusions_raw.split(",") if x.strip()]
        
        # Verschlüsselung laden
        enc_enabled = config.get("encryption_enabled", False)
        enc_pw = config.get("encryption_password", "")
        
        # Zeitstempel generieren
        now = datetime.now()
        ts = now.strftime("%Y-%m-%d %H:%M:%S")
        ts_f = now.strftime("%Y-%m-%d_%H-%M-%S")
        zip_filename = f"backup_{ts_f}.zip"
        zip_path = os.path.join(dest, zip_filename)
        
        # 2. Archivierung
        current_job_status.update({"step": "archiving", "message": "Analysiere Dateistruktur...", "progress": 5})
        
        total_files_est = 0
        total_bytes_est = 0
        
        # Multi-File Detection
        is_multi_file = "|" in source
        multi_files = []
        if is_multi_file:
            multi_files = [f.strip() for f in source.split("|") if f.strip()]
        
        # Grobe Schätzung für Progress Bar (Files & Bytes)
        if is_multi_file:
            total_files_est = len(multi_files)
            for fpath in multi_files:
                try: total_bytes_est += os.path.getsize(fpath)
                except: pass
        elif os.path.isfile(source):
             total_files_est = 1
             try: total_bytes_est = os.path.getsize(source)
             except: total_bytes_est = 1
        else:
            for r, _, f in os.walk(source):
                for file in f:
                    if not is_excluded(file, exclusions):
                        total_files_est += 1
                        try:
                            total_bytes_est += os.path.getsize(os.path.join(r, file))
                        except: pass
        
        if total_files_est == 0: total_files_est = 1
        if total_bytes_est == 0: total_bytes_est = 1
        
        logger.info(f"Starte Archivierung von {source} nach {zip_path} ({total_files_est} Dateien, {total_bytes_est/1024/1024:.2f} MB)")
        
        current_job_status.update({"message": f"Archiviere {total_files_est} Dateien...", "progress": 10})
        
        processed_bytes = 0
        file_count = 0
        
        # Verwende ZIP_DEFLATED für Kompression, optional AES-Verschlüsselung
        if enc_enabled and enc_pw:
            logger.info("Verschlüsselung (AES) aktiviert.")
            # pyzipper verwenden für AES
            zip_ctx = pyzipper.AESZipFile(zip_path, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES)
            zip_ctx.setpassword(enc_pw.encode('utf-8'))
        else:
            # Standard zipfile
            zip_ctx = zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6)

        with zip_ctx as zipf:
            if is_multi_file:
                # Multi File Case
                for fpath in multi_files:
                    if current_job_status.get("abort_requested"): raise Exception("Benutzerabbruch")
                    if os.path.exists(fpath):
                        try:
                            fsize = os.path.getsize(fpath)
                            # Speichere nur den Dateinamen im ZIP
                            zipf.write(fpath, os.path.basename(fpath))
                            
                            file_count += 1
                            processed_bytes += fsize
                            
                            # Progress Update
                            prog = 10 + int((processed_bytes / total_bytes_est) * 80)
                            current_job_status["progress"] = min(prog, 90)
                        except Exception as write_err:
                            logger.warning(f"Konnte Datei {fpath} nicht in ZIP schreiben: {write_err}")
            elif os.path.isfile(source):
                 # Single File Case
                 if current_job_status.get("abort_requested"): raise Exception("Benutzerabbruch")
                 try:
                     fsize = os.path.getsize(source)
                     # Speichere nur den Dateinamen im ZIP, keine Pfade
                     zipf.write(source, os.path.basename(source))
                     file_count = 1
                     processed_bytes = fsize
                     current_job_status["progress"] = 90
                 except Exception as write_err:
                      logger.warning(f"Konnte Datei {source} nicht in ZIP schreiben: {write_err}")
            else:
                for root, dirs, files in os.walk(source):
                    if current_job_status.get("abort_requested"): raise Exception("Benutzerabbruch")
                    # In-place Filterung der Verzeichnisse (Ausschlüsse)
                    dirs[:] = [d for d in dirs if not is_excluded(d, exclusions)]
                    
                    for file in files:
                        if current_job_status.get("abort_requested"): raise Exception("Benutzerabbruch")
                        if not is_excluded(file, exclusions):
                            full_file_path = os.path.join(root, file)
                            relative_path = os.path.relpath(full_file_path, source)
                            try:
                                fsize = os.path.getsize(full_file_path)
                                zipf.write(full_file_path, relative_path)
                                
                                file_count += 1
                                processed_bytes += fsize
                                
                                # Progress Update (10% -> 90%) - Byte-basiert für mehr Genauigkeit
                                if file_count % 5 == 0 or fsize > (5*1024*1024): 
                                    prog = 10 + int((processed_bytes / total_bytes_est) * 80)
                                    current_job_status["progress"] = min(prog, 90)
                                    
                            except Exception as write_err:
                                logger.warning(f"Konnte Datei {file} nicht in ZIP schreiben: {write_err}")
        
        # 3. Post-Processing (Hashing & Historie)
        current_job_status.update({"step": "hashing", "message": "Berechne Integritäts-Hash...", "progress": 92})
        sha = calculate_sha256(zip_path, salt=ts)
        zip_size = os.path.getsize(zip_path)
        
        current_job_status.update({"step": "retention", "message": "Bereinige Historie...", "progress": 98})
        apply_retention(dest, limit)
        
        # Cloud Upload (SFTP)
        cloud_enabled = config.get("cloud_sync_enabled", False)
        if cloud_enabled and config.get("cloud_provider") == "SFTP":
            try:
                current_job_status.update({"step": "cloud", "message": "Lade in Cloud hoch (SFTP)...", "progress": 95})
                
                c_host = config.get("cloud_host", "")
                c_user = config.get("cloud_user", "")
                c_pass = config.get("cloud_password", "")
                c_path = config.get("cloud_target_path", "/backups")
                
                if c_host and c_user:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(c_host, username=c_user, password=c_pass)
                    
                    sftp = ssh.open_sftp()
                    # Stelle sicher, dass Remote-Ordner existiert (einfacher Check)
                    try: sftp.chdir(c_path)
                    except: 
                        try: sftp.mkdir(c_path)
                        except: pass
                    
                    remote_file = os.path.join(c_path, zip_filename).replace("\\", "/")
                    sftp.put(zip_path, remote_file)
                    sftp.close()
                    ssh.close()
                    logger.info("SFTP Upload erfolgreich.")
                else:
                    logger.warning("Cloud Upload übersprungen: Host oder User fehlt.")
                    
            except Exception as cloud_err:
                logger.error(f"Cloud Upload fehlgeschlagen: {cloud_err}")
                # Kein Abbruch des Gesamt-Backups, nur Log

        # Historie aktualisieren
        history = load_history()
        history.append({
            "timestamp": ts, 
            "filename": zip_filename, 
            "sha256": sha, 
            "size": zip_size, 
            "comment": comment, 
            "file_count": file_count
        })
        
        # Historie auf Limit kürzen
        if len(history) > limit: 
            history = history[-limit:]
            
        if safe_write_json(HISTORY_FILE, history):
            logger.info(f"Backup erfolgreich abgeschlossen: {zip_filename}")
            res = {"status": "success", "file": zip_filename, "sha256": sha}
            current_job_status.update({"active": False, "progress": 100, "step": "done", "message": "Fertig", "result": res})
            return res
        else:
            res = {"status": "error", "message": "Backup erstellt, aber Historie konnte nicht gespeichert werden."}
            current_job_status.update({"active": False, "result": res})
            return res

    except Exception as e:
        logger.error(f"Kritischer Fehler in run_backup_logic: {e}")
        
        # Aufräumen bei Abbruch
        if "Benutzerabbruch" in str(e):
            logger.info("Backup durch Benutzer abgebrochen. Räume auf...")
            time.sleep(1) # Kurze Pause damit Zip-Handle sicher frei ist
            try:
                if os.path.exists(zip_path): os.remove(zip_path)
            except: pass
            res = {"status": "error", "message": "Vorgang durch Benutzer abgebrochen."}
        else:
            res = {"status": "error", "message": str(e)}
            
        current_job_status.update({"active": False, "step": "error", "message": res["message"], "result": res})
        return res
    finally:
        backup_lock.release()

# --- Auto-Backup Scheduler Thread ---

def auto_backup_scheduler():
    """Hintergrund-Thread, der die Zeitintervalle überwacht."""
    last_backup_time = time.time()
    
    while True:
        # Kurze Pause um CPU-Last zu minimieren
        time.sleep(30) 
        
        try:
            config = load_config()
            enabled = config.get("auto_backup_enabled", False)
            interval_min = config.get("auto_interval", 0)
            source = config.get("default_source")
            dest = config.get("default_dest")
            
            if enabled and interval_min > 0 and source and dest:
                interval_sec = interval_min * 60
                if time.time() - last_backup_time >= interval_sec:
                    logger.info("Auto-Backup: Intervall erreicht. Starte Prozess.")
                    run_backup_logic(source, dest, "System Auto-Snapshot")
                    last_backup_time = time.time()
        except Exception as e:
            logger.error(f"Fehler im Auto-Backup Scheduler: {e}")

# --- UI Template (Commander UI v7.1) ---

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup OS Pro Commander v7.2 - Hybrid Kernel Edition</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Inter:wght@300;400;600;700&display=swap');
        :root {
            --bg: #0a0b10;
            --card: #11141d;
            --accent: #0084ff;
            --border: #1f2430;
            --glow: 0 0 15px rgba(0, 132, 255, 0.3);
        }
        body { font-family: 'Inter', sans-serif; background-color: var(--bg); color: #c0c8d6; margin: 0; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .commander-module { background-color: var(--card); border: 1px solid var(--border); border-radius: 12px; transition: all 0.3s; }
        .commander-module:hover { border-color: #30374a; box-shadow: 0 4px 20px rgba(0,0,0,0.4); }
        
        .sidebar-item { border-left: 4px solid transparent; cursor: pointer; transition: all 0.2s; }
        .sidebar-item:hover { background-color: rgba(0, 132, 255, 0.05); border-left: 4px solid var(--accent); }
        .sidebar-item.active { background-color: rgba(0, 132, 255, 0.1); border-left: 4px solid var(--accent); color: var(--accent); }
        
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-thumb { background: #1f2430; border-radius: 10px; }
        
        .health-score { font-size: 2.5rem; font-weight: 800; text-shadow: 0 0 15px rgba(0, 132, 255, 0.2); }
        .score-good { color: #00ff88; text-shadow: 0 0 10px rgba(0, 255, 136, 0.3); }
        .score-warn { color: #f59e0b; }
        .score-crit { color: #ef4444; }

        .btn-pro { background: var(--accent); font-weight: 800; text-transform: uppercase; letter-spacing: 0.1em; transition: all 0.2s; box-shadow: var(--glow); }
        .btn-pro:hover { filter: brightness(1.2); transform: translateY(-1px); }

        #hash-modal { background-color: rgba(0, 0, 0, 0.9); backdrop-filter: blur(12px); display: none; }
        #hash-modal.flex { display: flex; }
        .modal-content { animation: modalIn 0.3s cubic-bezier(0.18, 0.89, 0.32, 1.28); }
        @keyframes modalIn { from { transform: scale(0.95); opacity: 0; } to { transform: scale(1); opacity: 1; } }

        .terminal-log div { margin-bottom: 2px; border-left: 2px solid transparent; padding-left: 10px; }
        .log-success { border-color: #10b981 !important; color: #34d399; }
        .log-error { border-color: #ef4444 !important; color: #f87171; background: rgba(239, 68, 68, 0.05); }
        .log-warn { border-color: #f59e0b !important; color: #fbbf24; }
        .log-info { border-color: #3b82f6 !important; color: #60a5fa; }
        
        .health-mini-bar { height: 3px; background: #1f2430; border-radius: 2px; overflow: hidden; margin-top: 4px; }
        .health-mini-fill { height: 100%; background: var(--accent); transition: width 0.5s ease-out; }

        .delta-badge { font-size: 10px; font-weight: 800; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; }
        .delta-neutral { background: #1a1e2a; color: #64748b; }
        .delta-plus { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.2); }
        .delta-minus { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.2); }

        .handbook-item h3 { color: #fff; font-weight: 700; margin-bottom: 0.5rem; text-transform: uppercase; font-size: 14px; letter-spacing: 0.05em; border-left: 3px solid var(--accent); padding-left: 10px; }
        .handbook-item p { font-size: 14px; line-height: 1.6; margin-bottom: 1.5rem; color: #94a3b8; }
        .handbook-tag { background: rgba(0, 132, 255, 0.15); color: #0084ff; padding: 2px 6px; border-radius: 4px; font-weight: 800; font-size: 10px; margin-right: 5px; }

        .unit-switch { background: #08090d; border: 1px solid var(--border); padding: 2px; border-radius: 6px; display: flex; gap: 2px; }
        .unit-btn { padding: 4px 10px; font-size: 10px; font-weight: 900; border-radius: 4px; cursor: pointer; transition: all 0.2s; color: #64748b; }
        .unit-btn.active { background: var(--accent); color: white; box-shadow: 0 0 10px rgba(0, 132, 255, 0.3); }
        .unit-btn:not(.active):hover { background: rgba(255,255,255,0.05); color: #c0c8d6; }
    </style>
</head>
<body class="flex h-screen overflow-hidden text-slate-300">

    <!-- Detail Modal -->
    <div id="hash-modal" class="fixed inset-0 z-[999] items-center justify-center p-4">
        <div class="modal-content bg-[#11141d] border border-[#0084ff55] w-full max-w-2xl rounded-2xl p-8 relative shadow-2xl text-slate-200">
            <button onclick="closeHashModal()" class="absolute top-6 right-6 text-slate-500 hover:text-white transition-colors">✕</button>
            <div class="flex items-center gap-3 mb-6">
                <div class="p-2 bg-blue-500/20 rounded text-blue-400">🛡️</div>
                <h3 class="text-lg font-black uppercase tracking-widest text-white">Snapshot Integrität</h3>
            </div>
            <div class="space-y-6">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <label class="text-[11px] text-slate-500 uppercase font-black mb-2 block tracking-widest">Dateiname</label>
                        <div id="modal-filename" class="bg-black/40 p-3 rounded border border-white/5 text-sm font-bold text-blue-400 mono truncate">--</div>
                    </div>
                    <div>
                        <label class="text-[11px] text-slate-500 uppercase font-black mb-2 block tracking-widest">Status</label>
                        <div class="bg-green-500/10 p-3 rounded border border-green-500/20 text-xs font-bold text-green-500 uppercase flex items-center gap-2">
                             <span class="w-1.5 h-1.5 bg-green-500 rounded-full"></span> Verifiziert
                        </div>
                    </div>
                </div>
                <div>
                    <label class="text-[11px] text-slate-500 uppercase font-black mb-2 block tracking-widest">SHA256 Signatur</label>
                    <div id="modal-hash" class="bg-black/40 p-4 rounded border border-white/5 text-[11px] mono text-white break-all leading-relaxed shadow-inner"></div>
                </div>
                <div class="grid grid-cols-2 gap-6 bg-black/20 p-4 rounded-xl">
                    <div><label class="text-[11px] text-slate-500 uppercase font-black block mb-1">Zeitpunkt</label><div id="modal-ts" class="text-sm font-bold text-white"></div></div>
                    <div><label class="text-[11px] text-slate-500 uppercase font-black block mb-1">Größe</label><div id="modal-size" class="text-sm font-bold text-white"></div></div>
                </div>
            </div>
            <div class="flex gap-4 mt-8">
                <button onclick="copyHash()" class="flex-1 bg-[#1a1e2a] py-3 rounded text-[11px] font-black uppercase tracking-widest hover:bg-slate-700 transition-all text-white border border-white/5">Signatur kopieren</button>
                <button id="modal-delete-btn" class="flex-1 bg-red-900/20 py-3 rounded text-[11px] font-black uppercase tracking-widest hover:bg-red-900/40 transition-all text-red-500 border border-red-500/20">Löschen</button>
            </div>
        </div>
    </div>

    <!-- Sidebar -->
    <aside class="w-64 bg-[#0d0f16] border-r border-[#1a1e2a] flex flex-col z-50">
        <div class="p-6 border-b border-[#1a1e2a] flex items-center gap-3">
            <div class="p-2 bg-[#0084ff] rounded-lg shadow-lg">🛡️</div>
            <div class="flex flex-col">
                <span class="font-black text-white leading-none">BACKUP OS</span>
                <span class="text-[10px] text-[#0084ff] font-bold tracking-widest uppercase">Commander Pro</span>
            </div>
        </div>

        <nav class="flex-1 mt-6">
            <div onclick="switchTab('dashboard')" id="nav-dashboard" class="sidebar-item active px-6 py-4 flex items-center gap-4">
                <span class="text-sm font-bold text-white font-mono">01 ZENTRALE</span>
            </div>
            <div onclick="switchTab('restore')" id="nav-restore" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold font-mono">02 RESTORE</span>
            </div>
            <div onclick="switchTab('cloud')" id="nav-cloud" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold font-mono">03 CLOUD</span>
            </div>
            <div onclick="switchTab('duplicates')" id="nav-duplicates" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold font-mono">04 ANALYSE</span>
            </div>
            <div onclick="switchTab('settings')" id="nav-settings" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold font-mono">05 PARAMETER</span>
            </div>
            <div onclick="switchTab('help')" id="nav-help" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500 border-t border-white/5 mt-4">
                <span class="text-sm font-bold font-mono text-blue-400">?? HANDBUCH</span>
            </div>
        </nav>

        <div class="p-6 bg-[#08090d] border-t border-[#1a1e2a]">
            <div class="flex justify-between items-center mb-1">
                <span class="text-[10px] uppercase font-black text-slate-500 tracking-tighter">Drive Telemetrie</span>
                <span id="disk-percent" class="text-[11px] font-bold text-blue-400">--%</span>
            </div>
            <div class="w-full bg-[#1a1e2a] h-2 rounded-full overflow-hidden mb-2">
                <div id="disk-bar" class="bg-blue-500 h-full w-0 transition-all duration-1000 shadow-[0_0_8px_rgba(0,132,255,0.4)]"></div>
            </div>
            <div id="disk-details" class="text-[9px] font-bold mono text-slate-600 uppercase flex justify-between mb-4">
                <span>Frei: <span id="disk-free-val" class="text-slate-400">--</span></span>
                <span>Total: <span id="disk-total-val" class="text-slate-400">--</span></span>
            </div>
            
            <!-- Copyright Safe Zone -->
            <div class="pt-3 border-t border-white/5 text-center">
                <p class="text-[9px] font-black text-slate-700 uppercase tracking-widest hover:text-slate-500 transition-colors cursor-default">
                    &copy; 2025 Exulizer
                </p>
            </div>
        </div>
    </aside>

    <!-- Main -->
    <main class="flex-1 flex flex-col overflow-hidden relative">
        <header class="h-14 bg-[#0d0f16] border-b border-[#1a1e2a] flex items-center justify-between px-8">
            <div class="flex items-center gap-4">
                <span class="w-2.5 h-2.5 bg-green-500 rounded-full animate-pulse shadow-[0_0_8px_#10b981]"></span>
                <span class="text-[12px] font-black uppercase tracking-widest text-white">v7.2 Hybrid Kernel | Creator: Exulizer</span>
            </div>
            <div class="flex items-center gap-6">
                <div class="flex items-center gap-4 mr-4">
                    <span class="text-[10px] font-black uppercase text-slate-500 tracking-widest">Unit Engine</span>
                    <div class="unit-switch" id="global-unit-switch">
                        <div onclick="setGlobalUnit('MB')" id="unit-mb" class="unit-btn active">MB</div>
                        <div onclick="setGlobalUnit('GB')" id="unit-gb" class="unit-btn">GB</div>
                    </div>
                </div>
                <div class="flex flex-col items-end border-l border-white/5 pl-6">
                    <span id="header-date" class="text-[11px] font-bold text-slate-400 mono">--.--.----</span>
                    <span id="header-time" class="text-[14px] font-black text-blue-400 mono">00:00:00</span>
                </div>
            </div>
        </header>

        <!-- Tab: Dashboard -->
        <section id="tab-dashboard" class="tab-content flex-1 overflow-y-auto p-8 space-y-8">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div class="commander-module p-5 relative overflow-hidden">
                    <div class="flex justify-between items-start mb-2">
                         <span class="text-[11px] uppercase font-black text-slate-500 tracking-widest">System Health</span>
                         <span id="health-label" class="text-[9px] font-black text-blue-400 uppercase tracking-tighter">--</span>
                    </div>
                    <div class="flex items-baseline gap-2">
                        <span class="health-score" id="score-val">--</span>
                        <span class="text-[12px] font-black text-slate-600">%</span>
                    </div>
                    <div id="health-breakdown" class="mt-4 grid grid-cols-3 gap-3 border-t border-white/5 pt-3">
                        <div class="flex flex-col">
                            <span class="text-[9px] uppercase text-slate-500 font-bold mb-1">COV</span>
                            <div class="health-mini-bar"><div id="bar-cov" class="health-mini-fill" style="width: 0%"></div></div>
                        </div>
                        <div class="flex flex-col">
                            <span class="text-[9px] uppercase text-slate-500 font-bold mb-1">REC</span>
                            <div class="health-mini-bar"><div id="bar-rec" class="health-mini-fill" style="width: 0%"></div></div>
                        </div>
                        <div class="flex flex-col">
                            <span class="text-[9px] uppercase text-slate-500 font-bold mb-1">DSK</span>
                            <div class="health-mini-bar"><div id="bar-disk" class="health-mini-fill" style="width: 0%"></div></div>
                        </div>
                    </div>
                </div>

                <div class="commander-module p-5">
                    <span class="text-[11px] uppercase font-black text-slate-500 block mb-2 tracking-widest">Archive Volume</span>
                    <div class="flex items-baseline gap-1 mt-4">
                        <span class="text-3xl font-black text-white" id="total-val-display">0.00</span>
                        <span class="text-[12px] font-bold text-slate-600" id="total-unit-display">MB</span>
                    </div>
                </div>

                <div class="commander-module p-5">
                    <span class="text-[11px] uppercase font-black text-slate-500 block mb-2 tracking-widest">Change Delta</span>
                    <div class="flex items-baseline gap-2 mt-4">
                        <span id="delta-val" class="text-3xl font-black text-white">0</span>
                        <span id="delta-badge" class="delta-badge delta-neutral">Neutral</span>
                    </div>
                </div>

                <div class="commander-module p-5 bg-blue-500/5 border-blue-500/20 group text-center flex items-center justify-center">
                    <button onclick="runBackup()" id="main-action" class="w-full h-full flex flex-col items-center justify-center gap-3">
                        <div class="w-12 h-12 bg-blue-600 rounded-full flex items-center justify-center group-hover:scale-110 transition-transform shadow-xl shadow-blue-500/20 text-xl">⚡</div>
                        <span class="text-[11px] font-black uppercase text-blue-400 tracking-widest">Snapshot anlegen</span>
                    </button>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="commander-module p-6 lg:col-span-2 space-y-6">
                    <h2 class="text-sm font-black uppercase tracking-widest text-slate-400 border-b border-white/5 pb-3">Manueller Snapshot</h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div class="space-y-4">
                            <div>
                                <label class="text-[11px] font-black uppercase text-slate-500 mb-1 block tracking-widest">Quelle</label>
                                <input type="text" id="source" readonly class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs mono text-blue-300 outline-none">
                            </div>
                            <div>
                                <label class="text-[11px] font-black uppercase text-slate-500 mb-1 block tracking-widest">Ziel</label>
                                <input type="text" id="dest" readonly class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs mono text-emerald-300 outline-none">
                            </div>
                            <div>
                                <label class="text-[11px] font-black uppercase text-slate-500 mb-1 block tracking-widest">Kommentar</label>
                                <input type="text" id="snap-comment" placeholder="Zweck der Sicherung..." class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500">
                            </div>
                        </div>
                        <div class="bg-[#08090d] p-6 rounded-xl border border-white/5">
                            <span class="text-[11px] font-black uppercase text-slate-600 mb-2 block tracking-widest">Quell-Zustand</span>
                            <div id="src-size" class="text-3xl font-black text-white">--</div>
                            <div id="src-files" class="text-[11px] mono text-blue-500 font-bold mt-2 uppercase tracking-widest">-- FILES</div>
                            
                            <div id="zipProgressArea" class="w-full mt-6 hidden space-y-2">
                                <div class="flex justify-between items-center text-[10px] font-black uppercase tracking-widest text-blue-400">
                                    <span>ZIP-Archivierung...</span>
                                    <span id="zipPercent">0%</span>
                                </div>
                                <div class="w-full bg-[#0a0b10] h-1.5 rounded-full overflow-hidden">
                                    <div id="zipBar" class="bg-blue-500 h-full w-0 transition-all duration-300"></div>
                                </div>
                                <div class="flex justify-center pt-2">
                                    <button onclick="cancelBackup()" id="cancel-btn" class="text-[9px] font-black uppercase text-red-500 border border-red-500/30 px-3 py-1 rounded hover:bg-red-500/10 transition-colors hidden">
                                        ABBRECHEN
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="commander-module p-6 flex flex-col h-full min-h-[350px]">
                    <div class="flex items-center justify-between mb-4 border-b border-white/5 pb-3">
                        <h2 class="text-sm font-black uppercase tracking-widest text-slate-400">Command Terminal</h2>
                    </div>
                    <div id="log" class="terminal-log flex-1 bg-[#08090d] p-4 rounded-lg mono text-[11px] space-y-1 overflow-y-auto border border-white/5"></div>
                </div>
            </div>

            <div class="commander-module p-6">
                <h2 class="text-sm font-black uppercase tracking-widest text-slate-400 mb-6">Wachstums-Telemetrie (Historisch)</h2>
                <div class="h-[200px] w-full relative"><canvas id="storageChart"></canvas></div>
            </div>

            <div class="commander-module p-6">
                <h2 class="text-[12px] text-slate-500 uppercase font-bold mb-6 tracking-widest">Snapshot Historie</h2>
                <div class="overflow-x-auto">
                    <table class="min-w-full text-left text-sm">
                        <thead><tr class="text-slate-500 uppercase text-[10px] font-black"><th class="px-4 py-3">Datum</th><th class="px-4 py-3">Datei</th><th class="px-4 py-3 text-right" id="history-size-header">Größe (MB)</th></tr></thead>
                        <tbody id="history-table-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- Tab: Restore -->
        <section id="tab-restore" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden">
            <div class="commander-module p-6">
                <h2 class="text-sm font-black uppercase tracking-widest text-slate-400 border-b border-white/5 pb-3 mb-6">Wiederherstellungs-Zentrum</h2>
                <div class="overflow-x-auto text-slate-200">
                    <table class="min-w-full text-left text-sm">
                        <thead><tr class="bg-[#0d0f16]"><th class="px-4 py-3">Zeitpunkt</th><th class="px-4 py-3">Archiv</th><th class="px-4 py-3">Aktion</th></tr></thead>
                        <tbody id="restore-table-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- Tab: Cloud -->
        <section id="tab-cloud" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden text-slate-200">
            <div class="commander-module p-8 max-w-2xl mx-auto space-y-8">
                <h2 class="text-sm font-black uppercase text-slate-400 border-b border-white/5 pb-4">Cloud Tresor & Remote Sync</h2>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div class="bg-black/20 p-5 rounded-xl border border-white/5">
                        <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block tracking-widest">Provider</label>
                        <select id="config-cloud-provider" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none">
                            <option>SFTP</option>
                            <option>Dropbox</option>
                            <option>S3 (Amazon)</option>
                            <option>WebDAV</option>
                        </select>
                    </div>
                    <div class="bg-black/20 p-5 rounded-xl border border-white/5">
                        <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block tracking-widest">Remote Path</label>
                        <input type="text" id="config-cloud-path" placeholder="/backups/pro" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-blue-400 outline-none">
                    </div>
                </div>

                <div class="bg-black/20 p-5 rounded-xl border border-white/5 space-y-6">
                    <h3 class="text-[11px] font-black uppercase text-slate-400 border-b border-white/5 pb-2">Authentifizierung</h3>
                    <div class="mb-4">
                         <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block tracking-widest">Server Host (nur SFTP)</label>
                         <input type="text" id="config-cloud-host" placeholder="z.B. 192.168.1.100 oder sftp.example.com" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-blue-400 outline-none focus:border-blue-500 mono">
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                             <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block tracking-widest">Benutzer / ID</label>
                             <input type="text" id="config-cloud-user" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500">
                        </div>
                        <div>
                             <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block tracking-widest">Passwort / Secret</label>
                             <input type="password" id="config-cloud-password" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500">
                        </div>
                    </div>
                    <div class="mt-4">
                         <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block tracking-widest">API-Key (Optional)</label>
                         <input type="text" id="config-cloud-api-key" placeholder="Optionaler API Key..." class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-blue-400 outline-none focus:border-blue-500 mono">
                    </div>
                </div>

                <div class="bg-black/20 p-5 rounded-xl border border-white/5 space-y-4">
                    <h3 class="text-[11px] font-black uppercase text-slate-400 border-b border-white/5 pb-2">Sicherheit</h3>
                    <div class="flex items-center gap-4">
                        <input type="checkbox" id="config-enc-enabled" class="w-4 h-4 bg-[#08090d] border-white/10 rounded">
                        <label for="config-enc-enabled" class="text-[11px] font-bold text-white uppercase tracking-wider">AES-256 Verschlüsselung aktivieren</label>
                    </div>
                    <div>
                        <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block tracking-widest">Encryption Password</label>
                        <input type="password" id="config-enc-password" placeholder="Sicheres Passwort für das Archiv..." class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-yellow-500 outline-none focus:border-yellow-500">
                    </div>
                </div>

                <div class="bg-black/20 p-5 rounded-xl border border-white/5 space-y-4">
                    <div class="flex items-center justify-between">
                         <span class="text-[11px] font-black uppercase text-slate-400">Automatische Cloud-Synchronisierung</span>
                         <span id="cloud-status-badge" class="px-2 py-1 bg-yellow-500/10 border border-yellow-500/20 text-yellow-500 text-[9px] font-black uppercase">Konfiguration erforderlich</span>
                    </div>
                    <p class="text-[11px] text-slate-500 italic">Hinweis: Die Cloud-Synchronisierung überträgt Ihre Snapshots nach Abschluss des lokalen Backups verschlüsselt an den gewählten Provider.</p>
                </div>

                <button onclick="saveProfile()" class="btn-pro w-full py-4 rounded text-sm text-white shadow-lg shadow-blue-500/30">Cloud Parameter Speichern</button>
            </div>
        </section>

        <!-- Tab: Analyse -->
        <section id="tab-duplicates" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden text-slate-200">
            <div class="commander-module p-6 space-y-6">
                <div class="flex justify-between items-center border-b border-white/5 pb-4">
                    <h2 class="text-sm font-black uppercase tracking-widest text-slate-400">Deep-Scan Duplikatanalyse</h2>
                    <button onclick="scanDuplicates()" class="text-[10px] font-black bg-blue-500/10 border border-blue-500/20 px-4 py-2 rounded text-blue-400 hover:bg-blue-500/20 transition-all uppercase tracking-widest">Scan starten</button>
                </div>
                
                <div id="duplicate-results" class="space-y-4">
                    <div class="text-center py-20 opacity-30 italic text-sm">Kein Scan aktiv. Starten Sie die Analyse, um redundante Daten aufzuspüren.</div>
                </div>
            </div>
        </section>

        <!-- Tab: Parameter -->
        <section id="tab-settings" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden text-slate-200">
            <div class="commander-module p-8 max-w-2xl mx-auto text-slate-200">
                <h2 class="text-sm font-black uppercase text-slate-400 border-b border-white/5 pb-4 mb-8">Kernel Parameter & Automatisierung</h2>
                <div class="space-y-8">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                             <label class="text-[10px] font-black uppercase text-slate-500">Source Path</label>
                             <div class="flex gap-2">
                                <input type="text" id="config-source" readonly class="flex-1 bg-[#08090d] border border-white/5 rounded p-2 text-xs mono text-blue-300">
                                <button onclick="pickFile('config-source')" class="bg-white/5 p-2 rounded text-[10px] uppercase font-black transition-colors hover:bg-white/10" title="Einzelne Datei wählen">📄</button>
                                <button onclick="pickFiles('config-source')" class="bg-white/5 p-2 rounded text-[10px] uppercase font-black transition-colors hover:bg-white/10" title="Mehrere Dateien wählen">📑</button>
                                <button onclick="pickFolder('config-source')" class="bg-white/5 p-2 rounded text-[10px] uppercase font-black transition-colors hover:bg-white/10" title="Ordner wählen">📁</button>
                             </div>
                        </div>
                        <div>
                             <label class="text-[10px] font-black uppercase text-slate-500">Target Path</label>
                             <div class="flex gap-2">
                                <input type="text" id="config-dest" readonly class="flex-1 bg-[#08090d] border border-white/5 rounded p-2 text-xs mono text-emerald-300">
                                <button onclick="pickFolder('config-dest')" class="bg-white/5 p-2 rounded text-[10px] uppercase font-black transition-colors hover:bg-white/10">Pick</button>
                             </div>
                        </div>
                    </div>

                    <div class="bg-black/20 p-5 rounded-xl border border-white/5 space-y-4">
                        <div class="flex items-center justify-between">
                            <div class="flex flex-col">
                                <span class="text-[11px] font-black uppercase text-slate-400 tracking-wider">Automatischer Snapshot</span>
                                <span class="text-[9px] text-slate-500">Sichert Daten im gewählten Intervall im Hintergrund.</span>
                            </div>
                            <div class="w-12 h-6 bg-slate-800 rounded-full relative cursor-pointer" onclick="toggleAutoBackup()">
                                <div id="auto-toggle-knob" class="absolute top-1 left-1 w-4 h-4 bg-slate-500 rounded-full transition-all"></div>
                            </div>
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="text-[10px] font-black uppercase text-slate-500 mb-1 block">Intervall (Minuten)</label>
                                <input type="number" id="config-auto-interval" placeholder="z.B. 60" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-blue-400 outline-none">
                            </div>
                            <div>
                                <label class="text-[10px] font-black uppercase text-slate-500 mb-1 block">Retention Limit</label>
                                <input type="number" id="config-retention" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none">
                            </div>
                        </div>
                    </div>

                    <button onclick="saveProfile()" class="btn-pro w-full py-4 rounded text-sm text-white shadow-xl shadow-blue-600/20">Parameter persistent speichern</button>
                </div>
            </div>
        </section>

        <!-- Tab: Handbook (Optimiert v7.3) -->
        <section id="tab-help" class="tab-content flex-1 overflow-y-auto p-8 hidden text-slate-200">
            <div class="max-w-5xl mx-auto pb-24">
                
                <!-- Header -->
                <header class="text-center space-y-4 mb-10 pt-4">
                    <h1 class="text-3xl font-black text-white tracking-widest uppercase italic">Benutzerhandbuch</h1>
                    <div class="h-1 w-16 bg-emerald-500 mx-auto rounded-full"></div>
                    <p class="text-slate-500 max-w-lg mx-auto text-sm leading-relaxed">Einfache Anleitung für Backup Pro.</p>
                </header>

                <!-- 00 Erste Schritte (User Requested Style) -->
                <div class="commander-module p-8 bg-emerald-500/5 border border-emerald-500/20 rounded-xl mb-12 shadow-lg shadow-emerald-500/5">
                    <h3 class="text-xl font-black text-emerald-400 mb-6 uppercase tracking-wider flex items-center gap-3">
                        <span class="text-2xl">🚀</span> 00 Erste Schritte & Workflow
                    </h3>
                    <div class="space-y-6 text-sm text-slate-300 leading-relaxed">
                        <div class="bg-black/20 p-4 rounded-lg border border-white/5">
                            <p class="mb-2"><strong class="text-white">Willkommen!</strong> Backup Pro ist so aufgebaut, dass Sie alles Wichtige sofort finden. Links im Menü sehen Sie die 5 Bereiche:</p>
                            <ul class="list-disc pl-5 space-y-1 text-xs text-slate-400 marker:text-emerald-500">
                                <li><strong class="text-white">01 ZENTRALE:</strong> Ihre Hauptübersicht. Hier starten Sie Backups und sehen, ob alles okay ist.</li>
                                <li><strong class="text-white">02 RESTORE:</strong> "Wiederherstellen". Hier holen Sie gelöschte Dateien zurück.</li>
                                <li><strong class="text-white">03 CLOUD:</strong> Wenn Sie Ihre Daten auch im Internet sichern wollen (optional).</li>
                                <li><strong class="text-white">04 ANALYSE:</strong> Hilft beim Aufräumen von doppelten Dateien.</li>
                                <li><strong class="text-white">05 PARAMETER:</strong> Die Einstellungen. Hier legen Sie fest, WAS und WOHIN gesichert wird.</li>
                            </ul>
                        </div>
                        
                        <div>
                            <h4 class="font-bold text-white text-base mb-3 border-b border-white/10 pb-2">Ihr erstes Backup in 3 Minuten:</h4>
                            <ol class="list-decimal pl-5 space-y-3 text-sm text-slate-300 marker:text-emerald-500 marker:font-bold">
                                <li>Klicken Sie links auf <strong class="text-emerald-400">05 PARAMETER</strong>.</li>
                                <li>Bei "Source Path" (Quelle): Wählen Sie einen <strong>Ordner</strong> (📁), eine <strong>einzelne Datei</strong> (📄) oder <strong>mehrere Dateien</strong> (📑) aus.</li>
                                <li>Bei "Target Path" (Ziel): Wählen Sie den Ort, wo die Sicherung hin soll (z.B. USB-Stick).</li>
                                <li>Klicken Sie unten auf den großen Button <strong class="text-white bg-blue-600/20 px-2 py-0.5 rounded border border-blue-500/30">Parameter persistent speichern</strong>.</li>
                                <li>Gehen Sie zurück zur <strong class="text-emerald-400">01 ZENTRALE</strong>.</li>
                                <li>Klicken Sie auf <strong>"Snapshot anlegen"</strong> (Blitz-Symbol). Das war's!</li>
                            </ol>
                        </div>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4">
                            <div class="bg-red-500/5 p-4 rounded border border-red-500/10">
                                <h4 class="font-bold text-red-400 mb-2 text-xs uppercase tracking-wider">⚠️ Daten wiederherstellen (Restore)</h4>
                                <p class="text-xs text-slate-400">Wenn eine Datei fehlt, gehen Sie zu <strong>02 RESTORE</strong>. Wählen Sie das Datum und klicken Sie auf "Restore". <br><br><strong>ACHTUNG:</strong> Der gesamte Ordner wird auf diesen alten Stand zurückgesetzt. Neue Dateien könnten dabei verloren gehen!</p>
                            </div>
                            <div class="bg-blue-500/5 p-4 rounded border border-blue-500/10">
                                <h4 class="font-bold text-blue-400 mb-2 text-xs uppercase tracking-wider">💡 Platz sparen mit Analyse</h4>
                                <p class="text-xs text-slate-400">Unter <strong>04 ANALYSE</strong> sucht das Programm nach doppelten Dateien. Wenn Sie diese vor dem Backup löschen, geht das Backup schneller und braucht weniger Platz.</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Divider -->
                <div class="flex items-center gap-4 mb-12 opacity-30">
                    <div class="h-px bg-white flex-1"></div>
                    <span class="text-xs uppercase tracking-widest">Wissen & Details</span>
                    <div class="h-px bg-white flex-1"></div>
                </div>

                <!-- Detailed Handbook Grid -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-12">
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">01</span> Was ist ein Snapshot?</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Ein "Snapshot" ist wie ein Foto Ihrer Daten zu einem bestimmten Zeitpunkt. Backup Pro packt alle Ihre Dateien in ein Päckchen (ZIP-Datei). So können Sie später genau diesen Zustand wiederherstellen.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">02</span> Aufräum-Regel (Retention)</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Damit Ihre Festplatte nicht voll wird, löscht Backup Pro automatisch uralte Sicherungen. Unter "Parameter" -> "Retention Limit" stellen Sie ein, wie viele Backups Sie behalten wollen (z.B. die letzten 10). Das älteste wird dann automatisch gelöscht.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">03</span> Delta (Änderungen)</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">In der <strong>01 ZENTRALE</strong> sehen Sie "Change Delta". Das zeigt einfach an, wie viel sich seit dem letzten Backup verändert hat. Viele Änderungen = Zeit für ein neues Backup!</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">04</span> Cloud & Server</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Unter <strong>03 CLOUD</strong> können Sie eine zusätzliche Sicherung im Internet einrichten. Wichtig: Tragen Sie bei "Server Host" die Adresse Ihres Servers ein. Das Backup wird dann automatisch nach dem lokalen Backup hochgeladen.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">05</span> Fehlerbehebung</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Wenn ein Backup fehlschlägt, ist meistens eine Datei noch geöffnet (z.B. eine Excel-Tabelle). Schließen Sie alle Programme und versuchen Sie es nochmal. Prüfen Sie auch, ob der USB-Stick voll ist.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">06</span> System Health (Ampel)</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Die "System Health" in der Zentrale ist wie eine Ampel. Grün ist super. Gelb heißt "naja". Rot heißt "Achtung!". Wenn sie rot ist, sollten Sie dringend ein Backup machen oder Speicherplatz freigeben.</p>
                    </div>
                </div>

                <!-- Profi Tipps -->
                <div class="commander-module p-6 bg-blue-500/5 border border-blue-500/20 rounded-xl">
                    <h4 class="text-xs font-black uppercase text-blue-400 mb-4 tracking-widest">Profi Tipps</h4>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 text-[11px] mono text-slate-400">
                        <ul class="space-y-3">
                            <li class="flex gap-2"><span class="text-blue-500">>></span> <span>Machen Sie vor jedem Windows-Update oder großen Änderungen ein Backup. Sicher ist sicher.</span></li>
                            <li class="flex gap-2"><span class="text-blue-500">>></span> <span>Denken Sie daran: Ein Restore macht alles wie früher. Kopieren Sie wichtige neue Dateien vorher woanders hin!</span></li>
                        </ul>
                        <ul class="space-y-3">
                            <li class="flex gap-2"><span class="text-blue-500">>></span> <span>Sie können unter Parameter ein "Intervall" einstellen (z.B. 60 Minuten). Dann müssen Sie gar nichts mehr drücken.</span></li>
                            <li class="flex gap-2"><span class="text-blue-500">>></span> <span>Icons: Gelbes Schild = "Datei geändert", Rotes Kreuz = "Datei gelöscht", Grünes Plus = "Datei neu".</span></li>
                        </ul>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <script>
        let storageChart = null;
        let globalHistory = [];
        let currentDiskUsedPercent = 0;
        let currentLimit = 10;
        let cloudEnabled = false;
        let autoBackupEnabled = false;
        let globalUnit = 'MB';

        function updateAutoToggleUI() {
            const knob = document.getElementById('auto-toggle-knob');
            if(autoBackupEnabled) {
                knob.style.left = '24px';
                knob.style.backgroundColor = '#0084ff';
            } else {
                knob.style.left = '4px';
                knob.style.backgroundColor = '#64748b';
            }
        }

        function toggleAutoBackup() {
            autoBackupEnabled = !autoBackupEnabled;
            updateAutoToggleUI();
        }

        async function loadConfigUI() {
            const resp = await fetch('/api/get_config');
            const conf = await resp.json();
            
            // Bestehende Felder
            if(document.getElementById('config-source')) document.getElementById('config-source').value = conf.default_source || "";
            if(document.getElementById('config-dest')) document.getElementById('config-dest').value = conf.default_dest || "";
            if(document.getElementById('config-retention')) document.getElementById('config-retention').value = conf.retention_count || 10;
            if(document.getElementById('config-auto-interval')) document.getElementById('config-auto-interval').value = conf.auto_interval || 0;
            
            autoBackupEnabled = conf.auto_backup_enabled || false;
            updateAutoToggleUI();
            
            // Cloud Felder
            if(document.getElementById('config-cloud-provider')) document.getElementById('config-cloud-provider').value = conf.cloud_provider || "SFTP";
            if(document.getElementById('config-cloud-host')) document.getElementById('config-cloud-host').value = conf.cloud_host || "";
            if(document.getElementById('config-cloud-path')) document.getElementById('config-cloud-path').value = conf.cloud_target_path || "";
            if(document.getElementById('config-cloud-user')) document.getElementById('config-cloud-user').value = conf.cloud_user || "";
            if(document.getElementById('config-cloud-password')) document.getElementById('config-cloud-password').value = conf.cloud_password || "";
            if(document.getElementById('config-cloud-api-key')) document.getElementById('config-cloud-api-key').value = conf.cloud_api_key || "";
            
            // Encryption Felder
            if(document.getElementById('config-enc-enabled')) document.getElementById('config-enc-enabled').checked = conf.encryption_enabled || false;
            if(document.getElementById('config-enc-password')) document.getElementById('config-enc-password').value = conf.encryption_password || "";
        }

        function updateHeaderClock() {
            const now = new Date();
            const timeStr = now.toLocaleTimeString('de-DE', { hour12: false });
            const dateStr = now.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' });
            if(document.getElementById('header-time')) document.getElementById('header-time').innerText = timeStr;
            if(document.getElementById('header-date')) document.getElementById('header-date').innerText = dateStr;
        }
        setInterval(updateHeaderClock, 1000);
        updateHeaderClock();

        function setGlobalUnit(unit) {
            globalUnit = unit;
            document.querySelectorAll('.unit-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById('unit-' + unit.toLowerCase()).classList.add('active');
            const header = document.getElementById('history-size-header');
            if(header) header.innerText = `Größe (${unit})`;
            updateDashboardDisplays();
        }

        /**
         * Formatiert Byte-Werte basierend auf der gewählten Einheit.
         * Erhöht die Präzision im GB Modus für kleine Werte, um "0,0 GB" zu vermeiden.
         */
        function formatSize(bytes) {
            if (!bytes || bytes === 0) return "0,00 " + globalUnit;
            const isGB = globalUnit === 'GB';
            const divisor = isGB ? (1024**3) : (1024**2);
            let val = bytes / divisor;
            
            // User Request: MB mit 2 Nachkommastellen
            let precision = 1;
            if (!isGB) {
                precision = 2;
            } else {
                // GB: Dynamisch (2 bei sehr kleinen Werten, sonst 1)
                precision = (val < 0.1 && val > 0) ? 2 : 1;
            }
            return val.toFixed(precision).replace('.', ',') + " " + globalUnit;
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.sidebar-item').forEach(el => el.classList.remove('active'));
            document.getElementById('tab-' + tabId).classList.remove('hidden');
            document.getElementById('nav-' + tabId).classList.add('active');
            if(tabId === 'dashboard' && storageChart) {
                setTimeout(() => { storageChart.resize(); storageChart.update(); }, 100);
            }
        }

        function calculateHealth() {
            let score = 0;
            let covPts = 0, recPts = 0, dskPts = 0;
            const healthEl = document.getElementById('score-val');
            const labelEl = document.getElementById('health-label');
            
            covPts = Math.min(40, (globalHistory.length / currentLimit) * 40);
            score += covPts;

            if (globalHistory.length > 0) {
                const last = new Date(globalHistory[globalHistory.length - 1].timestamp.replace(' ', 'T'));
                const diffHours = (new Date() - last) / (1000 * 60 * 60);
                if (diffHours < 24) recPts = 40;
                else if (diffHours < 72) recPts = 20;
                else recPts = 5;
            }
            score += recPts;

            if (currentDiskUsedPercent < 80) dskPts = 20;
            else if (currentDiskUsedPercent < 95) dskPts = 10;
            else dskPts = 2;
            score += dskPts;

            const finalScore = Math.min(100, Math.round(score));
            if(healthEl) healthEl.innerText = finalScore;
            
            if(document.getElementById('bar-cov')) document.getElementById('bar-cov').style.width = (covPts / 40 * 100) + "%";
            if(document.getElementById('bar-rec')) document.getElementById('bar-rec').style.width = (recPts / 40 * 100) + "%";
            if(document.getElementById('bar-disk')) document.getElementById('bar-disk').style.width = (dskPts / 20 * 100) + "%";

            if(healthEl) {
                healthEl.classList.remove('score-good', 'score-warn', 'score-crit');
                if(finalScore > 80) { healthEl.classList.add('score-good'); labelEl.innerText = "Status: Optimal"; }
                else if(finalScore > 40) { healthEl.classList.add('score-warn'); labelEl.innerText = "Status: Eingeschränkt"; }
                else { healthEl.classList.add('score-crit'); labelEl.innerText = "Status: Kritisch"; }
            }
        }

        function initChart() {
            const ctx = document.getElementById('storageChart').getContext('2d');
            storageChart = new Chart(ctx, {
                type: 'line',
                data: { labels: [], datasets: [{ 
                    label: 'Snapshot Size', data: [], borderColor: '#0084ff', backgroundColor: 'rgba(0, 132, 255, 0.05)', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 4, pointBackgroundColor: '#0084ff'
                }]},
                options: { 
                    responsive: true, maintainAspectRatio: false, 
                    plugins: { legend: { display: false } }, 
                    scales: { 
                        x: { grid: { display: false }, ticks: { color: '#666', font: { size: 9 } } }, 
                        y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#475569', font: { size: 9 } } } 
                    } 
                }
            });
        }

        async function scanDuplicates() {
            const source = document.getElementById('source').value;
            if(!source) return addLog("Kein Quellpfad für Analyse gewählt.", "error");
            
            const resultsDiv = document.getElementById('duplicate-results');
            resultsDiv.innerHTML = '<div class="text-center py-20 animate-pulse text-blue-400 font-black uppercase tracking-widest">Analysiere Datei-Integritäten...</div>';
            
            try {
                const resp = await fetch('/api/find_duplicates', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path: source}) });
                const data = await resp.json();
                
                if(data.length === 0) {
                    resultsDiv.innerHTML = '<div class="text-center py-20 text-emerald-500 font-bold">Keine redundanten Daten im Quellverzeichnis gefunden. Optimaler Zustand.</div>';
                } else {
                    resultsDiv.innerHTML = '<h3 class="text-xs font-black uppercase text-red-400 mb-4">Redundanzen gefunden:</h3>';
                    data.forEach(group => {
                        let groupHtml = '<div class="bg-black/40 border border-white/5 p-4 rounded-xl space-y-2">';
                        groupHtml += `<div class="text-[10px] uppercase font-black text-slate-500">Hash-Match (ID: ${Math.random().toString(16).slice(2,8)})</div>`;
                        group.files.forEach(f => {
                            groupHtml += `<div class="text-xs mono text-slate-300 truncate opacity-70 border-l border-red-500/30 pl-3">${f}</div>`;
                        });
                        groupHtml += '</div>';
                        resultsDiv.insertAdjacentHTML('beforeend', groupHtml);
                    });
                }
            } catch(e) {
                resultsDiv.innerHTML = '<div class="text-center py-20 text-red-500 font-bold">Fehler bei der Analyse. Kernel-Zugriff verweigert.</div>';
            }
        }

        async function updateDiskStats() {
            const dest = document.getElementById('dest').value;
            if(!dest) return;
            try {
                const resp = await fetch('/api/get_disk_stats', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path: dest}) });
                const data = await resp.json();
                if(data.total > 0) {
                    currentDiskUsedPercent = (data.used / data.total) * 100;
                    if(document.getElementById('disk-bar')) document.getElementById('disk-bar').style.width = currentDiskUsedPercent + '%';
                    if(document.getElementById('disk-percent')) document.getElementById('disk-percent').innerText = currentDiskUsedPercent.toFixed(1) + '%';
                    if(document.getElementById('disk-free-val')) document.getElementById('disk-free-val').innerText = formatSize(data.free);
                    if(document.getElementById('disk-total-val')) document.getElementById('disk-total-val').innerText = formatSize(data.total);
                    calculateHealth();
                }
            } catch(e) {}
        }

        async function loadData() {
            try {
                // UI Felder aus Config laden
                await loadConfigUI();
                
                const cResp = await fetch('/api/get_config');
                const config = await cResp.json();
                currentLimit = config.retention_count || 10;
                
                document.getElementById('source').value = config.default_source || "";
                document.getElementById('dest').value = config.default_dest || "";
                
                const badge = document.getElementById('cloud-status-badge');
                if(config.cloud_user && (config.cloud_password || config.cloud_api_key)) {
                    badge.innerText = "Bereit zum Sync";
                    badge.classList.replace('text-yellow-500', 'text-emerald-500');
                    badge.classList.replace('bg-yellow-500/10', 'bg-emerald-500/10');
                    badge.classList.replace('border-yellow-500/20', 'border-emerald-500/20');
                }
                
                if(config.auto_backup_enabled && !autoBackupEnabled) toggleAutoBackup();

                const hResp = await fetch('/api/get_history');
                globalHistory = await hResp.json();
                updateDashboardDisplays();
            } catch(e) { console.error("Load Error:", e); }
        }

        function updateDashboardDisplays() {
            const table = document.getElementById('history-table-body');
            const restoreTable = document.getElementById('restore-table-body');
            if(!table || !restoreTable) return;
            
            table.innerHTML = ''; restoreTable.innerHTML = '';
            let totalBytes = 0;
            storageChart.data.labels = [];
            storageChart.data.datasets[0].data = [];

            [...globalHistory].reverse().forEach((entry) => {
                totalBytes += entry.size;
                const formatted = formatSize(entry.size);
                const displayValNumeric = formatted.split(' ')[0].replace(',', '.');
                const originalIdx = globalHistory.indexOf(entry);

                table.insertAdjacentHTML('beforeend', `<tr onclick="showDetails(${originalIdx})" class="bg-white/5 border-b border-white/5 cursor-pointer hover:bg-white/10 transition-all">
                    <td class="px-4 py-3 mono text-[10px] text-slate-400">${entry.timestamp}</td>
                    <td class="px-4 py-3 font-bold text-blue-400 text-xs">${entry.filename}</td>
                    <td class="px-4 py-3 text-right mono text-white text-xs">${formatted.split(' ')[0]}</td>
                </tr>`);
                
                restoreTable.insertAdjacentHTML('beforeend', `<tr><td class="px-4 py-3 text-xs text-slate-400 mono">${entry.timestamp}</td><td class="px-4 py-3 font-bold text-xs text-white">${entry.filename}</td><td class="px-4 py-3 flex gap-2"><button onclick="restoreBackup('${entry.filename}')" class="text-[9px] font-black uppercase text-emerald-500 border border-emerald-500/30 px-3 py-1 rounded hover:bg-emerald-500/10 transition-colors">Restore</button><button onclick="deleteBackupApi('${entry.filename}')" class="text-[9px] font-black uppercase text-red-500 border border-red-500/30 px-3 py-1 rounded hover:bg-red-500/10 transition-colors">Delete</button></td></tr>`);
                
                const datePart = entry.timestamp.split(' ')[0].split('-').slice(1).join('.'); 
                storageChart.data.labels.push(datePart);
                storageChart.data.datasets[0].data.push(parseFloat(displayValNumeric));
            });
            
            const totalFmt = formatSize(totalBytes).split(' ');
            if(document.getElementById('total-val-display')) document.getElementById('total-val-display').innerText = totalFmt[0];
            if(document.getElementById('total-unit-display')) document.getElementById('total-unit-display').innerText = totalFmt[1];

            storageChart.data.datasets[0].label = `Größe (${globalUnit})`;
            storageChart.update();
            updateDiskStats();
            
            const sourcePath = document.getElementById('source').value;
            if(sourcePath) {
                fetch('/api/analyze_source', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path: sourcePath}) })
                    .then(r => r.json())
                    .then(sData => {
                        if(document.getElementById('src-size')) document.getElementById('src-size').innerText = formatSize(sData.size);
                        if(document.getElementById('src-files')) document.getElementById('src-files').innerText = sData.count + " FILES";

                        // Delta Calculation
                        const deltaVal = document.getElementById('delta-val');
                        const deltaBadge = document.getElementById('delta-badge');
                        
                        if(deltaVal && deltaBadge && globalHistory.length > 0) {
                            // Sortierung sicherstellen: Wir nehmen an, globalHistory ist chronologisch (letzter Eintrag = aktuellstes Backup)
                            // Aber da wir es oben reversed haben für die Tabelle, ist globalHistory[globalHistory.length - 1] das aktuellste Backup im Original Array
                            // Warte, globalHistory ist das rohe Array vom Server.
                            // Der Server sendet es vermutlich chronologisch (append).
                            // Prüfen wir load_history() -> append. Ja.
                            // Also ist der letzte Eintrag das neuste Backup.
                            
                            const lastEntry = globalHistory[globalHistory.length - 1];
                            const lastCount = lastEntry.file_count || 0;
                            const currentCount = sData.count || 0;
                            const delta = currentCount - lastCount;
                            
                            deltaVal.innerText = (delta > 0 ? "+" : "") + delta;
                            
                            if(delta === 0) {
                                deltaBadge.className = "delta-badge delta-neutral";
                                deltaBadge.innerText = "Neutral";
                            } else if(delta > 0) {
                                deltaBadge.className = "delta-badge delta-plus";
                                deltaBadge.innerText = "Zunahme";
                            } else {
                                deltaBadge.className = "delta-badge delta-minus";
                                deltaBadge.innerText = "Abnahme";
                            }
                        } else if (deltaVal && deltaBadge) {
                            // Kein Backup vorhanden -> Delta ist quasi alles
                            deltaVal.innerText = "+" + (sData.count || 0);
                            deltaBadge.className = "delta-badge delta-plus";
                            deltaBadge.innerText = "Initial";
                        }
                    });
            }
            calculateHealth();
        }

        function addLog(msg, type='info') {
            const log = document.getElementById('log');
            if(!log) return;
            const div = document.createElement('div');
            div.className = `log-${type}`;
            div.innerText = `[${new Date().toLocaleTimeString()}] ${msg}`;
            log.appendChild(div);
            log.scrollTop = log.scrollHeight;
        }

        async function runBackup() {
            const source = document.getElementById('source').value;
            const dest = document.getElementById('dest').value;
            if(!source || !dest) return addLog("Pfade fehlen!", "error");
            
            addLog("Kernel: Initiiere Hintergrund-Job...", "info");
            document.getElementById('zipProgressArea').classList.remove('hidden');
            document.getElementById('cancel-btn').classList.remove('hidden'); // Abbruch-Button zeigen
            document.getElementById('zipPercent').innerText = "0%";
            document.getElementById('zipBar').style.width = "0%";
            
            try {
                // Robustere Fehlerbehandlung für Fetch
                const resp = await fetch('/api/start_backup', { 
                    method: 'POST', headers: {'Content-Type': 'application/json'}, 
                    body: JSON.stringify({source, dest, comment: document.getElementById('snap-comment').value}) 
                });
                
                if (!resp.ok) {
                    throw new Error(`HTTP Error: ${resp.status}`);
                }

                const data = await resp.json();
                
                if(data.status === 'error') {
                     addLog("Start Fehler: " + data.message, "error");
                     document.getElementById('zipProgressArea').classList.add('hidden');
                     document.getElementById('cancel-btn').classList.add('hidden');
                     return;
                }
                
                // Polling starten
                const pollTimer = setInterval(async () => {
                    try {
                        const sResp = await fetch('/api/get_backup_status');
                        if (!sResp.ok) return; // Silent fail on poll error to prevent log spam
                        
                        const sData = await sResp.json();
                        
                        document.getElementById('zipBar').style.width = sData.progress + "%";
                        document.getElementById('zipPercent').innerText = sData.progress + "%";
                        
                        if(!sData.active) {
                            clearInterval(pollTimer);
                            document.getElementById('cancel-btn').classList.add('hidden'); // Abbruch-Button verstecken
                            
                            if(sData.result && sData.result.status === 'success') {
                                addLog("Kernel: Snapshot erfolgreich abgeschlossen.", "success");
                                loadData();
                                setTimeout(() => document.getElementById('zipProgressArea').classList.add('hidden'), 3000);
                            } else {
                                 const msg = sData.result ? sData.result.message : (sData.message || "Unbekannter Fehler");
                                 if (msg.includes("Benutzerabbruch")) {
                                     addLog("Vorgang abgebrochen.", "error");
                                 } else {
                                     addLog("Kernel Error: " + msg, "error");
                                 }
                                 document.getElementById('zipProgressArea').classList.add('hidden');
                            }
                        }
                    } catch(e) {
                        console.error("Polling error", e);
                    }
                }, 1000);

            } catch(e) {
                console.error(e);
                addLog("Netzwerk Fehler: " + e.message, "error");
                document.getElementById('zipProgressArea').classList.add('hidden');
                document.getElementById('cancel-btn').classList.add('hidden');
            }
        }

        async function cancelBackup() {
            try {
                addLog("Sende Abbruch-Signal...", "info");
                const resp = await fetch('/api/cancel_backup');
                const data = await resp.json();
                if(data.status !== 'success') {
                    addLog("Abbruch fehlgeschlagen: " + data.message, "error");
                }
            } catch(e) {
                addLog("Fehler beim Senden des Abbruch-Signals.", "error");
            }
        }

        async function restoreBackup(filename) {
            const dest = document.getElementById('dest').value;
            const source = document.getElementById('source').value;
            addLog("Kernel: Starte Wiederherstellung...", "info");
            const resp = await fetch('/api/restore_backup', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ filename, dest, target: source }) });
            if((await resp.json()).status === 'success') addLog("Kernel: Daten erfolgreich rekonstruiert!", "success");
            else addLog("Restore fehlgeschlagen.", "error");
        }

        async function deleteBackupApi(filename) {
            if(!confirm(`Backup ${filename} wirklich löschen?`)) return;
            const resp = await fetch('/api/delete_backup', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ filename }) });
            const result = await resp.json();
            if(result.status === 'success') {
                addLog("Backup gelöscht.", "info");
                loadData();
            } else addLog("Löschen fehlgeschlagen.", "error");
        }

        function showDetails(idx) {
            const entry = globalHistory[idx];
            document.getElementById('modal-filename').innerText = entry.filename;
            document.getElementById('modal-hash').innerText = entry.sha256;
            document.getElementById('modal-ts').innerText = entry.timestamp;
            document.getElementById('modal-size').innerText = formatSize(entry.size);
            document.getElementById('modal-delete-btn').onclick = () => { closeHashModal(); deleteBackupApi(entry.filename); };
            document.getElementById('hash-modal').classList.add('flex');
        }

        function closeHashModal() { document.getElementById('hash-modal').classList.remove('flex'); }
        async function pickFolder(id) {
            const resp = await fetch('/api/pick_folder');
            const data = await resp.json();
            if(data.path) {
                document.getElementById(id).value = data.path;
                updateDashboardDisplays();
            }
        }

        async function pickFile(id) {
            const resp = await fetch('/api/pick_file');
            const data = await resp.json();
            if(data.path) {
                document.getElementById(id).value = data.path;
                updateDashboardDisplays();
            }
        }

        async function pickFiles(id) {
            const resp = await fetch('/api/pick_files');
            const data = await resp.json();
            if(data.path) {
                document.getElementById(id).value = data.path;
                updateDashboardDisplays();
            }
        }

        async function saveProfile() {
            const conf = { 
                default_source: document.getElementById('config-source').value, 
                default_dest: document.getElementById('config-dest').value, 
                retention_count: parseInt(document.getElementById('config-retention').value),
                auto_interval: parseInt(document.getElementById('config-auto-interval').value) || 0,
                auto_backup_enabled: autoBackupEnabled,
                // Cloud Settings
                cloud_provider: document.getElementById('config-cloud-provider').value,
                cloud_host: document.getElementById('config-cloud-host').value,
                cloud_target_path: document.getElementById('config-cloud-path').value,
                cloud_user: document.getElementById('config-cloud-user').value,
                cloud_password: document.getElementById('config-cloud-password').value,
                cloud_api_key: document.getElementById('config-cloud-api-key').value,
                // Encryption
                encryption_enabled: document.getElementById('config-enc-enabled').checked,
                encryption_password: document.getElementById('config-enc-password').value
            };
            try {
                const resp = await fetch('/api/save_config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(conf) });
                const res = await resp.json();
                if (res.status === 'success') {
                    addLog("Kernel: Parameter persistent gespeichert.", "success");
                    
                    // Visuelles Feedback auf allen Speicher-Buttons
                    const buttons = document.getElementsByTagName('button');
                    for(let btn of buttons) {
                        if(btn.innerText.toLowerCase().includes("speichern")) {
                            const original = btn.innerText;
                            btn.innerText = "ERFOLGREICH GESPEICHERT ✓";
                            btn.style.color = "#4ade80"; // green-400
                            setTimeout(() => {
                                btn.innerText = original;
                                btn.style.color = ""; 
                            }, 2000);
                        }
                    }

                    // Trigger re-load to update history potentially based on new path
                    loadData();
                } else {
                    addLog("Fehler beim Speichern: " + (res.message || "Unbekannt"), "error");
                }
            } catch (e) {
                addLog("Kommunikationsfehler beim Speichern.", "error");
            }
        }

        function copyHash() {
            const hash = document.getElementById('modal-hash').innerText;
            const el = document.createElement('textarea');
            el.value = hash; document.body.appendChild(el); el.select(); document.execCommand('copy'); document.body.removeChild(el);
            addLog("System: Hash in Zwischenablage kopiert.", "info");
        }

        window.onload = () => { initChart(); loadData(); };
    </script>
</body>
</html>
"""

# --- Flask API Endpunkte ---

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/get_config")
def get_config_api():
    return jsonify(load_config())

def run_async_reindex(dest):
    """Wrapper für Re-Indexing im Hintergrund."""
    global reindexing_active
    
    # Schneller Check ohne Lock
    if reindexing_active: 
        return

    with reindexing_lock:
        if reindexing_active:
            return
        reindexing_active = True
    
    try:
        # Kurze Pause, damit der Request-Response-Cycle für die UI erstmal durchgeht
        time.sleep(0.5)
        sync_history_with_disk(dest)
    except Exception as e:
        logger.error(f"Async Re-Index Fehler: {e}")
    finally:
        reindexing_active = False

@app.route("/api/get_history")
def get_history_api():
    # Auto-Sync asynchron starten, um UI nicht zu blockieren
    config = load_config()
    dest = config.get("default_dest")
    
    if dest and not reindexing_active:
        threading.Thread(target=run_async_reindex, args=(dest,), daemon=True).start()
    
    # Sicherstellen, dass wir eine Liste zurückgeben
    history = load_history()
    if history is None:
        history = []
    return jsonify(history)

@app.route("/api/get_disk_stats", methods=["POST"])
def get_disk_stats():
    path = request.json.get("path")
    if not path or not os.path.exists(path): return jsonify({"total": 0, "used": 0, "free": 0})
    try:
        total, used, free = shutil.disk_usage(path)
        return jsonify({"total": total, "used": used, "free": free})
    except:
        return jsonify({"total": 0, "used": 0, "free": 0})

@app.route("/api/save_config", methods=["POST"])
def save_config_api():
    current = load_config()
    current.update(request.json)
    if safe_write_json(CONFIG_FILE, current):
        return jsonify({"status": "success"})
    return jsonify({"status": "error"})

@app.route("/api/pick_files")
def pick_files():
    """Öffnet den Multi-Datei-Dialog (Windows native)."""
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        # askopenfilenames gibt ein Tuple von Pfaden zurück
        file_paths = filedialog.askopenfilenames()
        root.destroy()
        
        # Verbinde Pfade mit | für das Backend
        joined_paths = " | ".join(file_paths) if file_paths else ""
        return jsonify({"path": joined_paths})
    except Exception as e:
        logger.error(f"Fehler im Multi-File-Picker: {e}")
        return jsonify({"path": ""})

@app.route("/api/pick_file")
def pick_file():
    """Öffnet den Datei-Dialog (Windows native)."""
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        file_path = filedialog.askopenfilename()
        root.destroy()
        return jsonify({"path": file_path})
    except Exception as e:
        logger.error(f"Fehler im File-Picker: {e}")
        return jsonify({"path": ""})

@app.route("/api/pick_folder")
def pick_folder():
    """Öffnet den Ordner-Dialog (Windows native)."""
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        folder_path = filedialog.askdirectory()
        root.destroy()
        return jsonify({"path": folder_path})
    except Exception as e:
        logger.error(f"Fehler im Folder-Picker: {e}")
        return jsonify({"path": ""})

@app.route("/api/analyze_source", methods=["POST"])
def analyze_source():
    """Analysiert das Quellverzeichnis auf Größe und Dateianzahl."""
    path = request.json.get("path", "")
    size, count = 0, 0
    
    if not path:
        return jsonify({"size": 0, "count": 0})
        
    # Multi-File Detection
    if "|" in path:
        files = [f.strip() for f in path.split("|") if f.strip()]
        for f in files:
            if os.path.exists(f):
                if os.path.isfile(f):
                    count += 1
                    try: size += os.path.getsize(f)
                    except: pass
                elif os.path.isdir(f):
                    for root, _, fs in os.walk(f):
                        count += len(fs)
                        for file in fs:
                            try: size += os.path.getsize(os.path.join(root, file))
                            except: pass
        return jsonify({"size": size, "count": count})

    # Single File/Folder Detection
    if os.path.exists(path):
        if os.path.isfile(path):
             try:
                 size = os.path.getsize(path)
                 count = 1
             except: pass
        else:
            for root, _, files in os.walk(path):
                count += len(files)
                for f in files:
                    try: 
                        size += os.path.getsize(os.path.join(root, f))
                    except: pass
                    
    return jsonify({"size": size, "count": count})

@app.route("/api/start_backup", methods=["POST"])
def start_backup():
    data = request.json
    source, dest, comment = data.get("source"), data.get("dest"), data.get("comment", "")
    
    if current_job_status["active"]:
        return jsonify({"status": "error", "message": "Backup läuft bereits."})
        
    # Thread starten
    thread = threading.Thread(target=run_backup_logic, args=(source, dest, comment))
    thread.start()
    
    return jsonify({"status": "started", "message": "Backup im Hintergrund gestartet."})

@app.route("/api/get_backup_status")
def get_backup_status():
    return jsonify(current_job_status)

@app.route("/api/restore_backup", methods=["POST"])
def restore_backup():
    """Rekonstruiert Daten aus einem ZIP-Archiv, unterstützt AES."""
    data = request.json
    filename, dest, target = data.get("filename"), data.get("dest"), data.get("target")
    
    config = load_config()
    enc_password = config.get("encryption_password", "")

    if not target:
        return jsonify({"status": "error", "message": "Kein Zielpfad für Restore definiert."})

    # Intelligente Zielpfad-Korrektur für Einzeldatei/Multi-File Szenarien
    if "|" in target or (os.path.exists(target) and os.path.isfile(target)):
        first_path = target.split("|")[0].strip()
        if os.path.exists(first_path) and os.path.isfile(first_path):
            target = os.path.dirname(first_path)
        elif not os.path.exists(first_path):
            target = os.path.dirname(first_path)

    try:
        archive_full_path = os.path.join(dest, filename)
        if not os.path.exists(archive_full_path):
            return jsonify({"status": "error", "message": "Archiv nicht gefunden."})
            
        # Versuche mit pyzipper zu öffnen (kompatibel mit Standard ZIP und AES)
        try:
            with pyzipper.AESZipFile(archive_full_path, 'r') as z:
                # Check ob verschlüsselt
                is_encrypted = False
                for info in z.infolist():
                    if info.flag_bits & 0x1:
                        is_encrypted = True
                        break
                
                if is_encrypted:
                    if not enc_password:
                        return jsonify({"status": "error", "message": "Backup ist verschlüsselt, aber kein Passwort in Konfig."})
                    z.setpassword(enc_password.encode('utf-8'))
                
                z.extractall(target)
        except RuntimeError as re:
            if 'Bad password' in str(re):
                return jsonify({"status": "error", "message": "Falsches Entschlüsselungs-Passwort."})
            raise re
        except Exception as zip_err:
             # Fallback auf Standard zipfile falls pyzipper Probleme macht (selten)
             logger.warning(f"Pyzipper Fehler, versuche Standard-Lib: {zip_err}")
             with zipfile.ZipFile(archive_full_path, 'r') as z:
                z.extractall(target)

        return jsonify({"status": "success"})
    except Exception as e: 
        logger.error(f"Restore Fehler: {e}")
        return jsonify({"status": "error", "message": str(e)})

@app.route("/api/delete_backup", methods=["POST"])
def delete_backup():
    """Löscht ein spezifisches Backup manuell."""
    filename = request.json.get("filename")
    config = load_config()
    dest = config.get("default_dest")
    
    if not dest or not filename:
        return jsonify({"status": "error"})
        
    try:
        path = os.path.join(dest, filename)
        if os.path.exists(path):
            os.remove(path)
            
        history = load_history()
        history = [h for h in history if h['filename'] != filename]
        safe_write_json(HISTORY_FILE, history)
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Löschfehler: {e}")
        return jsonify({"status": "error"})

@app.route("/api/find_duplicates", methods=["POST"])
def find_duplicates_api():
    """Findet redundante Dateien im Quellverzeichnis."""
    path = request.json.get("path")
    if not path or not os.path.exists(path):
        return jsonify([])
    
    hashes = defaultdict(list)
    try:
        for root, _, files in os.walk(path):
            for f in files:
                fpath = os.path.join(root, f)
                # Nur kleine Dateien schnell hashen für UI-Reaktionsfähigkeit
                if os.path.getsize(fpath) < 50 * 1024 * 1024:
                    h = calculate_sha256(fpath)
                    if h != "HASH_ERROR":
                        hashes[h].append(fpath)
                        
        redundant = [{"files": paths} for h, paths in hashes.items() if len(paths) > 1]
        return jsonify(redundant)
    except Exception as e:
        logger.error(f"Duplicate Scan Error: {e}")
        return jsonify([])

if __name__ == "__main__":
    ensure_files_exist()

    # Port-Check und dynamische Zuweisung
    target_port = 5000
    
    # Prüfe ob Port 5000 belegt ist
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', target_port))
    sock.close()
    
    if result == 0: # Port ist belegt (Verbindung erfolgreich)
        # Suche nächsten freien Port
        found_port = target_port + 1
        while found_port < 65535:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            res = sock.connect_ex(('127.0.0.1', found_port))
            sock.close()
            if res != 0: # Port ist frei
                break
            found_port += 1
            
        # User fragen
        try:
            root = tk.Tk()
            root.withdraw() # Hauptfenster verstecken
            root.attributes("-topmost", True) # In den Vordergrund
            
            msg = (f"Der Standard-Port {target_port} ist bereits belegt.\n\n"
                   f"Möchten Sie Backup Pro stattdessen auf Port {found_port} starten?")
            
            should_switch = messagebox.askyesno("Port belegt", msg, parent=root)
            root.destroy()
            
            if should_switch:
                target_port = found_port
            else:
                sys.exit(0) # Beenden wenn User ablehnt
        except Exception as e:
            logger.error(f"Fehler bei Port-Dialog: {e}")
            # Fallback: Einfach den freien Port nehmen ohne Frage (headless?)
            target_port = found_port
    
    # Start Scheduler Thread
    scheduler_thread = threading.Thread(target=auto_backup_scheduler, daemon=True)
    scheduler_thread.start()
    
    # Start Webbrowser
    webbrowser.open(f"http://127.0.0.1:{target_port}")
    
    # Flask Server Start
    app.run(port=target_port, debug=False)