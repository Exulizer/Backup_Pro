import os
import shutil
import hashlib
import json
import time
import zipfile
# import pyzipper -> Lazy Loaded
import fnmatch
import subprocess
import threading
import logging
import errno
# import paramiko -> Lazy Loaded
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template_string, jsonify, request, send_file, Response
import concurrent.futures
# import tkinter as tk -> Lazy Loaded
# from tkinter import filedialog, messagebox -> Lazy Loaded

import sqlite3

# --- Konfiguration & Logging ---

# Logging initialisieren für bessere Fehlerbehebung
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Log Filtering ---
class EndpointFilter(logging.Filter):
    """Filtert erfolgreiche Status-Abfragen aus dem Log, um Spam zu vermeiden."""
    def filter(self, record):
        msg = record.getMessage()
        # Unterdrücke 200 OK Logs für Polling-Endpunkte
        ignored_endpoints = [
            "/api/get_backup_status",
            "/api/get_events",
            "/api/get_cloud_backup_status",
            "/api/scan_progress",
            "/api/stream"
        ]
        if any(endpoint in msg for endpoint in ignored_endpoints) and " 200 " in msg:
            return False
        return True

# Filter auf den Werkzeug-Logger anwenden
logging.getLogger("werkzeug").addFilter(EndpointFilter())

# Globaler Status für Async-Jobs
current_job_status = {
    "active": False,
    "progress": 0,
    "step": "idle",
    "message": "",
    "result": None
}
cloud_job_status = {
    "active": False,
    "progress": 0,
    "step": "idle",
    "message": "",
    "result": None
}
backup_lock = threading.RLock()

def is_backup_locked():
    """Helper to check if RLock is locked by another thread."""
    if backup_lock.acquire(blocking=False):
        backup_lock.release()
        return False
    return True

event_queue = [] # Queue für UI-Nachrichten

# --- SSE Announcer ---
import queue
class MessageAnnouncer:
    def __init__(self):
        self.listeners = []

    def listen(self):
        q = queue.Queue(maxsize=200) # Increased buffer
        self.listeners.append(q)
        return q

    def remove_listener(self, q):
        try:
            self.listeners.remove(q)
        except ValueError:
            pass

    def announce(self, msg, event_type=None):
        if isinstance(msg, dict):
             import json
             data_str = json.dumps(msg)
        else:
             data_str = str(msg)
        
        if event_type:
            sse_msg = f"event: {event_type}\ndata: {data_str}\n\n"
        else:
            sse_msg = f"data: {data_str}\n\n"
        
        for i in reversed(range(len(self.listeners))):
            try:
                self.listeners[i].put_nowait(sse_msg)
            except queue.Full:
                # If full, drop message but keep connection (client might be slow)
                # Cleanup happens in stream() finally block
                pass

sse_announcer = MessageAnnouncer()

def add_event(message, type="info"):
    """Fügt eine Nachricht zur Event-Queue hinzu."""
    global event_queue
    try:
        # Keep queue manageable
        if len(event_queue) > 50:
             event_queue.pop(0)
        
        # Try to translate if it looks like a key
        msg_text = message
        key = None
        try:
            translated = tr(message)
            if translated != message:
                msg_text = translated
                key = message
        except:
            pass
            
        event_data = {"message": msg_text, "key": key, "type": type, "timestamp": time.time()}
        event_queue.append(event_data)
        
        # Push to SSE
        sse_announcer.announce(event_data, event_type="log")
    except: pass


# Re-Indexing Status
reindexing_lock = threading.Lock()
reindexing_active = False

app = Flask(__name__)
app.secret_key = "backup_pro_secure_session_key_992834"

# Pfade definieren
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE = os.path.join(BASE_DIR, "backup_history.json")
DB_FILE = os.path.join(BASE_DIR, "backup_history.db")
CONFIG_FILE = os.path.join(BASE_DIR, "backup_config.json")
I18N_DIR = os.path.join(BASE_DIR, "i18n")
DEFAULT_LANG = "de"
CURRENT_LANG = DEFAULT_LANG
I18N_CACHE = {}

def load_language_dict(lang_code):
    global I18N_CACHE
    if lang_code in I18N_CACHE:
        return I18N_CACHE[lang_code]
    
    path = os.path.join(I18N_DIR, f"lang_{lang_code}.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            I18N_CACHE[lang_code] = data
            return data
        except Exception as e:
            logger.error(f"Failed to load language {lang_code}: {e}")
    return {}

def tr(key, default=None, **kwargs):
    """
    Backend translation helper.
    Uses CURRENT_LANG to find the translation for 'key'.
    If not found, returns default (or key if default is None).
    Supports format strings: tr("hello.name", "Hello {name}", name="World")
    """
    lang_data = load_language_dict(CURRENT_LANG)
    val = lang_data.get(key)
    
    if val is None:
        val = default if default is not None else key
        
    try:
        if kwargs:
            return val.format(**kwargs)
    except:
        pass
    return val

def get_current_language():
    return CURRENT_LANG

def init_db():
    """Initialisiert die SQLite-Datenbank und migriert JSON-Daten falls nötig."""
    try:
        conn = sqlite3.connect(DB_FILE)
        # Performance Optimizations
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
        except: pass
        
        c = conn.cursor()
        
        # Tabelle erstellen
        c.execute('''CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            timestamp TEXT,
            size INTEGER,
            sha256 TEXT,
            path TEXT,
            source_path TEXT,
            comment TEXT,
            file_count INTEGER,
            locked INTEGER DEFAULT 0
        )''')
        
        # Check integrity / missing columns (migration for existing DBs)
        c.execute("PRAGMA table_info(history)")
        columns = [info[1] for info in c.fetchall()]
        
        if "locked" not in columns:
            try:
                c.execute("ALTER TABLE history ADD COLUMN locked INTEGER DEFAULT 0")
                logger.info("Spalte 'locked' zur Datenbank hinzugefügt.")
            except Exception as e:
                logger.error(f"Fehler beim Hinzufügen der Spalte 'locked': {e}")

        if "source_size" not in columns:
            try:
                c.execute("ALTER TABLE history ADD COLUMN source_size INTEGER DEFAULT 0")
                logger.info("Spalte 'source_size' zur Datenbank hinzugefügt.")
            except Exception as e:
                logger.error(f"Fehler beim Hinzufügen der Spalte 'source_size': {e}")

        # Migration von JSON zu SQLite prüfen
        c.execute("SELECT COUNT(*) FROM history")
        count = c.fetchone()[0]
        
        if count == 0 and os.path.exists(HISTORY_FILE):
            logger.info("Migriere backup_history.json zu SQLite...")
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    history_data = json.load(f)
                    if isinstance(history_data, list):
                        for entry in history_data:
                            c.execute('''INSERT INTO history 
                                (filename, timestamp, size, sha256, path, source_path, comment, file_count, locked, source_size)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                                (
                                    entry.get("filename", ""),
                                    entry.get("timestamp", ""),
                                    entry.get("size", 0),
                                    entry.get("sha256", ""),
                                    entry.get("path", ""),
                                    entry.get("source_path", ""),
                                    entry.get("comment", ""),
                                    entry.get("file_count", 0),
                                    1 if entry.get("locked") else 0,
                                    entry.get("source_size", 0)
                                )
                            )
                        logger.info(f"{len(history_data)} Einträge erfolgreich migriert.")
                        # Optional: HISTORY_FILE umbenennen oder löschen nach erfolgreicher Migration
                        # os.rename(HISTORY_FILE, HISTORY_FILE + ".bak")
            except Exception as e:
                logger.error(f"Fehler bei der Migration: {e}")

        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Datenbank-Initialisierungsfehler: {e}")

# Helper functions for DB access
def get_history_from_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row # Dictionary-like access
        c = conn.cursor()
        c.execute("SELECT * FROM history ORDER BY timestamp DESC")
        rows = c.fetchall()
        history = []
        for row in rows:
            history.append(dict(row))
        conn.close()
        return history
    except Exception as e:
        logger.error(f"DB Read Error: {e}")
        return []

def add_history_entry_to_db(entry):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''INSERT INTO history 
            (filename, timestamp, size, sha256, path, source_path, comment, file_count, locked, source_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
            (
                entry.get("filename", ""),
                entry.get("timestamp", ""),
                entry.get("size", 0),
                entry.get("sha256", ""),
                entry.get("path", ""),
                entry.get("source_path", ""),
                entry.get("comment", ""),
                entry.get("file_count", 0),
                1 if entry.get("locked") else 0,
                entry.get("source_size", 0)
            )
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"DB Write Error: {e}")
        return False

def update_history_comment_in_db(filename, new_comment):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("UPDATE history SET comment = ? WHERE filename = ?", (new_comment, filename))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"DB Update Error: {e}")
        return False

def delete_history_entry_from_db(filename):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM history WHERE filename = ?", (filename,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"DB Delete Error: {e}")
        return False

def clear_history_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM history")
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"DB Clear Error: {e}")
        return False

def toggle_lock_in_db(filename):
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Get current state
        c.execute("SELECT locked FROM history WHERE filename = ?", (filename,))
        row = c.fetchone()
        
        if row:
            # Toggle logic: 1 -> 0, 0/None -> 1
            current = row['locked']
            new_state = 0 if current else 1
            
            c.execute("UPDATE history SET locked = ? WHERE filename = ?", (new_state, filename))
            conn.commit()
            conn.close()
            return True, bool(new_state)
        
        conn.close()
        return False, False
    except Exception as e:
        logger.error(f"DB Toggle Lock Error: {e}")
        return False, False

# --- Security Module ---
try:
    from cryptography.fernet import Fernet
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False
    logger.warning("Cryptography module not found. Config encryption disabled.")

SECRET_KEY_FILE = os.path.join(BASE_DIR, ".secret.key")
_cipher_suite = None

def init_security():
    global _cipher_suite
    if not SECURITY_AVAILABLE: return
    try:
        if not os.path.exists(SECRET_KEY_FILE):
            key = Fernet.generate_key()
            with open(SECRET_KEY_FILE, "wb") as f:
                f.write(key)
            # Hide the key file on Windows
            try:
                subprocess.check_call(["attrib", "+H", SECRET_KEY_FILE])
            except: pass
        else:
            with open(SECRET_KEY_FILE, "rb") as f:
                key = f.read()
        _cipher_suite = Fernet(key)
    except Exception as e:
        logger.error(f"Security Init Error: {e}")

def encrypt_value(val):
    if not val or not _cipher_suite: return val
    try:
        if str(val).startswith("ENC:"): return val
        return "ENC:" + _cipher_suite.encrypt(str(val).encode()).decode()
    except: return val

def decrypt_value(val):
    if not val or not _cipher_suite: return val
    if not str(val).startswith("ENC:"): return val
    try:
        return _cipher_suite.decrypt(val[4:].encode()).decode()
    except: return val

# Initialize Security
init_security()

# --- Hilfsfunktionen für Robustheit ---

def format_size(size):
    """Formatiert Bytes in lesbare Größe (KB, MB, GB)."""
    try:
        size = float(size)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    except:
        return "0 B"

def ensure_files_exist():
    """Initialisierung der Systemdateien beim ersten Start mit Fehlerprüfung."""
    try:
        # Initialisiere DB (und migriere falls nötig)
        init_db()

        if not os.path.exists(CONFIG_FILE):
            default_conf = {
                "default_source": "", 
                "default_dest": "", 
                "retention_count": 10,
                "exclusions": "node_modules, .git, .tmp, *.log, __pycache__",
                "safety_snapshots": True,
                "auto_interval": 0, # In Minuten, 0 = Aus
                "auto_backup_enabled": False,
                "auto_shutdown": False,
                "encryption_enabled": False,
                "encryption_password": "",
                "cloud_sync_enabled": False,
                "cloud_provider": "SFTP",
                "cloud_user": "",
                "cloud_password": "",
                "cloud_api_key": "",
                "cloud_target_path": "/backups",
                "naming_custom_text": "backup",
                "naming_include_date": True,
                "naming_include_time": True,
                "naming_include_seq": False,
                "naming_seq_counter": 1
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

def calculate_hash(file_path, salt="", algorithm="sha256", check_abort=None, progress_callback=None):
    """
    Berechnet einen Hash (SHA256 oder BLAKE2b) mit optionalem Salt.
    Optimiert für große Dateien durch Block-Reading (8MB Blöcke).
    check_abort: Optional callable that raises exception if abort requested.
    progress_callback: Optional callable(processed_bytes, total_bytes)
    """
    try:
        # Setup Hash Algo
        if algorithm == "blake2b":
             # 64 bytes digest (512 bits) default. BLAKE2b ist deutlich schneller als SHA256.
             hasher = hashlib.blake2b() 
        else:
             hasher = hashlib.sha256()

        if salt:
            hasher.update(salt.encode('utf-8'))
        
        # Normalisiere Pfad für Windows (Backslashes)
        file_path = os.path.normpath(file_path)
        
        if not os.path.exists(file_path):
            return "FILE_NOT_FOUND"
        
        # Ignoriere Verzeichnisse oder spezielle Links
        if not os.path.isfile(file_path):
            return "HASH_ERROR"

        total_size = 0
        if progress_callback:
            try: total_size = os.path.getsize(file_path)
            except: pass

        processed_bytes = 0

        with open(file_path, "rb") as f:
            # Erhöhte Blockgröße (8MB) für bessere Performance
            while True:
                if check_abort and check_abort():
                     raise Exception("Aborted during hashing")
                chunk = f.read(8 * 1024 * 1024)
                if not chunk: break
                hasher.update(chunk)
                
                if progress_callback and total_size > 0:
                    processed_bytes += len(chunk)
                    progress_callback(processed_bytes, total_size)
        
        digest = hasher.hexdigest()
        
        # Prefix for BLAKE2b to distinguish from SHA256 in DB
        if algorithm == "blake2b":
            return f"blake2b:{digest}"
        return digest
        
    except OSError as e:
        # Errno 22 = Invalid Argument (häufig bei OneDrive "Online Only" Dateien oder zu langen Pfaden)
        if e.errno == 22:
            return "HASH_ERROR" 
        logger.error(f"OS Fehler beim Hashen für {file_path}: {e}")
        return "HASH_ERROR"
    except Exception as e:
        logger.error(f"Fehler beim Berechnen des Hashes für {file_path}: {e}")
        return "HASH_ERROR"

def calculate_sha256(file_path, salt=""):
    """Wrapper für Backward Compatibility."""
    return calculate_hash(file_path, salt, algorithm="sha256")

def is_excluded(item_name, exclusions):
    """Prüft, ob eine Datei oder ein Ordner von der Sicherung ausgeschlossen werden soll."""
    for pattern in exclusions:
        if fnmatch.fnmatch(item_name, pattern) or pattern in item_name:
            return True
    return False

def apply_retention(dest_path, limit, prefix="backup_"):
    """
    Entfernt alte Backups basierend auf dem Namen (enthält Zeitstempel).
    Respektiert 'locked' Status aus der Historie.
    """
    try:
        if not os.path.exists(dest_path):
            return []
            
        # Lade Historie um Locked-Status zu prüfen
        history = load_history()
        locked_filenames = {h['filename'] for h in history if h.get('locked', False)}
        
        # Nur ZIP Dateien erfassen, die dem Backup-Schema entsprechen
        backups = [f for f in os.listdir(dest_path) if f.startswith(prefix) and f.endswith(".zip")]
        # Sortierung nach Name ist bei diesem Zeitstempelformat chronologisch korrekt
        backups.sort()
        
        # Filtere gelockte Backups aus der Lösch-Liste heraus (sie zählen nicht gegen das Limit oder werden übersprungen)
        # Strategie: Wir zählen nur nicht-gelockte Backups gegen das Limit.
        # D.h. wenn Limit=10 und ich habe 5 Locked + 8 Normal = 13 Total.
        # Ich lösche so lange die ältesten Normalen, bis ich <= 10 Normale habe?
        # Oder Strict Count: Total <= 10, aber Locked darf nicht gelöscht werden?
        # User-Friendly: Locked zählt NICHT ins Limit (Bonus-Storage).
        
        deletable_backups = [b for b in backups if b not in locked_filenames]
        
        deleted = []
        while len(deletable_backups) > limit:
            oldest_filename = deletable_backups.pop(0)
            full_path = os.path.join(dest_path, oldest_filename)
            if os.path.exists(full_path):
                try:
                    os.remove(full_path)
                    delete_history_entry_from_db(oldest_filename)
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
    """Lädt die Backup-Historie aus der SQLite-Datenbank."""
    return get_history_from_db()

def sync_history_with_disk(dest_path):
    """
    Synchronisiert die DB-Historie mit den tatsächlichen Dateien auf der Festplatte.
    Fügt fehlende ZIPs hinzu (Re-Indexing) und entfernt Einträge von gelöschten Dateien.
    """
    if not dest_path or not os.path.exists(dest_path):
        return
    
    history = get_history_from_db()
    disk_files = set()
    
    config = load_config()
    custom_text = config.get("naming_custom_text", "backup")
    prefix = (custom_text + "_") if custom_text else "backup_"
    
    # 1. Scanne Disk nach validen Backups
    try:
        for f in os.listdir(dest_path):
            if f.startswith(prefix) and f.endswith(".zip"):
                disk_files.add(f)
    except OSError:
        return

    history_map = {entry['filename']: entry for entry in history}
    changed = False

    # 2. Entferne Einträge aus History, die nicht mehr auf Disk sind
    to_remove = []
    for entry in history:
        filename = entry.get('filename')
        # Wenn wir einen Pfad haben, prüfen wir dort. Sonst im Standard-Dest.
        stored_path = entry.get('path')
        
        if stored_path:
             if not os.path.exists(stored_path):
                 to_remove.append(filename)
        else:
             # Fallback für alte Einträge
             full_path = os.path.join(dest_path, filename)
             if not os.path.exists(full_path):
                 to_remove.append(filename)
    
    if to_remove:
        for fname in to_remove:
            delete_history_entry_from_db(fname)
        changed = True
        logger.info(f"Sync: {len(to_remove)} verwaiste Einträge entfernt.")

    # 3. Füge neue Dateien von Disk zur History hinzu
    missing_files = [f for f in disk_files if f not in history_map]
    
    if missing_files:
        logger.info(f"Sync: {len(missing_files)} neue Dateien gefunden. Starte parallele Indizierung (BLAKE2b)...")
        
        def process_new_file(filename):
            full_path = os.path.join(dest_path, filename)
            try:
                # Timestamp aus Dateinamen parsen
                ts_part = filename.replace("backup_", "").replace(".zip", "")
                try:
                    dt = datetime.strptime(ts_part, "%Y-%m-%d_%H-%M-%S")
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    timestamp = datetime.fromtimestamp(os.path.getmtime(full_path)).strftime("%Y-%m-%d %H:%M:%S")
                
                size = os.path.getsize(full_path)
                
                # Hash berechnen (BLAKE2b ist extrem schnell, wir erhöhen Limit auf 500MB)
                if size < 500 * 1024 * 1024:
                    sha256 = calculate_hash(full_path, algorithm="blake2b")
                else:
                    sha256 = "SHA256_SKIPPED_ON_REINDEX"
                
                return {
                    "filename": filename,
                    "timestamp": timestamp,
                    "size": size,
                    "path": full_path,
                    "sha256": sha256,
                    "source_path": dest_path,
                    "comment": "Re-Indexed / Extern erkannt"
                }
            except Exception as e:
                logger.error(f"Fehler beim Indexieren von {filename}: {e}")
                return None

        # Parallel Execution (4 Workers)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(process_new_file, f) for f in missing_files]
            for future in concurrent.futures.as_completed(futures):
                entry = future.result()
                if entry:
                    add_history_entry_to_db(entry)
                    changed = True
                    logger.info(f"Sync: Datei {entry['filename']} indexiert.")

def send_notifications(config, message, level="info"):
    """
    Versendet Benachrichtigungen via Webhooks (Discord/Telegram).
    Level: 'success', 'error', 'info', 'test'
    """
    try:
        # 1. Check Settings
        notify_on_success = config.get("notify_on_success", False)
        notify_on_error = config.get("notify_on_error", False)
        
        should_send = False
        if level == "success" and notify_on_success: should_send = True
        if level == "error" and notify_on_error: should_send = True
        if level == "test": should_send = True
        
        if not should_send: return

        # 2. Discord Webhook
        discord_url = config.get("discord_webhook_url", "")
        if discord_url and discord_url.startswith("http"):
            color = 3066993 # Green
            if level == "error": color = 15158332 # Red
            
            payload = {
                "username": "Backup Pro",
                "embeds": [{
                    "title": f"Backup Status: {level.upper()}",
                    "description": message,
                    "color": color,
                    "timestamp": datetime.now().isoformat()
                }]
            }
            req = urllib.request.Request(
                discord_url, 
                data=json.dumps(payload).encode('utf-8'), 
                headers={'Content-Type': 'application/json', 'User-Agent': 'BackupPro/7.3'}
            )
            urllib.request.urlopen(req, timeout=5)

        # 3. Telegram Bot
        tg_token = config.get("telegram_token", "")
        tg_chat_id = config.get("telegram_chat_id", "")
        if tg_token and tg_chat_id:
            icon = "✅" if level == "success" else "❌" if level == "error" else "ℹ️"
            text = f"{icon} *Backup Pro*\n\n{message}"
            
            tg_url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
            payload = {"chat_id": tg_chat_id, "text": text, "parse_mode": "Markdown"}
            
            req = urllib.request.Request(
                tg_url, 
                data=json.dumps(payload).encode('utf-8'), 
                headers={'Content-Type': 'application/json'}
            )
            urllib.request.urlopen(req, timeout=5)

    except Exception as e:
        logger.error(f"Notification Error: {e}")

def load_config():
    """Lädt die Konfiguration mit Fehlerprüfung und Entschlüsselung."""
    if not os.path.exists(CONFIG_FILE):
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            config = data if isinstance(data, dict) else {}
            
            # Decrypt sensitive fields
            sensitive = ["cloud_password", "cloud_api_key", "encryption_password"]
            for field in sensitive:
                if field in config:
                    config[field] = decrypt_value(config[field])
            return config
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Fehler beim Laden der Konfiguration: {e}")
        return {}

@app.route("/api/cancel_backup", methods=["GET", "POST"])
def cancel_backup():
    """Setzt das Abbruch-Flag für den laufenden Job."""
    global current_job_status, cloud_job_status
    
    triggered = False
    
    abort_msg = tr("console.abortRequested", "Abbruch angefordert...")
    abort_local = tr("console.abortRequestedLocal", "Benutzerabbruch angefordert (Lokal).")
    abort_cloud = tr("console.abortRequestedCloud", "Benutzerabbruch angefordert (Cloud).")
    abort_processed = tr("console.abortSignalProcessed", "Abbruchsignal verarbeitet.")
    stopping_msg = tr("console.stoppingProcess", "Stoppe Prozess...")
    abort_sent = tr("console.abortSignalSent", "Abbruchsignal an laufende Prozesse gesendet.")
    no_job = tr("console.noActiveJob", "Kein aktiver Job gefunden.")
    
    if current_job_status.get("active"):
        current_job_status["abort_requested"] = True
        current_job_status["message"] = abort_msg
        if "logs" in current_job_status:
            current_job_status["logs"].append(
                f"[{datetime.now().strftime('%H:%M:%S')}] [SYSTEM] {abort_local}"
            )
        triggered = True
    
    if cloud_job_status.get("active"):
        cloud_job_status["abort_requested"] = True
        cloud_job_status["message"] = abort_msg
        if "logs" in cloud_job_status:
             cloud_job_status["logs"].append(
                 f"[{datetime.now().strftime('%H:%M:%S')}] [SYSTEM] {abort_cloud}"
             )
        triggered = True
    
    try:
        sse_announcer.announce({
            "kind": "status_update", 
            "log_entry": f"[{datetime.now().strftime('%H:%M:%S')}] [SYSTEM] {abort_processed}",
            "active": True,
            "message": stopping_msg
        }, event_type="status")
    except:
        pass
    
    if triggered:
        return jsonify({"status": "success", "message": abort_sent})
    else:
        return jsonify({"status": "ignored", "message": no_job})
    
@app.route("/api/test_notification", methods=["POST"])
def test_notification():
    """Testet die Benachrichtigungseinstellungen."""
    try:
        data = request.json
        test_config = {
            "discord_webhook_url": data.get("discord_webhook_url", ""),
            "telegram_token": data.get("telegram_token", ""),
            "telegram_chat_id": data.get("telegram_chat_id", ""),
            "notify_on_success": True, 
            "notify_on_error": True
        }
        
        body = tr("console.testNotificationBody", "Dies ist eine Test-Benachrichtigung von Backup Pro.")
        ok_msg = tr("console.testNotificationResponse", "Test gesendet.")
        send_notifications(test_config, body, "test")
        return jsonify({"status": "success", "message": ok_msg})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

def save_config(config_data):
    """Speichert die Konfiguration sicher und verschlüsselt sensible Daten."""
    try:
        to_save = config_data.copy()
        sensitive = ["cloud_password", "cloud_api_key", "encryption_password"]
        for field in sensitive:
            if field in to_save:
                to_save[field] = encrypt_value(to_save[field])
        
        if safe_write_json(CONFIG_FILE, to_save):
            return True
        else:
            add_event(tr("console.saveConfigIOError", "Fehler beim Speichern der Konfiguration (IO)."), "error")
            return False
    except Exception as e:
        logger.error(f"Fehler beim Speichern der Konfiguration: {e}")
        add_event(tr("console.saveConfigError", "Config Save Error: {error}", error=str(e)), "error")
        return False

# --- GitHub Helper ---

def run_github_sync(config, dest_root, job_status_update=True, status_tracker=None):
    """
    Führt die GitHub-Synchronisierung durch (Clone/Pull).
    Kann unabhängig vom Haupt-Backup aufgerufen werden.
    """
    global current_job_status
    status_obj = status_tracker if status_tracker else current_job_status
    
    # 1. Check Git availability
    if shutil.which("git") is None:
        msg = tr("console.githubGitMissing", "Git ist nicht installiert oder nicht im PATH gefunden.")
        logger.error(msg)
        add_event(msg, "error")
        return {"status": "error", "message": msg}

    gh_url = config.get("github_url", "")
    gh_token = config.get("github_token", "")
    
    if not gh_url:
        return {"status": "skipped", "message": "Keine URL konfiguriert."}

    # Helper for unified status logging
    def log_status(msg, type="info", updates=None):
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            if updates: status_obj.update(updates)
            entry = None
            if msg:
                entry = f"[{timestamp}] [GITHUB] [{type.upper()}] {msg}"
                if "logs" not in status_obj: status_obj["logs"] = []
                status_obj["logs"].append(entry)
            sse_announcer.announce({
                "kind": "status_update", 
                "log_entry": entry,
                "active": status_obj.get("active"),
                "progress": status_obj.get("progress"),
                "step": status_obj.get("step"),
                "message": status_obj.get("message")
            }, event_type="status")
        except: pass

    try:
        if job_status_update:
            log_status(tr("console.githubJobStarted", "Starte GitHub Sync..."), "info", updates={"step": "github", "message": "GitHub Backup...", "progress": 99})
        
        # Determine Repo Name
        repo_name = gh_url.rstrip("/").split("/")[-1]
        if repo_name.endswith(".git"): repo_name = repo_name[:-4]
        
        # Target Path
        custom_gh_path = config.get("github_path", "").strip()
        if custom_gh_path:
            gh_dest_root = custom_gh_path
        else:
            gh_dest_root = os.path.join(dest_root, "github_backups")

        if not os.path.exists(gh_dest_root):
            os.makedirs(gh_dest_root)
            
        repo_path = os.path.join(gh_dest_root, repo_name)
        
        # Auth URL Construction
        auth_url = gh_url
        if gh_token:
            # Encode Token for URL safety (handles special chars)
            encoded_token = urllib.parse.quote(gh_token, safe="")
            
            if "https://" in gh_url:
                auth_url = gh_url.replace("https://", f"https://{encoded_token}@")
            else:
                # Fallback if no protocol specified, assume https
                auth_url = f"https://{encoded_token}@{gh_url}"
        
        # Git Command Environment (prevent interactive prompts)
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        
        # Git Command
        if os.path.exists(os.path.join(repo_path, ".git")):
            # Pull
            log_status(tr("console.githubUpdating", "GitHub: Updating {name}...", name=repo_name), "info")
            
            # Update Remote URL to ensure latest token is used
            try:
                subprocess.run(["git", "-C", repo_path, "remote", "set-url", "origin", auth_url], 
                             check=True, capture_output=True, env=env)
            except:
                pass # Ignore error if remote doesn't exist, pull might still work or fail later
            
            subprocess.run(["git", "-C", repo_path, "pull"], check=True, capture_output=True, env=env)
            msg = tr("console.githubRepoUpdated", "GitHub: Repo {name} aktualisiert.", name=repo_name)
            log_status(msg, "success")
            add_event(msg, "success")
            return {"status": "success", "message": msg}
        else:
            # Clone
            log_status(tr("console.githubCloning", "GitHub: Cloning {name}...", name=repo_name), "info")
            subprocess.run(["git", "clone", auth_url, repo_path], check=True, capture_output=True, env=env)
            msg = tr("console.githubRepoCloned", "GitHub: Repo {name} geklont.", name=repo_name)
            log_status(msg, "success")
            add_event(msg, "success")
            return {"status": "success", "message": msg}
            
    except subprocess.CalledProcessError as e:
        err_raw = e.stderr.decode() if e.stderr else str(e)
        # Mask token in logs
        clean_err = err_raw
        if gh_token and len(gh_token) > 5:
             clean_err = clean_err.replace(gh_token, "***")
        
        logger.error(f"GitHub Error: {clean_err}")
        msg = tr("console.githubError", "GitHub Fehler: {error}", error=clean_err)
        log_status(msg, "error")
        add_event(msg, "error")
        return {"status": "error", "message": clean_err}
    except Exception as e:
        logger.error(f"GitHub Module Error: {e}")
        msg = tr("console.githubError", "GitHub Fehler: {error}", error=str(e))
        log_status(msg, "error")
        add_event(msg, "error")
        return {"status": "error", "message": str(e)}

# --- Datenbank Helper ---

def run_db_dump(config, dest_root, job_status_update=True, status_tracker=None):
    """
    Führt einen Datenbank-Dump durch (MySQL/PostgreSQL).
    """
    global current_job_status
    status_obj = status_tracker if status_tracker else current_job_status
    
    if not config.get("db_backup_enabled", False):
        return {"status": "skipped", "message": "DB Backup deaktiviert."}

    db_type = config.get("db_type", "mysql")
    host = config.get("db_host", "localhost")
    port = config.get("db_port", "3306")
    user = config.get("db_user", "root")
    password = config.get("db_password", "")
    db_names = config.get("db_names", "*")
    
    # Helper for unified status logging
    def log_status(msg, type="info", updates=None):
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            if updates: status_obj.update(updates)
            entry = None
            if msg:
                entry = f"[{timestamp}] [DB] [{type.upper()}] {msg}"
                if "logs" not in status_obj: status_obj["logs"] = []
                status_obj["logs"].append(entry)
            sse_announcer.announce({
                "kind": "status_update", 
                "log_entry": entry,
                "active": status_obj.get("active"),
                "progress": status_obj.get("progress"),
                "step": status_obj.get("step"),
                "message": status_obj.get("message")
            }, event_type="status")
        except: pass

    if job_status_update:
        log_status(f"Dumping {db_type}...", "info", updates={"step": "database", "message": f"Dumping {db_type}...", "progress": 50})
        
    # Zielordner
    dump_dir = os.path.join(dest_root, "database_dumps")
    if not os.path.exists(dump_dir):
        os.makedirs(dump_dir)
        
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    outfile = os.path.join(dump_dir, f"{db_type}_dump_{timestamp}.sql")
    
    env = os.environ.copy()
    cmd = []
    
    try:
        if db_type == "mysql":
            # MySQL / MariaDB
            # mysqldump -h host -P port -u user -p --databases ...
            # Password via MYSQL_PWD env var to avoid warning
            env["MYSQL_PWD"] = password
            
            cmd = ["mysqldump", "-h", host, "-P", str(port), "-u", user]
            
            if db_names == "*" or not db_names:
                cmd.append("--all-databases")
            else:
                cmd.append("--databases")
                # Split by comma and strip
                dbs = [d.strip() for d in db_names.split(",") if d.strip()]
                cmd.extend(dbs)
                
            # Execute
            with open(outfile, "w") as f:
                subprocess.run(cmd, env=env, stdout=f, check=True)
                
        elif db_type == "postgres":
            # PostgreSQL
            env["PGPASSWORD"] = password
            
            if db_names == "*" or not db_names:
                cmd = ["pg_dumpall", "-h", host, "-p", str(port), "-U", user, "-f", outfile]
                subprocess.run(cmd, env=env, check=True)
            else:
                dbs = [d.strip() for d in db_names.split(",") if d.strip()]
                with open(outfile, "w") as f:
                    for db in dbs:
                        cmd = ["pg_dump", "-h", host, "-p", str(port), "-U", user, db]
                        subprocess.run(cmd, env=env, stdout=f, check=True)
                        f.write("\n\n") # Separator
                        
        msg = tr("console.dbDumpSuccess", "DB Dump erfolgreich: {filename}", filename=os.path.basename(outfile))
        log_status(msg, "success")
        add_event(msg, "success")
        return {"status": "success", "message": msg}
        
    except FileNotFoundError:
        err = tr("console.dbExecutableMissing", "DB Fehler: Executable für {db_type} nicht gefunden (mysqldump/pg_dump). Bitte installieren oder zu PATH hinzufügen.", db_type=db_type)
        logger.error(err)
        log_status(err, "error")
        add_event(err, "error")
        return {"status": "error", "message": err}
    except subprocess.CalledProcessError as e:
        err = tr("console.dbDumpExitError", "DB Dump Fehler (Exit {code})", code=e.returncode)
        logger.error(err)
        log_status(err, "error")
        add_event(err, "error")
        return {"status": "error", "message": err}
    except Exception as e:
        logger.error(f"DB Module Error: {e}")
        err = tr("console.dbModuleError", "DB Fehler: {error}", error=str(e))
        log_status(err, "error")
        add_event(err, "error")
        return {"status": "error", "message": err}

# --- Kern-Backup Logik ---

def run_cloud_download_logic(config, dest, status_tracker):
    """
    Spezielle Logik für Cloud Download (Backup Source = Cloud).
    Lädt Dateien vom SFTP herunter, zippt sie und speichert sie lokal.
    """
    def log_status(msg, type="info", updates=None):
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if updates:
                status_tracker.update(updates)
            
            entry = None
            if msg:
                entry = f"[{timestamp}] [CLOUD] [{type.upper()}] {msg}"
                if "logs" not in status_tracker: status_tracker["logs"] = []
                status_tracker["logs"].append(entry)
                
            sse_announcer.announce({
                "kind": "status_update", 
                "log_entry": entry,
                "active": status_tracker.get("active"),
                "progress": status_tracker.get("progress"),
                "step": status_tracker.get("step"),
                "message": status_tracker.get("message")
            }, event_type="status")
        except: pass

    try:
        c_host = config.get("cloud_host", "")
        c_user = config.get("cloud_user", "")
        c_pass = config.get("cloud_password", "")
        c_path = config.get("cloud_target_path", "/backups")
        
        provider = config.get("cloud_provider", "SFTP")
        
        if provider != "SFTP":
             log_status(f"Cloud Download für {provider} noch nicht implementiert.", "warning")
             return {"status": "error", "message": "Nur SFTP Download unterstützt."}

        log_status(f"Verbinde zu SFTP: {c_host}...", "info", updates={"step": "cloud_download", "message": f"Verbinde zu {c_host}...", "progress": 10})
        
        import paramiko
        from stat import S_ISDIR
        
        # Connection Logic
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        port = 22
        if config.get("cloud_port"):
            try: port = int(config.get("cloud_port"))
            except: pass
            
        ssh.connect(c_host, port=port, username=c_user, password=c_pass, timeout=20)
        sftp = ssh.open_sftp()
        
        log_status(tr("console.cloudConnSuccess", "Verbindung hergestellt.") + " " + tr("console.startManualCloud", "Starte Download..."), "info")
        
        # Temp Folder
        temp_dir = os.path.join(dest, ".cloud_temp_" + str(int(time.time())))
        os.makedirs(temp_dir, exist_ok=True)
        
        downloaded_count = 0
        
        def _recursive_download(remote_dir, local_dir):
            nonlocal downloaded_count
            try:
                for entry in sftp.listdir_attr(remote_dir):
                    remote_file = remote_dir.rstrip("/") + "/" + entry.filename
                    local_file = os.path.join(local_dir, entry.filename)
                    
                    if S_ISDIR(entry.st_mode):
                        os.makedirs(local_file, exist_ok=True)
                        _recursive_download(remote_file, local_file)
                    else:
                        sftp.get(remote_file, local_file)
                        downloaded_count += 1
                        if downloaded_count % 10 == 0:
                            log_status(f"Downloading: {entry.filename}", "info")
            except Exception as e:
                logger.warning(f"Fehler bei {remote_dir}: {e}")

        try:
            _recursive_download(c_path, temp_dir)
            
            log_status(tr("console.cloudSuccess", "Download abgeschlossen.") + f" {downloaded_count} files.", "success")
            
            # Now ZIP
            log_status(tr("backup.archiving", "Erstelle lokales Archiv...", count="?", size="?"), "info", updates={"step": "archiving", "message": "Archiving...", "progress": 60})
            
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            zip_name = f"cloud_download_{timestamp}.zip"
            zip_path = os.path.join(dest, zip_name)
            
            # --- Robust Chunked Zipping Implementation ---
            files_to_zip = []
            total_size_to_zip = 0
            
            # 1. Pre-Scan for Size & Progress Calculation
            scan_count = 0
            for root, dirs, files in os.walk(temp_dir):
                if status_tracker.get("abort_requested"): raise Exception("Benutzerabbruch beim Scan")
                for file in files:
                    fp = os.path.join(root, file)
                    try:
                        sz = os.path.getsize(fp)
                        total_size_to_zip += sz
                        files_to_zip.append((fp, os.path.relpath(fp, temp_dir), sz))
                        scan_count += 1
                        if scan_count % 1000 == 0:
                            log_status(f"Scan für Archiv: {scan_count} Dateien...", "info")
                    except: pass
            
            processed_zip_bytes = 0
            total_uncompressed_size = 0
            
            last_zip_pct = 0
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for fp, arcname, fsize in files_to_zip:
                    # Check Global Abort
                    if status_tracker.get("abort_requested"):
                         raise Exception("Benutzerabbruch beim Cloud-Zippen")
                    
                    # Update Log occasionally for large files
                    if fsize > 20 * 1024 * 1024:
                         log_status(f"Archiviere: {arcname}...", "info")

                    # Use Chunked Writer
                    write_file_to_zip_chunked(zipf, fp, arcname, status_tracker)
                    
                    processed_zip_bytes += fsize
                    total_uncompressed_size += fsize
                    
                    # Progress Update (Scale 60% -> 95%)
                    if total_size_to_zip > 0:
                        pct = 60 + int((processed_zip_bytes / total_size_to_zip) * 35)
                        if pct > 95: pct = 95
                        
                        # Update Tracker directly
                        if status_tracker.get("progress") != pct:
                            status_tracker["progress"] = pct
                            # Force broadcast if percentage changed
                            if pct > last_zip_pct:
                                last_zip_pct = pct
                                log_status(None, updates={"progress": pct})

            log_status(f"Archiv erstellt: {zip_name} ({format_size(os.path.getsize(zip_path))})", "success", updates={"progress": 98})
            
            # Post Processing
            log_status("Verifiziere Integrität (Hash)...", "info")
            
            # Use Check Abort Lambda for Hash Calculation
            check_abort = lambda: status_tracker.get("abort_requested")
            
            last_hash_update = -1
            def hash_progress(curr, total):
                nonlocal last_hash_update
                # Update alle 1% für besseres Feedback
                pct = int((curr / total) * 100)
                if pct > last_hash_update:
                    last_hash_update = pct
                    status_tracker["message"] = f"Verifiziere Integrität: {pct}%"
                    # Explicit SSE Update
                    sse_announcer.announce({
                        "kind": "status_update",
                        "active": True,
                        "step": "hashing",
                        "message": f"Verifiziere Integrität: {pct}%",
                        "progress": 98 
                    }, event_type="status")

            sha256 = calculate_hash(zip_path, algorithm="blake2b", check_abort=check_abort, progress_callback=hash_progress)
            
            if check_abort():
                 raise Exception("Benutzerabbruch bei Hash-Berechnung")

            log_status("Speichere in Datenbank...", "info", updates={"step": "database", "message": "Schreibe Historie...", "progress": 99})

            new_entry = {
                "filename": zip_name,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "size": os.path.getsize(zip_path),
                "sha256": sha256,
                "path": zip_path,
                "source_path": dest,
                "comment": "Cloud Download (SFTP)",
                "file_count": downloaded_count,
                "source_size": total_uncompressed_size
            }
            
            # Use lock to ensure DB integrity
            with backup_lock:
                 if add_history_entry_to_db(new_entry):
                      logger.info(f"Cloud History entry added to DB: {zip_name}")
                      log_status("Datenbank-Eintrag erfolgreich.", "success")
                 else:
                      logger.error("Failed to add Cloud history to DB")
                      log_status("Warnung: Datenbank-Eintrag fehlgeschlagen.", "warning")
            
            # Apply Retention locally
            log_status("Bereinige alte Backups...", "info", updates={"step": "retention", "message": "Bereinige Historie..."})
            limit = config.get("retention_count", 10)
            apply_retention(dest, limit)
            
            status_tracker["progress"] = 100
            status_tracker["message"] = "Cloud Download erfolgreich."
            # Final Status Update with Result
            log_status("Download erfolgreich beendet.", "success", updates={"active": False, "step": "done", "progress": 100})
            
            return {"status": "success", "message": "Download erfolgreich."}
            
        finally:
            try: sftp.close()
            except: pass
            try: ssh.close()
            except: pass
            if os.path.exists(temp_dir): shutil.rmtree(temp_dir, ignore_errors=True)

    except Exception as e:
        logger.error(f"Cloud Download Fehler: {e}")
        log_status(f"FEHLER: {e}", "error")
        return {"status": "error", "message": str(e)}

def create_safety_snapshot(source, dest):
    """
    Erstellt einen Sicherheits-Snapshot, falls in der Config aktiviert.
    Dient dazu, vor kritischen Operationen einen Restore-Punkt zu haben.
    """
    try:
        config = load_config()
        if config.get("safety_snapshots", False):
            # Prüfen ob wir den Lock bekommen können, sonst überspringen wir
            if not is_backup_locked():
                log_status("Erstelle Safety-Snapshot...", "info")
                # Wir rufen run_backup_logic auf, aber müssen aufpassen nicht in Endlosschleife zu geraten
                # Da run_backup_logic selbst den Lock holt, rufen wir es normal auf.
                # Wir starten es NICHT in einem Thread, sondern synchron, damit die nachfolgende Operation wartet.
                # Aber run_backup_logic ist synchron (außer wenn als Thread gestartet).
                run_backup_logic(source, dest, "System Auto-Snapshot (Safety)")
            else:
                logger.warning("Safety-Snapshot übersprungen: Backup läuft bereits.")
    except Exception as e:
        logger.error(f"Safety Snapshot Fehler: {e}")

def write_file_to_zip_chunked(zip_file, source_path, arcname, status_tracker, chunk_size=4*1024*1024):
    """
    Writes a file to the zip archive in chunks to allow cancellation checks.
    Default Chunk Size: 4MB for better throughput.
    """
    if status_tracker.get("abort_requested"): raise Exception("Benutzerabbruch")
    
    # Create ZipInfo manually to set permissions and time correctly
    try:
        st = os.stat(source_path)
        zinfo = zipfile.ZipInfo.from_file(source_path, arcname)
        
        # Try to inherit compression type
        if hasattr(zip_file, 'compression'):
            zinfo.compress_type = zip_file.compression
        
        # If encrypted (pyzipper), we might need special handling, but usually open() handles it.
        # Note: pyzipper's AESZipFile.open(..., 'w') might not support password setting directly on the stream 
        # if not set globally on the zipfile object. Assuming setpassword() was called on zip_file.
        
        with zip_file.open(zinfo, 'w') as dest:
            with open(source_path, 'rb') as src:
                while True:
                    if status_tracker.get("abort_requested"): raise Exception("Benutzerabbruch")
                    chunk = src.read(chunk_size)
                    if not chunk: break
                    dest.write(chunk)
    except Exception as e:
        # Re-raise cancellation
        if "Benutzerabbruch" in str(e): raise
        raise Exception(f"Fehler beim chunked write: {e}")

def run_backup_logic(source, dest, comment="Automatisches Backup", custom_filename_prefix=None, task_options=None, allowed_modules=None):
    global current_job_status, cloud_job_status

    status_tracker = current_job_status
    if task_options and task_options.get("status_target") == "cloud":
        status_tracker = cloud_job_status

    if allowed_modules is None and task_options and "modules" in task_options:
        allowed_modules = task_options["modules"]

    def log_status(msg, type="info", updates=None):
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            if updates:
                status_tracker.update(updates)
            prefix = ""
            if task_options and task_options.get("status_target") == "cloud":
                prefix = "[CLOUD] "
            elif allowed_modules:
                prefix = f"[{'|'.join(allowed_modules).upper()}] "
            entry = None
            if msg:
                entry = f"[{timestamp}] {prefix}[{type.upper()}] {msg}"
                if "logs" not in status_tracker:
                    status_tracker["logs"] = []
                status_tracker["logs"].append(entry)
            sse_announcer.announce(
                {
                    "kind": "status_update",
                    "log_entry": entry,
                    "active": status_tracker.get("active"),
                    "progress": status_tracker.get("progress"),
                    "step": status_tracker.get("step"),
                    "message": status_tracker.get("message"),
                },
                event_type="status",
            )
        except:
            pass

    if not backup_lock.acquire(blocking=False):
        logger.warning("Backup läuft bereits. Abgelehnt.")
        return {"status": "error", "message": "Backup läuft bereits."}

    try:
        job_name = comment if comment else "Manuelles Backup"
        init_msg = tr("backup.validating", f"Initialisiere: {job_name}...")
        log_status(
            init_msg,
            "info",
            updates={
                "active": True,
                "progress": 0,
                "step": "init",
                "job_name": job_name,
                "result": None,
                "abort_requested": False,
                "logs": [],
            },
        )

        if not status_tracker.get("logs"):
            status_tracker["logs"] = []

        if allowed_modules and "cloud" in allowed_modules:
            config = load_config()
            direction = config.get("cloud_direction", "upload")
            if direction == "download":
                start_msg = tr(
                    "backup.startCloudDownload",
                    f"Backup Prozess gestartet: {job_name} (Cloud Download)",
                    name=job_name,
                )
                log_status(start_msg, "info")
                local_dest_path = config.get("cloud_local_path", dest)
                if local_dest_path and local_dest_path.strip():
                    custom_dest_msg = tr(
                        "backup.customCloudLocalDest",
                        f"Verwende benutzerdefinierten lokalen Zielpfad: {local_dest_path}",
                        path=local_dest_path,
                    )
                    log_status(custom_dest_msg, "info")
                    dest = local_dest_path
                return run_cloud_download_logic(config, dest, status_tracker)

        start_msg = tr(
            "backup.startJob",
            f"Backup Prozess gestartet: {job_name}",
            name=job_name,
        )
        log_status(start_msg, "info")

        if allowed_modules is not None:
            mode_msg = tr(
                "backup.isolatedMode",
                "Isolierter Modus (Debug): {modules}",
                modules=", ".join(allowed_modules),
            )
            log_status(mode_msg, "info")
        else:
            mode_msg = tr(
                "backup.standardMode",
                "Standard Modus (Global Config)",
            )
            log_status(mode_msg, "info")

        add_event("console.backupStarted", "info")

        log_status(tr("backup.validating", "Validiere Pfade..."), "debug")
        is_multi_file = "|" in source

        if not is_multi_file and not os.path.exists(source):
            err = tr(
                "backup.sourceMissing",
                "FEHLER: Quellpfad existiert nicht: {path}",
                path=source,
            )
            log_status(err, "error")
            return {"status": "error", "message": err}

        if is_multi_file:
            parts = [p.strip() for p in source.split("|") if p.strip()]
            if not any(os.path.exists(p) for p in parts):
                err = tr(
                    "backup.noValidFiles",
                    "FEHLER: Keine der ausgewählten Dateien existiert.",
                )
                log_status(err, "error")
                return {"status": "error", "message": err}

        if not os.path.exists(dest):
            try:
                msg = tr(
                    "backup.creatingDest",
                    "Erstelle Zielverzeichnis: {path}",
                    path=dest,
                )
                log_status(msg, "info")
                os.makedirs(dest)
            except:
                err = tr(
                    "backup.destCreateFail",
                    "FEHLER: Zielpfad konnte nicht erstellt werden: {path}",
                    path=dest,
                )
                log_status(err, "error")
                return {"status": "error", "message": err}

        try:
            _, _, free_space = shutil.disk_usage(dest)
            if free_space < (500 * 1024 * 1024):
                logger.warning("Kritischer Speicherplatzmangel auf Zielmedium!")
                low_msg = tr(
                    "backup.lowSpace",
                    "WARNUNG: Nur noch {size} MB Speicherplatz!",
                    size=f"{free_space/1024/1024:.1f}",
                )
                status_tracker["message"] = low_msg
                log_status(low_msg, "warning")
        except:
            pass

        config = load_config()
        limit = config.get("retention_count", 10)
        exclusions_raw = config.get("exclusions", "")
        exclusions = [x.strip() for x in exclusions_raw.split(",") if x.strip()]

        enc_enabled = config.get("encryption_enabled", False)
        enc_pw = config.get("encryption_password", "")

        now = datetime.now()
        ts = now.strftime("%Y-%m-%d %H:%M:%S")

        custom_text = config.get("naming_custom_text", "backup")

        try:
            comp_level = int(config.get("compression_level", 3))
            if comp_level < 0:
                comp_level = 0
            if comp_level > 9:
                comp_level = 9
        except:
            comp_level = 3

        if task_options and task_options.get("naming_custom_text"):
            custom_text = task_options.get("naming_custom_text")
        elif custom_filename_prefix:
            custom_text = custom_filename_prefix

        if task_options:
            inc_date = task_options.get("naming_include_date", True)
            inc_time = task_options.get("naming_include_time", True)
            inc_seq = task_options.get("naming_include_seq", False)
        else:
            inc_date = config.get("naming_include_date", True)
            inc_time = config.get("naming_include_time", True)
            inc_seq = config.get("naming_include_seq", False)

        seq_num = config.get("naming_seq_counter", 1)

        name_parts = []
        if custom_text:
            name_parts.append(custom_text)
        if inc_date:
            name_parts.append(now.strftime("%Y-%m-%d"))
        if inc_time:
            name_parts.append(now.strftime("%H-%M-%S"))
        if inc_seq:
            name_parts.append(f"{seq_num:03d}")

        if not name_parts:
            name_parts.append("backup")
            name_parts.append(now.strftime("%Y-%m-%d_%H-%M-%S"))

        zip_filename = "_".join(name_parts) + ".zip"
        zip_path = os.path.join(dest, zip_filename)

        log_status(
            tr("backup.analyzing", "Analysiere Dateistruktur (Parallel)..."),
            "info",
            updates={"step": "archiving", "progress": 5},
        )

        total_files_est = 0
        total_bytes_est = 0

        is_multi_file = "|" in source
        scan_paths = []
        multi_files = []

        if is_multi_file:
            scan_paths = [f.strip() for f in source.split("|") if f.strip()]
            multi_files = scan_paths
        elif os.path.isfile(source):
            scan_paths = [source]
        else:
            try:
                scan_paths = [
                    os.path.join(source, item) for item in os.listdir(source)
                ]
            except:
                scan_paths = []

        def scan_path_worker(path):
            count = 0
            size = 0
            mtime = 0
            if not os.path.exists(path):
                return 0, 0, 0
            if is_excluded(os.path.basename(path), exclusions):
                return 0, 0, 0
            if os.path.isfile(path):
                try:
                    return 1, os.path.getsize(path), os.path.getmtime(path)
                except:
                    return 0, 0, 0
            for r, dirs, f in os.walk(path):
                if status_tracker.get("abort_requested"):
                    return count, size, mtime
                dirs[:] = [d for d in dirs if not is_excluded(d, exclusions)]
                for file in f:
                    if not is_excluded(file, exclusions):
                        count += 1
                        fp = os.path.join(r, file)
                        try:
                            size += os.path.getsize(fp)
                            mt = os.path.getmtime(fp)
                            if mt > mtime:
                                mtime = mt
                        except:
                            pass
            return count, size, mtime

        current_max_mtime = 0
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                future_to_path = {
                    executor.submit(scan_path_worker, p): p for p in scan_paths
                }
                for future in concurrent.futures.as_completed(
                    future_to_path, timeout=300
                ):
                    try:
                        c, s, m = future.result()
                        total_files_est += c
                        total_bytes_est += s
                        if m > current_max_mtime:
                            current_max_mtime = m
                    except Exception as exc:
                        path = future_to_path[future]
                        logger.warning(f"Scan failed for {path}: {exc}")
        except concurrent.futures.TimeoutError:
            logger.warning(
                "Parallel Scan Timeout! Continuing with partial results."
            )
            log_status(tr("backup.scanTimeout", "Scan-Zeitüberschreitung - fahre mit Teilergebnissen fort."), "warning")
        except Exception as scan_err:
            logger.warning(
                f"Parallel Scan Error: {scan_err}. Fallback to sequential."
            )
            if total_files_est == 0:
                total_files_est = 0
                total_bytes_est = 0
                current_max_mtime = 0
                if is_multi_file:
                    for fpath in scan_paths:
                        c, s, m = scan_path_worker(fpath)
                        total_files_est += c
                        total_bytes_est += s
                        if m > current_max_mtime:
                            current_max_mtime = m
                elif os.path.isfile(source):
                    c, s, m = scan_path_worker(source)
                    total_files_est += c
                    total_bytes_est += s
                    if m > current_max_mtime:
                        current_max_mtime = m
                else:
                    for r, dirs, f in os.walk(source):
                        dirs[:] = [
                            d for d in dirs if not is_excluded(d, exclusions)
                        ]
                        for file in f:
                            if not is_excluded(file, exclusions):
                                total_files_est += 1
                                fp = os.path.join(r, file)
                                try:
                                    total_bytes_est += os.path.getsize(fp)
                                    mt = os.path.getmtime(fp)
                                    if mt > current_max_mtime:
                                        current_max_mtime = mt
                                except:
                                    pass

        if total_files_est > 0:
            log_status(
                tr("backup.smartCheck", "Prüfe Smart Skipping Kriterien..."),
                "debug",
            )
            try:
                lookup_source = source
                if is_multi_file:
                    lookup_source = " | ".join(multi_files)
                conn = sqlite3.connect(DB_FILE)
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute(
                    "SELECT * FROM history WHERE source_path = ? ORDER BY timestamp DESC LIMIT 1",
                    (lookup_source,),
                )
                last_backup = c.fetchone()
                conn.close()

                if last_backup:
                    last_count = last_backup["file_count"]
                    last_source_size = (
                        last_backup["source_size"]
                        if last_backup["source_size"]
                        else 0
                    )
                    last_ts_str = last_backup["timestamp"]
                    try:
                        dt = datetime.strptime(last_ts_str, "%Y-%m-%d %H:%M:%S")
                        last_ts = dt.timestamp()
                    except:
                        last_ts = 0
                    if (
                        last_count == total_files_est
                        and last_source_size == total_bytes_est
                    ):
                        if current_max_mtime <= last_ts + 2.0:
                            log_status(
                                tr(
                                    "backup.smartSkip",
                                    "Smart Skipping: Keine Änderungen seit letztem Backup.",
                                ),
                                "success",
                            )
                            add_event(
                                tr(
                                    "backup.skipped",
                                    "Backup übersprungen: Keine Änderungen ({size})",
                                    size=format_size(total_bytes_est),
                                ),
                                "info",
                            )
                            res = {
                                "status": "success",
                                "message": tr(
                                    "backup.smartSkip",
                                    "Smart Skipping: Keine Änderungen seit letztem Backup.",
                                ),
                                "file": last_backup["filename"],
                                "sha256": last_backup["sha256"],
                                "skipped": True,
                            }
                            log_status(
                                tr(
                                    "backup.skipSuccess",
                                    "Fertig (Übersprungen)",
                                ),
                                "success",
                                updates={
                                    "active": False,
                                    "progress": 100,
                                    "step": "done",
                                    "result": res,
                                },
                            )
                            return res
            except Exception as skip_err:
                logger.warning(f"Smart Skip Check failed: {skip_err}")

        if total_files_est == 0:
            total_files_est = 1
        if total_bytes_est == 0:
            total_bytes_est = 1

        logger.info(
            f"Starte Archivierung von {source} nach {zip_path} ({total_files_est} Dateien, {total_bytes_est/1024/1024:.2f} MB)"
        )
        arch_msg = tr(
            "backup.archiving",
            "Archiviere {count} Dateien ({size} MB)...",
            count=total_files_est,
            size=f"{total_bytes_est/1024/1024:.2f}",
        )
        log_status(
            arch_msg,
            "info",
            updates={
                "message": arch_msg,
                "progress": 10,
            },
        )

        processed_bytes = 0
        file_count = 0

        if enc_enabled and enc_pw:
            import pyzipper

            logger.info("Verschlüsselung (AES) aktiviert.")
            log_status(
                tr(
                    "backup.encEnabled",
                    "Verschlüsselung (AES-256) aktiviert.",
                ),
                "info",
            )
            zip_ctx = pyzipper.AESZipFile(
                zip_path,
                "w",
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
                compresslevel=comp_level,
            )
            zip_ctx.setpassword(enc_pw.encode("utf-8"))
        else:
            zip_ctx = zipfile.ZipFile(
                zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=comp_level
            )

        with zip_ctx as zipf:
            if is_multi_file:
                for fpath in multi_files:
                    if status_tracker.get("abort_requested"):
                        raise Exception("Benutzerabbruch")
                    if os.path.exists(fpath):
                        try:
                            fsize = os.path.getsize(fpath)
                            write_file_to_zip_chunked(
                                zipf,
                                fpath,
                                os.path.basename(fpath),
                                status_tracker,
                            )
                            file_count += 1
                            processed_bytes += fsize
                            prog = 10 + int(
                                (processed_bytes / total_bytes_est) * 80
                            )
                            log_status(
                                None,
                                updates={"progress": min(prog, 90)},
                            )
                        except Exception as write_err:
                            logger.warning(
                                f"Konnte Datei {fpath} nicht in ZIP schreiben: {write_err}"
                            )
            elif os.path.isfile(source):
                if status_tracker.get("abort_requested"):
                    raise Exception("Benutzerabbruch")
                try:
                    fsize = os.path.getsize(source)
                    write_file_to_zip_chunked(
                        zipf, source, os.path.basename(source), status_tracker
                    )
                    file_count = 1
                    processed_bytes = fsize
                    log_status(None, updates={"progress": 90})
                except Exception as write_err:
                    logger.warning(
                        f"Konnte Datei {source} nicht in ZIP schreiben: {write_err}"
                    )
            else:
                for root, dirs, files in os.walk(source):
                    if status_tracker.get("abort_requested"):
                        raise Exception("Benutzerabbruch")
                    dirs[:] = [d for d in dirs if not is_excluded(d, exclusions)]
                    for file in files:
                        if status_tracker.get("abort_requested"):
                            raise Exception("Benutzerabbruch")
                        if not is_excluded(file, exclusions):
                            full_file_path = os.path.join(root, file)
                            relative_path = os.path.relpath(full_file_path, source)
                            try:
                                fsize = os.path.getsize(full_file_path)
                                write_file_to_zip_chunked(
                                    zipf,
                                    full_file_path,
                                    relative_path,
                                    status_tracker,
                                )
                                file_count += 1
                                processed_bytes += fsize
                                if (
                                    file_count % 5 == 0
                                    or fsize > (5 * 1024 * 1024)
                                ):
                                    prog = 10 + int(
                                        (processed_bytes / total_bytes_est) * 80
                                    )
                                    msg = tr(
                                        "backup.archiving",
                                        "Archiviere {count} Dateien ({size} MB)...",
                                        count=file_count,
                                        size=f"{processed_bytes/1024/1024:.2f}",
                                    )
                                    log_status(
                                        None,
                                        updates={
                                            "progress": min(prog, 90),
                                            "message": msg,
                                        },
                                    )
                            except Exception as write_err:
                                logger.warning(
                                    f"Konnte Datei {file} nicht in ZIP schreiben: {write_err}"
                                )

        log_status(
            tr(
                "backup.hashing",
                "Erstelle Integritäts-Hash (BLAKE2b)...",
            ),
            "info",
            updates={"step": "hashing", "progress": 92},
        )

        last_hash_update = -1

        def hash_progress_local(curr, total):
            nonlocal last_hash_update
            pct = int((curr / total) * 100)
            if pct > last_hash_update:
                last_hash_update = pct
                msg = tr(
                    "backup.integrity",
                    "Integritäts-Hash: {pct}%",
                    pct=pct,
                )
                status_tracker["message"] = msg
                sse_announcer.announce(
                    {
                        "kind": "status_update",
                        "active": True,
                        "step": "hashing",
                        "message": msg,
                        "progress": 92,
                    },
                    event_type="status",
                )

        sha = calculate_hash(
            zip_path,
            salt=ts,
            algorithm="blake2b",
            check_abort=lambda: status_tracker.get("abort_requested"),
            progress_callback=hash_progress_local,
        )
        zip_size = os.path.getsize(zip_path)
        success_msg = tr(
            "backup.success",
            "Archiv erstellt: {size}",
            size=format_size(zip_size),
        )
        log_status(success_msg, "success")

        try:
            sp = source
            if isinstance(multi_files, list) and len(multi_files) > 0:
                sp = " | ".join(multi_files)
            new_entry = {
                "filename": zip_filename,
                "timestamp": ts,
                "size": zip_size,
                "sha256": sha,
                "path": zip_path,
                "source_path": sp,
                "comment": comment,
                "file_count": file_count,
                "source_size": processed_bytes,
            }
            if add_history_entry_to_db(new_entry):
                logger.info(f"History entry added to DB: {zip_filename}")
            else:
                logger.error("Failed to add history to DB (Return False)")
        except Exception as db_err:
            logger.error(f"Failed to add history to DB: {db_err}")

        log_status(
            tr(
                "backup.retention",
                "Prüfe Retention Policy...",
            ),
            "info",
            updates={
                "step": "retention",
                "message": tr(
                    "backup.cleaning",
                    "Bereinige Historie...",
                ),
                "progress": 98,
            },
        )
        retention_prefix = (custom_text + "_") if custom_text else "backup_"
        apply_retention(dest, limit, prefix=retention_prefix)

        if inc_seq:
            try:
                new_conf = load_config()
                new_conf["naming_seq_counter"] = seq_num + 1
                safe_write_json(CONFIG_FILE, new_conf)
            except Exception as e:
                logger.error(
                    f"Konnte Sequence Counter nicht erhöhen: {e}"
                )

        should_run_db = False
        if allowed_modules is not None:
            should_run_db = "db" in allowed_modules
        else:
            if config.get("db_backup_enabled", False):
                should_run_db = True

        if should_run_db:
            log_status(
                tr(
                    "backup.dbStart",
                    "Starte Datenbank-Backup... (Allowed: {allowed})",
                    allowed=str(allowed_modules),
                ),
                "info",
            )
            run_db_dump(config, dest, status_tracker=status_tracker)

        should_run_github = False
        if allowed_modules is not None:
            should_run_github = "github" in allowed_modules
        else:
            should_run_github = config.get("github_backup_enabled", False)

        if should_run_github:
            log_status(
                tr(
                    "backup.githubStart",
                    "Starte GitHub-Sync... (Allowed: {allowed})",
                    allowed=str(allowed_modules),
                ),
                "info",
            )
            run_github_sync(config, dest, status_tracker=status_tracker)

        should_run_cloud = False
        if allowed_modules is not None:
            if "cloud" in allowed_modules:
                should_run_cloud = True
        else:
            if config.get("cloud_sync_enabled", False):
                should_run_cloud = True

        if should_run_cloud:
            c_direction = config.get("cloud_direction", "upload")
            if c_direction == "download":
                log_status(
                    tr(
                        "backup.cloudSkipDownload",
                        "Cloud-Sync übersprungen (Richtung ist 'Download').",
                    ),
                    "info",
                )
                should_run_cloud = False

        if should_run_cloud:
            provider = config.get("cloud_provider", "SFTP")
            try:
                msg_upload = tr(
                    "backup.cloudUpload",
                    f"Lade in Cloud hoch ({provider})...",
                    provider=provider,
                )
                log_status(
                    msg_upload,
                    "info",
                    updates={
                        "step": "cloud",
                        "message": msg_upload,
                        "progress": 95,
                    },
                )

                c_host = config.get("cloud_host", "")
                c_user = config.get("cloud_user", "")
                c_pass = config.get("cloud_password", "")
                c_path = config.get("cloud_target_path", "/backups")

                if provider == "Local":
                    try:
                        msg = tr(
                            "backup.localCopy",
                            "Kopiere zu lokalem Pfad: {path}",
                            path=c_path,
                        )
                        log_status(msg, "info")
                        if not os.path.exists(c_path):
                            os.makedirs(c_path, exist_ok=True)
                        shutil.copy2(zip_path, os.path.join(c_path, zip_filename))
                        log_status(
                            tr(
                                "backup.localCopySuccess",
                                "Lokale Kopie erfolgreich.",
                            ),
                            "success",
                        )
                    except Exception as e:
                        log_status(
                            tr(
                                "backup.localCopyError",
                                "Fehler bei lokaler Kopie: {error}",
                                error=str(e),
                            ),
                            "error",
                        )

                elif provider == "SFTP":
                    if c_host and c_user:
                        log_status(
                            tr(
                                "backup.sftpStart",
                                "Starte SFTP Upload zu {host}...",
                                host=c_host,
                            ),
                            "info",
                        )
                        import paramiko
                        import socket

                        host_clean = (
                            c_host.strip()
                            .replace("sftp://", "")
                            .replace("ssh://", "")
                        )
                        port_int = 22
                        if config.get("cloud_port"):
                            try:
                                port_int = int(config.get("cloud_port"))
                            except:
                                pass

                        try:
                            log_status(
                                tr(
                                    "backup.sftpConnect",
                                    "Verbinde zu {host}:{port}...",
                                    host=host_clean,
                                    port=port_int,
                                ),
                                "info",
                            )
                            sock = socket.create_connection(
                                (host_clean, port_int), timeout=30
                            )
                            transport = paramiko.Transport(sock)

                            try:
                                sec_opts = transport.get_security_options()
                                extra_kex = (
                                    "diffie-hellman-group14-sha1",
                                    "diffie-hellman-group-exchange-sha1",
                                    "diffie-hellman-group1-sha1",
                                )
                                extra_ciphers = (
                                    "aes128-cbc",
                                    "3des-cbc",
                                    "aes256-cbc",
                                )
                                extra_keys = ("ssh-rsa", "ssh-dss")
                                sec_opts.kex = tuple(
                                    list(sec_opts.kex)
                                    + [
                                        k
                                        for k in extra_kex
                                        if k not in sec_opts.kex
                                    ]
                                )
                                sec_opts.ciphers = tuple(
                                    list(sec_opts.ciphers)
                                    + [
                                        c
                                        for c in extra_ciphers
                                        if c not in sec_opts.ciphers
                                    ]
                                )
                                sec_opts.key_types = tuple(
                                    list(sec_opts.key_types)
                                    + [
                                        k
                                        for k in extra_keys
                                        if k not in sec_opts.key_types
                                    ]
                                )
                                log_status(
                                    tr(
                                        "backup.sftpLegacy",
                                        "Legacy-Algorithmen aktiviert.",
                                    ),
                                    "info",
                                )
                            except:
                                pass

                            log_status(
                                tr(
                                    "backup.sftpAuth",
                                    "Authentifiziere...",
                                ),
                                "info",
                            )
                            try:
                                transport.connect(
                                    username=c_user, password=c_pass
                                )
                            except paramiko.AuthenticationException:
                                log_status(
                                    tr(
                                        "backup.sftpAuthFallback",
                                        "Standard-Auth fehlgeschlagen, versuche Interactive...",
                                    ),
                                    "warning",
                                )

                                def handler(title, instructions, prompt_list):
                                    return [c_pass] * len(prompt_list)

                                try:
                                    transport.connect(
                                        username=c_user, password=c_pass
                                    )
                                except:
                                    transport.auth_interactive(
                                        c_user, handler
                                    )

                            sftp = paramiko.SFTPClient.from_transport(transport)
                            log_status(
                                tr(
                                    "backup.sftpSession",
                                    "SFTP Session etabliert.",
                                ),
                                "success",
                            )

                            try:
                                sftp.chdir(c_path)
                            except:
                                log_status(
                                    tr(
                                        "backup.sftpMkdir",
                                        "Erstelle Ordner: {path}",
                                        path=c_path,
                                    ),
                                    "info",
                                )
                                try:
                                    sftp.mkdir(c_path)
                                except:
                                    pass

                            remote_file = os.path.join(
                                c_path, zip_filename
                            ).replace("\\", "/")
                            log_status(
                                tr(
                                    "backup.sftpUploadFile",
                                    "Lade Datei hoch: {name} ({size})",
                                    name=zip_filename,
                                    size=format_size(zip_size),
                                ),
                                "info",
                            )

                            last_sftp_pct = 0

                            def sftp_progress(transferred, total):
                                nonlocal last_sftp_pct
                                if status_tracker.get("abort_requested"):
                                    raise Exception(
                                        "Benutzerabbruch während SFTP Upload"
                                    )
                                pct = int((transferred / total) * 100)
                                if pct > last_sftp_pct + 4:
                                    last_sftp_pct = pct
                                    msg = f"SFTP Upload: {pct}% ({format_size(transferred)} / {format_size(total)})"
                                    status_tracker["message"] = msg
                                    sse_announcer.announce(
                                        {
                                            "kind": "status_update",
                                            "active": True,
                                            "step": "cloud",
                                            "message": msg,
                                            "progress": 95,
                                        },
                                        event_type="status",
                                    )

                            sftp.put(zip_path, remote_file, callback=sftp_progress)

                            sftp.close()
                            transport.close()
                            sock.close()

                            log_status(
                                tr(
                                    "backup.sftpSuccess",
                                    "Upload erfolgreich abgeschlossen.",
                                ),
                                "success",
                            )
                            logger.info("SFTP Upload erfolgreich.")
                        except Exception as sftp_ex:
                            log_status(
                                tr(
                                    "backup.sftpError",
                                    "SFTP Fehler: {error}",
                                    error=str(sftp_ex),
                                ),
                                "error",
                            )
                            raise sftp_ex
                    else:
                        msg = tr(
                            "backup.sftpSkipped",
                            "Cloud Upload (SFTP) übersprungen: Host oder User fehlt.",
                        )
                        log_status(msg, "warning")
                        logger.warning(msg)

                elif provider == "Dropbox":
                    log_status(
                        tr(
                            "backup.dropboxStart",
                            "Starte Dropbox Upload...",
                        ),
                        "info",
                    )
                    token = c_pass
                    if token:
                        import dropbox
                        from dropbox.files import WriteMode

                        dbx = dropbox.Dropbox(token)
                        if not c_path.startswith("/"):
                            c_path = "/" + c_path

                        remote_file = f"{c_path}/{zip_filename}"
                        log_status(
                            tr(
                                "backup.dropboxUploadFile",
                                "Lade Datei hoch: {name}",
                                name=zip_filename,
                            ),
                            "info",
                        )
                        with open(zip_path, "rb") as f:
                            dbx.files_upload(
                                f.read(), remote_file, mode=WriteMode("overwrite")
                            )
                        log_status(
                            tr(
                                "backup.dropboxSuccess",
                                "Dropbox Upload erfolgreich.",
                            ),
                            "success",
                        )
                        logger.info("Dropbox Upload erfolgreich.")
                    else:
                        log_status(
                            tr(
                                "backup.dropboxTokenMissing",
                                "Token fehlt für Dropbox.",
                            ),
                            "warning",
                        )
                        logger.warning(
                            "Cloud Upload (Dropbox) übersprungen: Token fehlt."
                        )

                elif provider == "S3 (Amazon)":
                    log_status(
                        tr(
                            "backup.s3Start",
                            "Starte S3 Upload...",
                        ),
                        "info",
                    )
                    aws_access_key = c_user
                    aws_secret_key = c_pass
                    bucket_name = config.get("cloud_bucket", "")
                    region = config.get("cloud_region", "")

                    if aws_access_key and aws_secret_key and bucket_name:
                        import boto3

                        s3_client = boto3.client(
                            "s3",
                            aws_access_key_id=aws_access_key,
                            aws_secret_access_key=aws_secret_key,
                            region_name=region if region else None,
                        )
                        s3_key = (
                            os.path.join(c_path, zip_filename)
                            .replace("\\", "/")
                            .lstrip("/")
                        )
                        log_status(
                            tr(
                                "backup.s3UploadFile",
                                "Upload zu Bucket '{bucket}': {key}",
                                bucket=bucket_name,
                                key=s3_key,
                            ),
                            "info",
                        )
                        s3_client.upload_file(zip_path, bucket_name, s3_key)
                        log_status(
                            tr(
                                "backup.s3Success",
                                "S3 Upload erfolgreich.",
                            ),
                            "success",
                        )
                        logger.info("S3 Upload erfolgreich.")
                    else:
                        log_status(
                            tr(
                                "backup.s3MissingCreds",
                                "Credentials oder Bucket fehlen für S3.",
                            ),
                            "warning",
                        )
                        logger.warning(
                            "Cloud Upload (S3) übersprungen: Credentials oder Bucket fehlen."
                        )

                elif provider == "WebDAV":
                    log_status(
                        tr(
                            "backup.webdavStart",
                            "Starte WebDAV Upload...",
                        ),
                        "info",
                    )
                    webdav_url = c_host
                    if webdav_url and c_user and c_pass:
                        import requests

                        remote_url = (
                            f"{webdav_url.rstrip('/')}/{c_path.strip('/')}/{zip_filename}"
                        )
                        log_status(
                            tr(
                                "backup.webdavPut",
                                "PUT: {url}",
                                url=remote_url,
                            ),
                            "info",
                        )
                        with open(zip_path, "rb") as f:
                            resp = requests.put(
                                remote_url, data=f, auth=(c_user, c_pass)
                            )
                        if resp.status_code in [200, 201, 204]:
                            log_status(
                                tr(
                                    "backup.webdavSuccess",
                                    "WebDAV Upload erfolgreich.",
                                ),
                                "success",
                            )
                            logger.info("WebDAV Upload erfolgreich.")
                        else:
                            raise Exception(
                                f"WebDAV Status: {resp.status_code} - {resp.text}"
                            )
                    else:
                        log_status(
                            tr(
                                "backup.webdavMissingCreds",
                                "URL oder Credentials fehlen für WebDAV.",
                            ),
                            "warning",
                        )
                        logger.warning(
                            "Cloud Upload (WebDAV) übersprungen: URL oder Credentials fehlen."
                        )
            except Exception as cloud_err:
                err_msg = tr(
                    "console.cloudUploadError",
                    "Cloud Upload Fehler ({provider}): {error}",
                    provider=provider,
                    error=str(cloud_err),
                )
                log_status(err_msg, "error")
                logger.error(f"Cloud Upload fehlgeschlagen: {cloud_err}")
                add_event(err_msg, "error")

        logger.info(f"Backup erfolgreich abgeschlossen: {zip_filename}")
        add_event(
            tr(
                "console.backupFinished",
                "Backup beendet: {filename}",
                filename=zip_filename,
            ),
            "success",
        )
        send_notifications(
            config,
            f"Backup erfolgreich abgeschlossen.\nDatei: {zip_filename}\nGröße: {format_size(zip_size)}",
            "success",
        )

        res = {
            "status": "success",
            "file": zip_filename,
            "sha256": sha,
        }
        log_status(
            None,
            updates={
                "active": False,
                "progress": 100,
                "step": "done",
                "message": tr(
                    "backup.success",
                    "Archiv erstellt: {size}",
                    size=format_size(zip_size),
                ),
                "result": res,
            },
        )
        return res

    except Exception as e:
        logger.error(f"Kritischer Fehler in run_backup_logic: {e}")
        if "Benutzerabbruch" in str(e):
            logger.info("Backup durch Benutzer abgebrochen. Räume auf...")
            time.sleep(1)
            try:
                if "zip_path" in locals() and os.path.exists(zip_path):
                    os.remove(zip_path)
            except:
                pass
            res = {
                "status": "error",
                "message": tr(
                    "backup.userAbortShort",
                    "Vorgang durch Benutzer abgebrochen.",
                ),
            }
            log_status(
                tr("backup.userAbortShort", "Benutzerabbruch."),
                "warning",
            )
            add_event(
                tr(
                    "backup.userAbortShort",
                    "Backup abgebrochen durch Benutzer.",
                ),
                "error",
            )
        else:
            res = {"status": "error", "message": str(e)}
            log_status(f"CRASH: {str(e)}", "error")
            add_event(
                tr(
                    "backup.failed",
                    "Backup fehlgeschlagen: {error}",
                    error=str(e),
                ),
                "error",
            )
            send_notifications(
                config,
                f"Backup fehlgeschlagen!\nFehler: {str(e)}",
                "error",
            )

        log_status(
            None,
            updates={
                "active": False,
                "step": "error",
                "message": res["message"],
                "result": res,
            },
        )
        return res
    finally:
        backup_lock.release()

# --- Auto-Backup Scheduler Thread ---

def auto_backup_scheduler():
    """Hintergrund-Thread, der die Zeitintervalle überwacht."""
    # Kurze Start-Verzögerung, damit System bereit ist
    time.sleep(3)
    add_event("console.autoSchedulerStarted", "info")
    
    last_backup_time = time.time()
    
    while True:
        try:
            config = load_config()
            any_backup_ran = False
            
            # 1. Global Auto Backup
            enabled = config.get("auto_backup_enabled", False)
            interval_min = config.get("auto_interval", 0)
            source = config.get("default_source")
            dest = config.get("default_dest")
            
            if enabled and interval_min > 0 and source and dest:
                interval_sec = interval_min * 60
                if time.time() - last_backup_time >= interval_sec:
                    if is_backup_locked():
                        logger.debug("Auto-Backup deferred: Backup in progress.")
                    else:
                        logger.info("Auto-Backup: Intervall erreicht. Starte Prozess.")
                        add_event(tr("console.autoSchedulerGlobalStart", "Auto-Scheduler: Starte Globales Backup..."), "info")
                        res = run_backup_logic(source, dest, "System Auto-Snapshot")
                        if res.get("status") == "success":
                            last_backup_time = time.time()
                            any_backup_ran = True
            
            # 2. Task Specific Auto Backup
            tasks = config.get("tasks", [])
            tasks_modified = False
            current_time = time.time()
            
            for task in tasks:
                t_interval = int(task.get("interval", 0))
                t_last = float(task.get("last_run", 0))
                t_active = task.get("active", True)
                t_source = task.get("source")
                t_dest = task.get("dest")
                t_name = task.get("name", "Unnamed Task")

                # Debug Log
                # logger.info(f"Check Task: {t_name} | Active: {t_active} | Last: {t_last} | Interval: {t_interval}")

                if t_active and t_interval > 0 and t_source and t_dest:
                    diff_min = (current_time - t_last) / 60
                    # Debug Info im Log falls überfällig aber nicht gestartet (nur zum Testen)
                    # if diff_min >= t_interval:
                    #     add_event(f"Debug: Task {t_name} ist fällig (Diff: {diff_min:.1f}m >= {t_interval}m)", "info")

                    if current_time - t_last >= t_interval * 60:
                        if is_backup_locked():
                            # Retry next loop
                            logger.info(f"Task '{t_name}' deferred: Backup in progress.")
                            add_event(tr("console.schedulerTaskDeferred", "Scheduler: Task '{name}' verschoben (Backup läuft bereits)", name=t_name), "warning")
                            continue
                            
                        logger.info(f"Task Auto-Backup: '{t_name}' fällig. Starte...")
                        add_event(tr("console.autoSchedulerTaskStart", "Auto-Scheduler: Starte Task '{name}'...", name=t_name), "info")
                        try:
                            # Prepare Task Options
                            task_opts = {
                                "naming_include_date": task.get("naming_include_date", True),
                                "naming_include_time": task.get("naming_include_time", True),
                                "naming_include_seq": task.get("naming_include_seq", False)
                            }
                            res = run_backup_logic(t_source, t_dest, f"Task: {t_name}", custom_filename_prefix=t_name, task_options=task_opts)
                            if res.get("status") == "success":
                                task["last_run"] = current_time
                                tasks_modified = True
                                any_backup_ran = True
                            else:
                                add_event(tr("console.schedulerTaskNotRun", "Task '{name}' nicht ausgeführt: {reason}", name=t_name, reason=res.get('message')), "warning")
                        except Exception as e:
                            logger.error(f"Fehler bei Task Backup '{t_name}': {e}")
                            add_event(tr("console.schedulerTaskError", "Scheduler Fehler bei '{name}': {error}", name=t_name, error=str(e)), "error")
            
            if tasks_modified:
                # Sicherer Update-Mechanismus
                try:
                    current_conf_fresh = load_config()
                    fresh_tasks = current_conf_fresh.get("tasks", [])
                    
                    # Updates übertragen
                    for t_mod in tasks:
                        # Finde entsprechenden Task in fresh config
                        found = False
                        for t_fresh in fresh_tasks:
                            if t_fresh.get("id") == t_mod.get("id"):
                                # Update last_run nur wenn neuer
                                if t_mod.get("last_run", 0) > t_fresh.get("last_run", 0):
                                    t_fresh["last_run"] = t_mod.get("last_run")
                                found = True
                                break
                        # Falls nicht gefunden (Task gelöscht?), ignorieren oder hinzufügen?
                        # Hier: ignorieren, da wir nur last_run updaten wollen
                    
                    current_conf_fresh["tasks"] = fresh_tasks
                    if save_config(current_conf_fresh):
                         add_event(tr("console.schedulerStatusUpdated", "Scheduler: Task-Status aktualisiert."), "success")
                    else:
                         add_event(tr("console.schedulerStatusUpdateFailed", "Scheduler: Konnte Task-Status nicht speichern!"), "error")
                except Exception as ex:
                    logger.error(f"Fehler beim Speichern der Task-Updates: {ex}")
                    add_event(tr("console.schedulerSaveError", "Scheduler Save Error: {error}", error=str(ex)), "error")
            
            # Auto-Shutdown Check Removed

        except Exception as e:
            logger.error(f"Fehler im Auto-Backup Scheduler: {e}")
        
        # Pause am Ende des Loops
        time.sleep(10)

# --- UI Template (Commander UI v7.1) ---

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="{{ lang }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Backup OS Pro Commander v7.4.0 - Hybrid Kernel Edition</title>
    <link rel="icon" href="/favicon.ico">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        window.BP_LANG = "{{ lang }}";
    </script>
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

        .commander-tooltip { background-color: #1a1b26; border-color: rgba(37, 99, 235, 0.2); color: #e5e7eb; }
        .commander-tooltip strong { color: #60a5fa; }
        .commander-tooltip ul { color: #9ca3af; }
        .commander-tooltip .tooltip-arrow { background-color: #1a1b26; border-left-color: rgba(37, 99, 235, 0.2); border-top-color: rgba(37, 99, 235, 0.2); }

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

        /* --- Klipper-Style Loader --- */
        #startup-loader {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background-color: #050505;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            transition: opacity 0.5s ease-out;
        }
        .loader-content {
            width: 300px;
            text-align: center;
        }
        .loader-logo {
            font-size: 4rem;
            margin-bottom: 1rem;
            animation: pulse-glow 2s infinite;
        }
        .loader-bar-bg {
            width: 100%;
            height: 4px;
            background: #1f2430;
            border-radius: 2px;
            overflow: hidden;
            margin-top: 1rem;
            position: relative;
        }
        .loader-bar-fill {
            height: 100%;
            background: #0084ff;
            width: 0%;
            animation: load-progress 2s cubic-bezier(0.22, 1, 0.36, 1) forwards;
            box-shadow: 0 0 10px #0084ff;
        }
        .loader-text {
            font-family: 'JetBrains Mono', monospace;
            font-size: 10px;
            color: #0084ff;
            margin-top: 0.5rem;
            letter-spacing: 0.2em;
            text-transform: uppercase;
        }
        @keyframes pulse-glow {
            0% { filter: drop-shadow(0 0 5px rgba(0,132,255,0.4)); opacity: 0.8; }
            50% { filter: drop-shadow(0 0 15px rgba(0,132,255,0.8)); opacity: 1; }
            100% { filter: drop-shadow(0 0 5px rgba(0,132,255,0.4)); opacity: 0.8; }
        }
        @keyframes load-progress {
            0% { width: 0%; }
            30% { width: 40%; }
            70% { width: 80%; }
            100% { width: 100%; }
        }
        
        /* Modal Tabs */
        .modal-tabs { display: flex; border-bottom: 1px solid rgba(255,255,255,0.1); margin-bottom: 20px; }
        .modal-tab { 
            padding: 10px 20px; 
            font-size: 11px; 
            font-weight: 900; 
            text-transform: uppercase; 
            letter-spacing: 0.1em; 
            color: #64748b; 
            cursor: pointer; 
            border-bottom: 2px solid transparent; 
            transition: all 0.2s;
        }
        .modal-tab:hover { color: #94a3b8; }
        .modal-tab.active { color: #3b82f6; border-bottom-color: #3b82f6; }
        
        .file-list { max-height: 300px; overflow-y: auto; background: rgba(0,0,0,0.3); border-radius: 8px; border: 1px solid rgba(255,255,255,0.05); }
        .file-list-item { 
            padding: 6px 12px; 
            border-bottom: 1px solid rgba(255,255,255,0.05); 
            font-family: 'JetBrains Mono', monospace; 
            font-size: 10px; 
            color: #cbd5e1; 
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .file-list-item:last-child { border-bottom: none; }
        .file-icon { color: #3b82f6; font-size: 10px; }
    </style>
</head>
<body class="flex h-screen overflow-hidden text-slate-300" id="bp-root">

    <!-- Startup Loader -->
    <div id="startup-loader">
        <div class="loader-content">
            <img src="/favicon.ico" class="loader-logo" style="width: 130px; height: 130px; object-fit: contain; display: block; margin: 0 auto 20px auto;">
            <div class="text-xl font-black text-white tracking-[0.3em] uppercase mb-1">BACKUP<span class="text-blue-500">OS</span></div>
            <div class="text-[9px] text-slate-500 uppercase tracking-widest mb-6">Hybrid Kernel v7.4</div>
            
            <div class="loader-bar-bg">
                <div class="loader-bar-fill"></div>
            </div>
            <div class="flex justify-between items-center mt-2 w-64">
                 <div class="loader-text" id="loader-msg">INITIALIZING...</div>
                 <div class="loader-text text-blue-500" id="loader-percent">0%</div>
            </div>
            <div id="loader-console" class="text-[9px] font-mono text-slate-600 mt-2 h-4 overflow-hidden text-center uppercase tracking-wider"></div>
        </div>
    </div>

    <!-- Detail Modal -->
    <div id="hash-modal" class="fixed inset-0 z-[999] items-center justify-center p-4 hidden">
        <div class="modal-content bg-[#11141d] border border-[#0084ff55] w-full max-w-4xl rounded-2xl p-8 relative shadow-2xl text-slate-200 flex flex-col max-h-[90vh]">
            <button onclick="closeHashModal()" class="absolute top-6 right-6 text-slate-500 hover:text-white transition-colors z-10">✕</button>
            
            <div class="flex items-center gap-3 mb-2">
                <div class="p-2 bg-blue-500/20 rounded text-blue-400">
                    <img src="/favicon.ico" class="w-6 h-6">
                </div>
                <h3 class="text-lg font-black uppercase tracking-widest text-white">Snapshot Inspektor</h3>
                <div id="lock-badge" class="hidden bg-amber-500/10 text-amber-500 border border-amber-500/20 px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-widest flex items-center gap-1">
                    <span>🔒</span> RETENTION LOCK
                </div>
            </div>

            <!-- Integrity Result (Prominent) -->
            <div id="integrity-result" class="mb-4 hidden p-3 rounded-lg text-center font-bold text-xs tracking-wide border"></div>

            <div class="modal-tabs">
                <div class="modal-tab active" onclick="switchModalTab('meta')">Metadaten</div>
                <div class="modal-tab" onclick="switchModalTab('content')">Inhalt (Dateien)</div>
            </div>

            <div id="tab-meta" class="modal-tab-content space-y-6 overflow-y-auto pr-2">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <label class="text-[11px] text-slate-500 uppercase font-black mb-2 block tracking-widest">Dateiname</label>
                        <div id="modal-filename" class="bg-black/40 p-3 rounded border border-white/5 text-sm font-bold text-blue-400 mono truncate">--</div>
                    </div>
                    <div>
                        <label class="text-[11px] text-slate-500 uppercase font-black mb-2 block tracking-widest">Status</label>
                        <div class="flex gap-2">
                            <div class="bg-green-500/10 p-3 rounded border border-green-500/20 text-xs font-bold text-green-500 uppercase flex items-center gap-2 flex-1">
                                <span class="w-1.5 h-1.5 bg-green-500 rounded-full"></span> Verifiziert
                            </div>
                            <button id="btn-lock" onclick="toggleLock()" class="bg-amber-500/10 p-3 rounded border border-amber-500/20 text-amber-500 hover:bg-amber-500/20 transition-colors" title="Retention Lock umschalten">
                                🔓
                            </button>
                        </div>
                    </div>
                </div>
                
                <div>
                    <label class="text-[11px] text-slate-500 uppercase font-black mb-2 block tracking-widest">Kommentar</label>
                    <div class="flex gap-2">
                        <input type="text" id="modal-comment" class="flex-1 bg-black/40 border border-white/5 rounded p-3 text-xs text-white outline-none focus:border-blue-500 transition-colors" placeholder="Kein Kommentar...">
                        <button onclick="saveComment()" class="px-4 bg-blue-600/20 border border-blue-600/40 text-blue-400 rounded hover:bg-blue-600/30 transition-colors text-[10px] font-black uppercase tracking-widest">Save</button>
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

                <div class="border-t border-white/5 pt-6">
                    <label class="text-[11px] text-slate-500 uppercase font-black mb-4 block tracking-widest">Erweiterte Aktionen</label>
                    <div class="flex gap-4">
                        <button onclick="verifyIntegrity()" id="btn-integrity" class="flex-1 bg-emerald-900/10 py-3 rounded text-[11px] font-black uppercase tracking-widest hover:bg-emerald-900/20 transition-all text-emerald-500 border border-emerald-500/20 flex items-center justify-center gap-2">
                            <span>⚡</span> Integrität Prüfen (Deep Scan)
                        </button>
                        <button id="modal-delete-btn" class="flex-1 bg-red-900/10 py-3 rounded text-[11px] font-black uppercase tracking-widest hover:bg-red-900/20 transition-all text-red-500 border border-red-500/20 flex items-center justify-center gap-2">
                            <span>✕</span> Snapshot Löschen
                        </button>
                    </div>
                </div>
            </div>

            <div id="tab-content" class="modal-tab-content hidden flex-1 flex flex-col min-h-0">
                <div class="flex justify-between items-center mb-4">
                    <span class="text-[11px] text-slate-500 uppercase font-black tracking-widest">Enthaltene Dateien</span>
                    <span id="file-count-badge" class="text-[10px] bg-white/10 px-2 py-1 rounded text-white font-mono">-- Files</span>
                </div>
                <div id="zip-file-list" class="file-list flex-1">
                    <div class="p-8 text-center text-slate-500 text-xs uppercase tracking-widest animate-pulse">Lade Dateistruktur...</div>
                </div>
            </div>

        </div>
    </div>

    <!-- Shutdown Modal Removed -->

    <!-- Sidebar -->
    <!-- Mobile Sidebar Backdrop -->
    <div id="sidebar-backdrop" onclick="toggleSidebar()" class="fixed inset-0 bg-black/80 z-40 hidden md:hidden backdrop-blur-sm transition-opacity"></div>
    <aside id="main-sidebar" class="fixed inset-y-0 left-0 w-64 bg-[#0d0f16] border-r border-[#1a1e2a] flex flex-col z-50 transform transition-transform duration-300 -translate-x-full md:relative md:translate-x-0">
        <div class="p-6 border-b border-[#1a1e2a] flex items-center gap-3">
            <div>
                <img src="/favicon.ico" class="w-10 h-10 object-contain">
            </div>
            <div class="flex flex-col">
                <span class="font-black text-white leading-none">BACKUP OS</span>
                <span class="text-[10px] text-[#0084ff] font-bold tracking-widest uppercase">Commander Pro</span>
            </div>
        </div>

        <nav class="flex-1 mt-6">
            <div onclick="switchTab('dashboard')" id="nav-dashboard" class="sidebar-item active px-6 py-4 flex items-center gap-4">
                <span class="text-sm font-bold text-white font-mono" data-i18n="nav.dashboard">01 ZENTRALE</span>
            </div>
            <div onclick="switchTab('restore')" id="nav-restore" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold font-mono" data-i18n="nav.restore">02 RESTORE</span>
            </div>
            <div onclick="switchTab('cloud')" id="nav-cloud" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold font-mono" data-i18n="nav.cloud">03 CLOUD</span>
            </div>
            <div onclick="switchTab('duplicates')" id="nav-duplicates" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold font-mono" data-i18n="nav.duplicates">04 ANALYSE</span>
            </div>
            <div onclick="switchTab('settings')" id="nav-settings" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold font-mono" data-i18n="nav.settings">05 PARAMETER</span>
            </div>
            <div onclick="switchTab('tasks')" id="nav-tasks" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500">
                <span class="text-sm font-bold font-mono" data-i18n="nav.tasks">06 TASKS</span>
            </div>
            <div onclick="switchTab('help')" id="nav-help" class="sidebar-item px-6 py-4 flex items-center gap-4 text-slate-500 border-t border-white/5 mt-4">
                <span class="text-sm font-bold font-mono text-blue-400" data-i18n="nav.help">?? HANDBUCH</span>
            </div>
        </nav>

        <div class="p-6 bg-[#08090d] border-t border-[#1a1e2a]">
            <div class="flex justify-between items-center mb-1">
                <span class="text-[10px] uppercase font-black text-slate-500 tracking-tighter">Drive Telemetrie</span>
                <span id="disk-percent" class="text-[11px] font-bold text-blue-400">--%</span>
            </div>
            <div class="w-full bg-[#1a1e2a] h-2 rounded-full overflow-hidden mb-2 relative">
                <div id="disk-bar" class="bg-blue-500 h-full w-0 transition-all duration-1000 shadow-[0_0_8px_rgba(0,132,255,0.4)] relative z-10"></div>
                <!-- Tech Stripe Pattern -->
                <div class="absolute inset-0 opacity-10" style="background-image: linear-gradient(45deg, #000 25%, transparent 25%, transparent 50%, #000 50%, #000 75%, transparent 75%, transparent); background-size: 4px 4px;"></div>
            </div>
            
            <div id="disk-details" class="grid grid-cols-3 gap-1 text-[9px] font-bold mono text-slate-600 uppercase mb-4 text-center">
                 <div class="flex flex-col items-start">
                     <span class="text-[8px] text-slate-700 tracking-wider">Belegt</span>
                     <span id="disk-used-val" class="text-blue-400">--</span>
                 </div>
                 <div class="flex flex-col items-center">
                     <span class="text-[8px] text-slate-700 tracking-wider">Frei</span>
                     <span id="disk-free-val" class="text-slate-400">--</span>
                 </div>
                 <div class="flex flex-col items-end">
                     <span class="text-[8px] text-slate-700 tracking-wider">Total</span>
                     <span id="disk-total-val" class="text-slate-400">--</span>
                 </div>
            </div>
            
            <div id="disk-warning" class="hidden mb-4 p-2 bg-red-500/10 border border-red-500/20 rounded text-center animate-pulse">
                <span class="text-[9px] font-black text-red-500 uppercase tracking-widest">⚠ Speicher kritisch</span>
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
        <header class="h-14 bg-[#0d0f16] border-b border-[#1a1e2a] flex items-center justify-between px-4 md:px-8">
            <div class="flex items-center gap-3 md:gap-4">
                <!-- Hamburger Menu -->
                <button onclick="toggleSidebar()" class="md:hidden text-slate-400 hover:text-white transition-colors p-1">
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
                    </svg>
                </button>
                <span class="w-2.5 h-2.5 bg-green-500 rounded-full animate-pulse shadow-[0_0_8px_#10b981]"></span>
                <span class="text-[12px] font-black uppercase tracking-widest text-white">v7.4 <span class="hidden sm:inline">Hybrid Kernel</span><span class="hidden xl:inline"> | Creator: Exulizer</span></span>
            </div>
            <div class="flex items-center gap-2 md:gap-6">
                <div class="flex items-center gap-2 md:gap-4 mr-2 md:mr-4">
                    <span class="text-[10px] font-black uppercase text-slate-500 tracking-widest hidden md:block">Unit Engine</span>
                    <div class="unit-switch" id="global-unit-switch">
                        <div onclick="setGlobalUnit('MB')" id="unit-mb" class="unit-btn active">MB</div>
                        <div onclick="setGlobalUnit('GB')" id="unit-gb" class="unit-btn">GB</div>
                    </div>
                </div>
                <div class="flex flex-col items-end border-l border-white/5 pl-3 md:pl-6">
                    <span id="header-date" class="text-[11px] font-bold text-slate-400 mono">--.--.----</span>
                    <span id="header-time" class="text-[14px] font-black text-blue-400 mono">00:00:00</span>
                </div>
            </div>
        </header>

        <!-- Tab: Dashboard -->
        <section id="tab-dashboard" class="tab-content flex-1 overflow-y-auto p-8 space-y-8">
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
                <div class="commander-module p-5 relative group">
                    <div class="absolute top-full left-0 mt-2 w-full border text-[10px] px-3 py-3 rounded shadow-2xl opacity-0 group-hover:opacity-100 transition-all duration-300 pointer-events-none z-50 text-left leading-relaxed backdrop-blur-sm transform translate-y-2 group-hover:translate-y-0 commander-tooltip">
                        <strong class="text-blue-400 block mb-1" data-i18n="dashboard.healthTitle">ℹ️ System Health Score</strong>
                        <p class="mb-1" data-i18n="dashboard.healthDesc">Berechnet den Gesundheitszustand basierend auf Backup-Konsistenz und Speicherplatz.</p>
                        <ul class="list-disc list-inside space-y-0.5">
                            <li><span class="font-bold">COV:</span> <span data-i18n="dashboard.covDesc">Coverage (Abdeckung/Häufigkeit)</span></li>
                            <li><span class="font-bold">REC:</span> <span data-i18n="dashboard.recDesc">Recoverability (Wiederherstellbarkeit)</span></li>
                            <li><span class="font-bold">DSK:</span> <span data-i18n="dashboard.diskDesc">Disk Space (Speicherplatz)</span></li>
                        </ul>
                        <div class="absolute -top-1 left-8 w-2 h-2 rotate-45 tooltip-arrow"></div>
                    </div>

                    <div class="flex justify-between items-start mb-2">
                         <span class="text-[11px] uppercase font-black text-slate-500 tracking-widest cursor-help" data-i18n="dashboard.healthLabel">System Health</span>
                         <span id="health-label" class="text-[9px] font-black text-blue-400 uppercase tracking-tighter">--</span>
                    </div>
                    <div class="flex items-baseline gap-2">
                        <span class="health-score" id="score-val">--</span>
                        <span class="text-[12px] font-black text-slate-600">%</span>
                    </div>
                    <div id="health-breakdown" class="mt-4 grid grid-cols-3 gap-3 border-t border-white/5 pt-3">
                        <div class="flex flex-col">
                            <div class="flex justify-between items-end mb-1">
                                <span class="text-[9px] uppercase text-slate-500 font-bold">COV</span>
                                <span id="val-cov" class="text-[9px] font-mono text-blue-400">0%</span>
                            </div>
                            <div class="health-mini-bar"><div id="bar-cov" class="health-mini-fill" style="width: 0%"></div></div>
                        </div>
                        <div class="flex flex-col">
                            <div class="flex justify-between items-end mb-1">
                                <span class="text-[9px] uppercase text-slate-500 font-bold">REC</span>
                                <span id="val-rec" class="text-[9px] font-mono text-blue-400">0%</span>
                            </div>
                            <div class="health-mini-bar"><div id="bar-rec" class="health-mini-fill" style="width: 0%"></div></div>
                        </div>
                        <div class="flex flex-col">
                            <div class="flex justify-between items-end mb-1">
                                <span class="text-[9px] uppercase text-slate-500 font-bold">DSK</span>
                                <span id="val-disk" class="text-[9px] font-mono text-blue-400">0%</span>
                            </div>
                            <div class="health-mini-bar"><div id="bar-disk" class="health-mini-fill" style="width: 0%"></div></div>
                        </div>
                    </div>
                </div>

                <div class="commander-module p-5 relative group">
                    <div class="absolute top-full left-0 mt-2 w-full border text-[10px] px-3 py-3 rounded shadow-2xl opacity-0 group-hover:opacity-100 transition-all duration-300 pointer-events-none z-50 text-left leading-relaxed backdrop-blur-sm transform translate-y-2 group-hover:translate-y-0 commander-tooltip">
                        <strong class="text-blue-400 block mb-1" data-i18n="dashboard.volumeTitle">ℹ️ Archive Volume Stats</strong>
                        <p class="mb-1" data-i18n="dashboard.volumeDesc">Zeigt den gesamten Speicherplatzverbrauch aller gespeicherten Backups sowie die Anzahl der Snapshots.</p>
                        <ul class="list-disc list-inside space-y-0.5">
                            <li><span class="font-bold" data-i18n="dashboard.snapshotsLabel">Snapshots:</span> <span data-i18n="dashboard.snapDesc">Anzahl der Sicherungspunkte.</span></li>
                            <li><span class="font-bold" data-i18n="dashboard.volumeLabel">Volume:</span> <span data-i18n="dashboard.volDesc">Physischer Speicher auf dem Datenträger.</span></li>
                        </ul>
                        <div class="absolute -top-1 left-8 w-2 h-2 rotate-45 tooltip-arrow"></div>
                    </div>

                    <span class="text-[11px] uppercase font-black text-slate-500 block mb-2 tracking-widest cursor-help" data-i18n="dashboard.volumeLabel">Archive Volume</span>
                    <div class="flex items-baseline gap-1 mt-4">
                        <span class="text-3xl font-black text-white card-number" id="total-val-display">0.00</span>
                        <span class="text-[12px] font-bold text-slate-600" id="total-unit-display">MB</span>
                    </div>
                    <div class="flex justify-between items-center mt-3 pt-3 border-t border-white/5">
                        <span class="text-[9px] uppercase text-slate-500 font-bold tracking-wider" data-i18n="dashboard.snapshotsLabel">Snapshots</span>
                        <span id="total-snapshots-display" class="text-[10px] font-mono text-blue-400">0</span>
                    </div>
                </div>

                <div class="commander-module p-5 relative group">
                    <div class="absolute top-full left-0 mt-2 w-full border text-[10px] px-3 py-3 rounded shadow-2xl opacity-0 group-hover:opacity-100 transition-all duration-300 pointer-events-none z-50 text-left leading-relaxed backdrop-blur-sm transform translate-y-2 group-hover:translate-y-0 commander-tooltip">
                        <strong class="text-blue-400 block mb-1" data-i18n="dashboard.deltaTitle">ℹ️ Workspace Delta Monitor</strong>
                        <p class="mb-1" data-i18n="dashboard.deltaDesc">Vergleicht live den Inhalt Ihres lokalen Ordners mit dem letzten Backup desselben Ordners.</p>
                        <ul class="list-disc list-inside space-y-0.5">
                            <li><span class="font-bold">Initial:</span> <span data-i18n="dashboard.deltaInitial">Noch kein Vergleich möglich (erster Snapshot).</span></li>
                            <li><span class="font-bold">Remote:</span> <span data-i18n="dashboard.deltaRemote">Zeigt Cloud-Daten im Download-Modus.</span></li>
                        </ul>
                        <div class="absolute -top-1 left-8 w-2 h-2 rotate-45 tooltip-arrow"></div>
                    </div>

                    <span class="text-[11px] uppercase font-black text-slate-500 block mb-3 tracking-widest flex justify-between items-center cursor-help">
                        <span class="border-b border-dashed border-slate-700" data-i18n="dashboard.deltaLabel">Workspace Delta</span>
                        <span id="delta-mode-badge" class="text-[9px] px-1.5 py-0.5 rounded bg-white/5 text-slate-500">LOCAL</span>
                    </span>
                    
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <span class="text-[9px] uppercase text-slate-600 font-bold block mb-1" data-i18n="dashboard.sizeLabel">Größe</span>
                            <div class="flex items-baseline gap-1">
                                <span id="delta-size-val" class="text-xl font-black text-white card-number">--</span>
                            </div>
                            <span id="delta-size-badge" class="text-[10px] font-bold text-slate-500 block mt-1">--</span>
                        </div>
                        <div class="pl-4 border-l border-white/5">
                            <span class="text-[9px] uppercase text-slate-600 font-bold block mb-1" data-i18n="dashboard.filesLabel">Dateien</span>
                            <div class="flex items-baseline gap-1">
                                <span id="delta-files-val" class="text-xl font-black text-white card-number">--</span>
                            </div>
                            <span id="delta-files-badge" class="text-[10px] font-bold text-slate-500 block mt-1">--</span>
                        </div>
                    </div>

                    <div class="flex justify-between items-center mt-3 pt-3 border-t border-white/5">
                        <span class="text-[9px] uppercase text-slate-500 font-bold tracking-wider" data-i18n="dashboard.refLabel">Ref</span>
                        <span id="delta-ref-info" class="text-[9px] font-mono text-slate-400 truncate max-w-[120px]" title="Vergleichsbasis" data-i18n-title="dashboard.refLabel">--</span>
                    </div>
                </div>

                <div class="commander-module p-5 bg-blue-500/5 border-blue-500/20 group text-center flex items-center justify-center">
                    <button onclick="runBackup()" id="main-action" class="w-full h-full flex flex-col items-center justify-center gap-3">
                        <div class="w-12 h-12 bg-blue-600 rounded-full flex items-center justify-center group-hover:scale-110 transition-transform shadow-xl shadow-blue-500/20 text-xl">⚡</div>
                        <span class="text-[11px] font-black uppercase text-blue-400 tracking-widest" data-i18n="dashboard.createSnapshot">Snapshot anlegen</span>
                    </button>
                </div>
            </div>

            <!-- Backup Success/Activity Chart -->
            <div class="commander-module p-6">
                <div class="flex justify-between items-end mb-6">
                    <div>
                        <h3 class="text-sm font-black uppercase text-slate-400 tracking-widest" data-i18n="dashboard.chartTitle">Backup Verlauf & Aktivität</h3>
                        <p class="text-xs text-slate-500 mt-1" data-i18n="dashboard.chartDesc">Visuelle Darstellung der Backup-Integrität und Volumina über die Zeit.</p>
                    </div>
                    <div class="flex gap-2 text-[10px] font-bold text-slate-500 uppercase">
                        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-blue-500"></span> <span data-i18n="dashboard.legendVol">Volumen</span></span>
                        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-emerald-500"></span> <span data-i18n="dashboard.legendBackup">Tag mit Backup</span></span>
                        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-full border border-red-500 bg-transparent"></span> <span data-i18n="dashboard.legendNoBackup">Kein Backup</span></span>
                    </div>
                </div>

                <!-- Live Stats Bar -->
                <div id="activity-stats-bar" class="grid grid-cols-3 gap-4 mb-4 opacity-50">
                    <!-- Will be populated by JS -->
                </div>
                
                <!-- Chart Container -->
                <div class="relative h-48 w-full bg-black/20 rounded-lg border border-white/5 overflow-hidden group" id="activity-chart-container">
                    <!-- SVG will be injected here -->
                    <div class="absolute inset-0 flex items-center justify-center text-xs text-slate-600 font-mono">
                        Lade Statistik...
                    </div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="commander-module p-6 lg:col-span-2 space-y-6">
                    <h2 class="text-sm font-black uppercase tracking-widest text-slate-400 border-b border-white/5 pb-3" data-i18n="dashboard.manualSnapshotTitle">Manueller Snapshot</h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div class="space-y-4">
                            <div>
                                <label class="text-[11px] font-black uppercase text-slate-500 mb-1 block tracking-widest" data-i18n="dashboard.sourceLabel">Quelle</label>
                                <input type="text" id="source" readonly class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs mono text-blue-300 outline-none">
                            </div>
                            <div>
                                <label class="text-[11px] font-black uppercase text-slate-500 mb-1 block tracking-widest" data-i18n="dashboard.targetLabel">Ziel</label>
                                <input type="text" id="dest" readonly class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs mono text-emerald-300 outline-none">
                            </div>
                            <div>
                                <label class="text-[11px] font-black uppercase text-slate-500 mb-1 block tracking-widest" data-i18n="dashboard.commentLabel">Kommentar</label>
                                <input type="text" id="snap-comment" placeholder="Zweck der Sicherung..." data-i18n-placeholder="dashboard.commentPlaceholder" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500">
                            </div>
                        </div>
                        <div class="bg-[#08090d] p-6 rounded-xl border border-white/5">
                            <span class="text-[11px] font-black uppercase text-slate-600 mb-2 block tracking-widest" data-i18n="dashboard.sourceState">Quell-Zustand</span>
                            <div id="src-size" class="text-3xl font-black text-white">--</div>
                            <div id="src-files" class="text-[11px] mono text-blue-500 font-bold mt-2 uppercase tracking-widest">-- FILES</div>
                            
                            <!-- Progress Area moved to Terminal -->
                        </div>
                    </div>
                </div>
                <div class="commander-module p-6 flex flex-col h-full min-h-[250px]">
                    <div class="flex items-center justify-between mb-4 border-b border-white/5 pb-3">
                        <h2 class="text-sm font-black uppercase tracking-widest text-slate-400" data-i18n="dashboard.terminalTitle">Command Terminal</h2>
                        <div class="flex gap-2">
                             <button onclick="document.getElementById('log').innerHTML=''" class="text-[9px] font-black uppercase text-slate-500 hover:text-white transition-colors" title="Log leeren" data-i18n-title="dashboard.clearLog" data-i18n="dashboard.clearBtn">CLEAR</button>
                             <button onclick="cancelBackup()" class="text-[9px] font-black uppercase text-red-500 hover:text-red-400 transition-colors border border-red-500/20 px-2 rounded hover:bg-red-500/10" title="Laufenden Prozess abbrechen" data-i18n-title="dashboard.cancelBackup" data-i18n="dashboard.cancelBtn">ABBRECHEN</button>
                        </div>
                    </div>
                    <div id="log" class="terminal-log h-[200px] bg-[#050608] p-4 rounded-lg mono text-[11px] space-y-1 overflow-y-auto border border-white/10 mb-4 shadow-inner"></div>

                    <!-- Permanent Console Status & Progress -->
                    <div id="console-status-area" class="bg-[#08090d] p-4 rounded-lg border border-blue-500/20 shadow-lg shadow-blue-900/10">
                        <div class="flex justify-between items-center mb-2">
                             <div class="flex items-center gap-2">
                                 <div id="status-indicator" class="w-2 h-2 rounded-full bg-slate-600 transition-colors duration-300"></div>
                                 <span id="console-status-text" class="text-[10px] font-black uppercase tracking-widest text-slate-400" data-i18n="dashboard.systemReady">System Bereit</span>
                             </div>
                             <span id="zipPercent" class="text-[10px] font-mono text-blue-400">0%</span>
                        </div>
                        <div class="w-full bg-[#0a0b10] h-2 rounded-full overflow-hidden border border-white/5 relative">
                            <div id="zipBar" class="bg-blue-500 h-full w-0 transition-all duration-300 relative"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="commander-module p-6">
                <div class="flex justify-between items-center mb-6">
                    <h2 class="text-sm font-black uppercase tracking-widest text-slate-400" data-i18n="dashboard.telemetryTitle">Wachstums-Telemetrie (Historisch)</h2>
                    <div class="flex items-center gap-3">
                         <div class="flex items-center gap-2 bg-black/20 px-2 py-1 rounded border border-white/5">
                            <input type="checkbox" id="chart-log-scale" onchange="toggleChartScale()" class="w-3 h-3 bg-[#08090d] border-white/10 rounded accent-blue-500 cursor-pointer">
                            <label for="chart-log-scale" class="text-[9px] font-black uppercase text-slate-500 cursor-pointer select-none tracking-wider hover:text-blue-400 transition-colors" data-i18n="dashboard.logScale">Log-Skala</label>
                         </div>
                    </div>
                </div>
                <div class="h-[200px] w-full relative">
                    <canvas id="storageChart"></canvas>
                </div>
                <div class="mt-1 flex justify-end">
                    <div class="bg-black/70 px-2 py-1 rounded border border-white/10 text-[9px] text-slate-400 flex items-center gap-2">
                        <span class="flex items-center gap-1">
                            <span class="w-3 h-3 rounded-full" style="background-color: hsl(200,80%,70%);"></span>
                            <span class="uppercase tracking-wider" data-i18n="dashboard.legendNew">Neu</span>
                        </span>
                        <span class="flex items-center gap-1">
                            <span class="w-3 h-3 rounded-full" style="background-color: hsl(280,80%,40%);"></span>
                            <span class="uppercase tracking-wider" data-i18n="dashboard.legendOld">Alt</span>
                        </span>
                    </div>
                </div>
            </div>

            <div class="commander-module p-6">
                <h2 class="text-[12px] text-slate-500 uppercase font-bold mb-6 tracking-widest">
                    <span data-i18n="dashboard.historyTitle">Snapshot Historie</span>
                    <span id="total-snaps-badge" class="ml-2 bg-blue-500/10 text-blue-400 px-2 py-0.5 rounded text-[10px] border border-blue-500/20">0</span>
                </h2>
                
                <div class="flex gap-2 mb-4 items-center">
                    <button onclick="window.clearHistory()" class="text-[10px] font-black uppercase bg-red-500/10 border border-red-500/20 px-3 py-1 rounded text-red-400 hover:bg-red-500/20 transition-all tracking-widest" data-i18n="dashboard.clearHistoryBtn">
                        Historie leeren
                    </button>
                    <button onclick="window.toggleSort()" id="btn-sort" class="text-[10px] font-black uppercase bg-blue-500/10 border border-blue-500/20 px-3 py-1 rounded text-blue-400 hover:bg-blue-500/20 transition-all tracking-widest min-w-[140px]" data-i18n="dashboard.sortBtn">
                        Sort: Datum (Neu)
                    </button>
                    <button onclick="window.refreshHistory()" title="Aktualisieren" data-i18n-title="dashboard.refreshBtn" class="text-[10px] font-black uppercase bg-emerald-500/10 border border-emerald-500/20 px-2 py-1 rounded text-emerald-400 hover:bg-emerald-500/20 transition-all">
                        <svg xmlns="http://www.w3.org/2000/svg" id="btn-refresh-hist" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                        </svg>
                    </button>
                    <div class="ml-auto flex items-center gap-2">
                         <span class="text-[10px] font-black uppercase text-slate-500 tracking-widest" data-i18n="dashboard.limitLabel">Limit:</span>
                         <select id="history-limit" onchange="window.updateHistoryLimit()" class="bg-[#08090d] border border-white/5 rounded px-2 py-1 text-[10px] font-black uppercase text-blue-400 outline-none">
                             <option value="5">5</option>
                             <option value="10" selected>10</option>
                             <option value="25">25</option>
                             <option value="50">50</option>
                             <option value="100">100</option>
                             <option value="all" data-i18n="dashboard.limitAll">Alle</option>
                         </select>
                    </div>
                </div>

                <div class="overflow-x-auto">
                    <table class="min-w-full text-left text-sm">
                        <thead><tr class="text-slate-500 uppercase text-[10px] font-black"><th class="px-4 py-3">Datum</th><th class="px-4 py-3">Datei</th><th class="px-4 py-3 text-right" id="history-size-header">Größe</th></tr></thead>
                        <tbody id="history-table-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- Tab: Restore -->
        <section id="tab-restore" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden">
            <div class="commander-module p-6">
                <h2 class="text-sm font-black uppercase tracking-widest text-slate-400 border-b border-white/5 pb-3 mb-6" data-i18n="restore.title">Wiederherstellungs-Zentrum</h2>
                <div class="overflow-x-auto text-slate-200">
                    <table class="min-w-full text-left text-sm">
                        <thead><tr class="bg-[#0d0f16]"><th class="px-4 py-3" data-i18n="restore.tableTime">Zeitpunkt</th><th class="px-4 py-3" data-i18n="restore.tableArchive">Archiv</th><th class="px-4 py-3" data-i18n="restore.tableAction">Aktion</th></tr></thead>
                        <tbody id="restore-table-body"></tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- Tab: Cloud -->
        <section id="tab-cloud" class="tab-content flex-1 overflow-y-auto hidden text-slate-200" style="scrollbar-gutter: stable;">
            <div class="max-w-5xl mx-auto p-8 space-y-12">
                
                <!-- MODULE 1: CLOUD STORAGE TARGET -->
                <div id="module-cloud-tresor" class="commander-module relative overflow-hidden group">
                    <!-- Decorator Line Removed -->
                    
                    <div class="p-8 space-y-8">
                        <div class="flex items-center justify-between border-b border-white/5 pb-6">
                            <div>
                                <h2 class="text-lg font-black uppercase text-slate-200 tracking-wide" data-i18n="cloud.tresorTitle">Cloud Tresor</h2>
                                <p class="text-xs text-slate-500 mt-1" data-i18n="cloud.tresorSubtitle">Sichere deine Backups verschlüsselt auf externen Servern.</p>
                                <button onclick="saveProfile()" class="mt-2 bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/20 rounded px-2 py-1 text-[9px] font-black uppercase transition-colors" title="Speichert Status" data-i18n="cloud.saveButton" data-i18n-title="cloud.saveButtonTitle">💾 Speichern</button>
                            </div>
                            <div class="flex items-center gap-3 bg-black/20 px-4 py-2 rounded-lg border border-white/5">
                                <input type="checkbox" id="config-cloud-enabled" onchange="updateCloudTresorUI()" class="w-4 h-4 bg-[#08090d] border-white/10 rounded accent-blue-500 cursor-pointer">
                                <label for="config-cloud-enabled" class="text-[10px] font-black text-blue-400 uppercase tracking-wider cursor-pointer select-none" data-i18n="cloud.enabledLabel">Aktiviert</label>
                            </div>
                        </div>

                        <!-- Main Configuration Grid -->
                        <div class="grid grid-cols-1 lg:grid-cols-12 gap-8">
                            
                            <!-- Left Column: Settings -->
                            <div class="lg:col-span-8 space-y-6">
                                
                                <!-- Provider & Path -->
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div class="bg-black/20 p-4 rounded-xl border border-white/5">
                                        <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="cloud.serviceProviderLabel">Service Provider</label>
                                        <select id="config-cloud-provider" onchange="updateCloudTresorUI()" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500/50 transition-colors">
                                            <option>SFTP</option>
                                            <option>Dropbox</option>
                                            <option>S3 (Amazon)</option>
                                            <option>WebDAV</option>
                                        </select>
                                    </div>
                                    <div class="bg-black/20 p-4 rounded-xl border border-white/5">
                                        <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="cloud.directionLabel">Backup Richtung</label>
                                        <select id="config-cloud-direction" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500/50 transition-colors">
                                            <option value="upload" data-i18n="cloud.directionUploadOption">Upload (Lokal -> Cloud)</option>
                                            <option value="download" data-i18n="cloud.directionDownloadOption">Download (Cloud -> Lokal)</option>
                                        </select>
                                    </div>
                                    <div class="bg-black/20 p-4 rounded-xl border border-white/5 md:col-span-2">
                                        <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="cloud.remotePathLabel">Remote Path / Ordner</label>
                                        <div class="flex gap-2">
                                            <input type="text" id="config-cloud-path" placeholder="/backups/pro" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-blue-400 outline-none focus:border-blue-500/50 font-mono transition-colors" data-i18n-placeholder="cloud.remotePathPlaceholder">
                                            <button onclick="createStorageLocation()" class="bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 border border-blue-500/30 px-4 rounded text-[10px] font-bold uppercase tracking-wide transition-all whitespace-nowrap">
                                                <span data-i18n="cloud.createRemoteButton">Speicherort anlegen</span>
                                            </button>
                                        </div>
                                    </div>
                                    
                                    <!-- Local Download Path (Hidden by default, shown for Download direction) -->
                                    <div id="cloud-local-path-group" class="bg-black/20 p-4 rounded-xl border border-white/5 md:col-span-2 hidden">
                                        <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="cloud.localTargetLabel">Lokaler Zielordner (Download)</label>
                                        <div class="flex gap-2">
                                            <input type="text" id="config-cloud-local-path" placeholder="C:/Users/Backups/Download" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-green-400 outline-none focus:border-green-500/50 font-mono transition-colors">
                                            <button onclick="createLocalStorageLocation()" class="bg-green-500/20 hover:bg-green-500/30 text-green-400 border border-green-500/30 px-4 rounded text-[10px] font-bold uppercase tracking-wide transition-all whitespace-nowrap">
                                                <span data-i18n="cloud.createLocalFolderButton">Ordner erstellen</span>
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                <!-- Naming Options (NEW) -->
                                <div class="bg-black/20 p-4 rounded-xl border border-white/5">
                                    <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="cloud.namingTitle">Backup Name & Optionen</label>
                                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                             <input type="text" id="cloud-naming-custom" placeholder="backup-name" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500/50 font-mono transition-colors">
                                        </div>
                                        <div class="flex items-center gap-3">
                                             <label class="flex items-center gap-2 cursor-pointer">
                                                 <input type="checkbox" id="cloud-naming-date" checked class="w-3 h-3 bg-[#08090d] border-white/10 rounded accent-blue-500 cursor-pointer">
                                                 <span class="text-[10px] text-slate-400 font-bold uppercase select-none" data-i18n="cloud.namingDateLabel">Datum</span>
                                             </label>
                                             <label class="flex items-center gap-2 cursor-pointer">
                                                 <input type="checkbox" id="cloud-naming-time" checked class="w-3 h-3 bg-[#08090d] border-white/10 rounded accent-blue-500 cursor-pointer">
                                                 <span class="text-[10px] text-slate-400 font-bold uppercase select-none" data-i18n="cloud.namingTimeLabel">Zeit</span>
                                             </label>
                                             <label class="flex items-center gap-2 cursor-pointer">
                                                 <input type="checkbox" id="cloud-naming-seq" class="w-3 h-3 bg-[#08090d] border-white/10 rounded accent-blue-500 cursor-pointer">
                                                 <span class="text-[10px] text-slate-400 font-bold uppercase select-none" data-i18n="cloud.namingSeqLabel">Seq</span>
                                             </label>
                                        </div>
                                    </div>
                                </div>

                                <!-- Dynamic Auth Fields (JS controlled visibility) -->
                                <div class="bg-black/20 p-6 rounded-xl border border-white/5 space-y-6 relative overflow-hidden">
                                     
                                     <!-- Host Group -->
                                    <div id="cloud-host-group" class="grid grid-cols-4 gap-4">
                                         <div class="col-span-3">
                                             <label id="lbl-cloud-host" class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="cloud.hostLabel">Server Host / IP</label>
                                             <input type="text" id="config-cloud-host" placeholder="z.B. 192.168.1.100" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500/50 font-mono" data-i18n-placeholder="cloud.hostPlaceholder">
                                         </div>
                                         <div>
                                             <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="cloud.portLabel">Port</label>
                                             <input type="number" id="config-cloud-port" placeholder="22" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-slate-400 outline-none focus:border-blue-500/50 font-mono">
                                         </div>
                                    </div>

                                    <!-- S3 Group -->
                                    <div id="cloud-s3-group" class="grid grid-cols-2 gap-4 hidden">
                                         <div>
                                             <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="cloud.bucketLabel">S3 Bucket Name</label>
                                             <input type="text" id="config-cloud-bucket" placeholder="my-backup-bucket" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500/50 font-mono">
                                         </div>
                                         <div>
                                             <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="cloud.regionLabel">Region</label>
                                             <input type="text" id="config-cloud-region" placeholder="eu-central-1" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500/50 font-mono">
                                         </div>
                                    </div>

                                    <!-- Auth Group -->
                                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6" id="cloud-auth-group">
                                        <div id="cloud-user-wrap">
                                             <label id="lbl-cloud-user" class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="cloud.userLabel">Benutzer / Access ID</label>
                                             <input type="text" id="config-cloud-user" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500/50 font-mono">
                                        </div>
                                        <div>
                                             <label id="lbl-cloud-pass" class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="cloud.passwordLabel">Passwort / Secret / Token</label>
                                             <div class="relative">
                                                <input type="password" id="config-cloud-password" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-yellow-500 outline-none focus:border-yellow-500/50 pr-10 font-mono">
                                                <button onclick="togglePassword('config-cloud-password', this)" class="absolute right-0 top-0 h-full px-3 text-slate-500 hover:text-white focus:outline-none flex items-center justify-center transition-colors" tabindex="-1">
                                                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>
                                                </button>
                                             </div>
                                        </div>
                                    </div>
                                    
                                    <!-- API Key -->
                                    <div>
                                         <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="cloud.apiKeyLabel">Optionaler API-Key</label>
                                         <div class="relative">
                                            <input type="password" id="config-cloud-api-key" placeholder="Leer lassen falls nicht benötigt" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-slate-400 outline-none focus:border-blue-500/50 font-mono pr-10" data-i18n-placeholder="cloud.apiKeyPlaceholder">
                                            <button onclick="togglePassword('config-cloud-api-key', this)" class="absolute right-0 top-0 h-full px-3 text-slate-500 hover:text-white focus:outline-none flex items-center justify-center transition-colors" tabindex="-1">
                                                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>
                                            </button>
                                         </div>
                                    </div>

                                    <!-- Actions (Moved) -->
                                    <div class="grid grid-cols-3 gap-2 pt-2">
                                        <button onclick="runCloudBackupNow()" class="w-full bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 border border-blue-500/30 py-3 rounded text-[10px] font-bold uppercase tracking-wide transition-all truncate" title="Backup Jetzt & Upload" data-i18n-title="cloud.backupNowTitle">
                                            <span data-i18n="cloud.backupNowButton">⚡ Backup</span>
                                        </button>
                                        <button onclick="testCloudConnection()" class="w-full py-3 rounded text-[10px] text-slate-400 bg-white/5 border border-white/10 hover:bg-white/10 transition-colors font-bold uppercase tracking-wide truncate" title="Verbindung Testen" data-i18n="cloud.testButton" data-i18n-title="cloud.testTitle">Testen</button>
                                    </div>
                                </div>
                            </div>

                            <!-- Right Column: Status & Encryption -->
                            <div class="lg:col-span-4 space-y-6">
                                
                                <!-- Status Card -->
                                <div class="bg-black/40 p-6 rounded-xl border border-white/5 flex flex-col items-center justify-center text-center space-y-3 h-[140px]">
                                    <div class="text-[9px] font-black uppercase text-slate-500 tracking-widest" data-i18n="cloud.statusLabel">Status</div>
                                    <span id="cloud-status-badge" class="px-3 py-1 bg-slate-500/10 border border-slate-500/20 text-slate-500 text-[10px] font-black uppercase rounded" data-i18n="cloud.statusDisabled">Deaktiviert</span>
                                </div>

                                <!-- Encryption -->
                                <div class="bg-black/20 p-6 rounded-xl border border-white/5 space-y-4">
                                    <div class="flex items-center gap-3 border-b border-white/5 pb-3">
                                        <input type="checkbox" id="config-enc-enabled" class="w-4 h-4 bg-[#08090d] border-white/10 rounded accent-emerald-500 cursor-pointer">
                                        <label for="config-enc-enabled" class="text-[10px] font-black text-slate-300 uppercase tracking-wider cursor-pointer select-none" data-i18n="cloud.encToggleLabel">AES-256 Encryption</label>
                                    </div>
                                    <div>
                                        <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="cloud.encPasswordLabel">Archiv Passwort</label>
                                        <div class="relative">
                                            <input type="password" id="config-enc-password" placeholder="Key..." class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-emerald-400 outline-none focus:border-emerald-500/50 pr-10 font-mono" data-i18n-placeholder="cloud.encPasswordPlaceholder">
                                            <button onclick="togglePassword('config-enc-password', this)" class="absolute right-0 top-0 h-full px-3 text-slate-500 hover:text-white focus:outline-none flex items-center justify-center transition-colors" tabindex="-1">
                                                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>
                                            </button>
                                        </div>
                                    </div>
                                </div>



<!-- Cloud Status Area (Updated Design) -->
<div id="status-area-cloud-tresor" class="mt-4 bg-[#08090d] p-4 rounded-lg border border-blue-500/20 shadow-lg shadow-blue-900/10">
    <!-- Console Log Area -->
    <div id="console-cloud-tresor" class="h-[120px] bg-[#050608] p-3 rounded-lg mono text-[10px] text-slate-400 space-y-1 overflow-y-auto border border-white/10 mb-3 shadow-inner">
        <div class="text-slate-600 border-b border-white/5 mb-1 pb-1 font-black tracking-widest uppercase text-[9px]" data-i18n="cloud.terminalTitle">Cloud Terminal</div>
        <div id="console-content-cloud-tresor" class="space-y-1"></div>
    </div>

    <!-- Progress Bar -->
    <div class="flex justify-between items-center mb-2">
         <div class="flex items-center gap-2">
             <div class="w-1.5 h-1.5 rounded-full bg-slate-600" id="status-dot-cloud-tresor"></div>
             <span id="status-msg-cloud-tresor" class="text-[9px] font-black uppercase tracking-widest text-slate-400 truncate max-w-[150px]" data-i18n="cloud.statusWaitingLabel">Warte...</span>
         </div>
         <span id="status-pct-cloud-tresor" class="text-[9px] font-mono text-blue-400">0%</span>
    </div>
    <div class="w-full bg-[#0a0b10] h-1.5 rounded-full overflow-hidden border border-white/5 relative">
        <div id="status-bar-cloud-tresor" class="bg-blue-500 h-full w-0 transition-all duration-300 relative"></div>
    </div>
    
    <div id="status-err-cloud-tresor" class="hidden text-[10px] text-red-400 mt-2 font-mono break-all bg-red-500/10 p-2 rounded border border-red-500/20"></div>
</div>

                            </div>
                        </div>
                    </div>
                </div>

                <!-- MODULE: DATABASE BACKUP -->
                <div id="module-db" class="commander-module relative overflow-hidden group">
                    <div class="p-8 space-y-8">
                        <div class="flex items-center justify-between border-b border-white/5 pb-6">
                            <div>
                                <h2 class="text-lg font-black uppercase text-slate-200 tracking-wide" data-i18n="db.title">Datenbanken (Cloud Dump)</h2>
                                <p class="text-xs text-slate-500 mt-1" data-i18n="db.subtitle">Automatische Dumps von MySQL/PostgreSQL Datenbanken.</p>
                                <button onclick="saveProfile()" class="mt-2 bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/20 rounded px-2 py-1 text-[9px] font-black uppercase transition-colors" title="Speichert Status" data-i18n="db.saveButton" data-i18n-title="db.saveButtonTitle">💾 Speichern</button>
                            </div>
                            <div class="flex items-center gap-3 bg-black/20 px-4 py-2 rounded-lg border border-white/5">
                                <input type="checkbox" id="config-db-enabled" onchange="updateDbUI()" class="w-4 h-4 bg-[#08090d] border-white/10 rounded accent-blue-500 cursor-pointer">
                                <label for="config-db-enabled" class="text-[10px] font-black text-blue-400 uppercase tracking-wider cursor-pointer select-none" data-i18n="db.enabledLabel">Aktiviert</label>
                            </div>
                        </div>
                        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                            <!-- Left: Connection Settings -->
                            <div class="space-y-6">
                                <div class="bg-black/20 p-5 rounded-xl border border-white/5">
                                    <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="db.typeLabel">Datenbank Typ</label>
                                    <select id="config-db-type" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500/50 transition-colors">
                                        <option value="mysql">MySQL / MariaDB</option>
                                        <option value="postgres">PostgreSQL</option>
                                    </select>
                                </div>
                                <div class="grid grid-cols-3 gap-4">
                                    <div class="col-span-2">
                                        <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="db.hostLabel">Host</label>
                                        <input type="text" id="config-db-host" placeholder="localhost" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500/50 font-mono">
                                    </div>
                                    <div>
                                        <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="db.portLabel">Port</label>
                                        <input type="number" id="config-db-port" placeholder="3306" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-slate-400 outline-none focus:border-blue-500/50 font-mono">
                                    </div>
                                </div>
                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="db.userLabel">Benutzer</label>
                                        <input type="text" id="config-db-user" placeholder="root" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500/50 font-mono">
                                    </div>
                                    <div>
                                        <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="db.passwordLabel">Passwort</label>
                                        <input type="password" id="config-db-password" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-yellow-500 outline-none focus:border-yellow-500/50 font-mono">
                                    </div>
                                </div>
                            </div>
                            <!-- Right: Target & Actions -->
                            <div class="space-y-6 flex flex-col justify-between">
                                <div class="bg-black/20 p-5 rounded-xl border border-white/5">
                                    <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="db.namesLabel">Datenbank Name(n)</label>
                                    <input type="text" id="config-db-names" placeholder="db1, db2 (Kommagetrennt) oder *" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs mono text-emerald-300 outline-none focus:border-blue-500/50 transition-colors mb-2" data-i18n-placeholder="db.namesPlaceholder">
                                    <p class="text-[9px] text-slate-600" data-i18n="db.namesHelpText">Verwenden Sie * für alle Datenbanken (nur root).</p>
                                </div>
                                <div class="grid grid-cols-2 gap-4">
                                    <button onclick="runDbBackupNow(this)" class="py-4 rounded text-xs text-emerald-300 bg-emerald-500/5 border border-emerald-500/10 hover:bg-emerald-500/20 transition-all font-black uppercase tracking-wide" data-i18n="db.dumpNowButton">
                                        ⚡ Dump Erstellen
                                    </button>
                                </div>


                                <!-- DB Status Area -->
                                <div id="status-area-db" class="hidden mt-4 bg-slate-900/50 rounded p-3 border border-white/5 shadow-inner">
                                    <div class="flex justify-between items-center mb-2">
                                        <span id="status-msg-db" class="text-[10px] text-slate-400 font-mono truncate max-w-[200px]" data-i18n="db.statusWaitingLabel">Warte...</span>
                                        <span id="status-pct-db" class="text-[10px] text-emerald-400 font-bold">0%</span>
                                    </div>
                                    <div class="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                                        <div id="status-bar-db" class="h-full bg-emerald-500 w-0 transition-all duration-300 relative overflow-hidden">
                                            <div class="absolute inset-0 bg-white/20 w-full h-full animate-pulse"></div>
                                        </div>
                                    </div>
                                    <div id="status-err-db" class="hidden text-[10px] text-red-400 mt-2 font-mono break-all bg-red-500/10 p-2 rounded border border-red-500/20"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- MODULE 2: GITHUB REPOSITORIES -->
                <div id="module-github" class="commander-module relative overflow-hidden group">
                    <!-- Decorator Line Removed -->

                    <div class="p-8 space-y-8">
                        <div class="flex items-center justify-between border-b border-white/5 pb-6">
                            <div>
                                <h2 class="text-lg font-black uppercase text-slate-200 tracking-wide" data-i18n="github.title">GitHub Sources</h2>
                                <p class="text-xs text-slate-500 mt-1" data-i18n="github.subtitle">Klone und sichere Git-Repositories automatisch.</p>
                                <button onclick="saveProfile()" class="mt-2 bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 border border-purple-500/20 rounded px-2 py-1 text-[9px] font-black uppercase transition-colors" title="Speichert Status" data-i18n="github.saveButton" data-i18n-title="github.saveButtonTitle">💾 Speichern</button>
                            </div>
                            <div class="flex items-center gap-3 bg-black/20 px-4 py-2 rounded-lg border border-white/5">
                                <input type="checkbox" id="config-github-enabled" onchange="updateGithubUI()" class="w-4 h-4 bg-[#08090d] border-white/10 rounded accent-purple-500 cursor-pointer">
                                <label for="config-github-enabled" class="text-[10px] font-black text-purple-400 uppercase tracking-wider cursor-pointer select-none" data-i18n="github.enabledLabel">Aktiviert</label>
                            </div>
                        </div>

                        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                            <!-- Left: Connection -->
                            <div class="space-y-6">
                                <div class="bg-black/20 p-5 rounded-xl border border-white/5">
                                    <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="github.repoUrlLabel">Repository URL</label>
                                    <div class="flex gap-2 items-center">
                                        <span class="text-lg opacity-30">🌐</span>
                                        <input type="text" id="config-github-url" placeholder="https://github.com/username/repo" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-purple-300 outline-none focus:border-purple-500/50 font-mono transition-colors">
                                    </div>
                                    <p class="text-[9px] text-slate-600 mt-2 pl-8" data-i18n="github.repoHelpText">Unterstützt HTTPS URLs öffentlicher und privater Repos.</p>
                                </div>

                                <div class="bg-black/20 p-5 rounded-xl border border-white/5">
                                    <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="github.tokenLabel">Personal Access Token (PAT)</label>
                                    <div class="flex gap-2">
                                        <div class="relative flex-1">
                                            <input type="password" id="config-github-token" placeholder="Nur für private Repos nötig..." class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-yellow-500 outline-none focus:border-yellow-500/50 pr-10 font-mono" data-i18n-placeholder="github.tokenPlaceholder">
                                            <button onclick="togglePassword('config-github-token', this)" class="absolute right-0 top-0 h-full px-3 text-slate-500 hover:text-white focus:outline-none flex items-center justify-center transition-colors" tabindex="-1">
                                                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>
                                            </button>
                                        </div>
                                        <button onclick="testGithubConnection(this)" class="px-4 py-2 bg-purple-500/10 hover:bg-purple-500/20 border border-purple-500/20 rounded text-[10px] font-bold uppercase text-purple-300 transition-colors" data-i18n="github.testConnectionButton">Verbindung Testen</button>
                                    </div>
                                </div>
                            </div>

                            <!-- Right: Target & Actions -->
                            <div class="space-y-6 flex flex-col justify-between">
                                <div class="bg-black/20 p-5 rounded-xl border border-white/5">
                                    <label class="text-[9px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="github.localTargetLabel">Lokaler Zielordner (Optional)</label>
                                    <div class="flex gap-2">
                                        <input type="text" id="config-github-path" placeholder="Standard: /github_backups" class="flex-1 bg-[#08090d] border border-white/5 rounded p-2 text-xs mono text-slate-300 outline-none focus:border-purple-500/50 transition-colors" data-i18n-placeholder="github.localTargetPlaceholder">
                                        <button onclick="pickFolder('config-github-path')" class="bg-white/5 p-2 rounded text-xs hover:bg-white/10 transition-colors text-slate-400" title="Ordner wählen" data-i18n-title="duplicates.chooseFolderTitle">📁</button>
                                    </div>
                                    <p class="text-[9px] text-slate-600 mt-2" data-i18n="github.localTargetHelpText">Lässt du dies leer, wird ein Standardordner im Backup-Ziel erstellt.</p>
                                </div>

                                <div class="grid grid-cols-2 gap-4">
                                    <button onclick="runGithubBackupNow(this)" class="py-4 rounded text-xs text-purple-300 bg-purple-500/5 border border-purple-500/10 hover:bg-purple-500/20 transition-all font-black uppercase tracking-wide" data-i18n="github.runNowButton">
                                        ⚡ Jetzt Ausführen
                                    </button>
                                </div>

                                <!-- GitHub Status Area -->
                                <div id="status-area-github" class="hidden mt-4 bg-slate-900/50 rounded p-3 border border-white/5 shadow-inner">
                                    <div class="flex justify-between items-center mb-2">
                                        <span id="status-msg-github" class="text-[10px] text-slate-400 font-mono truncate max-w-[200px]" data-i18n="github.statusWaitingLabel">Warte...</span>
                                        <span id="status-pct-github" class="text-[10px] text-purple-400 font-bold">0%</span>
                                    </div>
                                    <div class="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                                        <div id="status-bar-github" class="h-full bg-purple-500 w-0 transition-all duration-300 relative overflow-hidden">
                                            <div class="absolute inset-0 bg-white/20 w-full h-full animate-pulse"></div>
                                        </div>
                                    </div>
                                    <div id="status-err-github" class="hidden text-[10px] text-red-400 mt-2 font-mono break-all bg-red-500/10 p-2 rounded border border-red-500/20"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </section>

        <!-- Tab: Analyse -->
        <section id="tab-duplicates" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden text-slate-200" style="scrollbar-gutter: stable;">
            <div class="commander-module p-6 space-y-6 max-w-3xl mx-auto">
                <div class="flex flex-col gap-4 border-b border-white/5 pb-4">
                    <div class="flex justify-between items-center">
                        <h2 class="text-sm font-black uppercase tracking-widest text-slate-400" data-i18n="duplicates.title">Deep-Scan Duplikatanalyse</h2>
                        <div class="flex gap-2">
                             <button id="btn-cancel-scan" onclick="stopScan()" class="hidden text-[10px] font-black bg-red-500/10 border border-red-500/20 px-4 py-2 rounded text-red-400 hover:bg-red-500/20 transition-all uppercase tracking-widest" data-i18n="duplicates.cancelButton">Abbruch</button>
                             <button id="btn-start-scan" onclick="scanDuplicates()" class="text-[10px] font-black bg-blue-500/10 border border-blue-500/20 px-4 py-2 rounded text-blue-400 hover:bg-blue-500/20 transition-all uppercase tracking-widest" data-i18n="duplicates.startButton">Scan starten</button>
                        </div>
                    </div>

                    <!-- Custom Path -->
                    <div>
                        <label class="text-[10px] font-black uppercase text-slate-500 block mb-1" data-i18n="duplicates.searchPathLabel">Suchpfad (Optional)</label>
                        <div class="flex gap-2">
                            <input type="text" id="scan-path" placeholder="Leer lassen für Standard-Quellpfad..." class="flex-1 bg-[#08090d] border border-white/5 rounded p-2 text-xs mono text-slate-300 outline-none focus:border-blue-500/50 transition-colors" data-i18n-placeholder="duplicates.searchPathPlaceholder">
                            <button onclick="pickFolder('scan-path')" class="bg-white/5 p-2 rounded text-xs hover:bg-white/10 transition-colors" title="Ordner wählen" data-i18n-title="duplicates.chooseFolderTitle">📁</button>
                        </div>
                    </div>
                    
                    <!-- Filters -->
                    <div class="grid grid-cols-2 gap-4">
                         <div>
                            <label class="text-[10px] font-black uppercase text-slate-500 block mb-1" data-i18n="duplicates.minSizeLabel">Min. Dateigröße</label>
                            <select id="scan-min-size" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none">
                                <option value="0" data-i18n="duplicates.sizeAll">Alle Größen</option>
                                <option value="1048576" data-i18n="duplicates.sizeFrom1MB">Ab 1 MB</option>
                                <option value="10485760" data-i18n="duplicates.sizeFrom10MB">Ab 10 MB</option>
                                <option value="104857600" data-i18n="duplicates.sizeFrom100MB">Ab 100 MB</option>
                                <option value="1073741824" data-i18n="duplicates.sizeFrom1GB">Ab 1 GB</option>
                            </select>
                         </div>
                         <div>
                            <label class="text-[10px] font-black uppercase text-slate-500 block mb-1" data-i18n="duplicates.typesLabel">Dateitypen</label>
                            <select id="scan-extensions" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none">
                                <option value="all" data-i18n="duplicates.typesAll">Alle Dateien</option>
                                <option value="images" data-i18n="duplicates.typesImages">Bilder (.jpg, .png, .raw, ...)</option>
                                <option value="videos" data-i18n="duplicates.typesVideos">Videos (.mp4, .mov, .mkv, ...)</option>
                                <option value="docs" data-i18n="duplicates.typesDocs">Dokumente (.pdf, .docx, .txt, ...)</option>
                                <option value="archives" data-i18n="duplicates.typesArchives">Archive (.zip, .rar, .7z, ...)</option>
                            </select>
                         </div>
                    </div>
                </div>
                
                <div id="duplicate-results" class="space-y-4 min-h-[300px]">
                    <div class="text-center py-20 opacity-30 italic text-sm" data-i18n="duplicates.emptyState">Kein Scan aktiv. Starten Sie die Analyse, um redundante Daten aufzuspüren.</div>
                </div>
            </div>
        </section>

        <!-- Tab: Parameter -->
        <section id="tab-settings" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden text-slate-200">
            <div class="commander-module p-8 max-w-2xl mx-auto text-slate-200">
                <h2 class="text-sm font-black uppercase text-slate-400 border-b border-white/5 pb-4 mb-4" data-i18n="settings.kernelTitle">Kernel Parameter & Automatisierung</h2>
                <div class="flex items-center justify-between mb-6">
                    <span class="text-[10px] font-black uppercase text-slate-500 tracking-widest" data-i18n="settings.languageLabel">Sprache / Language</span>
                    <button id="config-language-button" class="px-3 py-1 rounded border border-white/10 text-[10px] font-black uppercase tracking-widest text-slate-300 hover:text-white hover:border-blue-500/40 hover:bg-blue-500/10 transition-colors" data-i18n="settings.languageButton">Deutsch / English</button>
                </div>
                <div class="space-y-8">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                             <label class="text-[10px] font-black uppercase text-slate-500" data-i18n="settings.sourcePathLabel">Source Path</label>
                             <div class="flex gap-2">
                                <input type="text" id="config-source" readonly class="flex-1 bg-[#08090d] border border-white/5 rounded p-2 text-xs mono text-blue-300">
                                <button onclick="pickFile('config-source')" class="bg-white/5 p-2 rounded text-[10px] uppercase font-black transition-colors hover:bg-white/10" title="Einzelne Datei wählen" data-i18n-title="settings.sourceFileTitle">📄</button>
                                <button onclick="pickFiles('config-source')" class="bg-white/5 p-2 rounded text-[10px] uppercase font-black transition-colors hover:bg-white/10" title="Mehrere Dateien wählen" data-i18n-title="settings.sourceFilesTitle">📑</button>
                                <button onclick="pickFolder('config-source')" class="bg-white/5 p-2 rounded text-[10px] uppercase font-black transition-colors hover:bg-white/10" title="Ordner wählen" data-i18n-title="settings.sourceFolderTitle">📁</button>
                             </div>
                        </div>
                        <div>
                             <label class="text-[10px] font-black uppercase text-slate-500" data-i18n="settings.targetPathLabel">Target Path</label>
                             <div class="flex gap-2">
                                <input type="text" id="config-dest" readonly class="flex-1 bg-[#08090d] border border-white/5 rounded p-2 text-xs mono text-emerald-300">
                                <button onclick="pickFolder('config-dest')" class="bg-white/5 p-2 rounded text-[10px] uppercase font-black transition-colors hover:bg-white/10" data-i18n="settings.targetFolderButton">Pick</button>
                             </div>
                        </div>
                    </div>

                    <div class="bg-black/20 p-5 rounded-xl border border-white/5 space-y-4">
                        <div class="flex items-center justify-between">
                            <div class="flex flex-col">
                                <span class="text-[11px] font-black uppercase text-slate-400 tracking-wider" data-i18n="settings.autoSnapshotTitle">Automatischer Snapshot</span>
                                <span class="text-[9px] text-slate-500" data-i18n="settings.autoSnapshotSubtitle">Sichert Daten im gewählten Intervall im Hintergrund.</span>
                            </div>
                            <div class="flex items-center gap-3">
                                <div class="w-12 h-6 bg-slate-800 rounded-full relative cursor-pointer" onclick="toggleAutoBackup()">
                                    <div id="auto-toggle-knob" class="absolute top-1 left-1 w-4 h-4 bg-slate-500 rounded-full transition-all"></div>
                                </div>
                                <button onclick="saveProfile()" class="bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 border border-blue-500/20 rounded px-2 py-1 text-[9px] font-black uppercase transition-colors" title="Speichert alle Einstellungen" data-i18n-title="settings.saveProfileButtonTitle">💾</button>
                            </div>
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="text-[10px] font-black uppercase text-slate-500 mb-1 block" data-i18n="settings.intervalLabel">Intervall (Minuten)</label>
                                <input type="number" id="config-auto-interval" placeholder="z.B. 60" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-blue-400 outline-none" data-i18n-placeholder="settings.intervalPlaceholder">
                            </div>
                            <div>
                                <label class="text-[10px] font-black uppercase text-slate-500 mb-1 block" data-i18n="settings.retentionLabel">Retention Limit</label>
                                <input type="number" id="config-retention" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none">
                            </div>
                        </div>

                    </div>

                    <div class="bg-black/20 p-5 rounded-xl border border-white/5 space-y-4">
                        <h3 class="text-[11px] font-black uppercase text-slate-400 border-b border-white/5 pb-2" data-i18n="settings.namingTitle">Backup-Benennung</h3>
                        
                        <div>
                             <label class="text-[10px] font-black uppercase text-slate-500 mb-2 block tracking-widest" data-i18n="settings.namingCustomLabel">Eigener Name (Präfix)</label>
                             <input type="text" id="config-naming-custom" placeholder="z.B. projekt_alpha" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-blue-500 mb-2" oninput="updateNamingPreview()" data-i18n-placeholder="settings.namingCustomPlaceholder">
                        </div>

                        <div class="grid grid-cols-3 gap-4">
                            <div class="flex items-center gap-2">
                                <input type="checkbox" id="config-naming-date" class="w-3 h-3 bg-[#08090d] border-white/10 rounded" onchange="updateNamingPreview()">
                                <label for="config-naming-date" class="text-[10px] font-bold text-slate-400 uppercase" data-i18n="settings.namingDateLabel">Datum</label>
                            </div>
                            <div class="flex items-center gap-2">
                                <input type="checkbox" id="config-naming-time" class="w-3 h-3 bg-[#08090d] border-white/10 rounded" onchange="updateNamingPreview()">
                                <label for="config-naming-time" class="text-[10px] font-bold text-slate-400 uppercase" data-i18n="settings.namingTimeLabel">Zeit</label>
                            </div>
                            <div class="flex items-center gap-2">
                                <input type="checkbox" id="config-naming-seq" class="w-3 h-3 bg-[#08090d] border-white/10 rounded" onchange="updateNamingPreview()">
                                <label for="config-naming-seq" class="text-[10px] font-bold text-slate-400 uppercase" data-i18n="settings.namingSeqLabel">Laufende Nr.</label>
                                <input type="number" id="config-naming-seq-val" class="w-12 bg-[#08090d] border border-white/5 rounded p-1 text-[10px] text-center text-blue-400 outline-none" value="1" min="1" oninput="updateNamingPreview()" title="Aktueller Zählerstand (Startwert)" data-i18n-title="settings.namingSeqTitle">
                            </div>
                        </div>

                        <div class="pt-2 border-t border-white/5">
                            <div class="flex justify-between items-center">
                                <span class="text-[10px] font-black uppercase text-slate-500" data-i18n="settings.namingPreviewLabel">Vorschau:</span>
                                <span id="naming-preview" class="text-xs mono text-emerald-400" data-i18n="settings.namingPreviewExample">backup_2023-10-27.zip</span>
                            </div>
                        </div>
                    </div>

                    <!-- Erweiterte Optionen -->
                    <div class="bg-black/20 p-5 rounded-xl border border-white/5 space-y-4">
                        <h3 class="text-[11px] font-black uppercase text-slate-400 border-b border-white/5 pb-2" data-i18n="settings.advancedOptionsTitle">Erweiterte Optionen</h3>
                        
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="text-[10px] font-black uppercase text-slate-500 mb-1 block" data-i18n="settings.compressionLabel">Komprimierung</label>
                                <select id="config-compression" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none">
                                    <option value="0" data-i18n="settings.compressionNone">Keine (Nur Speichern)</option>
                                    <option value="1" data-i18n="settings.compressionFast">Schnell (Level 1)</option>
                                    <option value="3" selected data-i18n="settings.compressionStandard">Standard (Level 3)</option>
                                    <option value="5" data-i18n="settings.compressionStrong">Stark (Level 5)</option>
                                    <option value="9" data-i18n="settings.compressionMax">Maximal (Level 9)</option>
                                </select>
                            </div>
                            <div>
                                 <label class="text-[10px] font-black uppercase text-slate-500 mb-1 block" data-i18n="settings.exclusionsLabel">Ausschlüsse (Glob Pattern)</label>
                                <input type="text" id="config-exclusions" placeholder="Beispiel: *.tmp, *.log, node_modules" title="Beispiel: *.tmp, *.log, node_modules" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none" data-i18n-placeholder="settings.exclusionsPlaceholder" data-i18n-title="settings.exclusionsTitle">
                            </div>
                        </div>
                    </div>

                    <!-- Benachrichtigungen -->
                    <div class="bg-black/20 p-5 rounded-xl border border-white/5 space-y-4">
                        <h3 class="text-[11px] font-black uppercase text-slate-400 border-b border-white/5 pb-2" data-i18n="settings.notificationsTitle">Benachrichtigungen (Webhooks)</h3>
                        
                        <!-- Trigger -->
                        <div class="flex gap-4 mb-2">
                            <label class="flex items-center gap-2 cursor-pointer group">
                                <input type="checkbox" id="config-notify-success" class="rounded bg-white/5 border-white/10 text-emerald-500 focus:ring-0">
                                <span class="text-xs text-slate-400 group-hover:text-emerald-400 transition-colors" data-i18n="settings.notifyOnSuccess">Bei Erfolg</span>
                            </label>
                            <label class="flex items-center gap-2 cursor-pointer group">
                                <input type="checkbox" id="config-notify-error" class="rounded bg-white/5 border-white/10 text-red-500 focus:ring-0">
                                <span class="text-xs text-slate-400 group-hover:text-red-400 transition-colors" data-i18n="settings.notifyOnError">Bei Fehler</span>
                            </label>
                        </div>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <!-- Discord -->
                            <div class="space-y-2">
                                <div class="flex justify-between items-center">
                                    <label class="text-[10px] font-black uppercase text-slate-500" data-i18n="settings.discordLabel">Discord Webhook URL</label>
                                    <button onclick="testNotification('discord')" class="text-[9px] font-black uppercase bg-indigo-500/10 text-indigo-400 px-2 py-0.5 rounded border border-indigo-500/20 hover:bg-indigo-500/20" data-i18n="settings.discordTestButton">Test</button>
                                </div>
                                <input type="text" id="config-discord-url" placeholder="https://discord.com/api/webhooks/..." class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-indigo-500/50 transition-colors" data-i18n-placeholder="settings.discordPlaceholder">
                            </div>

                            <!-- Telegram -->
                            <div class="space-y-2">
                                <div class="flex justify-between items-center">
                                    <label class="text-[10px] font-black uppercase text-slate-500" data-i18n="settings.telegramLabel">Telegram Bot</label>
                                    <button onclick="testNotification('telegram')" class="text-[9px] font-black uppercase bg-sky-500/10 text-sky-400 px-2 py-0.5 rounded border border-sky-500/20 hover:bg-sky-500/20" data-i18n="settings.telegramTestButton">Test</button>
                                </div>
                                <div class="grid grid-cols-2 gap-2">
                                    <input type="text" id="config-telegram-token" placeholder="Bot Token" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-sky-500/50 transition-colors" data-i18n-placeholder="settings.telegramTokenPlaceholder">
                                    <input type="text" id="config-telegram-chatid" placeholder="Chat ID" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-white outline-none focus:border-sky-500/50 transition-colors" data-i18n-placeholder="settings.telegramChatPlaceholder">
                                </div>
                            </div>
                        </div>
                    </div>

                    <button onclick="saveProfile()" class="btn-pro w-full py-4 rounded text-sm text-white shadow-xl shadow-blue-600/20" data-i18n="settings.saveParametersButton">Parameter persistent speichern</button>
                </div>
            </div>
        </section>

        <!-- Tab: Tasks -->
        <section id="tab-tasks" class="tab-content flex-1 overflow-y-auto p-8 space-y-6 hidden text-slate-200">
             <div class="max-w-6xl mx-auto flex gap-6 h-[calc(100vh-100px)]">
                
                <!-- Left: Task List -->
                <div class="w-1/3 bg-[#11141d] border border-white/5 rounded-xl flex flex-col">
                    <div class="p-4 border-b border-white/5 flex justify-between items-center">
                        <h2 class="text-xs font-black uppercase text-slate-400" data-i18n="tasks.myTasksTitle">Meine Tasks</h2>
                        <button onclick="createNewTask()" class="bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-600/30 text-[10px] font-black uppercase px-2 py-1 rounded transition-all" data-i18n="tasks.newButton">
                            + Neu
                        </button>
                    </div>
                    <div id="task-list-container" class="flex-1 overflow-y-auto p-2 space-y-2">
                        <!-- Task Items injected by JS -->
                        <div class="text-center py-10 opacity-30 italic text-[10px]" data-i18n="tasks.loadingPlaceholder">Lade Tasks...</div>
                    </div>
                </div>

                <!-- Right: Task Editor -->
                <div class="w-2/3 bg-[#11141d] border border-white/5 rounded-xl p-6 overflow-y-auto">
                    <div id="task-editor-empty" class="h-full flex flex-col items-center justify-center text-slate-500 opacity-50">
                        <div class="text-4xl mb-4">📝</div>
                        <div class="text-sm" data-i18n="tasks.editorEmptyText">Wähle einen Task oder erstelle einen neuen.</div>
                    </div>

                    <div id="task-editor" class="hidden space-y-6">
                        <div class="flex justify-between items-center border-b border-white/5 pb-4">
                            <input type="text" id="task-name" placeholder="Task Name" class="bg-transparent text-lg font-bold text-white outline-none w-full placeholder-slate-600" data-i18n-placeholder="tasks.namePlaceholder">
                            <div class="flex items-center gap-2">
                                <label class="text-[10px] font-bold uppercase text-slate-500" data-i18n="tasks.activeLabel">Aktiv</label>
                                <input type="checkbox" id="task-active" class="w-4 h-4 bg-slate-800 border-white/10 rounded cursor-pointer">
                            </div>
                        </div>

                        <!-- Source & Dest (Borrowed from Parameter) -->
                        <div class="space-y-4">
                            <div>
                                <label class="text-[10px] font-black uppercase text-slate-500" data-i18n="tasks.sourcePathLabel">Source Path</label>
                                <div class="flex gap-2">
                                   <input type="text" id="task-source" class="flex-1 bg-[#08090d] border border-white/5 rounded p-2 text-xs mono text-blue-300 outline-none">
                                   <button onclick="pickFile('task-source')" class="bg-white/5 p-2 rounded text-[10px] uppercase font-black transition-colors hover:bg-white/10" title="Einzelne Datei" data-i18n-title="tasks.singleFileTitle">📄</button>
                                   <button onclick="pickFiles('task-source')" class="bg-white/5 p-2 rounded text-[10px] uppercase font-black transition-colors hover:bg-white/10" title="Mehrere Dateien" data-i18n-title="tasks.multiFileTitle">📑</button>
                                   <button onclick="pickFolder('task-source')" class="bg-white/5 p-2 rounded text-[10px] uppercase font-black transition-colors hover:bg-white/10" title="Ordner" data-i18n-title="tasks.folderTitle">📁</button>
                                </div>
                                <p class="text-[9px] text-slate-500 mt-1" data-i18n="tasks.tipPaths">Tipp: Mehrere Pfade mit | trennen.</p>
                            </div>
                            <div>
                                <label class="text-[10px] font-black uppercase text-slate-500" data-i18n="tasks.targetPathLabel">Target Path</label>
                                <div class="flex gap-2">
                                   <input type="text" id="task-dest" class="flex-1 bg-[#08090d] border border-white/5 rounded p-2 text-xs mono text-emerald-300 outline-none">
                                   <button onclick="pickFolder('task-dest')" class="bg-white/5 p-2 rounded text-[10px] uppercase font-black transition-colors hover:bg-white/10" data-i18n="tasks.targetFolderButton">Pick</button>
                                </div>
                            </div>
                        </div>

                        <!-- Automation Section -->
                        <div class="bg-black/20 p-5 rounded-xl border border-white/5 space-y-4">
                            <div class="flex items-center justify-between">
                                <div class="flex flex-col">
                                    <span class="text-[11px] font-black uppercase text-slate-400 tracking-wider" data-i18n="tasks.automationTitle">Automatisierung</span>
                                    <span class="text-[9px] text-slate-500" data-i18n="tasks.automationSubtitle">Führt diesen Task automatisch aus.</span>
                                </div>
                            </div>
                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="text-[10px] font-black uppercase text-slate-500 mb-1 block" data-i18n="tasks.intervalLabel">Intervall (Minuten)</label>
                                    <input type="number" id="task-interval" placeholder="0 = Manuell" class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-blue-400 outline-none" data-i18n-placeholder="tasks.intervalPlaceholder">
                                </div>
                                <div>
                                    <label class="text-[10px] font-black uppercase text-slate-500 mb-1 block" data-i18n="tasks.lastRunLabel">Letzter Lauf</label>
                                    <input type="text" id="task-last-run" readonly class="w-full bg-[#08090d] border border-white/5 rounded p-2 text-xs text-slate-500 outline-none cursor-not-allowed">
                                </div>
                            </div>
                        </div>

                        <!-- Actions -->
                        <div class="pt-4 border-t border-white/5 flex justify-between">
                            <button onclick="deleteCurrentTask()" class="text-red-400 hover:text-red-300 text-xs font-bold uppercase transition-colors" data-i18n="tasks.deleteButton">Löschen</button>
                            <div class="flex gap-3">
                                <button onclick="runTaskNow()" class="bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-600/30 text-xs font-black uppercase px-4 py-2 rounded transition-all" data-i18n="tasks.runNowButton">
                                    Jetzt Ausführen
                                </button>
                                <button onclick="saveCurrentTask()" class="bg-blue-600 text-white shadow-lg shadow-blue-600/20 text-xs font-black uppercase px-6 py-2 rounded transition-all hover:bg-blue-500" data-i18n="tasks.saveButton">
                                    Speichern
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Tab: Handbook (Optimiert v7.4) -->
        <section id="tab-help" class="tab-content flex-1 overflow-y-auto p-8 hidden text-slate-200">
            <div class="max-w-5xl mx-auto pb-24">
                
                <!-- Header -->
                <header class="text-center space-y-4 mb-10 pt-4">
                    <h1 class="text-3xl font-black text-white tracking-widest uppercase italic" data-i18n="handbook.title">Benutzerhandbuch</h1>
                    <div class="h-1 w-16 bg-emerald-500 mx-auto rounded-full"></div>
                    <p class="text-slate-500 max-w-lg mx-auto text-sm leading-relaxed" data-i18n="handbook.subtitle">Einfache Anleitung für Backup Pro.</p>
                </header>

                <!-- 00 Erste Schritte (User Requested Style) -->
                <div class="commander-module p-8 bg-emerald-500/5 border border-emerald-500/20 rounded-xl mb-12 shadow-lg shadow-emerald-500/5" data-i18n="handbook.section00">
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
                <div class="flex items-center gap-4 mb-12 opacity-30" data-i18n="handbook.sectionDivider">
                    <div class="h-px bg-white flex-1"></div>
                    <span class="text-xs uppercase tracking-widest">Wissen & Details</span>
                    <div class="h-px bg-white flex-1"></div>
                </div>

                <!-- Detailed Handbook Grid -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8 mb-12" data-i18n="handbook.sectionDetails">
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">01</span> Was ist ein Snapshot?</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Ein "Snapshot" ist wie ein Foto Ihrer Daten zu einem bestimmten Zeitpunkt. Backup Pro packt alle Ihre Dateien in ein Päckchen (ZIP-Datei). So können Sie später genau diesen Zustand wiederherstellen.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">02</span> Aufräum-Regel (Retention)</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Damit Ihre Festplatte nicht voll wird, löscht Backup Pro automatisch uralte Sicherungen. Unter "Parameter" -> "Retention Limit" stellen Sie ein, wie viele Backups Sie behalten wollen (z.B. die letzten 10). Das älteste wird dann automatisch gelöscht.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">03</span> Workspace Delta (Neu)</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">In der <strong>01 ZENTRALE</strong> sehen Sie jetzt das "Workspace Delta". Es zeigt Ihnen live, wie viele Dateien und wie viel Speicherplatz (MB/GB) sich im Vergleich zum letzten Backup geändert haben. Achten Sie auf den Modus oben rechts (LOCAL, UPLOAD, DOWNLOAD).</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">04</span> Cloud Tresor & SFTP</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Unter <strong>03 CLOUD</strong> steuern Sie Ihre Remote-Backups. Wählen Sie zwischen "Upload" (Lokal -> Cloud) und "Download" (Cloud -> Lokal). Neu: Bei SFTP können Sie mit "Speicherort anlegen" direkt Ordner auf dem Server erstellen. Beim Download können Sie einen speziellen lokalen Zielordner definieren.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">05</span> Fehlerbehebung</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Wenn ein Backup fehlschlägt, ist meistens eine Datei noch geöffnet (z.B. eine Excel-Tabelle). Schließen Sie alle Programme und versuchen Sie es nochmal. Prüfen Sie auch, ob der USB-Stick voll ist.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">06</span> System Health (Ampel)</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Die "System Health" in der Zentrale ist wie eine Ampel. Grün ist super. Gelb heißt "naja". Rot heißt "Achtung!". Wenn sie rot ist, sollten Sie dringend ein Backup machen oder Speicherplatz freigeben.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">07</span> Snapshot Inspektor & Lock</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Klicken Sie in der Liste auf ein Backup, um Details zu sehen. <strong class="text-emerald-400">Neu:</strong> Im Tab "Inhalt" sehen Sie alle Dateien im ZIP, ohne Restore! Mit dem <strong class="text-amber-500">Schloss-Symbol (Lock)</strong> können Sie wichtige Backups sperren – sie werden dann nie automatisch gelöscht, auch wenn das Limit erreicht ist.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">08</span> Deep Scan (Integrität)</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Im Inspektor finden Sie den Button <strong class="text-emerald-400">INTEGRITÄT PRÜFEN</strong>. Das ist ein Gesundheitscheck: Das Programm berechnet den digitalen Fingerabdruck (Hash) neu und vergleicht ihn. So erkennen Sie sofort, ob Dateien auf der Festplatte beschädigt wurden (Bit Rot).</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">09</span> Historie & Log-Skala</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Die Historie listet alle Backups auf. Neu: Mit dem Schalter <strong>LOG-SKALA</strong> über dem Diagramm können Sie auch sehr kleine Dateien neben riesigen Backups sichtbar machen. Sortieren Sie die Liste mit dem "Sort"-Button nach Datum oder Größe.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">10</span> Datenbanken (Cloud Dump)</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Im Cloud-Tab können Sie automatische Backups Ihrer MySQL oder PostgreSQL Datenbanken einrichten. Diese werden als SQL-Dateien exportiert und sicher in Ihrem Backup-Ziel abgelegt.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">11</span> Benachrichtigungen</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Backup Pro informiert Sie über wichtige Ereignisse direkt in der Oberfläche. Fehler werden rot, erfolgreiche Aktionen grün markiert. Überprüfen Sie regelmäßig das Protokoll (Terminal) in der Zentrale.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">12</span> System Health Details</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Fahren Sie mit der Maus über die "System Health" Karte, um detaillierte Infos zu sehen. Die neue Anzeige schlüsselt Ihren Score exakt in Prozent auf: <strong>COV</strong> (Abdeckung), <strong>REC</strong> (Wiederherstellbarkeit) und <strong>DSK</strong> (Speicherplatz).</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">13</span> Erweiterte Statistiken</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Die Karten "Gesamtvolumen" und "Backups" zeigen jetzt mehr Details: Durchschnittsgröße pro Snapshot, Zeit seit dem letzten Backup und die Backup-Frequenz pro Tag. Tooltips erklären beim Hovern weitere Details.</p>
                    </div>
                    <div class="handbook-item p-6 bg-[#0f111a] rounded-xl border border-white/5 hover:border-blue-500/30 transition-all group">
                        <h3 class="text-lg font-bold text-white mb-3 group-hover:text-blue-400 transition-colors"><span class="text-blue-500/50 mr-2">14</span> Aktivitäts-Diagramm</h3>
                        <p class="text-sm text-slate-400 leading-relaxed">Das Diagramm in der Zentrale unterscheidet nun visuell zwischen Tagen mit Backup (gefüllte Punkte) und Tagen ohne Backup (leere Punkte). Neue Grid-Linien und verbesserte Achsen helfen Ihnen, Lücken in Ihrer Sicherungsstrategie schneller zu erkennen.</p>
                    </div>
                </div>

                <!-- Profi Tipps -->
                <div class="commander-module p-6 bg-blue-500/5 border border-blue-500/20 rounded-xl" data-i18n="handbook.proTips">
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

                <!-- Support / Buy Me A Coffee -->
                <div class="commander-module p-6 bg-gradient-to-r from-yellow-500/10 to-orange-500/10 border border-yellow-500/20 rounded-xl mt-8 shadow-lg shadow-yellow-500/5" data-i18n="handbook.support">
                    <div class="flex flex-col md:flex-row items-center justify-between gap-6">
                        <div class="flex-1">
                            <h4 class="text-xs font-black uppercase text-yellow-400 mb-2 tracking-widest flex items-center gap-2">
                                <span>☕</span> Support Development
                            </h4>
                            <p class="text-sm text-slate-300 leading-relaxed">
                                Gefällt Ihnen <strong>Backup OS Pro</strong>? Helfen Sie mit, die Entwicklung voranzutreiben! 
                                <span class="text-slate-500 block text-xs mt-1">Jede Unterstützung fließt direkt in neue Features und Updates.</span>
                            </p>
                        </div>
                        <a href="https://buymeacoffee.com/exulizer" target="_blank" class="group relative shrink-0">
                            <div class="absolute -inset-1 bg-yellow-400 rounded-lg opacity-20 group-hover:opacity-40 blur transition duration-200"></div>
                            <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" class="relative block h-12 w-auto transform group-hover:scale-105 transition-all duration-200" style="height: 50px !important;">
                        </a>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <script>
        // Global Error Handler for Boot Issues
        window.onerror = function(msg, url, line, col, error) {
            const loader = document.getElementById('startup-loader');
            if(loader) {
                 const consoleEl = document.getElementById('loader-console');
                 if(consoleEl) consoleEl.innerHTML = `<span style="color:#ef4444">CRITICAL ERROR: ${msg} (Line ${line})</span>`;
                 const msgEl = document.getElementById('loader-msg');
                 if(msgEl) {
                     msgEl.innerText = "SYSTEM HALTED";
                     msgEl.style.color = "#ef4444";
                 }
                 // Auto-hide after 5s to allow user to see UI if partially loaded
                 setTimeout(() => { loader.style.display = 'none'; }, 5000);
            }
        };

        // Failsafe: Force hide loader after 10s
        setTimeout(() => {
            const loader = document.getElementById('startup-loader');
            if(loader) {
                console.warn("Loader timeout - forcing hide.");
                loader.style.opacity = '0';
                setTimeout(() => { loader.style.display = 'none'; }, 500);
            }
        }, 10000);

        // Boot Sequence Simulation
        window.bootInterval = null;
        (function() {
            const msgs = [
                "LOADING KERNEL MODULES...",
                "MOUNTING VIRTUAL FILESYSTEM...",
                "CHECKING INTEGRITY...",
                "LOADING CONFIGURATION...",
                "ESTABLISHING SECURE LINK...",
                "STARTING DAEMON PROCESSES...",
                "SYSTEM READY."
            ];
            let i = 0;
            window.bootInterval = setInterval(() => {
                const consoleEl = document.getElementById('loader-console');
                const percentEl = document.getElementById('loader-percent');
                
                if(i >= msgs.length) {
                    if(window.bootInterval) clearInterval(window.bootInterval);
                    if(consoleEl) consoleEl.innerText = "> WAITING FOR BACKEND...";
                    return;
                }
                
                if(consoleEl) consoleEl.innerText = "> " + msgs[i];
                if(percentEl) percentEl.innerText = Math.round(((i + 1) / msgs.length) * 100) + "%";
                i++;
            }, 200);
        })();

        let storageChart = null;
        let globalHistory = [];
        let currentDiskUsedPercent = 0;
        
        // --- Central Limit Initialization (Synchronous) ---
        // Initializes from localStorage immediately to ensure stability
        let currentLimit = 10;
        try {
            const saved = localStorage.getItem('backup_pro_limit');
            if(saved) currentLimit = saved === 'all' ? 999999 : parseInt(saved);
        } catch(e) { console.error("LocalStorage Error:", e); }

        let configuredRetention = 10; // For Health Calculation
        let cloudEnabled = false;
        let autoBackupEnabled = false;
        console.log("BACKUP PRO SCRIPT INITIALIZING...");
        let globalUnit = 'MB';

        // --- Sorting & History Logic (Global) ---
        let currentSortMode = 0; // 0=DateDesc, 1=DateAsc, 2=SizeDesc, 3=SizeAsc
        const sortLabels = ["Datum ▼ (Neu)", "Datum ▲ (Alt)", "Größe ▼", "Größe ▲"];

        window.updateHistoryLimit = function() {
            const val = document.getElementById('history-limit').value;
            currentLimit = val === 'all' ? 999999 : parseInt(val);
            localStorage.setItem('backup_pro_limit', val);
            const label = (val === 'all' ? t("dashboard.limitAll", "Alle") : val);
            addLog(t("console.limitChanged", "Limit geändert: ") + label, "info");
            updateDashboardDisplays();
        };

        window.applySort = function() {
            if(!globalHistory || globalHistory.length === 0) return;
            
            // FIX: Use Date objects for reliable sorting
            const getTs = (item) => {
                if(!item.timestamp) return 0;
                // Replace German format if present (just in case)
                let s = item.timestamp.replace(/(\d{2})\.(\d{2})\.(\d{4})/, '$3-$2-$1');
                // Replace space with T for ISO compatibility
                s = s.replace(" ", "T");
                return new Date(s).getTime();
            };

            if(currentSortMode === 0) { // Date Desc (Newest First)
                globalHistory.sort((a, b) => getTs(b) - getTs(a));
            } else if(currentSortMode === 1) { // Date Asc (Oldest First)
                globalHistory.sort((a, b) => getTs(a) - getTs(b));
            } else if(currentSortMode === 2) { // Size Desc
                globalHistory.sort((a, b) => b.size - a.size);
            } else if(currentSortMode === 3) { // Size Asc
                globalHistory.sort((a, b) => a.size - b.size);
            }
        };

        window.toggleSort = function() {
            currentSortMode = (currentSortMode + 1) % 4;
            const btn = document.getElementById('btn-sort');
            if(btn) btn.innerText = "Sort: " + sortLabels[currentSortMode];
            
            window.applySort();
            updateDashboardDisplays();
        };

        window.clearHistory = async function() {
            if(!confirm("Historie wirklich leeren? (Dateien bleiben erhalten)")) return;
            try {
                const resp = await fetch('/api/clear_history', { method: 'POST' });
                const data = await resp.json();
                if(data.status === 'success') {
                    addLog(t("console.historyCleared", "Historie geleert."), "success");
                    loadData();
                } else {
                    addLog(t("console.errorPrefix", "Fehler: ") + data.message, "error");
                }
            } catch(e) {
                addLog(t("console.connectionError", "Verbindungsfehler."), "error");
            }
        };

        window.refreshHistory = async function() {
            const btn = document.getElementById('btn-refresh-hist');
            if(btn) btn.classList.add('animate-spin');
            
            try {
                const hResp = await fetch('/api/get_history');
                globalHistory = await hResp.json();
                window.applySort();
                updateDashboardDisplays();
                addLog(t("console.historyUpdated", "Historie aktualisiert."), "info");
            } catch(e) {
                addLog(t("console.historyUpdateError", "Fehler beim Aktualisieren der Historie."), "error");
                console.error(e);
            } finally {
                if(btn) btn.classList.remove('animate-spin');
            }
        };

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

        function updateNamingPreview() {
            const custom = document.getElementById('config-naming-custom').value;
            const incDate = document.getElementById('config-naming-date').checked;
            const incTime = document.getElementById('config-naming-time').checked;
            const incSeq = document.getElementById('config-naming-seq').checked;
            
            const now = new Date();
            const dateStr = now.toISOString().split('T')[0]; // YYYY-MM-DD
            const timeStr = now.toTimeString().split(' ')[0].replace(/:/g, '-'); // HH-MM-SS
            
            let parts = [];
            if(custom) parts.push(custom);
            if(incDate) parts.push(dateStr);
            if(incTime) parts.push(timeStr);
            if(incSeq) {
                const seqVal = document.getElementById('config-naming-seq-val').value || "1";
                // Pad to 3 digits
                let s = seqVal.toString();
                while(s.length < 3) s = "0" + s;
                parts.push(s);
            }
            
            if(parts.length === 0) {
                parts.push("backup");
                parts.push(dateStr + "_" + timeStr);
            }
            
            document.getElementById('naming-preview').innerText = parts.join('_') + ".zip";
        }

        async function loadConfigUI() {
            const resp = await fetch('/api/get_config');
            const conf = await resp.json();
            
            // Bestehende Felder
            if(document.getElementById('config-source')) document.getElementById('config-source').value = conf.default_source || "";
            if(document.getElementById('config-dest')) document.getElementById('config-dest').value = conf.default_dest || "";
            if(document.getElementById('config-retention')) document.getElementById('config-retention').value = conf.retention_count || 10;
            if(document.getElementById('config-auto-interval')) document.getElementById('config-auto-interval').value = conf.auto_interval || 0;
            
            // Naming Felder
            if(document.getElementById('config-naming-custom')) document.getElementById('config-naming-custom').value = conf.naming_custom_text || "backup";
            if(document.getElementById('config-naming-date')) document.getElementById('config-naming-date').checked = (conf.naming_include_date !== undefined) ? conf.naming_include_date : true;
            if(document.getElementById('config-naming-time')) document.getElementById('config-naming-time').checked = (conf.naming_include_time !== undefined) ? conf.naming_include_time : true;
            if(document.getElementById('config-naming-seq')) document.getElementById('config-naming-seq').checked = (conf.naming_include_seq !== undefined) ? conf.naming_include_seq : false;
            if(document.getElementById('config-naming-seq-val')) document.getElementById('config-naming-seq-val').value = conf.naming_seq_counter || 1;
            
            updateNamingPreview();

            // Advanced Felder
            if(document.getElementById('config-compression')) document.getElementById('config-compression').value = (conf.compression_level !== undefined) ? conf.compression_level : 3;
            if(document.getElementById('config-exclusions')) document.getElementById('config-exclusions').value = conf.exclusions || "";

            // Notifications
            if(document.getElementById('config-notify-success')) document.getElementById('config-notify-success').checked = conf.notify_on_success || false;
            if(document.getElementById('config-notify-error')) document.getElementById('config-notify-error').checked = conf.notify_on_error || false;
            if(document.getElementById('config-discord-url')) document.getElementById('config-discord-url').value = conf.discord_webhook_url || "";
            if(document.getElementById('config-telegram-token')) document.getElementById('config-telegram-token').value = conf.telegram_token || "";
            if(document.getElementById('config-telegram-chatid')) document.getElementById('config-telegram-chatid').value = conf.telegram_chat_id || "";

            autoBackupEnabled = conf.auto_backup_enabled || false;
            updateAutoToggleUI();

            // Cloud Felder
            if(document.getElementById('config-cloud-enabled')) document.getElementById('config-cloud-enabled').checked = conf.cloud_sync_enabled || false;
            if(document.getElementById('config-cloud-provider')) document.getElementById('config-cloud-provider').value = conf.cloud_provider || "SFTP";
            if(document.getElementById('config-cloud-direction')) document.getElementById('config-cloud-direction').value = conf.cloud_direction || "upload";
            if(document.getElementById('config-cloud-host')) document.getElementById('config-cloud-host').value = conf.cloud_host || "";
            if(document.getElementById('config-cloud-port')) document.getElementById('config-cloud-port').value = conf.cloud_port || "22";
            if(document.getElementById('config-cloud-bucket')) document.getElementById('config-cloud-bucket').value = conf.cloud_bucket || "";
            if(document.getElementById('config-cloud-region')) document.getElementById('config-cloud-region').value = conf.cloud_region || "";
            if(document.getElementById('config-cloud-path')) document.getElementById('config-cloud-path').value = conf.cloud_target_path || "";
            if(document.getElementById('config-cloud-local-path')) document.getElementById('config-cloud-local-path').value = conf.cloud_local_path || "";
            if(document.getElementById('config-cloud-user')) document.getElementById('config-cloud-user').value = conf.cloud_user || "";
            if(document.getElementById('config-cloud-password')) document.getElementById('config-cloud-password').value = conf.cloud_password || "";
            if(document.getElementById('config-cloud-api-key')) document.getElementById('config-cloud-api-key').value = conf.cloud_api_key || "";
            
            // DB Backup Felder
            if(document.getElementById('config-db-enabled')) document.getElementById('config-db-enabled').checked = conf.db_backup_enabled || false;
            if(document.getElementById('config-db-type')) document.getElementById('config-db-type').value = conf.db_type || "mysql";
            if(document.getElementById('config-db-host')) document.getElementById('config-db-host').value = conf.db_host || "";
            if(document.getElementById('config-db-port')) document.getElementById('config-db-port').value = conf.db_port || "";
            if(document.getElementById('config-db-user')) document.getElementById('config-db-user').value = conf.db_user || "";
            if(document.getElementById('config-db-password')) document.getElementById('config-db-password').value = conf.db_password || "";
            if(document.getElementById('config-db-names')) document.getElementById('config-db-names').value = conf.db_names || "";

            // GitHub Felder
            if(document.getElementById('config-github-enabled')) document.getElementById('config-github-enabled').checked = conf.github_backup_enabled || false;
            if(document.getElementById('config-github-url')) document.getElementById('config-github-url').value = conf.github_url || "";
            if(document.getElementById('config-github-path')) document.getElementById('config-github-path').value = conf.github_path || "";
            if(document.getElementById('config-github-token')) document.getElementById('config-github-token').value = conf.github_token || "";
            
            updateCloudTresorUI();
            updateGithubUI();
            updateDbUI();

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
            if(header) header.innerText = `Größe`; // Einheit wird jetzt pro Zeile angezeigt
            updateDashboardDisplays();
        }

        /**
         * Formatiert Byte-Werte intelligent.
         * Beachtet die globale Einheit (GB/MB), schaltet aber bei kleinen Werten automatisch runter,
         * um "0,00 GB" zu vermeiden (z.B. 500 KB statt 0,00 GB).
         */
        function formatSize(bytes) {
            if (!bytes || bytes === 0) return "0,00 " + globalUnit;
            
            const G = 1024**3;
            const M = 1024**2;
            const K = 1024;
            
            // Wenn GB als Basis gewählt ist
            if (globalUnit === 'GB') {
                // Unter 10 MB -> Anzeige in MB oder KB
                if (bytes < 0.01 * G) { 
                    if (bytes < 0.1 * M) { // Unter 100 KB -> Anzeige in KB
                        return (bytes / K).toFixed(2).replace('.', ',') + " KB";
                    }
                    return (bytes / M).toFixed(2).replace('.', ',') + " MB";
                }
                return (bytes / G).toFixed(2).replace('.', ',') + " GB";
            }
            
            // Wenn MB als Basis gewählt ist
            if (globalUnit === 'MB') {
                 if (bytes < 0.1 * M) { // Unter 100 KB -> Anzeige in KB
                    return (bytes / K).toFixed(2).replace('.', ',') + " KB";
                }
                return (bytes / M).toFixed(2).replace('.', ',') + " MB";
            }
            
            return (bytes / M).toFixed(2).replace('.', ',') + " MB"; // Fallback
        }

        function toggleSidebar() {
            const sb = document.getElementById('main-sidebar');
            const bd = document.getElementById('sidebar-backdrop');
            if(sb.classList.contains('-translate-x-full')) {
                sb.classList.remove('-translate-x-full');
                bd.classList.remove('hidden');
            } else {
                sb.classList.add('-translate-x-full');
                bd.classList.add('hidden');
            }
        }

        function switchTab(tabId) {
            // Close sidebar on mobile if open
            if(window.innerWidth < 768) {
                const sb = document.getElementById('main-sidebar');
                if(sb && !sb.classList.contains('-translate-x-full')) {
                    toggleSidebar();
                }
            }

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
            
            // COV: Based on configured retention, not display limit
            covPts = Math.min(40, (globalHistory.length / configuredRetention) * 40);
            score += covPts;

            if (globalHistory.length > 0) {
                // Find actual latest backup (independent of sort)
                const timestamps = globalHistory.map(h => new Date(h.timestamp.replace(' ', 'T')).getTime());
                const latestTs = Math.max(...timestamps);
                const diffHours = (Date.now() - latestTs) / (1000 * 60 * 60);

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
            
            // Update percentage texts
            if(document.getElementById('val-cov')) document.getElementById('val-cov').innerText = Math.round(covPts / 40 * 100) + "%";
            if(document.getElementById('val-rec')) document.getElementById('val-rec').innerText = Math.round(recPts / 40 * 100) + "%";
            if(document.getElementById('val-disk')) document.getElementById('val-disk').innerText = Math.round(dskPts / 20 * 100) + "%";

            if(healthEl) {
                healthEl.classList.remove('score-good', 'score-warn', 'score-crit');
                if(finalScore > 80) { healthEl.classList.add('score-good'); labelEl.innerText = "Status: Optimal"; }
                else if(finalScore > 40) { healthEl.classList.add('score-warn'); labelEl.innerText = "Status: Eingeschränkt"; }
                else { healthEl.classList.add('score-crit'); labelEl.innerText = "Status: Kritisch"; }
            }
        }

        function toggleChartScale() {
            if(!storageChart) return;
            const isLog = document.getElementById('chart-log-scale').checked;
            storageChart.options.scales.y.type = isLog ? 'logarithmic' : 'linear';
            storageChart.update();
        }

        function initChart() {
            const ctx = document.getElementById('storageChart').getContext('2d');
            storageChart = new Chart(ctx, {
                type: 'bar',
                data: { 
                    labels: [], 
                    datasets: [{ 
                        label: 'Snapshot Size', 
                        data: [],
                        filenames: [], 
                        backgroundColor: [], 
                        borderColor: [], 
                        borderWidth: 1,
                        borderRadius: 4,
                        barPercentage: 0.9,
                        categoryPercentage: 0.8,
                        minBarLength: 5
                    }]
                },
                options: { 
                    responsive: true, 
                    maintainAspectRatio: false,
                    interaction: {
                        mode: 'index',
                        intersect: false,
                    },
                    plugins: { 
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: 'rgba(17, 20, 29, 0.9)',
                            titleColor: '#94a3b8',
                            bodyColor: '#fff',
                            bodyFont: { family: 'JetBrains Mono' },
                            callbacks: {
                                title: function(context) {
                                    let idx = context[0].dataIndex;
                                    let fname = context[0].dataset.filenames[idx] || "";
                                    return context[0].label + (fname ? " (" + fname + ")" : "");
                                },
                                label: function(context) {
                                    let val = context.parsed.y;
                                    if (val === undefined || val === null) val = context.raw;
                                    return "Größe: " + Number(val).toFixed(2).replace('.', ',') + " " + globalUnit;
                                }
                            }
                        }
                    }, 
                    scales: { 
                        x: { 
                            grid: { display: false }, 
                            ticks: { color: '#64748b', font: { size: 9, family: 'JetBrains Mono' }, maxRotation: 45, minRotation: 45 } 
                        }, 
                        y: { 
                            type: 'linear',
                            grid: { color: 'rgba(255,255,255,0.05)' }, 
                            ticks: { 
                                color: '#475569', 
                                font: { size: 9 }, 
                                callback: function(value) { 
                                    return Number(value).toFixed(2).replace('.', ',') + ' ' + globalUnit; 
                                } 
                            } 
                        } 
                    } 
                }
            });
        }



        async function updateDiskStats() {
            const dest = document.getElementById('dest').value;
            if(!dest) return;
            try {
                const resp = await fetch('/api/get_disk_stats', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path: dest}) });
                const data = await resp.json();
                if(data.total > 0) {
                    currentDiskUsedPercent = (data.used / data.total) * 100;
                    
                    const bar = document.getElementById('disk-bar');
                    const pctEl = document.getElementById('disk-percent');
                    const warnEl = document.getElementById('disk-warning');
                    
                    // Reset Classes (preserve base structure)
                    bar.className = "h-full w-0 transition-all duration-1000 relative z-10";
                    pctEl.className = "text-[11px] font-bold";
                    
                    // Color Logic
                    let colorClass = "bg-blue-500 shadow-[0_0_8px_rgba(59,130,246,0.5)]";
                    let textClass = "text-blue-400";
                    
                    if(currentDiskUsedPercent > 90) {
                        colorClass = "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]";
                        textClass = "text-red-500";
                        if(warnEl) warnEl.classList.remove('hidden');
                    } else if(currentDiskUsedPercent > 75) {
                        colorClass = "bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.5)]";
                        textClass = "text-yellow-500";
                        if(warnEl) warnEl.classList.add('hidden');
                    } else {
                        if(warnEl) warnEl.classList.add('hidden');
                    }
                    
                    bar.className += " " + colorClass;
                    bar.style.width = currentDiskUsedPercent + '%';
                    pctEl.className += " " + textClass;
                    pctEl.innerText = currentDiskUsedPercent.toFixed(1) + '%';
                    
                    // Force GB display for Drive Telemetry
                    const formatGB = (b) => {
                        if (!b) return "0,00 GB";
                        return (b / (1024**3)).toFixed(2).replace('.', ',') + " GB";
                    };

                    if(document.getElementById('disk-used-val')) document.getElementById('disk-used-val').innerText = formatGB(data.used);
                    if(document.getElementById('disk-free-val')) document.getElementById('disk-free-val').innerText = formatGB(data.free);
                    if(document.getElementById('disk-total-val')) document.getElementById('disk-total-val').innerText = formatGB(data.total);
                    
                    calculateHealth();
                }
            } catch(e) {}
        }

        async function loadData() {
            try {
                // STOP Boot Sequence Simulation if running
                if(window.bootInterval) {
                    clearInterval(window.bootInterval);
                    window.bootInterval = null;
                }

                // UI Felder aus Config laden
                await loadConfigUI();
                
                const cResp = await fetch('/api/get_config');
                const config = await cResp.json();
                configuredRetention = config.retention_count || 10;
                
                document.getElementById('source').value = config.default_source || "";
                document.getElementById('dest').value = config.default_dest || "";
                

                
                if(config.auto_backup_enabled && !autoBackupEnabled) toggleAutoBackup();

                const hResp = await fetch('/api/get_history');
                globalHistory = await hResp.json();
                
                // Ensure default sort (Newest First) is applied immediately
                try { window.applySort(); } catch(e) { console.error("Sort Error:", e); }

                // Force UI Sync for Limit (Do NOT overwrite currentLimit here)
                const limitEl = document.getElementById('history-limit');
                if(limitEl) {
                     limitEl.value = (currentLimit === 999999) ? 'all' : currentLimit;
                }
                
                // addLog("Daten geladen. Einträge: " + globalHistory.length + " Limit: " + currentLimit, "info");
                try { updateDashboardDisplays(); } catch(e) { console.error("Update Dashboard Error:", e); }

                // Ladeanimation ausblenden - mit simuliertem Progress für "Lazy Load" Effekt
                const loader = document.getElementById('startup-loader');
                if(loader) {
                    const consoleEl = document.getElementById('loader-console');
                    const percentEl = document.getElementById('loader-percent');
                    const barFill = document.querySelector('.loader-bar-fill');
                    
                    const steps = [
                        { p: 30, msg: "LOADING KERNEL MODULES..." },
                        { p: 55, msg: "CONNECTING TO UI ENGINE..." },
                        { p: 75, msg: "VERIFYING INTEGRITY..." },
                        { p: 90, msg: "STARTING SERVICES..." },
                        { p: 100, msg: "READY." }
                    ];

                    let stepIdx = 0;
                    const stepInterval = setInterval(() => {
                        if(stepIdx >= steps.length) {
                            clearInterval(stepInterval);
                            loader.style.opacity = '0';
                            setTimeout(() => { loader.style.display = 'none'; }, 500);
                            return;
                        }
                        const s = steps[stepIdx];
                        if(consoleEl) consoleEl.innerText = s.msg;
                        if(percentEl) percentEl.innerText = s.p + "%";
                        if(barFill) barFill.style.width = s.p + "%";
                        stepIdx++;
                    }, 300); // Alle 300ms ein Schritt
                }

            } catch(e) { 
                console.error("Load Error:", e);
                // Emergency Hide Loader
                const loader = document.getElementById('startup-loader');
                if(loader) {
                     loader.innerHTML = '<div class="text-red-500 font-mono text-center">SYSTEM BOOT FAILED.<br>' + e + '</div>';
                     setTimeout(() => { loader.style.display = 'none'; }, 3000);
                }
            }
        }

        function renderActivityChart() {
            const container = document.getElementById('activity-chart-container');
            const statsContainer = document.getElementById('activity-stats-bar');
            if(!container) return;

            const dailyStats = {};
            const sortedHistory = [...globalHistory].sort((a, b) => (a.timestamp || "") > (b.timestamp || "") ? 1 : -1);

            if(sortedHistory.length === 0) {
                container.innerHTML = '<div class="absolute inset-0 flex items-center justify-center text-xs text-slate-600 font-mono">Keine Daten verfügbar</div>';
                if(statsContainer) statsContainer.innerHTML = '';
                return;
            }

            const limitPoints = 50;
            const relevantData = sortedHistory.slice(-limitPoints);

            let totalSize = 0;
            let totalCount = 0;

            relevantData.forEach(entry => {
                const date = (entry.timestamp || "").split(' ')[0];
                if(!date) return;
                if(!dailyStats[date]) dailyStats[date] = { size: 0, count: 0 };
                dailyStats[date].size += entry.size;
                dailyStats[date].count++;
                
                totalSize += entry.size;
                totalCount++;
            });

            let labels = Object.keys(dailyStats);
            if(labels.length === 0) {
                container.innerHTML = '<div class="absolute inset-0 flex items-center justify-center text-xs text-slate-600 font-mono">Keine Daten verfügbar</div>';
                if(statsContainer) statsContainer.innerHTML = '';
                return;
            }

            const firstDate = new Date(labels[0] + 'T00:00:00');
            const lastDate = new Date(labels[labels.length - 1] + 'T00:00:00');
            const fullLabels = [];
            const cursor = new Date(firstDate.getTime());
            while(cursor <= lastDate) {
                const y = cursor.getFullYear();
                const m = String(cursor.getMonth() + 1).padStart(2, '0');
                const d = String(cursor.getDate()).padStart(2, '0');
                const key = `${y}-${m}-${d}`;
                if(!dailyStats[key]) dailyStats[key] = { size: 0, count: 0 };
                fullLabels.push(key);
                cursor.setDate(cursor.getDate() + 1);
            }
            labels = fullLabels;

            const dataPoints = labels.map(d => dailyStats[d].size);
            const maxVal = Math.max(...dataPoints, 1);
            
            if(statsContainer) {
                statsContainer.classList.remove('opacity-50');
                const avgSize = totalSize / (labels.length || 1);
                const daysWithBackups = labels.filter(d => dailyStats[d].count > 0).length;
                const avgSizeActiveOnly = daysWithBackups > 0 ? totalSize / daysWithBackups : 0;
                const successRate = labels.length ? Math.round((daysWithBackups / labels.length) * 100) : 0;
                
                // Extra Stats Calculation
                const avgPerBackup = totalCount > 0 ? totalSize / totalCount : 0;
                const lastSnapSize = relevantData.length > 0 ? relevantData[relevantData.length - 1].size : 0;
                
                const avgDailyFreq = daysWithBackups > 0 ? (totalCount / daysWithBackups).toFixed(1) : "0.0";
                
                let timeAgoStr = "--";
                if(relevantData.length > 0) {
                     const lastTs = new Date(relevantData[relevantData.length - 1].timestamp.replace(" ", "T"));
                     const now = new Date();
                     const diffMs = now - lastTs;
                     const diffHrs = Math.floor(diffMs / (1000 * 60 * 60));
                     const diffDays = Math.floor(diffHrs / 24);
                     
                     if(diffDays > 0) timeAgoStr = `vor ${diffDays} Tag${diffDays!==1?'en':''}`;
                     else if(diffHrs > 0) timeAgoStr = `vor ${diffHrs} Std.`;
                     else {
                        const diffMin = Math.floor(diffMs / (1000 * 60));
                        timeAgoStr = `vor ${diffMin} Min.`;
                     }
                }

                statsContainer.innerHTML = `
                    <div class="bg-[#0f111a] p-3 rounded border border-white/5 flex flex-col justify-center relative overflow-hidden group/stat">
                        <div class="absolute top-0 right-0 p-2 opacity-10 group-hover/stat:opacity-20 transition-opacity">
                            <svg class="w-8 h-8 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                        </div>
                        <span class="text-[9px] font-bold text-slate-500 uppercase tracking-wider mb-3">Gesamtvolumen</span>
                        <div class="flex flex-col gap-1 mt-2">
                            <div class="flex justify-between items-baseline">
                                <span class="text-[10px] text-slate-400">Summe:</span>
                                <span class="text-sm font-black text-blue-400 font-mono">${formatSize(totalSize)}</span>
                            </div>
                            <div class="flex justify-between items-baseline">
                                <span class="text-[10px] text-slate-400">Ø pro Snap:</span>
                                <span class="text-xs font-bold text-slate-400 font-mono">${formatSize(avgPerBackup)}</span>
                            </div>
                            <div class="flex justify-between items-baseline border-t border-white/5 pt-1 mt-1">
                                <span class="text-[10px] text-slate-500">Letzter:</span>
                                <span class="text-xs font-bold text-blue-300 font-mono">${formatSize(lastSnapSize)}</span>
                            </div>
                        </div>
                    </div>
                    <div class="bg-[#0f111a] p-3 rounded border border-white/5 flex flex-col justify-center relative overflow-hidden group/stat">
                        <div class="absolute top-0 right-0 p-2 opacity-10 group-hover/stat:opacity-20 transition-opacity">
                            <svg class="w-8 h-8 text-purple-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /></svg>
                        </div>
                        <span class="text-[9px] font-bold text-slate-500 uppercase tracking-wider mb-3">Tägliches Volumen</span>
                        <div class="flex flex-col gap-1 mt-2">
                            <div class="flex justify-between items-baseline">
                                <span class="text-[10px] text-slate-400">Ø Gesamt:</span>
                                <span class="text-sm font-black text-slate-300 font-mono">${formatSize(avgSize)}</span>
                            </div>
                            <div class="flex justify-between items-baseline">
                                <span class="text-[10px] text-slate-400">Ø Aktiv:</span>
                                <span class="text-xs font-bold text-slate-400 font-mono">${formatSize(avgSizeActiveOnly)}</span>
                            </div>
                            <div class="flex justify-between items-baseline border-t border-white/5 pt-1 mt-1">
                                <span class="text-[10px] text-slate-500">Max Peak:</span>
                                <span class="text-xs font-bold text-purple-400 font-mono">${formatSize(maxVal)}</span>
                            </div>
                        </div>
                    </div>
                    <div class="bg-[#0f111a] p-3 rounded border border-white/5 flex flex-col justify-center relative overflow-hidden group/stat">
                        <div class="absolute top-0 right-0 p-2 opacity-10 group-hover/stat:opacity-20 transition-opacity">
                            <svg class="w-8 h-8 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                        </div>
                        <span class="text-[9px] font-bold text-slate-500 uppercase tracking-wider mb-3">Backups</span>
                        <div class="flex flex-col gap-1 mt-2">
                            <div class="flex justify-between items-baseline">
                                <span class="text-[10px] text-slate-400">Anzahl:</span>
                                <span class="text-sm font-black text-emerald-400 font-mono">${totalCount}</span>
                            </div>
                            <div class="flex justify-between items-baseline">
                                <span class="text-[10px] text-slate-400">Frequenz:</span>
                                <span class="text-xs font-bold text-slate-400 font-mono">~${avgDailyFreq} / Tag</span>
                            </div>
                            <div class="flex justify-between items-baseline border-t border-white/5 pt-1 mt-1">
                                <span class="text-[10px] text-slate-500">Letztes:</span>
                                <span class="text-xs font-bold text-emerald-300 font-mono">${timeAgoStr}</span>
                            </div>
                        </div>
                    </div>
                `;
            }
            
            const width = container.clientWidth || 800;
            const height = container.clientHeight || 192;
            const padding = 65; // Mehr Abstand für Y-Achsen-Labels
            const chartW = width - (padding * 2);
            const chartH = height - (padding * 2);

            if(labels.length < 2) {
                 container.innerHTML = '<div class="absolute inset-0 flex items-center justify-center text-xs text-slate-600 font-mono">Nicht genügend Daten für Verlauf (min. 2 Tage)</div>';
                 return;
            }

            const points = labels.map((label, idx) => {
                const val = dataPoints[idx];
                const x = padding + (idx / Math.max(labels.length - 1, 1)) * chartW;
                const y = height - padding - ((val / maxVal) * chartH);
                const stats = dailyStats[label];
                const hasBackup = stats.count > 0;
                return { x, y, val, date: label, count: stats.count, hasBackup };
            });

            // Berechne Bezier-Kontrollpunkte für smooth curves
            function getControlPoints(p0, p1, p2, t=0.4) {
                const d01 = Math.sqrt(Math.pow(p1.x - p0.x, 2) + Math.pow(p1.y - p0.y, 2));
                const d12 = Math.sqrt(Math.pow(p2.x - p1.x, 2) + Math.pow(p2.y - p1.y, 2));
                const fa = t * d01 / (d01 + d12);
                const fb = t * d12 / (d01 + d12);
                const p1x = p1.x - fa * (p2.x - p0.x);
                const p1y = p1.y - fa * (p2.y - p0.y);
                const p2x = p1.x + fb * (p2.x - p0.x);
                const p2y = p1.y + fb * (p2.y - p0.y);
                return [p1x, p1y, p2x, p2y];
            }

            let pathD = `M ${points[0].x} ${points[0].y}`;
            
            // Generate smooth curve path
            if (points.length > 2) {
                for(let i=0; i < points.length - 1; i++) {
                    const p0 = points[Math.max(0, i-1)];
                    const p1 = points[i];
                    const p2 = points[i+1];
                    const p3 = points[Math.min(points.length-1, i+2)];
                    
                    const cp1x = p1.x + (p2.x - p0.x) * 0.15; // Tension factor
                    const cp1y = p1.y + (p2.y - p0.y) * 0.15;
                    const cp2x = p2.x - (p3.x - p1.x) * 0.15;
                    const cp2y = p2.y - (p3.y - p1.y) * 0.15;
                    
                    pathD += ` C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${p2.x} ${p2.y}`;
                }
            } else {
                points.forEach(p => pathD += ` L ${p.x} ${p.y}`);
            }

            let areaD = pathD + ` L ${points[points.length-1].x} ${height - padding} L ${points[0].x} ${height - padding} Z`;
            const midY = padding + chartH / 2;
            const gridColor = '#ffffff';
            const textColor = '#94a3b8';

            const svg = `
            <svg width="100%" height="100%" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <linearGradient id="chartGradient" x1="0" x2="0" y1="0" y2="1">
                        <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.3"/>
                        <stop offset="100%" stop-color="#3b82f6" stop-opacity="0"/>
                    </linearGradient>
                </defs>
                <!-- Grid Lines -->
                <line x1="${padding}" y1="${height-padding}" x2="${width-padding}" y2="${height-padding}" stroke="${gridColor}" stroke-opacity="0.1" stroke-width="1" />
                <line x1="${padding}" y1="${padding}" x2="${padding}" y2="${height-padding}" stroke="${gridColor}" stroke-opacity="0.1" stroke-width="1" />
                <line x1="${padding}" y1="${midY}" x2="${width-padding}" y2="${midY}" stroke="${gridColor}" stroke-opacity="0.05" stroke-width="1" stroke-dasharray="4 4" />
                <line x1="${padding}" y1="${padding}" x2="${width-padding}" y2="${padding}" stroke="${gridColor}" stroke-opacity="0.05" stroke-width="1" stroke-dasharray="4 4" />
                
                <!-- Axis Labels -->
                <text x="${padding}" y="${height - padding + 20}" fill="${textColor}" font-size="10" text-anchor="middle">${labels[0]}</text>
                <text x="${width - padding}" y="${height - padding + 20}" fill="${textColor}" font-size="10" text-anchor="middle">${labels[labels.length-1]}</text>
                
                <text x="${padding - 12}" y="${height - padding + 4}" fill="${textColor}" font-size="10" text-anchor="end">0</text>
                <text x="${padding - 12}" y="${midY + 4}" fill="${textColor}" font-size="10" text-anchor="end">${formatSize(maxVal/2)}</text>
                <text x="${padding - 12}" y="${padding + 4}" fill="${textColor}" font-size="10" text-anchor="end">${formatSize(maxVal)}</text>

                <path d="${areaD}" fill="url(#chartGradient)" stroke="none" />
                <path d="${pathD}" fill="none" stroke="#3b82f6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
                ${points.map((p, i) => `
                    <g class="chart-point group/point">
                        <circle cx="${p.x}" cy="${p.y}" r="4" fill="#1e293b" stroke="${p.hasBackup ? '#22c55e' : '#ef4444'}" stroke-width="2" class="cursor-pointer transition-all duration-300 group-hover/point:r-6 group-hover/point:fill-white" />
                        <foreignObject x="${Math.min(Math.max(0, p.x - 75), width - 150)}" y="${Math.max(0, p.y - 80)}" width="150" height="70" class="opacity-0 group-hover/point:opacity-100 transition-opacity pointer-events-none overflow-visible">
                            <div xmlns="http://www.w3.org/1999/xhtml" class="bg-[#0f111a] text-xs rounded-lg p-3 border border-blue-500/30 shadow-2xl shadow-blue-900/20">
                                <div class="font-bold text-slate-200 mb-1 border-b border-white/5 pb-1">${p.date}</div>
                                <div class="flex justify-between"><span class="text-slate-500">Vol:</span><span class="text-blue-400 font-mono">${formatSize(p.val)}</span></div>
                                <div class="flex justify-between"><span class="text-slate-500">${p.hasBackup ? 'Erfolgreiche' : 'Erfolgreiche'}</span><span class="text-emerald-400 font-mono">${p.count}</span></div>
                                <div class="flex justify-between"><span class="text-slate-500">Status:</span><span class="font-mono ${p.hasBackup ? 'text-emerald-400' : 'text-red-400'}">${p.hasBackup ? 'Tag mit Backup' : 'Kein Backup'}</span></div>
                            </div>
                        </foreignObject>
                    </g>
                `).join('')}
            </svg>
            `;
            container.innerHTML = svg;
        }

        function updateDashboardDisplays() {
            const table = document.getElementById('history-table-body');
            const restoreTable = document.getElementById('restore-table-body');
            if(!table || !restoreTable) return;
            
            // ALWAYS ensure sort before display to guarantee consistency
            window.applySort();

            renderActivityChart();

            // Update Total Snaps Badge
            const totalBadge = document.getElementById('total-snaps-badge');
            if(totalBadge) totalBadge.innerText = globalHistory.length;

            // Debug Logging for Limit Issues
            // console.log("Rendering History. Limit:", currentLimit, "Total Items:", globalHistory.length);

            table.innerHTML = ''; restoreTable.innerHTML = '';
            let totalBytes = 0;
            storageChart.data.labels = [];
            storageChart.data.datasets[0].data = [];
            storageChart.data.datasets[0].filenames = [];
            storageChart.data.datasets[0].backgroundColor = [];
            storageChart.data.datasets[0].borderColor = [];

            // Apply Limit for Display
            const displayData = globalHistory.slice(0, currentLimit);
            const now = new Date();
            const indexedDisplay = displayData.map(e => ({ entry: e, idx: globalHistory.indexOf(e) }));
            const ageSorted = [...indexedDisplay].sort((a, b) => {
                const da = new Date(a.entry.timestamp);
                const db = new Date(b.entry.timestamp);
                return da - db;
            });
            const rankByIdx = {};
            ageSorted.forEach((it, rank) => { rankByIdx[it.idx] = rank; });
            const maxRank = Math.max(ageSorted.length - 1, 1);

            displayData.forEach((entry, idx) => {
                totalBytes += entry.size;
                const formatted = formatSize(entry.size); // Smart String (z.B. "500 KB" oder "2,5 GB")
                const originalIdx = globalHistory.indexOf(entry);

                // Chart Value STRICT in globalUnit calc
                const isGB = globalUnit === 'GB';
                const chartDivisor = isGB ? (1024**3) : (1024**2);
                const chartVal = entry.size / chartDivisor;

                const rank = rankByIdx[originalIdx] || 0;
                const t = maxRank === 0 ? 0 : rank / maxRank;
                const startHue = 200;
                const endHue = 280;
                const startLight = 70;
                const endLight = 40;
                const sat = 80;
                const hue = startHue + (endHue - startHue) * t;
                const light = startLight + (endLight - startLight) * t;
                const color = `hsl(${hue}, ${sat}%, ${light}%)`;
                const colorTransparent = `hsla(${hue}, ${sat}%, ${light}%, 0.35)`;
                
                const lockIcon = entry.locked ? '<span title="Locked" class="ml-2 text-[10px]">🔒</span>' : '';

                table.insertAdjacentHTML('beforeend', `<tr onclick="showDetails(${originalIdx})" class="bg-white/5 border-b border-white/5 cursor-pointer hover:bg-white/10 transition-all">
                    <td class="px-4 py-3 mono text-[10px] text-slate-400">${entry.timestamp}</td>
                    <td class="px-4 py-3 font-bold text-xs" style="color: ${color}">${entry.filename}${lockIcon}</td>
                    <td class="px-4 py-3 text-right mono text-white text-xs">${formatted}</td>
                </tr>`);
                
                restoreTable.insertAdjacentHTML('beforeend', `<tr><td class="px-4 py-3 text-xs text-slate-400 mono">${entry.timestamp}</td><td class="px-4 py-3 font-bold text-xs" style="color: ${color}">${entry.filename}</td><td class="px-4 py-3 flex gap-2"><button onclick="restoreBackup('${entry.filename}')" class="text-[9px] font-black uppercase text-emerald-500 border border-emerald-500/30 px-3 py-1 rounded hover:bg-emerald-500/10 transition-colors">Restore</button><button onclick="deleteBackupApi('${entry.filename}')" class="text-[9px] font-black uppercase text-red-500 border border-red-500/30 px-3 py-1 rounded hover:bg-red-500/10 transition-colors">Delete</button></td></tr>`);
                
                // Datum schöner formatieren: "DD.MM. HH:mm"
                let dateLabel = entry.timestamp;
                try {
                    const parts = entry.timestamp.split(' ');
                    const dateParts = parts[0].split('-'); // [YYYY, MM, DD]
                    const timeParts = parts[1].split(':'); // [HH, MM, SS]
                    dateLabel = `${dateParts[2]}.${dateParts[1]}. ${timeParts[0]}:${timeParts[1]}`;
                } catch(e) {}

                storageChart.data.labels.push(dateLabel);
                storageChart.data.datasets[0].data.push(chartVal);
                storageChart.data.datasets[0].filenames.push(entry.filename);
                storageChart.data.datasets[0].backgroundColor.push(colorTransparent); 
                storageChart.data.datasets[0].borderColor.push(color);            
            });
            
            // Chart Direction Correction: If sorted by Date Desc (Newest First), reverse chart to show Time Forward (Old->New)
            if(currentSortMode === 0) {
                 storageChart.data.labels.reverse();
                 storageChart.data.datasets[0].data.reverse();
                 storageChart.data.datasets[0].filenames.reverse();
                 storageChart.data.datasets[0].backgroundColor.reverse();
                 storageChart.data.datasets[0].borderColor.reverse();
            }
            
            const totalFmt = formatSize(totalBytes).split(' ');
            if(document.getElementById('total-val-display')) document.getElementById('total-val-display').innerText = totalFmt[0];
            if(document.getElementById('total-unit-display')) document.getElementById('total-unit-display').innerText = totalFmt[1];
            if(document.getElementById('total-snapshots-display')) document.getElementById('total-snapshots-display').innerText = globalHistory.length + " Snapshots";

            storageChart.data.datasets[0].label = `Größe (${globalUnit})`;
            storageChart.update();
            updateDiskStats();
            
            // Smart Path Selection: In Download mode, analyze the Destination (Local) instead of Source (Remote)
            let analysisPath = document.getElementById('source').value;
            if(document.getElementById('config-cloud-enabled') && document.getElementById('config-cloud-enabled').checked) {
                 const dir = document.getElementById('config-cloud-direction') ? document.getElementById('config-cloud-direction').value : 'upload';
                 if(dir === 'download') {
                     analysisPath = document.getElementById('dest').value;
                 }
            }
            
            if(analysisPath) {
                fetch('/api/analyze_source', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path: analysisPath}) })
                    .then(r => r.json())
                    .then(sData => {
                        if(document.getElementById('src-size')) document.getElementById('src-size').innerText = formatSize(sData.size);
                        if(document.getElementById('src-files')) document.getElementById('src-files').innerText = sData.count + " FILES";

                        // Delta Calculation (New Hybrid Logic)
                        const dSizeVal = document.getElementById('delta-size-val');
                        const dSizeBadge = document.getElementById('delta-size-badge');
                        const dFilesVal = document.getElementById('delta-files-val');
                        const dFilesBadge = document.getElementById('delta-files-badge');
                        const dRefInfo = document.getElementById('delta-ref-info');
                        const dModeBadge = document.getElementById('delta-mode-badge');

                        // Determine Mode
                        let deltaMode = "LOCAL";
                        if(document.getElementById('config-cloud-enabled') && document.getElementById('config-cloud-enabled').checked) {
                             const dir = document.getElementById('config-cloud-direction') ? document.getElementById('config-cloud-direction').value : 'upload';
                             deltaMode = dir === 'download' ? "DOWNLOAD" : "UPLOAD";
                        }
                        if(dModeBadge) dModeBadge.innerText = deltaMode;

                        // Unified Delta Calculation (Enabled for all modes including DOWNLOAD)
                        // Filter history for current analysis path (Normalize slashes for comparison)
                        // NOTE: We use quadruple backslash in Python string to result in double backslash in JS
                        const normAnalysisPath = analysisPath.replace(/\\\\/g, '/').toLowerCase();
                        
                        let relevantHistory = globalHistory.filter(e => {
                            if(!e.source_path) return false; // Ignore old entries without source_path
                            return e.source_path.replace(/\\\\/g, '/').toLowerCase() === normAnalysisPath;
                        });

                        if(dSizeVal && relevantHistory.length > 0) {
                            // Find latest backup
                            let lastEntry = relevantHistory[0];
                            for (let i = 1; i < relevantHistory.length; i++) {
                                const entry = relevantHistory[i];
                                if ((entry.timestamp || "") > (lastEntry.timestamp || "")) {
                                    lastEntry = entry;
                                }
                            }
                            
                            const lastCount = lastEntry.file_count || 0;
                            const currentCount = sData.count || 0;
                            const deltaCount = currentCount - lastCount;
                            
                            // Use source_size (uncompressed) if available
                            // If lastEntry has no source_size (old backup), we cannot compare accurately against current uncompressed source.
                            // To avoid misleading "Increase", we treat it as a fresh start for stats.
                            let deltaSize = 0;
                            let validDelta = false;

                            if (lastEntry.source_size) {
                                const lastSize = lastEntry.source_size;
                                const currentSize = sData.size || 0;
                                deltaSize = currentSize - lastSize;
                                validDelta = true;
                            } else {
                                // Fallback for old backups: Do not show misleading delta
                                validDelta = false;
                            }
                            
                            // Size Display
                            if (validDelta) {
                                const sizeFmt = formatSize(Math.abs(deltaSize));
                                dSizeVal.innerText = (deltaSize > 0 ? "+" : (deltaSize < 0 ? "-" : "")) + sizeFmt;
                                
                                if(deltaSize === 0) {
                                    dSizeBadge.innerText = "UNCHANGED";
                                    dSizeBadge.className = "text-[10px] font-bold text-slate-600 block mt-1";
                                } else if(deltaSize > 0) {
                                    dSizeBadge.innerText = "INCREASE";
                                    dSizeBadge.className = "text-[10px] font-bold text-red-400 block mt-1";
                                } else {
                                    dSizeBadge.innerText = "DECREASE";
                                    dSizeBadge.className = "text-[10px] font-bold text-emerald-400 block mt-1";
                                }
                            } else {
                                // Invalid Delta (Old Backup vs New Source) -> Show Current Size but no Delta
                                dSizeVal.innerText = formatSize(sData.size || 0);
                                dSizeBadge.innerText = "BASE UPDATE"; // Indicate that we are resetting the baseline
                                dSizeBadge.className = "text-[10px] font-bold text-blue-400 block mt-1";
                            }
                            
                            // Files Display
                            dFilesVal.innerText = (deltaCount > 0 ? "+" : "") + deltaCount;
                             if(deltaCount === 0) {
                                dFilesBadge.innerText = "UNCHANGED";
                                dFilesBadge.className = "text-[10px] font-bold text-slate-600 block mt-1";
                            } else if(deltaCount > 0) {
                                dFilesBadge.innerText = "INCREASE";
                                dFilesBadge.className = "text-[10px] font-bold text-red-400 block mt-1";
                            } else {
                                dFilesBadge.innerText = "DECREASE";
                                dFilesBadge.className = "text-[10px] font-bold text-emerald-400 block mt-1";
                            }
                            
                            if(dRefInfo) dRefInfo.innerText = lastEntry.timestamp || "Unknown";
                            
                        } else if (dSizeVal) {
                            // Initial State
                            dSizeVal.innerText = formatSize(sData.size || 0);
                            dSizeBadge.innerText = "INITIAL";
                            dFilesVal.innerText = (sData.count || 0);
                            dFilesBadge.innerText = "INITIAL";
                            if(dRefInfo) dRefInfo.innerText = "Kein Backup";
                        }
                    })
                    .catch(e => console.error("Analyze Source Error:", e));
            }
            calculateHealth();
        }

        function clearLogs() {
            const log = document.getElementById('log');
            if(log) log.innerHTML = '';
        }

        function addLog(msg, type='info', key=null) {
            const log = document.getElementById('log');
            if(!log) return;
            const div = document.createElement('div');
            div.className = `log-${type}`;
            // Improved display with HTML
            const time = new Date().toLocaleTimeString();
            
            let msgHtml = `<span class="font-medium">${msg}</span>`;
            if (key) {
                msgHtml = `<span class="font-medium" data-i18n="${key}">${msg}</span>`;
            }
            
            div.innerHTML = `<span class="opacity-50 text-[10px] mr-2 font-mono">[${time}]</span>${msgHtml}`;
            log.appendChild(div);
            
            // Limit to 100 lines buffer (scrolling enabled, ~25 visible)
            if(log.children.length > 100) {
                log.removeChild(log.firstChild);
            }

            log.scrollTop = log.scrollHeight;
        }

        async function runBackup() {
            const source = document.getElementById('source').value;
            const dest = document.getElementById('dest').value;
            if(!source || !dest) return addLog(t("console.pathsMissing", "Pfade fehlen!"), "error");
            
            clearLogs();
            addLog(t("console.kernelInit", "Kernel: Initiiere Hintergrund-Job..."), "info");
            
            // Set Initial Status
            const ind = document.getElementById('status-indicator');
            const txt = document.getElementById('console-status-text');
            if(ind) ind.className = "w-2 h-2 rounded-full bg-blue-500 animate-pulse transition-colors duration-300";
            if(txt) {
                txt.innerText = "INITIALISIERE...";
                txt.className = "text-[10px] font-black uppercase tracking-widest text-blue-400";
            }
            
            document.getElementById('zipPercent').innerText = "0%";
            document.getElementById('zipBar').style.width = "0%";
            isBackupActive = true;
            
            // Reset Module Status Areas
            ['status-area-github', 'status-area-db', 'status-area-cloud-tresor'].forEach(id => {
                const el = document.getElementById(id);
                if(el) el.classList.add('hidden');
            });

            // Gather Options (Snapshot + UI Checkboxes)
            const modules = ['snapshot'];
            const cloudCb = document.getElementById('config-cloud-enabled');
            if(cloudCb && cloudCb.checked) modules.push('cloud');
            
            const dbCb = document.getElementById('config-db-enabled');
            if(dbCb && dbCb.checked) modules.push('db');
            
            const ghCb = document.getElementById('config-github-enabled');
            if(ghCb && ghCb.checked) modules.push('github');

            const task_options = {
                modules: modules,
                naming_custom_text: document.getElementById('cloud-naming-custom') ? document.getElementById('cloud-naming-custom').value : "",
                naming_include_date: document.getElementById('cloud-naming-date') ? document.getElementById('cloud-naming-date').checked : true,
                naming_include_time: document.getElementById('cloud-naming-time') ? document.getElementById('cloud-naming-time').checked : true,
                naming_include_seq: document.getElementById('cloud-naming-seq') ? document.getElementById('cloud-naming-seq').checked : false
            };
            
            try {
                // Robustere Fehlerbehandlung für Fetch
                const resp = await fetch('/api/start_backup', { 
                    method: 'POST', headers: {'Content-Type': 'application/json'}, 
                    body: JSON.stringify({
                        source, 
                        dest, 
                        comment: document.getElementById('snap-comment').value,
                        task_options: task_options
                    }) 
                });
                
                if (!resp.ok) {
                    throw new Error(`HTTP Error: ${resp.status}`);
                }

                const data = await resp.json();
                
                if(data.status === 'error') {
                     addLog(t("console.startError", "Start Fehler: ") + data.message, "error");
                     // Reset Status
                     if(ind) ind.className = "w-2 h-2 rounded-full bg-red-500 transition-colors duration-300";
                     if(txt) {
                        txt.innerText = "FEHLER";
                        txt.className = "text-[10px] font-black uppercase tracking-widest text-red-400";
                     }
                     isBackupActive = false;
                     return;
                }
                
                // Polling wird nun global erledigt (globalPoll)
                // Wir zeigen nur den Start an.
                addLog(t("console.backupStarted", "Backup Prozess im Hintergrund gestartet..."), "info");

            } catch(e) {
                console.error(e);
                addLog(t("console.networkError", "Netzwerk Fehler: ") + e.message, "error");
                // Reset Status
                 if(ind) ind.className = "w-2 h-2 rounded-full bg-red-500 transition-colors duration-300";
                 if(txt) {
                    txt.innerText = "NETZWERK FEHLER";
                    txt.className = "text-[10px] font-black uppercase tracking-widest text-red-400";
                 }
                isBackupActive = false;
            }
        }

        async function cancelBackup() {
            try {
                addLog(t("console.sendingAbort", "Sende Abbruch-Signal..."), "info");
                const resp = await fetch('/api/cancel_backup');
                const data = await resp.json();
                if(data.status !== 'success') {
                    addLog(t("console.abortFailed", "Abbruch fehlgeschlagen: ") + data.message, "error");
                }
            } catch(e) {
                addLog(t("console.abortSignalError", "Fehler beim Senden des Abbruch-Signals."), "error");
            }
        }

        async function restoreBackup(filename) {
            const dest = document.getElementById('dest').value;
            const source = document.getElementById('source').value;
            addLog(t("console.kernelRestoreStart", "Kernel: Starte Wiederherstellung..."), "info");
            const resp = await fetch('/api/restore_backup', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ filename, dest, target: source }) });
            if((await resp.json()).status === 'success') addLog(t("console.kernelRestoreSuccess", "Kernel: Daten erfolgreich rekonstruiert!"), "success");
            else addLog(t("console.restoreFailed", "Restore fehlgeschlagen."), "error");
        }

        async function deleteBackupApi(filename) {
            if(!confirm(`Backup ${filename} wirklich löschen?`)) return;
            const resp = await fetch('/api/delete_backup', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ filename }) });
            const result = await resp.json();
            if(result.status === 'success') {
                addLog(t("console.backupDeleted", "Backup gelöscht."), "info");
                loadData();
            } else addLog(t("console.deleteFailed", "Löschen fehlgeschlagen."), "error");
        }

        let currentModalFilename = "";

        function showDetails(idx) {
            const entry = globalHistory[idx];
            currentModalFilename = entry.filename;
            
            // Basic Meta
            document.getElementById('modal-filename').innerText = entry.filename;
            document.getElementById('modal-hash').innerText = entry.sha256;
            document.getElementById('modal-ts').innerText = entry.timestamp;
            document.getElementById('modal-size').innerText = formatSize(entry.size);
            
            // Comment
            document.getElementById('modal-comment').value = entry.comment || "";
            
            // Lock Status UI
            updateLockUI(entry.locked || false);
            
            // Integrity Reset
            document.getElementById('integrity-result').classList.add('hidden');
            
            // Actions
            document.getElementById('modal-delete-btn').onclick = () => { closeHashModal(); deleteBackupApi(entry.filename); };
            
            // Reset Tabs
            switchModalTab('meta');
            document.getElementById('zip-file-list').innerHTML = '<div class="p-8 text-center text-slate-500 text-xs uppercase tracking-widest animate-pulse">Lade Dateistruktur...</div>';
            document.getElementById('file-count-badge').innerText = "-- Files";
            
            // Show Modal
            const modal = document.getElementById('hash-modal');
            modal.classList.remove('hidden');
            modal.classList.add('flex');
        }

        function closeHashModal() { 
            const modal = document.getElementById('hash-modal');
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }
        
        function switchModalTab(tab) {
            document.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.modal-tab-content').forEach(c => c.classList.add('hidden'));
            
            if(tab === 'meta') {
                document.querySelector('.modal-tab:nth-child(1)').classList.add('active');
                document.getElementById('tab-meta').classList.remove('hidden');
            } else {
                document.querySelector('.modal-tab:nth-child(2)').classList.add('active');
                document.getElementById('tab-content').classList.remove('hidden');
                loadZipContent();
            }
        }
        
        async function loadZipContent() {
            if(!currentModalFilename) return;
            // Nur laden wenn noch nicht geladen? Nein, immer laden um aktuell zu sein (obwohl Zip sich nicht ändert)
            // Cache könnte man machen, aber wir lassen es simpel.
            
            const listContainer = document.getElementById('zip-file-list');
            try {
                const resp = await fetch('/api/get_zip_content', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({filename: currentModalFilename}) });
                const data = await resp.json();
                
                document.getElementById('file-count-badge').innerText = data.files.length + " Files";
                
                let html = '';
                data.files.forEach(f => {
                    html += `<div class="file-list-item"><span class="file-icon">📄</span> ${f}</div>`;
                });
                listContainer.innerHTML = html;
            } catch(e) {
                listContainer.innerHTML = '<div class="p-4 text-red-500 text-xs">Fehler beim Laden der Dateiliste.</div>';
            }
        }
        
        async function toggleLock() {
            if(!currentModalFilename) return;
            try {
                const resp = await fetch('/api/toggle_lock', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({filename: currentModalFilename}) });
                const data = await resp.json();
                if(data.status === 'success') {
                    // Update Global History locally
                    const entry = globalHistory.find(h => h.filename === currentModalFilename);
                    if(entry) entry.locked = data.locked;
                    
                    updateLockUI(data.locked);
                    updateDashboardDisplays(); // Refresh Table Icons
                    addLog(data.locked ? t("console.backupLocked", "Backup gesperrt (Locked).") : t("console.backupUnlocked", "Backup entsperrt (Unlocked)."), "info");
                }
            } catch(e) { console.error(e); }
        }
        
        function updateLockUI(isLocked) {
            const badge = document.getElementById('lock-badge');
            const btn = document.getElementById('btn-lock');
            
            if(isLocked) {
                badge.classList.remove('hidden');
                btn.innerHTML = '🔒';
                btn.classList.add('bg-amber-500/20');
                btn.title = "Unlock";
            } else {
                badge.classList.add('hidden');
                btn.innerHTML = '🔓';
                btn.classList.remove('bg-amber-500/20');
                btn.title = "Lock (Vor Löschung schützen)";
            }
        }
        
        async function saveComment() {
            const comment = document.getElementById('modal-comment').value;
            if(!currentModalFilename) return;
            try {
                const resp = await fetch('/api/update_comment', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({filename: currentModalFilename, comment}) });
                const data = await resp.json();
                if(data.status === 'success') {
                    const entry = globalHistory.find(h => h.filename === currentModalFilename);
                    if(entry) entry.comment = comment;
                    addLog(t("console.commentSaved", "Kommentar gespeichert."), "success");
                }
            } catch(e) { addLog(t("console.saveError", "Fehler beim Speichern."), "error"); }
        }
        
        async function verifyIntegrity() {
            const resDiv = document.getElementById('integrity-result');
            resDiv.classList.remove('hidden');
            // Reset & Loading Style
            resDiv.className = 'mb-4 p-3 rounded-lg text-center font-bold text-xs tracking-wide border bg-blue-500/10 border-blue-500/20 text-blue-400 animate-pulse';
            resDiv.innerHTML = '⚡ BERECHNE HASH & VERGLEICHE... BITTE WARTEN...';
            
            try {
                const resp = await fetch('/api/verify_integrity', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({filename: currentModalFilename}) });
                const data = await resp.json();
                
                resDiv.classList.remove('animate-pulse');

                if(data.status === 'success') {
                    resDiv.className = 'mb-4 p-3 rounded-lg text-center font-bold text-xs tracking-wide border bg-emerald-500/10 border-emerald-500/20 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.2)]';
                    resDiv.innerHTML = `✓ ${data.message}`;
                } else if(data.status === 'mismatch') {
                    resDiv.className = 'mb-4 p-3 rounded-lg text-center font-bold text-xs tracking-wide border bg-red-500/10 border-red-500/20 text-red-500 shadow-[0_0_15px_rgba(239,68,68,0.2)]';
                    resDiv.innerHTML = `⚠️ ${data.message}`;
                } else {
                    resDiv.className = 'mb-4 p-3 rounded-lg text-center font-bold text-xs tracking-wide border bg-red-900/10 border-red-500/20 text-red-400';
                    resDiv.innerHTML = `Fehler: ${data.message}`;
                }
            } catch(e) {
                resDiv.className = 'mb-4 p-3 rounded-lg text-center font-bold text-xs tracking-wide border bg-red-900/10 border-red-500/20 text-red-400';
                resDiv.innerHTML = `Systemfehler.`;
            }
        }
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

        // onchange handler for direction
        const dirSelect = document.getElementById('config-cloud-direction');
        if(dirSelect) dirSelect.addEventListener('change', updateCloudTresorUI);

        function updateCloudTresorUI() {
            const enabled = document.getElementById('config-cloud-enabled').checked;
            const module = document.getElementById('module-cloud-tresor');
            
            // --- 1. Enable/Disable Inputs ---
            if(module) {
                const inputs = module.querySelectorAll('input:not(#config-cloud-enabled), select, button');
                inputs.forEach(el => {
                    // Skip Save Button to allow saving "disabled" state
                    if(el.getAttribute('onclick') && el.getAttribute('onclick').includes('saveProfile()')) return;

                    el.disabled = !enabled;
                    el.style.opacity = enabled ? "1" : "0.5";
                });
            }

            const provider = document.getElementById('config-cloud-provider').value;
            const direction = document.getElementById('config-cloud-direction').value;
            
            // --- 2. Visibility Logic ---
            const grpHost = document.getElementById('cloud-host-group');
            const grpS3 = document.getElementById('cloud-s3-group');
            const grpAuth = document.getElementById('cloud-auth-group');
            const userWrap = document.getElementById('cloud-user-wrap');
            const lblHost = document.getElementById('lbl-cloud-host');
            const lblUser = document.getElementById('lbl-cloud-user');
            const lblPass = document.getElementById('lbl-cloud-pass');
            const grpLocalPath = document.getElementById('cloud-local-path-group');
            
            grpHost.classList.remove('hidden');
            grpS3.classList.add('hidden');
            grpAuth.classList.remove('hidden');
            userWrap.classList.remove('hidden');
            
            // Direction Logic
            if (direction === 'download') {
                if(grpLocalPath) grpLocalPath.classList.remove('hidden');
            } else {
                if(grpLocalPath) grpLocalPath.classList.add('hidden');
            }
            
            if(provider === 'SFTP') {
                lblHost.innerText = "Server Host";
                lblUser.innerText = "Benutzer";
                lblPass.innerText = "Passwort";
                document.getElementById('config-cloud-port').parentElement.classList.remove('hidden');
            } else if(provider === 'S3 (Amazon)') {
                grpHost.classList.add('hidden');
                grpS3.classList.remove('hidden');
                lblUser.innerText = "Access Key ID";
                lblPass.innerText = "Secret Access Key";
            } else if(provider === 'Dropbox') {
                grpHost.classList.add('hidden');
                grpS3.classList.add('hidden');
                userWrap.classList.add('hidden'); 
                lblPass.innerText = "Access Token";
            } else if(provider === 'WebDAV') {
                lblHost.innerText = "WebDAV URL";
                document.getElementById('config-cloud-port').parentElement.classList.add('hidden');
                lblUser.innerText = "Benutzer";
                lblPass.innerText = "Passwort";
            } else if(provider === 'Local') {
                grpHost.classList.add('hidden');
                grpS3.classList.add('hidden');
                grpAuth.classList.add('hidden');
            }

            // --- 3. Badge Logic ---
            const badge = document.getElementById('cloud-status-badge');
            // Reset Classes
            badge.className = "px-2 py-1 text-[9px] font-black uppercase border";
            
            if(!enabled) {
                badge.innerText = "DEAKTIVIERT";
                badge.classList.add('bg-slate-500/10', 'border-slate-500/20', 'text-slate-500');
            } else {
                // Check completeness
                const host = document.getElementById('config-cloud-host').value;
                const user = document.getElementById('config-cloud-user').value;
                const pass = document.getElementById('config-cloud-password').value;
                const bucket = document.getElementById('config-cloud-bucket').value;
                
                let isComplete = false;
                if(provider === 'SFTP' && host && user && pass) isComplete = true;
                else if(provider === 'S3 (Amazon)' && user && pass && bucket) isComplete = true;
                else if(provider === 'Dropbox' && pass) isComplete = true; 
                else if(provider === 'WebDAV' && host && user && pass) isComplete = true;

                if(isComplete) {
                    badge.innerText = "BEREIT ZUM SYNC";
                    badge.classList.add('bg-emerald-500/10', 'border-emerald-500/20', 'text-emerald-500');
                } else {
                    badge.innerText = "KONFIGURATION ERFORDERLICH";
                    badge.classList.add('bg-yellow-500/10', 'border-yellow-500/20', 'text-yellow-500');
                }
            }
        }

        function updateGithubUI() {
            const enabled = document.getElementById('config-github-enabled').checked;
            const module = document.getElementById('module-github');
            if(module) {
                const inputs = module.querySelectorAll('input:not(#config-github-enabled), button');
                inputs.forEach(el => {
                    // Skip Save Button
                    if(el.getAttribute('onclick') && el.getAttribute('onclick').includes('saveProfile()')) return;

                    el.disabled = !enabled;
                    el.style.opacity = enabled ? "1" : "0.5";
                });
            }
        }

        function updateDbUI() {
            const enabled = document.getElementById('config-db-enabled').checked;
            const module = document.getElementById('module-db');
            if(module) {
                const inputs = module.querySelectorAll('input:not(#config-db-enabled), select, button');
                inputs.forEach(el => {
                    // Skip Save Button
                    if(el.getAttribute('onclick') && el.getAttribute('onclick').includes('saveProfile()')) return;

                    el.disabled = !enabled;
                    el.style.opacity = enabled ? "1" : "0.5";
                });
            }
        }

        async function runCloudBackupNow() {
            // 1. Speichere Config
            addLog(t("console.saveConfigBeforeCloud", "Speichere Konfiguration vor Cloud Backup..."), "info");
            await saveProfile(); 
            
            // 2. Lade aktuelle Config um Pfade zu prüfen
            const config = await fetch('/api/get_config').then(resp => resp.json());
            const source = config.default_source;
            const dest = config.default_dest;
            
            if(!source || !dest) {
                addLog(t("console.pathMissingSettings", "Quell- oder Zielpfad fehlt! Bitte in den Einstellungen prüfen."), "error");
                alert(t("dialog.sourceTargetMissing", "Please first define source and target path in settings."));
                return;
            }

            // Get Naming Options
            const custom = document.getElementById('cloud-naming-custom').value;
            const incDate = document.getElementById('cloud-naming-date').checked;
            const incTime = document.getElementById('cloud-naming-time').checked;
            const incSeq = document.getElementById('cloud-naming-seq').checked;

            if(!config.cloud_sync_enabled) {
                if(!confirm(t("dialog.cloudSyncDisabled", "Cloud-Sync is disabled. Still start backup (local + attempt)?"))) {
                    return;
                }
            }
            
            addLog(t("console.startManualCloud", "Starte manuelles Cloud Backup..."), "info");
            
            try {
                const resp = await fetch('/api/run_cloud_backup_now', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        source: source, 
                        dest: dest, 
                        comment: "Manuelles Cloud Backup",
                        naming_custom: custom,
                        naming_date: incDate,
                        naming_time: incTime,
                        naming_seq: incSeq
                    })
                });
                
                const res = await resp.json();
                if(res.status === 'started') {
                    addLog(t("console.cloudBackupStarted", "Cloud Backup gestartet."), "success");
                    pollCloudStatus();
                } else {
                    addLog(t("console.startError", "Start Fehler: ") + res.message, "error");
                }
            } catch(e) {
                addLog(t("console.cloudNetworkError", "Netzwerkfehler beim Starten des Cloud Backups."), "error");
            }
        }
        
        async function pollCloudStatus() {
            const statusArea = document.getElementById('status-area-cloud-tresor');
            const statusMsg = document.getElementById('status-msg-cloud-tresor');
            const statusPct = document.getElementById('status-pct-cloud-tresor');
            const statusBar = document.getElementById('status-bar-cloud-tresor');
            const statusErr = document.getElementById('status-err-cloud-tresor');
            
            // Console Elements
            const consoleArea = document.getElementById('console-cloud-tresor');
            const consoleContent = document.getElementById('console-content-cloud-tresor');
            const statusDot = document.getElementById('status-dot-cloud-tresor');
            
            if(statusArea) statusArea.classList.remove('hidden');
            if(statusErr) statusErr.classList.add('hidden');
            
            // Reset & Show Console
            /*
            if(consoleArea) {
                consoleArea.classList.remove('hidden');
                if(consoleContent) consoleContent.innerHTML = '<div class="text-slate-500 italic">Warte auf Logs...</div>';
            }
            */
            if(consoleContent) consoleContent.innerHTML = `<div class="text-slate-500 italic">${t("console.waitingForLogs", "Waiting for logs...")}</div>`;

            const pollInterval = setInterval(async () => {
                try {
                    const resp = await fetch('/api/get_cloud_backup_status');
                    const status = await resp.json();
                    
                    if(statusMsg) {
                        const waitLabel = t("console.statusWaiting", "Waiting...");
                        statusMsg.innerText = status.message || waitLabel;
                    }
                    if(statusPct) statusPct.innerText = status.progress + "%";
                    if(statusBar) statusBar.style.width = status.progress + "%";
                    
                    if(statusDot) {
                        if(status.active) {
                            statusDot.classList.remove('bg-slate-600');
                            statusDot.classList.add('bg-blue-500', 'animate-pulse');
                        } else {
                            statusDot.classList.add('bg-slate-600');
                            statusDot.classList.remove('bg-blue-500', 'animate-pulse');
                        }
                    }

                    // Update Console
                    if(consoleContent && status.logs && Array.isArray(status.logs)) {
                        const logHtml = status.logs.map(line => {
                            let color = "text-slate-400";
                            if(line.includes("[ERROR]")) color = "text-red-400 font-bold";
                            if(line.includes("[WARNING]")) color = "text-yellow-400";
                            if(line.includes("[SUCCESS]")) color = "text-green-400";
                            return `<div class="${color} break-all">${line}</div>`;
                        }).join('');
                        
                        if(consoleContent.innerHTML !== logHtml) {
                            consoleContent.innerHTML = logHtml;
                            consoleArea.scrollTop = consoleArea.scrollHeight;
                        }
                    }
                    
                    if(!status.active) {
                        clearInterval(pollInterval);
                    if(status.result && status.result.status === 'success') {
                             addLog(t("console.cloudSuccess", "Cloud Backup erfolgreich beendet."), "success");
                             if(statusMsg) statusMsg.innerText = "Fertig";
                             
                             // Hide after delay if success
                             /*
                             setTimeout(() => { 
                                 if(statusArea) statusArea.classList.add('hidden'); 
                                 if(consoleArea) consoleArea.classList.add('hidden');
                             }, 5000);
                             */
                        } else {
                             addLog(t("console.cloudFinishedWarn", "Cloud Backup beendet (evtl. Fehler)."), "warning");
                             if(statusErr) {
                                 statusErr.innerText = status.result ? status.result.message : "Unbekannter Fehler";
                                 statusErr.classList.remove('hidden');
                             }
                             // Keep Console Open on Error
                        }
                    }
                } catch(e) {
                    clearInterval(pollInterval);
                }
            }, 1000);
        }

        async function createLocalStorageLocation() {
        const btn = event.target;
        const originalText = btn.innerText;
        btn.innerText = "Erstelle...";
        btn.disabled = true;
        
        const path = document.getElementById('config-cloud-local-path').value;
        if(!path) {
            alert("Bitte einen lokalen Pfad angeben!");
            btn.innerText = originalText;
            btn.disabled = false;
            return;
        }
        
        try {
            const resp = await fetch('/api/create_cloud_path', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    provider: 'Local',
                    path: path
                })
            });
            const data = await resp.json();
            
            if(data.status === 'success') {
                addLog(t("console.localFolderCreated", "Lokaler Ordner erstellt!"), "success");
                btn.innerText = "Erfolg ✓";
                btn.classList.add('text-green-400', 'border-green-500/30');
            } else {
                addLog(t("console.errorPrefix", "Fehler: ") + data.message, "error");
                btn.innerText = "Fehler ✕";
                btn.classList.add('text-red-400', 'border-red-500/30');
            }
        } catch(e) {
            console.error(e);
            btn.innerText = "Error";
        }
        
        setTimeout(() => {
            btn.innerText = originalText;
            btn.disabled = false;
            btn.classList.remove('text-green-400', 'border-green-500/30', 'text-red-400', 'border-red-500/30');
        }, 3000);
    }

    async function createStorageLocation() {
            const btn = event.target;
            
            // User-Input abfragen
            let currentPath = document.getElementById('config-cloud-path').value;
            const newPath = prompt("Welchen Ordner möchten Sie anlegen?", currentPath);
            
            if (newPath === null) return; // Abbrechen
            if (!newPath) {
                 alert("Bitte einen Pfad angeben!");
                 return;
            }

            const originalText = btn.innerText;
            btn.innerText = "Erstelle...";
            btn.disabled = true;

            // 1. Parameter sammeln
            const provider = document.getElementById('config-cloud-provider').value;
            const host = document.getElementById('config-cloud-host').value;
            const user = document.getElementById('config-cloud-user').value;
            const pass = document.getElementById('config-cloud-password').value;
            // Wir nutzen den Pfad aus dem Prompt
            const path = newPath; 
            const port = document.getElementById('config-cloud-port').value;
            const bucket = document.getElementById('config-cloud-bucket').value;

            try {
                const resp = await fetch('/api/create_cloud_path', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        provider, host, user, password: pass, path, port, bucket
                    })
                });
                const data = await resp.json();
                
                if(data.status === 'success') {
                    addLog(t("console.remoteLocationCreated", "Speicherort erfolgreich angelegt!"), "success");
                    btn.innerText = "Erfolg ✓";
                    btn.classList.add('text-green-400', 'border-green-500/30');
                } else {
                    addLog(t("console.createError", "Fehler beim Anlegen: ") + data.message, "error");
                    btn.innerText = "Fehler ✕";
                    btn.classList.add('text-red-400', 'border-red-500/30');
                }
            } catch(e) {
                console.error(e);
                addLog(t("console.createNetworkError", "Netzwerkfehler beim Anlegen."), "error");
                btn.innerText = "Netzwerk Error";
            }

            setTimeout(() => {
                btn.innerText = originalText;
                btn.disabled = false;
                btn.classList.remove('text-green-400', 'border-green-500/30', 'text-red-400', 'border-red-500/30');
            }, 3000);
        }

        async function testCloudConnection() {
            const btn = event.target;
            const originalText = btn.innerText;
            btn.innerText = "Verbinde...";
            btn.disabled = true;
            
            const provider = document.getElementById('config-cloud-provider').value;
            const host = document.getElementById('config-cloud-host').value;
            const user = document.getElementById('config-cloud-user').value;
            const pass = document.getElementById('config-cloud-password').value;
            const bucket = document.getElementById('config-cloud-bucket').value;
            const port = document.getElementById('config-cloud-port').value;
            const region = document.getElementById('config-cloud-region').value;
            const path = document.getElementById('config-cloud-path').value;
            
            try {
                const resp = await fetch('/api/test_cloud_connection', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        provider: provider,
                        host: host,
                        user: user,
                        password: pass,
                        bucket: bucket,
                        port: port,
                        region: region,
                        path: path
                    })
                });
                const res = await resp.json();
                
                if(res.status === 'success') {
                    btn.innerText = "Verbindung OK ✓";
                    btn.classList.add('text-green-400', 'border-green-500/30', 'bg-green-500/10');
                    addLog(`Cloud Verbindung (${provider}) erfolgreich.`, "success");
                } else {
                    btn.innerText = "Fehler ✕";
                    btn.classList.add('text-red-400', 'border-red-500/30', 'bg-red-500/10');
                    addLog(`Cloud Verbindung fehlgeschlagen: ${res.message}`, "error");
                }
            } catch(e) {
                btn.innerText = "Netzwerkfehler";
                btn.classList.add('text-red-400', 'border-red-500/30', 'bg-red-500/10');
                addLog("Netzwerkfehler beim Cloud-Test.", "error");
            }
            
            setTimeout(() => {
                btn.innerText = originalText;
                btn.disabled = false;
                btn.classList.remove('text-green-400', 'border-green-500/30', 'bg-green-500/10', 'text-red-400', 'border-red-500/30', 'bg-red-500/10');
            }, 3000);
        }

        async function testNotification(type) {
            const btn = event.target;
            const originalText = btn.innerText;
            btn.innerText = "...";
            btn.disabled = true;
            
            const payload = {
                discord_webhook_url: document.getElementById('config-discord-url').value,
                telegram_token: document.getElementById('config-telegram-token').value,
                telegram_chat_id: document.getElementById('config-telegram-chatid').value
            };
            
            try {
                const resp = await fetch('/api/test_notification', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(payload)
                });
                const res = await resp.json();
                
                if(res.status === 'success') {
                    btn.innerText = "OK ✓";
                    btn.classList.add('text-green-400');
                    addLog("Test-Benachrichtigung gesendet.", "success");
                } else {
                    btn.innerText = "Err";
                    btn.classList.add('text-red-400');
                    addLog("Fehler: " + res.message, "error");
                }
            } catch(e) {
                btn.innerText = "Err";
                addLog("Netzwerkfehler.", "error");
            }
            
            setTimeout(() => {
                btn.innerText = originalText;
                btn.classList.remove('text-green-400', 'text-red-400');
                btn.disabled = false;
            }, 2000);
        }

        async function saveProfile() {
            const conf = { 
                default_source: document.getElementById('config-source').value, 
                default_dest: document.getElementById('config-dest').value, 
                retention_count: parseInt(document.getElementById('config-retention').value),
                auto_interval: parseInt(document.getElementById('config-auto-interval').value) || 0,
                auto_backup_enabled: autoBackupEnabled,
                // Cloud Settings
                cloud_sync_enabled: document.getElementById('config-cloud-enabled').checked,
                cloud_provider: document.getElementById('config-cloud-provider').value,
                cloud_direction: document.getElementById('config-cloud-direction') ? document.getElementById('config-cloud-direction').value : "upload",
                cloud_host: document.getElementById('config-cloud-host').value,
                cloud_port: document.getElementById('config-cloud-port').value,
                cloud_bucket: document.getElementById('config-cloud-bucket').value,
                cloud_region: document.getElementById('config-cloud-region').value,
                cloud_target_path: document.getElementById('config-cloud-path').value,
                cloud_local_path: document.getElementById('config-cloud-local-path') ? document.getElementById('config-cloud-local-path').value : "",
                cloud_user: document.getElementById('config-cloud-user').value,
                cloud_password: document.getElementById('config-cloud-password').value,
                cloud_api_key: document.getElementById('config-cloud-api-key').value,
                // GitHub Settings
                github_backup_enabled: document.getElementById('config-github-enabled').checked,
                github_url: document.getElementById('config-github-url').value,
                github_path: document.getElementById('config-github-path').value,
                github_token: document.getElementById('config-github-token').value,
                // Database Settings (New)
                db_backup_enabled: document.getElementById('config-db-enabled') ? document.getElementById('config-db-enabled').checked : false,
                db_type: document.getElementById('config-db-type') ? document.getElementById('config-db-type').value : 'mysql',
                db_host: document.getElementById('config-db-host') ? document.getElementById('config-db-host').value : '',
                db_port: document.getElementById('config-db-port') ? document.getElementById('config-db-port').value : '',
                db_user: document.getElementById('config-db-user') ? document.getElementById('config-db-user').value : '',
                db_password: document.getElementById('config-db-password') ? document.getElementById('config-db-password').value : '',
                db_names: document.getElementById('config-db-names') ? document.getElementById('config-db-names').value : '',
                // Naming Settings
                naming_custom_text: document.getElementById('config-naming-custom').value,
                naming_include_date: document.getElementById('config-naming-date').checked,
                naming_include_time: document.getElementById('config-naming-time').checked,
                naming_include_seq: document.getElementById('config-naming-seq').checked,
                naming_seq_counter: parseInt(document.getElementById('config-naming-seq-val').value) || 1,
                // Advanced
                compression_level: parseInt(document.getElementById('config-compression').value) || 3,
                exclusions: document.getElementById('config-exclusions').value,
                // Notifications
                notify_on_success: document.getElementById('config-notify-success').checked,
                notify_on_error: document.getElementById('config-notify-error').checked,
                discord_webhook_url: document.getElementById('config-discord-url').value,
                telegram_token: document.getElementById('config-telegram-token').value,
                telegram_chat_id: document.getElementById('config-telegram-chatid').value,
                // Encryption
                encryption_enabled: document.getElementById('config-enc-enabled').checked,
                encryption_password: document.getElementById('config-enc-password').value
            };
            try {
                const mainSaveBtn = document.querySelector('button[data-i18n="settings.saveParametersButton"]');
                let originalText = null;
                let originalColor = null;
                if (mainSaveBtn) {
                    originalText = mainSaveBtn.innerText;
                    originalColor = mainSaveBtn.style.color;
                    const savingText = typeof t === "function" ? t("settings.saveParametersSaving", "Saving...") : "Saving...";
                    mainSaveBtn.innerText = savingText;
                }
                const resp = await fetch('/api/save_config', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(conf) });
                const res = await resp.json();
                if (res.status === 'success') {
                    addLog(t("console.kernelParamsSaved", "Kernel: Parameter persistent gespeichert."), "success", "console.kernelParamsSaved");
                    
                    if (mainSaveBtn) {
                        const okText = typeof t === "function" ? t("settings.saveParametersSuccess", "Saved successfully ✓") : "Saved successfully ✓";
                        mainSaveBtn.innerText = okText;
                        mainSaveBtn.style.color = "#4ade80";
                        setTimeout(() => {
                            mainSaveBtn.innerText = originalText || mainSaveBtn.innerText;
                            mainSaveBtn.style.color = originalColor || "";
                        }, 2000);
                    }

                    // Trigger re-load to update history potentially based on new path
                    loadData();
                } else {
                    addLog(t("console.saveErrorUnknown", "Fehler beim Speichern: ") + (res.message || "Unbekannt"), "error", "console.saveErrorUnknown");
                    if (mainSaveBtn) {
                        const errText = typeof t === "function" ? t("settings.saveParametersError", "Error while saving") : "Error while saving";
                        mainSaveBtn.innerText = errText;
                        mainSaveBtn.style.color = "#f87171";
                        setTimeout(() => {
                            mainSaveBtn.innerText = originalText || mainSaveBtn.innerText;
                            mainSaveBtn.style.color = originalColor || "";
                        }, 2000);
                    }
                }
            } catch (e) {
                addLog(t("console.saveCommError", "Kommunikationsfehler beim Speichern."), "error", "console.saveCommError");
                const mainSaveBtn = document.querySelector('button[data-i18n="settings.saveParametersButton"]');
                if (mainSaveBtn) {
                    const errText = typeof t === "function" ? t("settings.saveParametersError", "Error while saving") : "Error while saving";
                    mainSaveBtn.innerText = errText;
                    mainSaveBtn.style.color = "#f87171";
                    setTimeout(() => {
                        mainSaveBtn.innerText = "Save parameters persistently";
                        mainSaveBtn.style.color = "";
                    }, 2000);
                }
            }
        }

        async function testGithubConnection(btn) {
            // Guard: Prevent execution if disabled (already handled by UI, but good for safety)
            if(btn.disabled) return;
            
            const originalText = btn.innerText;
            btn.innerText = "Prüfe...";
            btn.disabled = true;
            
            const url = document.getElementById('config-github-url').value;
            const token = document.getElementById('config-github-token').value;
            
            try {
                const resp = await fetch('/api/test_github_connection', { 
                    method: 'POST', 
                    headers: {'Content-Type': 'application/json'}, 
                    body: JSON.stringify({ url, token }) 
                });
                const res = await resp.json();
                
                if(res.status === 'success') {
                    btn.innerText = "OK ✓";
                    btn.classList.add('text-green-400', 'border-green-500/30', 'bg-green-500/10');
                    // Explicit "Manual" prefix to avoid confusion with automated processes
                    addLog("Manueller GitHub Test: Verbindung erfolgreich.", "success");
                } else {
                    btn.innerText = "Fehler";
                    btn.classList.add('text-red-400', 'border-red-500/30', 'bg-red-500/10');
                    addLog("Manueller GitHub Test fehlgeschlagen: " + res.message, "error");
                }
            } catch(e) {
                btn.innerText = "Error";
                addLog("Netzwerkfehler beim GitHub Test.", "error");
            }
            
            setTimeout(() => {
                btn.innerText = originalText;
                btn.disabled = false;
                btn.classList.remove('text-green-400', 'border-green-500/30', 'bg-green-500/10', 'text-red-400', 'border-red-500/30', 'bg-red-500/10');
            }, 3000);
        }

        async function runGithubBackupNow(btn) {
            const originalText = btn.innerText;
            btn.innerText = "Starte...";
            btn.disabled = true;
            
            // Erst speichern wir die aktuelle Config, damit das Backend die neuesten Werte hat
            await saveProfile();
            
            try {
                const resp = await fetch('/api/run_github_backup_now', { method: 'POST' });
                const res = await resp.json();
                if(res.status === 'started') {
                    addLog("GitHub Backup Job gestartet.", "success");
                } else {
                    addLog("Fehler: " + res.message, "error");
                }
            } catch(e) {
                addLog("Fehler beim Starten des GitHub Backups.", "error");
            }
            
            setTimeout(() => {
                btn.innerText = originalText;
                btn.disabled = false;
            }, 3000);
        }

        async function stopScan() {
            const btn = document.getElementById('btn-cancel-scan');
            if(btn) btn.innerText = "Beende...";
            try { await fetch('/api/stop_scan', { method: 'POST' }); } catch(e) {}
        }

        async function scanDuplicates() {
            const btnStart = document.getElementById('btn-start-scan');
            const btnCancel = document.getElementById('btn-cancel-scan');

            // Priority: 1. Specific Scan Path, 2. Config Source Path
            const scanPath = document.getElementById('scan-path')?.value;
            const configSource = document.getElementById('config-source')?.value;
            const source = scanPath || configSource || document.getElementById('source')?.value;
            if(!source) {
                alert(t("dialog.selectSourcePathFirst", "Please select a source path first."));
                return;
            }

            // Toggle UI
            if(btnStart) btnStart.classList.add('hidden');
            if(btnCancel) {
                btnCancel.classList.remove('hidden');
                btnCancel.innerText = "Abbruch";
            }
            
            // Get Filters
            const minSize = document.getElementById('scan-min-size').value;
            const extType = document.getElementById('scan-extensions').value;
            let extensions = [];
            
            const extMap = {
                'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.raw', '.nef', '.cr2', '.webp', '.svg'],
                'videos': ['.mp4', '.mkv', '.mov', '.avi', '.wmv', '.flv', '.webm', '.m4v'],
                'docs': ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt', '.xls', '.xlsx', '.ppt', '.pptx'],
                'archives': ['.zip', '.rar', '.7z', '.tar', '.gz', '.iso']
            };
            
            if(extMap[extType]) extensions = extMap[extType];
            
            const container = document.getElementById('duplicate-results');
            if(container) container.innerHTML = `
                <div class="flex flex-col items-center justify-center h-64">
                    <div class="relative w-16 h-16 mb-6">
                        <div class="absolute inset-0 border-4 border-blue-500/20 rounded-full"></div>
                        <div class="absolute inset-0 border-4 border-t-blue-500 rounded-full animate-spin"></div>
                    </div>
                    <div class="text-blue-400 text-xs font-bold uppercase tracking-widest mb-4">Deep-Scan läuft...</div>
                    <div class="w-64 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div id="scan-progress-bar" class="h-full bg-blue-500 w-0 transition-all duration-300 shadow-[0_0_10px_rgba(59,130,246,0.5)]"></div>
                    </div>
                    <div id="scan-progress-text" class="text-[10px] text-slate-500 mt-3 font-mono">Initialisiere...</div>
                </div>
            `;
            
            const pollInterval = setInterval(async () => {
                try {
                    const r = await fetch('/api/scan_progress');
                    const s = await r.json();
                    const bar = document.getElementById('scan-progress-bar');
                    const txt = document.getElementById('scan-progress-text');
                    if(bar && txt && s.total > 0) {
                        const pct = Math.round((s.current / s.total) * 100);
                        bar.style.width = pct + "%";
                        txt.innerText = `${s.current} / ${s.total} (${pct}%)`;
                    }
                } catch(e) {}
            }, 500);

            try {
                const resp = await fetch('/api/find_duplicates', { 
                    method: 'POST', 
                    headers: {'Content-Type': 'application/json'}, 
                    body: JSON.stringify({
                        path: source,
                        min_size: minSize,
                        extensions: extensions
                    }) 
                });
                const data = await resp.json();
                clearInterval(pollInterval);

                // Restore UI
                if(btnStart) btnStart.classList.remove('hidden');
                if(btnCancel) btnCancel.classList.add('hidden');
                
                if(!container) return;

                if(data.status === 'aborted') {
                    container.innerHTML = '<div class="text-center py-20 opacity-50 italic text-sm text-red-400 border border-red-500/20 bg-red-500/5 rounded">Scan wurde manuell abgebrochen.</div>';
                    return;
                }

                if(data.length === 0) {
                    container.innerHTML = '<div class="text-center py-20 opacity-50 italic text-sm text-green-400">Keine Duplikate gefunden. Perfekte Effizienz!</div>';
                    return;
                }
                
                let totalWasted = 0;
                data.forEach(g => totalWasted += g.size * (g.files.length - 1));
                
                // Header with Auto-Select Actions
                let html = `
                <div class="bg-amber-500/10 border border-amber-500/20 p-4 rounded mb-6">
                    <div class="flex justify-between items-center mb-4">
                        <div>
                            <div class="text-amber-400 text-xs font-bold uppercase tracking-widest">Analyse Ergebnis</div>
                            <div class="text-white text-lg font-black mt-1">${formatSize(totalWasted)} <span class="text-xs text-slate-500 font-normal">verschwendet durch ${data.length} redundante Gruppen</span></div>
                        </div>
                        <button onclick="deleteSelectedDuplicates()" class="bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30 text-[10px] font-black uppercase tracking-widest px-4 py-2 rounded transition-all">
                            Markierte Löschen
                        </button>
                    </div>
                    
                    <div class="flex gap-2 border-t border-white/5 pt-3">
                        <span class="text-[10px] uppercase font-black text-slate-500 self-center mr-2">Auto-Select:</span>
                        <button onclick="autoSelectDuplicates('keep-newest')" class="bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 text-[10px] px-3 py-1 rounded transition-all">
                            Behalte Neueste (Lösche Alte)
                        </button>
                        <button onclick="autoSelectDuplicates('keep-oldest')" class="bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 text-[10px] px-3 py-1 rounded transition-all">
                            Behalte Älteste (Lösche Neue)
                        </button>
                    </div>
                </div>`;
                
                data.forEach((group, idx) => {
                    html += `<div class="bg-black/40 border border-white/5 rounded-lg p-4 mb-4 group-item" data-group-id="${idx}">
                        <div class="flex justify-between mb-2">
                            <div class="text-[10px] font-black uppercase text-slate-500">Gruppe #${idx+1} • ${formatSize(group.size)} pro Datei</div>
                            <div class="text-[9px] text-slate-600 font-mono">HASH MATCH</div> 
                        </div>
                        <div class="space-y-1">`;
                        
                    // Backend returns files sorted by mtime DESC (Newest first)
                    group.files.forEach((fObj, fIdx) => {
                        const f = fObj.path;
                        const mtimeDate = new Date(fObj.mtime * 1000).toLocaleString();
                        const isNewest = fIdx === 0; 
                        const isOldest = fIdx === group.files.length - 1;
                        
                        const id = 'dup-' + Math.random().toString(36).substr(2, 9);
                        const safePath = f.replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'");
                        const safeVal = f.replace(/"/g, '&quot;');
                        
                        let badge = "";
                        if(isNewest) badge += '<span class="text-[9px] bg-emerald-500/20 text-emerald-400 px-1 rounded ml-2">NEU</span>';
                        if(isOldest) badge += '<span class="text-[9px] bg-slate-500/20 text-slate-400 px-1 rounded ml-2">ALT</span>';

                        html += `<div class="flex items-center gap-3 bg-[#0a0b10] p-2 rounded border border-white/5 hover:border-white/10 transition-colors duplicate-row" data-mtime="${fObj.mtime}">
                            <input type="checkbox" id="${id}" value="${safeVal}" class="dup-check w-4 h-4 bg-slate-800 border-slate-600 rounded cursor-pointer">
                            <div class="flex-1 min-w-0">
                                <label for="${id}" class="text-[10px] mono text-slate-300 truncate block cursor-pointer select-none" title="${safeVal}">${f}</label>
                                <div class="text-[9px] text-slate-600 flex items-center">${mtimeDate} ${badge}</div>
                            </div>
                            <button onclick="deleteFile('${safePath}')" class="text-[9px] font-black uppercase text-slate-600 hover:text-red-500 transition-colors" title="Einzeln löschen">🗑️</button>
                        </div>`;
                    });
                    
                    html += `</div></div>`;
                });
                
                container.innerHTML = html;
                
            } catch(e) {
                clearInterval(pollInterval);
                console.error(e);
                // Restore UI on error
                const btnStart = document.getElementById('btn-start-scan');
                const btnCancel = document.getElementById('btn-cancel-scan');
                if(btnStart) btnStart.classList.remove('hidden');
                if(btnCancel) btnCancel.classList.add('hidden');

                if(container) container.innerHTML = '<div class="text-center py-10 text-red-500">Fehler bei der Analyse.</div>';
            }
        }
        
        function autoSelectDuplicates(mode) {
             const groups = document.querySelectorAll('.group-item');
             groups.forEach(g => {
                 const rows = Array.from(g.querySelectorAll('.duplicate-row'));
                 if(rows.length < 2) return;
                 
                 // Reset checks
                 rows.forEach(r => {
                     const cb = r.querySelector('.dup-check');
                     if(cb) cb.checked = false; 
                 });
                 
                 if(mode === 'keep-newest') {
                     // Check all EXCEPT the first (newest)
                     for(let i = 1; i < rows.length; i++) {
                         const cb = rows[i].querySelector('.dup-check');
                         if(cb) cb.checked = true;
                     }
                 } else if(mode === 'keep-oldest') {
                     // Check all EXCEPT the last (oldest)
                     for(let i = 0; i < rows.length - 1; i++) {
                          const cb = rows[i].querySelector('.dup-check');
                          if(cb) cb.checked = true;
                     }
                 }
             });
        }
        
        async function deleteFile(path) {
            if(!confirm(t("dialog.deleteFileConfirm", "Permanently delete file?") + "\\n" + path)) return;
            try {
                const resp = await fetch('/api/delete_file', { 
                    method: 'POST', 
                    headers: {'Content-Type': 'application/json'}, 
                    body: JSON.stringify({path}) 
                });
                const res = await resp.json();
                if(res.status === 'success') {
                    scanDuplicates(); 
                } else {
                    alert(t("dialog.deleteError", "Error: ") + res.message);
                }
            } catch(e) { alert(t("dialog.deleteFailed", "Deletion failed.")); }
        }
        
        async function deleteSelectedDuplicates() {
            const checked = document.querySelectorAll('.dup-check:checked');
            if(checked.length === 0) return alert(t("dialog.noFilesSelected", "No files selected."));
            
            if(!confirm(`${checked.length} Dateien unwiderruflich löschen?`)) return;
            
            let successCount = 0;
            for(let box of checked) {
                const path = box.value;
                try {
                     const resp = await fetch('/api/delete_file', { 
                        method: 'POST', 
                        headers: {'Content-Type': 'application/json'}, 
                        body: JSON.stringify({path}) 
                    });
                    if((await resp.json()).status === 'success') successCount++;
                } catch(e) {}
            }
            
            alert(t("dialog.filesDeleted", "{successCount} of {totalCount} files deleted.")
                .replace("{successCount}", successCount)
                .replace("{totalCount}", checked.length));
            scanDuplicates();
        }

        function copyHash() {
            const hash = document.getElementById('modal-hash').innerText;
            const el = document.createElement('textarea');
            el.value = hash; document.body.appendChild(el); el.select(); document.execCommand('copy'); document.body.removeChild(el);
            addLog(t("console.hashCopied", "System: Hash copied to clipboard."), "info");
        }

        function togglePassword(id, btn) {
            const input = document.getElementById(id);
            if(input.type === "password") {
                input.type = "text";
                btn.style.color = "#4ade80";
            } else {
                input.type = "password";
                btn.style.color = "";
            }
        }

        // --- Tasks Logic ---
        let tasks = [];
        let currentTaskId = null;

        async function loadTasks() {
            try {
                const resp = await fetch('/api/get_config');
                const config = await resp.json();
                tasks = config.tasks || [];
                renderTaskList();
            } catch(e) {
                console.error("Fehler beim Laden der Tasks:", e);
            }
        }

        function renderTaskList() {
            const container = document.getElementById('task-list-container');
            if(!container) return;
            container.innerHTML = '';
            
            if(tasks.length === 0) {
                container.innerHTML = '<div class="text-center py-10 opacity-30 italic text-[10px]" data-i18n="tasks.emptyPlaceholder">Keine Tasks vorhanden.</div>';
                if (window.BP_I18N_DICT) {
                    try { applyTranslations(window.BP_I18N_DICT); } catch(e) {}
                }
                return;
            }
            
            tasks.forEach(task => {
                const activeClass = task.id === currentTaskId ? 'bg-blue-600/20 border-blue-600/30' : 'bg-white/5 border-white/5 hover:bg-white/10';
                const statusDot = task.active 
                    ? '<div class="w-3 h-3 rounded-full bg-emerald-500 shadow-[0_0_10px_#10b981] border border-emerald-400" title="Status: Aktiv" data-i18n-title="tasks.statusActiveTitle"></div>' 
                    : '<div class="w-3 h-3 rounded-full bg-red-500 shadow-[0_0_10px_#ef4444] border border-red-400 opacity-80" title="Status: Deaktiviert" data-i18n-title="tasks.statusInactiveTitle"></div>';
                
                const html = `
                <div onclick="selectTask('${task.id}')" class="${activeClass} border rounded p-3 cursor-pointer transition-all group relative">
                    <div class="flex justify-between items-start mb-1">
                        <div class="font-bold text-xs truncate pr-2 text-slate-200">${task.name}</div>
                        <div class="text-[10px]">${statusDot}</div>
                    </div>
                    <div class="text-[9px] font-mono text-slate-500 truncate" title="${task.source}">${task.source || '<span data-i18n="tasks.noSourceLabel">Keine Quelle</span>'}</div>
                    <div class="text-[9px] font-mono text-slate-500 truncate" title="${task.dest}">➜ ${task.dest || '<span data-i18n="tasks.noTargetLabel">Kein Ziel</span>'}</div>
                    <div class="mt-2 flex justify-between items-end">
                        <div class="text-[9px] text-slate-500">${task.interval > 0 ? task.interval + ' min' : '<span data-i18n="tasks.manualIntervalLabel">Manuell</span>'}</div>
                        <div class="text-[9px] text-blue-400 opacity-0 group-hover:opacity-100 transition-opacity" data-i18n="tasks.editLabel">Bearbeiten</div>
                    </div>
                </div>`;
                container.insertAdjacentHTML('beforeend', html);
            });
            
            if (window.BP_I18N_DICT) {
                try { applyTranslations(window.BP_I18N_DICT); } catch(e) {}
            }
        }

        function selectTask(id) {
            currentTaskId = id;
            const task = tasks.find(t => t.id === id);
            if(!task) return;
            
            renderTaskList(); // Update active state
            
            document.getElementById('task-editor-empty').classList.add('hidden');
            const editor = document.getElementById('task-editor');
            editor.classList.remove('hidden');
            
            const lastRunText = task.last_run ? new Date(task.last_run * 1000).toLocaleString() : '';
            const lastRunPlaceholder = task.last_run ? '' : 'Nie';

            editor.innerHTML = `
                <div class="flex justify-between items-center border-b border-white/5 pb-4">
                    <h3 class="font-bold text-lg text-white" data-i18n="tasks.editorTitle">Task bearbeiten</h3>
                    <div class="flex gap-2">
                        <button onclick="runTaskNow()" class="bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold px-3 py-1.5 rounded transition-all" data-i18n="tasks.runNowButton">
                            ▶ Jetzt Starten
                        </button>
                        <button onclick="deleteCurrentTask()" class="bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 text-xs font-bold px-3 py-1.5 rounded transition-all" data-i18n="tasks.deleteButton">
                            Löschen
                        </button>
                    </div>
                </div>
                
                <div class="grid grid-cols-2 gap-4">
                    <div class="col-span-2">
                        <label class="block text-[10px] uppercase font-black text-slate-500 mb-1" data-i18n="tasks.nameLabel">Task Name</label>
                        <input type="text" id="task-name" value="${task.name}" class="w-full bg-black/20 border border-white/10 rounded px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none transition-colors">
                    </div>
                    
                    <div class="col-span-2">
                        <label class="block text-[10px] uppercase font-black text-slate-500 mb-1" data-i18n="tasks.activeLabel">Aktiv</label>
                        <div class="flex items-center gap-2">
                            <input type="checkbox" id="task-active" ${task.active ? 'checked' : ''} class="w-4 h-4 bg-slate-800 border-slate-600 rounded">
                            <label for="task-active" class="text-sm text-slate-300 select-none" data-i18n="tasks.autoBackupHelp">Automatisches Backup aktivieren</label>
                        </div>
                    </div>

                    <div class="col-span-2 space-y-1">
                        <label class="block text-[10px] uppercase font-black text-slate-500 mb-1" data-i18n="tasks.namingSuffixLabel">Namensgebung (Suffix)</label>
                        <div class="flex gap-4 p-2 bg-black/20 rounded border border-white/5">
                             <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
                                 <input type="checkbox" id="task-inc-date" ${(task.naming_include_date !== false) ? 'checked' : ''} class="w-3 h-3 bg-slate-800 border-slate-600 rounded"> <span data-i18n="settings.namingDateLabel">Datum</span>
                             </label>
                             <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
                                 <input type="checkbox" id="task-inc-time" ${(task.naming_include_time !== false) ? 'checked' : ''} class="w-3 h-3 bg-slate-800 border-slate-600 rounded"> <span data-i18n="settings.namingTimeLabel">Zeit</span>
                             </label>
                             <label class="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
                                 <input type="checkbox" id="task-inc-seq" ${task.naming_include_seq ? 'checked' : ''} class="w-3 h-3 bg-slate-800 border-slate-600 rounded"> <span data-i18n="settings.namingSeqLabel">Seq. Nr.</span>
                             </label>
                        </div>
                    </div>

                    <div>
                        <label class="block text-[10px] uppercase font-black text-slate-500 mb-1" data-i18n="tasks.intervalLabel">Intervall (Minuten)</label>
                        <input type="number" id="task-interval" value="${task.interval}" min="0" class="w-full bg-black/20 border border-white/10 rounded px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none transition-colors">
                        <div class="text-[9px] text-slate-600 mt-1" data-i18n="tasks.intervalManualHint">0 = Nur Manuell</div>
                    </div>
                    
                    <div>
                        <label class="block text-[10px] uppercase font-black text-slate-500 mb-1" data-i18n="tasks.lastRunLabel">Letzte Ausführung</label>
                        <input type="text" disabled value="${lastRunText}" placeholder="${lastRunPlaceholder}" class="w-full bg-black/10 border border-white/5 rounded px-3 py-2 text-sm text-slate-500 cursor-not-allowed" data-i18n-placeholder="tasks.lastRunNeverLabel">
                    </div>

                    <div class="col-span-2 relative group">
                         <label class="block text-[10px] uppercase font-black text-slate-500 mb-1" data-i18n="tasks.sourcePathLabel">Quell-Ordner / Datei</label>
                         <div class="flex gap-2">
                             <input type="text" id="task-source" value="${task.source}" class="flex-1 bg-black/20 border border-white/10 rounded px-3 py-2 text-sm text-slate-300 focus:border-blue-500 focus:outline-none font-mono">
                             <button onclick="selectTaskFile()" class="bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 px-2 rounded" title="Datei" data-i18n-title="tasks.singleFileTitle">📄</button>
                             <button onclick="selectTaskFiles()" class="bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 px-2 rounded" title="Mehrere Dateien" data-i18n-title="tasks.multiFileTitle">📑</button>
                             <button onclick="selectTaskSource()" class="bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 px-2 rounded" title="Ordner" data-i18n-title="tasks.folderTitle">📁</button>
                         </div>
                         <p class="text-[9px] text-slate-600 mt-1" data-i18n="tasks.tipPaths">Für mehrere Dateien Pfade mit | trennen.</p>
                     </div>

                     <div class="col-span-2 relative group">
                        <label class="block text-[10px] uppercase font-black text-slate-500 mb-1" data-i18n="tasks.targetPathLabel">Ziel-Ordner (Backup)</label>
                        <div class="flex gap-2">
                            <input type="text" id="task-dest" value="${task.dest}" class="flex-1 bg-black/20 border border-white/10 rounded px-3 py-2 text-sm text-slate-300 focus:border-blue-500 focus:outline-none font-mono">
                            <button onclick="selectTaskDest()" class="bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 px-3 rounded" title="Ordner wählen" data-i18n-title="duplicates.chooseFolderTitle">📂</button>
                        </div>
                    </div>
                </div>

                <div class="pt-4 border-t border-white/5 flex justify-end">
                    <button id="btn-save-task" onclick="saveCurrentTask()" class="bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 border border-emerald-500/30 text-xs font-bold uppercase tracking-widest px-6 py-2 rounded transition-all" data-i18n="tasks.saveButton">
                        Speichern
                    </button>
                </div>
            `;

            if (window.BP_I18N_DICT) {
                applyTranslations(window.BP_I18N_DICT);
            }
        }

        function createNewTask() {
            const newId = 'task_' + Date.now();
            let defaultName = 'Neuer Task';
            try {
                if (window.BP_I18N_DICT && window.BP_I18N_DICT["tasks.defaultName"]) {
                    defaultName = window.BP_I18N_DICT["tasks.defaultName"];
                } else if (typeof t === "function") {
                    defaultName = t("tasks.defaultName", defaultName);
                }
            } catch(e) {}
            const newTask = {
                id: newId,
                name: defaultName,
                source: '',
                dest: '',
                active: false,
                interval: 0,
                last_run: 0,
                naming_include_date: true,
                naming_include_time: true,
                naming_include_seq: false
            };
            tasks.push(newTask);
            selectTask(newId);
        }

        async function saveCurrentTask() {
            if(!currentTaskId) return;
            const task = tasks.find(t => t.id === currentTaskId);
            if(!task) return;
            
            // Visual Feedback: Start
            const btn = document.getElementById('btn-save-task');
            if(btn) {
                btn.innerText = "Speichert...";
                btn.disabled = true;
            }

            // Update values from DOM
            task.name = document.getElementById('task-name').value;
            task.active = document.getElementById('task-active').checked;
            task.interval = parseInt(document.getElementById('task-interval').value) || 0;
            task.source = document.getElementById('task-source').value;
            task.dest = document.getElementById('task-dest').value;
            
            // Save Naming Options
            task.naming_include_date = document.getElementById('task-inc-date').checked;
            task.naming_include_time = document.getElementById('task-inc-time').checked;
            task.naming_include_seq = document.getElementById('task-inc-seq').checked;
            
            try {
                const resp = await fetch('/api/get_config');
                const config = await resp.json();
                config.tasks = tasks;
                
                const saveResp = await fetch('/api/save_config', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(config)
                });
                
                const res = await saveResp.json();
                if(res.status === 'success') {
                    addLog("Task gespeichert.", "success");
                    renderTaskList();
                    
                    // Visual Feedback: Success
                    if(btn) {
                        btn.innerText = "Gespeichert!";
                        btn.classList.remove('bg-emerald-500/20', 'text-emerald-400');
                        btn.classList.add('bg-emerald-500', 'text-white');
                        
                        setTimeout(() => {
                            btn.innerText = "Speichern";
                            btn.classList.add('bg-emerald-500/20', 'text-emerald-400');
                            btn.classList.remove('bg-emerald-500', 'text-white');
                            btn.disabled = false;
                        }, 2000);
                    }
                } else {
                    addLog("Fehler beim Speichern.", "error");
                    // Visual Feedback: Error
                    if(btn) {
                         btn.innerText = "Fehler!";
                         btn.classList.add('bg-red-500', 'text-white');
                         setTimeout(() => {
                             btn.innerText = "Speichern";
                             btn.classList.remove('bg-red-500', 'text-white');
                             btn.disabled = false;
                         }, 2000);
                    }
                }
            } catch(e) {
                addLog("Fehler beim Speichern.", "error");
                // Visual Feedback: Error
                if(btn) {
                     btn.innerText = "Fehler!";
                     btn.classList.add('bg-red-500', 'text-white');
                     setTimeout(() => {
                         btn.innerText = "Speichern";
                         btn.classList.remove('bg-red-500', 'text-white');
                         btn.disabled = false;
                     }, 2000);
                }
            }
        }

        async function deleteCurrentTask() {
            if(!currentTaskId) return;
            if(!confirm(t("dialog.taskDeleteConfirm", "Really delete task?"))) return;
            
            tasks = tasks.filter(t => t.id !== currentTaskId);
            currentTaskId = null;
            
            document.getElementById('task-editor').classList.add('hidden');
            document.getElementById('task-editor-empty').classList.remove('hidden');
            
            // Persist deletion
            try {
                const resp = await fetch('/api/get_config');
                const config = await resp.json();
                config.tasks = tasks;
                
                await fetch('/api/save_config', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(config)
                });
                renderTaskList();
                addLog(t("console.taskDeleted", "Task deleted."), "success");
            } catch(e) {
                addLog(t("console.deleteError", "Error while deleting."), "error");
            }
        }

        async function runTaskNow() {
            if(!currentTaskId) return;
            const task = tasks.find(t => t.id === currentTaskId);
            if(!task) return;
            
            if(!task.source || !task.dest) {
                alert("Bitte Source und Target angeben.");
                return;
            }

            // Update Last Run & Save
            task.last_run = Math.floor(Date.now() / 1000);
            await saveCurrentTask();

            addLog(`Starte Task: ${task.name}...`, "info");
            
            // Prepare Task Options
            const taskOpts = {
                naming_include_date: (task.naming_include_date !== undefined) ? task.naming_include_date : true,
                naming_include_time: (task.naming_include_time !== undefined) ? task.naming_include_time : true,
                naming_include_seq: (task.naming_include_seq !== undefined) ? task.naming_include_seq : false
            };

            try {
                const resp = await fetch('/api/start_backup', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        source: task.source,
                        dest: task.dest,
                        comment: `Manual Task: ${task.name}`,
                        task_options: taskOpts
                    })
                });
                const res = await resp.json();
                if(res.status === 'started') {
                    switchTab('dashboard');
                } else {
                    addLog("Konnte Task nicht starten: " + res.message, "error");
                }
            } catch(e) {
                addLog("Fehler beim Starten.", "error");
            }
        }

        async function selectTaskFile() {
            const resp = await fetch('/api/pick_file');
            const data = await resp.json();
            if(data.path) document.getElementById('task-source').value = data.path;
        }

        async function selectTaskFiles() {
            const resp = await fetch('/api/pick_files');
            const data = await resp.json();
            if(data.path) document.getElementById('task-source').value = data.path;
        }

        async function selectTaskSource() {
            const resp = await fetch('/api/pick_folder');
            const data = await resp.json();
            if(data.path) {
                document.getElementById('task-source').value = data.path;
            }
        }

        async function selectTaskDest() {
            const resp = await fetch('/api/pick_folder');
            const data = await resp.json();
            if(data.path) {
                document.getElementById('task-dest').value = data.path;
            }
        }

        let isBackupActive = false;

        // --- SSE & Status Management (Replaces Polling) ---
        let eventSource = null;
        let sseRetryCount = 0;
        // const maxSseRetries = 5; // Infinite retry now

        function setupSSE() {
            if(eventSource) eventSource.close();

            console.log("Connecting to SSE stream...");
            eventSource = new EventSource('/api/stream');

            eventSource.onopen = () => {
                console.log("SSE Connected.");
                sseRetryCount = 0;
                // Clear potential reconnect warning if it was the last message
                const log = document.getElementById('log');
                if(log && log.lastChild && log.lastChild.innerText.includes("Reconnect")) {
                    addLog(t("console.connectionRestored", "Connection restored."), "success");
                }
            };

            eventSource.addEventListener('status', (e) => {
                try {
                    lastHeartbeat = Date.now(); // Reset heartbeat
                    const data = JSON.parse(e.data);
                    
                    if(data.log_entry) {
                         // Fallback for combined status+log packets
                         addLog(data.log_entry.replace(/\[.*?\] /, ""), "info"); 
                    }
                    
                    updateStatusUI(data);
                } catch(err) { console.error("SSE Status Parse Error:", err); }
            });

            eventSource.addEventListener('log', (e) => {
                try {
                    lastHeartbeat = Date.now(); // Reset heartbeat
                    const data = JSON.parse(e.data);
                    
                    // Use key for dynamic translation if available
                    if (data.key) {
                        addLog(t(data.key, data.message), data.type, data.key);
                    } else {
                        addLog(t(data.message, data.message), data.type);
                    }

                    // Check for completion messages to trigger reload if needed
                    if (data.message && (data.message.includes("beendet") || data.message.includes("gespeichert"))) {
                        loadData();
                    }
                } catch(err) { console.error("SSE Log Parse Error:", err); }
            });
            
            eventSource.onmessage = (e) => {
                 // Catch keepalives
                 lastHeartbeat = Date.now();
            };

            eventSource.onerror = (err) => {
                // console.error("SSE Error:", err); // Suppress red error log
                if(eventSource) {
                    eventSource.close();
                    eventSource = null;
                }
                
                // Retry Logic (Infinite with backoff cap)
                sseRetryCount++;
                const delay = Math.min(1000 * (2 ** sseRetryCount), 30000); // Max 30s delay
                console.log(`Retrying SSE in ${delay}ms (Attempt ${sseRetryCount})...`);
                
                // Visual feedback if disconnected for too long (but don't spam)
                if(sseRetryCount > 2) {
                     const log = document.getElementById('log');
                     // Simple check to avoid spamming the log
                     if(log && log.lastChild && !log.lastChild.innerText.includes("Reconnect")) {
                         addLog(t("console.connectionLost", "Connection lost. Reconnect in ") + (delay/1000) + "s...", "warn");
                     }
                }
                
                setTimeout(setupSSE, delay);
            };
        }
        
        // Heartbeat Monitor (Fallback if SSE hangs silently)
        let lastHeartbeat = Date.now();
        setInterval(() => {
            // Check if backup is theoretically active but we haven't heard anything
            if(isBackupActive && (Date.now() - lastHeartbeat > 20000)) { // 20s without message during backup
                 console.warn("SSE Heartbeat missing during backup. Force Reconnecting...");
                 lastHeartbeat = Date.now();
                 setupSSE();
            } else if (!isBackupActive && (Date.now() - lastHeartbeat > 45000)) { // 45s idle
                 // Less aggressive when idle
                 console.warn("SSE Heartbeat missing (idle). Reconnecting...");
                 lastHeartbeat = Date.now();
                 setupSSE();
            }
        }, 5000);

        function updateStatusUI(sData) {
            // --- Module Status Helper ---
            const updateModule = (modName, msg, pct, err) => {
                const area = document.getElementById(`status-area-${modName}`);
                if(area) {
                    area.classList.remove('hidden');
                    const waitLabel = t("console.statusWaiting", "Waiting...");
                    document.getElementById(`status-msg-${modName}`).innerText = msg || waitLabel;
                    document.getElementById(`status-pct-${modName}`).innerText = (pct || 0) + "%";
                    document.getElementById(`status-bar-${modName}`).style.width = (pct || 0) + "%";
                    
                    const errDiv = document.getElementById(`status-err-${modName}`);
                    if(err && err.includes("Fehler")) {
                        errDiv.innerText = err;
                        errDiv.classList.remove('hidden');
                    } else {
                        errDiv.classList.add('hidden');
                    }
                }
            };

            const ind = document.getElementById('status-indicator');
            const txt = document.getElementById('console-status-text');

            if (sData.active) {
                isBackupActive = true;
                
                // Update Progress (nur setzen, wenn gültiger Wert vorhanden ist)
                const bar = document.getElementById('zipBar');
                const pctEl = document.getElementById('zipPercent');
                if (typeof sData.progress === "number" && !isNaN(sData.progress)) {
                    const pctVal = sData.progress;
                    if (bar) bar.style.width = pctVal + "%";
                    if (pctEl) pctEl.innerText = pctVal + "%";
                }
                
                // Update Console Status
                if(ind) ind.className = "w-2 h-2 rounded-full bg-blue-500 animate-pulse transition-colors duration-300";
                if(txt) {
                    const runningLabel = t("console.statusBackupRunning", "BACKUP RUNNING...");
                    txt.innerText = sData.message ? sData.message.substring(0, 40) : runningLabel;
                    txt.className = "text-[10px] font-black uppercase tracking-widest text-blue-400";
                }
                
                // Update specific module status based on step
                const step = sData.step || "";
                const msg = sData.message || "";
                const pct = sData.progress || 0;
                
                if (step.includes('github')) {
                    updateModule('github', msg, pct, msg.includes("Fehler") ? msg : null);
                } else if (step.includes('database')) {
                    updateModule('db', msg, pct, msg.includes("Fehler") ? msg : null);
                } else if (step.includes('cloud')) {
                    updateModule('cloud-tresor', msg, pct, msg.includes("Fehler") ? msg : null);
                }
                
            } else if (isBackupActive && !sData.active) {
                // Backup gerade beendet - 100% anzeigen
                document.getElementById('zipBar').style.width = "100%";
                document.getElementById('zipPercent').innerText = "100%";
                
                // Update Console Status - Success
                if(ind) ind.className = "w-2 h-2 rounded-full bg-green-500 transition-colors duration-300";
                if(txt) {
                    txt.innerText = t("console.statusDone", "COMPLETED");
                    txt.className = "text-[10px] font-black uppercase tracking-widest text-green-400";
                }
                
                // Update modules to 100% / Done before hiding
                ['github', 'db', 'cloud-tresor'].forEach(m => {
                    const area = document.getElementById(`status-area-${m}`);
                    if(area && !area.classList.contains('hidden')) {
                        document.getElementById(`status-pct-${m}`).innerText = "100%";
                        document.getElementById(`status-bar-${m}`).style.width = "100%";
                        document.getElementById(`status-msg-${m}`).innerText = "Fertig.";
                    }
                });
                
                setTimeout(() => {
                    isBackupActive = false;
                    
                    // Reset Status to Idle
                    if(ind) ind.className = "w-2 h-2 rounded-full bg-slate-600 transition-colors duration-300";
                    if(txt) {
                        txt.innerText = t("console.statusReady", "SYSTEM READY");
                        txt.className = "text-[10px] font-black uppercase tracking-widest text-slate-400";
                    }
                    
                    // Reset Bar
                    document.getElementById('zipBar').style.width = "0%";
                    document.getElementById('zipPercent').innerText = "0%";
                    
                    // Hide module status areas
                    ['github', 'db', 'cloud-tresor'].forEach(m => {
                        const area = document.getElementById(`status-area-${m}`);
                        if(area) area.classList.add('hidden');
                    });
                    
                    loadData(); // Sicherstellen dass Tabelle aktuell ist
                }, 2000);
            }
        }

        async function globalPoll() {
            return; // DEPRECATED: Replaced by SSE logic (setupSSE)
            try {
                // 1. Events Polling
                const eResp = await fetch('/api/get_events');
                if (eResp.ok) {
                    const events = await eResp.json();
                    events.forEach(e => addLog(e.message, e.type));
                    // Wenn Events da waren, ggf. Daten aktualisieren (z.B. nach Backup)
                    if (events.length > 0 && events.some(e => e.message.includes("beendet") || e.message.includes("gespeichert"))) {
                         loadData(); 
                    }
                }

                // 2. Status Polling
                const sResp = await fetch('/api/get_backup_status');
                if (sResp.ok) {
                    const sData = await sResp.json();
                    
                    updateStatusUI(sData);
                    /*
                    // --- Module Status Helper ---
                    const updateModule = (modName, msg, pct, err) => {
                        const area = document.getElementById(`status-area-${modName}`);
                        if(area) {
                            area.classList.remove('hidden');
                            document.getElementById(`status-msg-${modName}`).innerText = msg || "Warte...";
                            document.getElementById(`status-pct-${modName}`).innerText = (pct || 0) + "%";
                            document.getElementById(`status-bar-${modName}`).style.width = (pct || 0) + "%";
                            
                            const errDiv = document.getElementById(`status-err-${modName}`);
                            if(err && err.includes("Fehler")) {
                                errDiv.innerText = err;
                                errDiv.classList.remove('hidden');
                            } else {
                                errDiv.classList.add('hidden');
                            }
                        }
                    };

                    if (sData.active) {
                        isBackupActive = true;
                        // document.getElementById('zipProgressArea').classList.remove('hidden');
                        // document.getElementById('cancel-btn').classList.remove('hidden');
                        document.getElementById('zipBar').style.width = sData.progress + "%";
                        document.getElementById('zipPercent').innerText = sData.progress + "%";
                        
                        // Update specific module status based on step
                        const step = sData.step || "";
                        const msg = sData.message || "";
                        const pct = sData.progress || 0;
                        
                        if (step.includes('github')) {
                            updateModule('github', msg, pct, msg.includes("Fehler") ? msg : null);
                        } else if (step.includes('database')) {
                            updateModule('db', msg, pct, msg.includes("Fehler") ? msg : null);
                        } else if (step.includes('cloud')) {
                            updateModule('cloud-tresor', msg, pct, msg.includes("Fehler") ? msg : null);
                        }
                        
                    } else if (isBackupActive && !sData.active) {
                        // Backup gerade beendet - 100% anzeigen
                        document.getElementById('zipBar').style.width = "100%";
                        document.getElementById('zipPercent').innerText = "100%";
                        
                        // Update modules to 100% / Done before hiding
                         ['github', 'db', 'cloud-tresor'].forEach(m => {
                            const area = document.getElementById(`status-area-${m}`);
                            if(area && !area.classList.contains('hidden')) {
                                document.getElementById(`status-pct-${m}`).innerText = "100%";
                                document.getElementById(`status-bar-${m}`).style.width = "100%";
                                document.getElementById(`status-msg-${m}`).innerText = "Fertig.";
                            }
                        });
                        
                        setTimeout(() => {
                            isBackupActive = false;
                            // document.getElementById('zipProgressArea').classList.add('hidden');
                            // document.getElementById('cancel-btn').classList.add('hidden');
                            
                            // Hide module status areas
                            ['github', 'db', 'cloud-tresor'].forEach(m => {
                                const area = document.getElementById(`status-area-${m}`);
                                if(area) area.classList.add('hidden');
                            });
                            
                            loadData(); // Sicherstellen dass Tabelle aktuell ist
                        }, 2000);
                    }
                    */
                }
            } catch(e) { console.error("Global Poll Error", e); }
            
            setTimeout(globalPoll, 2000); // 2 Sekunden Intervall
        }

        // --- Startup Check ---
        
        async function initStartupCheck() {
            try {
                const resp = await fetch('/api/get_startup_tasks');
                const data = await resp.json();
                
                if(data.tasks && data.tasks.length > 0) {
                    showStartupModal(data.tasks);
                }
            } catch(e) { console.error("Startup Check Error:", e); }
        }
        
        function showStartupModal(tasks) {
            const listHtml = tasks.map(t => `<li class="text-blue-400 font-bold">• ${t}</li>`).join('');
            const modalHtml = `
            <div id="startup-modal" class="fixed inset-0 z-[60] flex items-center justify-center bg-black/80 backdrop-blur-sm">
                <div class="bg-[#0f111a] border border-blue-500/30 rounded-2xl w-[500px] shadow-[0_0_50px_rgba(59,130,246,0.2)] overflow-hidden animate-bounce-in">
                    <div class="bg-gradient-to-r from-blue-900/20 to-transparent p-6 border-b border-white/5">
                        <h3 class="text-xl font-black text-white flex items-center gap-3">
                            <span class="text-2xl">🚀</span>
                            AUTO-TASKS ERKANNT
                        </h3>
                    </div>
                    <div class="p-8">
                        <p class="text-slate-300 mb-4 text-sm leading-relaxed">
                            Es wurden <strong class="text-white">${tasks.length} aktive Tasks</strong> gefunden, die automatisch ausgeführt werden sollen.
                        </p>
                        <div class="bg-[#08090d] rounded-lg p-4 border border-white/5 mb-6 max-h-40 overflow-y-auto custom-scrollbar">
                            <ul class="space-y-2 text-xs font-mono">
                                ${listHtml}
                            </ul>
                        </div>
                        <p class="text-slate-400 text-xs italic mb-8">
                            Möchten Sie diese Backups jetzt sofort starten?
                        </p>
                        
                        <div class="flex gap-4">
                            <button onclick="runStartupTasks()" class="flex-1 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 text-white font-bold py-3 px-4 rounded-lg shadow-lg shadow-blue-500/20 transition-all text-sm uppercase tracking-wider flex justify-center items-center gap-2">
                                <span>Starten</span>
                                <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                            </button>
                            <button onclick="closeStartupModal()" class="flex-1 bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white font-bold py-3 px-4 rounded-lg border border-white/5 transition-all text-sm uppercase tracking-wider">
                                Nein, später
                            </button>
                        </div>
                    </div>
                </div>
            </div>
            `;
            
            document.body.insertAdjacentHTML('beforeend', modalHtml);
        }
        
        async function runStartupTasks() {
            closeStartupModal();
            addLog("Starte automatische Tasks...", "info");
            try {
                const resp = await fetch('/api/run_startup_tasks', { method: 'POST' });
                const data = await resp.json();
                if(data.status === 'started') {
                    addLog("Startup-Tasks initiiert.", "success");
                }
            } catch(e) {
                addLog("Fehler beim Starten der Tasks.", "error");
            }
        }
        
        function closeStartupModal() {
            const m = document.getElementById('startup-modal');
            if(m) m.remove();
        }

        function applyTheme(theme) {
            const root = document.getElementById('bp-root');
            if(!root) return;
            const icon = document.getElementById('theme-icon');
            const label = document.getElementById('theme-label');
            if(theme === 'light') {
                root.classList.add('theme-light');
                if(icon) icon.innerText = '☀️';
                if(label) label.innerText = 'Light';
            } else {
                root.classList.remove('theme-light');
                if(icon) icon.innerText = '🌙';
                if(label) label.innerText = 'Dark';
            }
            try { localStorage.setItem('bp_theme', theme); } catch(e) {}
            try { renderActivityChart(); } catch(e) {}
        }

        function toggleTheme() {
            const root = document.getElementById('bp-root');
            if(!root) return;
            const isLight = root.classList.contains('theme-light');
            applyTheme(isLight ? 'dark' : 'light');
        }

        function t(key, fallback) {
            const dict = window.BP_I18N_DICT || null;
            if (dict && Object.prototype.hasOwnProperty.call(dict, key)) {
                return dict[key];
            }
            return fallback !== undefined ? fallback : key;
        }

        async function initLanguage() {
            const lang = window.BP_LANG || 'de';
            try {
                const resp = await fetch(`/api/lang?code=${encodeURIComponent(lang)}`);
                if (!resp.ok) return;
                const dict = await resp.json();
                window.BP_I18N_DICT = dict;
                applyTranslations(dict);
            } catch(e) {
                console.error("Language init failed:", e);
            }
        }

        function applyTranslations(dict) {
            if (!dict) return;
            // Content
            const nodes = document.querySelectorAll('[data-i18n]');
            nodes.forEach(el => {
                const key = el.getAttribute('data-i18n');
                if (!key || !(key in dict)) return;
                const val = dict[key];
                if (typeof val !== 'string') return;
                if (val.indexOf('<') !== -1) {
                    el.innerHTML = val;
                } else {
                    el.textContent = val;
                }
            });
            // Placeholders
            const placeholders = document.querySelectorAll('[data-i18n-placeholder]');
            placeholders.forEach(el => {
                const key = el.getAttribute('data-i18n-placeholder');
                if (key && (key in dict)) {
                    el.setAttribute('placeholder', dict[key]);
                }
            });
            // Titles
            const titles = document.querySelectorAll('[data-i18n-title]');
            titles.forEach(el => {
                const key = el.getAttribute('data-i18n-title');
                if (key && (key in dict)) {
                    el.setAttribute('title', dict[key]);
                }
            });
        }

        window.addEventListener('beforeunload', function (e) {
            if(isBackupActive) {
                e.preventDefault();
                e.returnValue = ''; // Standard for Chrome
            }
        });
        
        window.onload = async () => { 
            console.log("Window loaded. Initializing...");
            await initLanguage();
            addLog(t("console.terminalReady", "Terminal initialisiert. System bereit."), "success", "console.terminalReady");

            let storedTheme = 'dark';
            try {
                const t = localStorage.getItem('bp_theme');
                if(t === 'light' || t === 'dark') storedTheme = t;
            } catch(e) {}
            applyTheme(storedTheme);


            // Restore History Limit immediately
            // currentLimit is already set globally

            // Prevent accidental reload if backup is active (Old method cleanup)
            // window.onbeforeunload handled via addEventListener above
            
            // Add click listener to Limit Dropdown to ensure focus
            const limitSel = document.getElementById('history-limit');
            if(limitSel) {
                limitSel.addEventListener('change', window.updateHistoryLimit);
                // Sync UI with global currentLimit immediately
                limitSel.value = (currentLimit === 999999) ? 'all' : currentLimit;
            }
            
            // Attach listeners to cloud tresor inputs for real-time badge update
            const cloudTresorInputs = document.querySelectorAll('#module-cloud-tresor input, #module-cloud-tresor select');
            cloudTresorInputs.forEach(el => {
                el.addEventListener('input', updateCloudTresorUI);
                el.addEventListener('change', updateCloudTresorUI);
            });

            const langBtn = document.getElementById('config-language-button');
            if (langBtn) {
                langBtn.addEventListener('click', async () => {
                    const current = window.BP_LANG || 'de';
                    const next = current === 'de' ? 'en' : 'de';
                    window.BP_LANG = next;
                    try {
                        const resp = await fetch(`/api/lang?code=${encodeURIComponent(next)}`);
                        if (resp.ok) {
                            const dict = await resp.json();
                            window.BP_I18N_DICT = dict;
                            applyTranslations(dict);
                        }
                    } catch(e) {
                        console.error("Language toggle failed:", e);
                    }
                });
            }

            // Load data first to ensure loader is removed even if Chart fails
            setTimeout(() => {
                try { loadData(); } catch(e) { console.error("LoadData failed:", e); }
                try { loadTasks(); } catch(e) { console.error("LoadTasks failed:", e); }
                
                // Start SSE Connection
                setupSSE();

                // Startup Check Delayed (6s)
                setTimeout(initStartupCheck, 6000);
            }, 100);
            
            // Init chart separately
            try { initChart(); } catch(e) { console.error("Chart Init failed:", e); }
        };
    </script>
</body>
</html>
"""

# --- Flask API Endpunkte ---

@app.route("/favicon.ico")
def custom_favicon():
    """Serviert ein benutzerdefiniertes Icon (logo.ico/png) oder das Standard-Icon."""
    # Priorität 1: static/favicon.ico (Download)
    static_icon = os.path.join(BASE_DIR, 'static', 'favicon.ico')
    if os.path.exists(static_icon):
        return send_file(static_icon, mimetype='image/vnd.microsoft.icon')

    # Priorität 2: Lokale Dateien im Root
    possible_icons = ["logo.ico", "logo.png", "favicon.ico"]
    for icon in possible_icons:
        if os.path.exists(icon):
            return send_file(icon)
    
    # Fallback: Standard SVG als Response
    svg_icon = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🛡️</text></svg>"""
    return Response(svg_icon, mimetype='image/svg+xml')

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE, lang=get_current_language())

@app.route("/api/lang")
def get_language():
    global CURRENT_LANG
    code = (request.args.get("code") or DEFAULT_LANG).lower()
    if code not in ("de", "en"):
        code = DEFAULT_LANG
    CURRENT_LANG = code
    
    # Persist language preference
    try:
        cfg = load_config()
        if cfg.get("language") != code:
            cfg["language"] = code
            save_config(cfg)
    except Exception as e:
        logger.error(f"Failed to save language preference: {e}")

    try:
        path = os.path.join(I18N_DIR, f"lang_{code}.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return jsonify(data)
    except Exception as e:
        logger.error(f"Language load error: {e}")
    return jsonify({})

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
    
    # SQLite History laden
    history = get_history_from_db()
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
    
    # Encrypt sensitive fields before saving
    to_save = current.copy()
    sensitive = ["cloud_password", "cloud_api_key", "encryption_password"]
    for field in sensitive:
        if field in to_save:
            to_save[field] = encrypt_value(to_save[field])

    if safe_write_json(CONFIG_FILE, to_save):
        return jsonify({"status": "success"})
    return jsonify({"status": "error"})

@app.route("/api/toggle_lock", methods=["POST"])
def toggle_lock():
    try:
        data = request.json
        filename = data.get("filename")
        
        success, new_state = toggle_lock_in_db(filename)
        
        if success:
            return jsonify({"status": "success", "locked": new_state})
        return jsonify({"status": "error", "message": "Eintrag nicht gefunden oder DB Fehler"})
    except Exception as e:
        logger.error(f"Lock Error: {e}")
        return jsonify({"status": "error", "message": str(e)})

@app.route("/api/update_comment", methods=["POST"])
def update_comment():
    try:
        data = request.json
        filename = data.get("filename")
        comment = data.get("comment", "")
        
        if update_history_comment_in_db(filename, comment):
            return jsonify({"status": "success"})
                
        return jsonify({"status": "error", "message": "Eintrag nicht gefunden oder DB Fehler"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/api/get_zip_content", methods=["POST"])
def get_zip_content():
    try:
        filename = request.json.get("filename")
        
        # Pfad aus Historie ermitteln (analog zu verify_integrity)
        history = get_history_from_db()
        entry = next((h for h in history if h['filename'] == filename), None)
        
        full_path = None
        if entry and entry.get("path") and os.path.exists(entry["path"]):
             full_path = entry["path"]
        else:
             # Fallback auf Standard-Ordner
             config = load_config()
             dest_path = config.get("default_dest")
             if dest_path:
                 full_path = os.path.join(dest_path, filename)
        
        if not full_path or not os.path.exists(full_path): 
            return jsonify({"files": ["Datei nicht gefunden"]})
        
        file_list = []
        # Lazy Load pyzipper falls nötig (verschlüsselt) oder standard zipfile
        # Wir versuchen erst Standard Zipfile für Speed
        try:
            with zipfile.ZipFile(full_path, 'r') as z:
                # Limit auf 1000 Dateien für Performance
                file_list = z.namelist()[:1000] 
                if len(z.namelist()) > 1000:
                    file_list.append(f"... und {len(z.namelist()) - 1000} weitere")
        except RuntimeError: # Passwort geschützt?
             # Wenn Encrypted Header, brauchen wir pyzipper aber wir haben kein PW hier
             # Für reines Listing ohne Decrypt kann zipfile manchmal funktionieren, aber oft nicht bei AES
             # Wir geben einen Hinweis zurück
             return jsonify({"files": ["(Verschlüsseltes Archiv - Inhalt verborgen)"]})
        except Exception as e:
             return jsonify({"files": [f"Fehler beim Lesen: {str(e)}"]})
             
        return jsonify({"files": file_list})
    except Exception as e:
        logger.error(f"Content Error: {e}")
        return jsonify({"files": []})

@app.route("/api/verify_integrity", methods=["POST"])
def verify_integrity():
    try:
        filename = request.json.get("filename")
        config = load_config()
        dest_path = config.get("default_dest")
        
        history = get_history_from_db()
        entry = next((h for h in history if h['filename'] == filename), None)
        
        if not entry: return jsonify({"status": "error", "message": "Historie Eintrag fehlt"})
        
        full_path = None
        if entry.get("path") and os.path.exists(entry["path"]):
             full_path = entry["path"]
        else:
             full_path = os.path.join(dest_path, filename)

        if not os.path.exists(full_path):
             return jsonify({"status": "error", "message": "Datei nicht gefunden"})

        stored_hash = entry.get('sha256')
        
        # Detect Algorithm from stored hash format
        algo = "sha256"
        if stored_hash and stored_hash.startswith("blake2b:"):
            algo = "blake2b"

        salt = entry['timestamp']
        current_hash = calculate_hash(full_path, salt=salt, algorithm=algo)
        
        if current_hash == stored_hash:
             return jsonify({"status": "success", "message": "Integrität bestätigt (Bit-Perfect)."})
        else:
             return jsonify({"status": "mismatch", "message": "WARNUNG: Hash-Abweichung erkannt!"})
             
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/api/pick_files")
def pick_files():
    """Öffnet den Multi-Datei-Dialog (Windows native)."""
    try:
        import tkinter as tk # Lazy Load
        from tkinter import filedialog # Lazy Load
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
        import tkinter as tk # Lazy Load
        from tkinter import filedialog # Lazy Load
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
        import tkinter as tk # Lazy Load
        from tkinter import filedialog # Lazy Load
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
    """Analysiert das Quellverzeichnis auf Größe und Dateianzahl (Parallelisiert)."""
    path = request.json.get("path", "")
    
    if not path:
        return jsonify({"size": 0, "count": 0})
        
    config = load_config()
    exclusions = config.get("exclusions", [])
    
    total_size = 0
    total_count = 0
    
    def scan_item(p):
        """Scans a single path (file or folder) and returns (size, count)."""
        s, c = 0, 0
        if not os.path.exists(p): return (0, 0)
        
        if os.path.isfile(p):
             if is_excluded(os.path.basename(p), exclusions): return (0, 0)
             try: return (os.path.getsize(p), 1)
             except: return (0, 0)
             
        # Directory
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if not is_excluded(d, exclusions)]
            for f in files:
                if not is_excluded(f, exclusions):
                    c += 1
                    try: s += os.path.getsize(os.path.join(root, f))
                    except: pass
        return (s, c)

    # Determine paths to scan
    scan_targets = []
    
    if "|" in path:
        scan_targets = [f.strip() for f in path.split("|") if f.strip()]
    elif os.path.isfile(path):
        scan_targets = [path]
    else:
        # Single Directory: Split into sub-items for parallelism
        try:
            # Add files in root
            root_files_size = 0
            root_files_count = 0
            # Use scandir for fast iteration
            with os.scandir(path) as it:
                for entry in it:
                    if entry.is_file():
                        if not is_excluded(entry.name, exclusions):
                            root_files_count += 1
                            try: root_files_size += entry.stat().st_size
                            except: pass
                    elif entry.is_dir():
                        if not is_excluded(entry.name, exclusions):
                            scan_targets.append(entry.path)
            
            # Add root files result immediately
            total_size += root_files_size
            total_count += root_files_count
            
        except Exception as e:
            logger.error(f"Error splitting path {path}: {e}")
            scan_targets = [path] # Fallback to single path

    # Parallel execution
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = executor.map(scan_item, scan_targets)
            for s, c in results:
                total_size += s
                total_count += c
    except Exception as e:
        logger.error(f"Analyze Source Error: {e}")
        # Fallback
        for p in scan_targets:
            s, c = scan_item(p)
            total_size += s
            total_count += c

    return jsonify({"size": total_size, "count": total_count})

@app.route("/api/test_github_connection", methods=["POST"])
def test_github_connection():
    data = request.json
    url = data.get("url")
    token = data.get("token")
    
    logger.info("API: test_github_connection aufgerufen.")
    
    if not url:
        return jsonify({"status": "error", "message": "URL fehlt."})
        
    auth_url = url
    if token:
        if "https://" in url:
            auth_url = url.replace("https://", f"https://{token}@")
        else:
            auth_url = f"https://{token}@{url}"
            
    try:
        # git ls-remote ist ein guter Test ohne Download
        subprocess.run(["git", "ls-remote", auth_url], check=True, capture_output=True)
        return jsonify({"status": "success", "message": "GitHub-Verbindung (Backend) erfolgreich."})
    except subprocess.CalledProcessError as e:
        logger.warning(f"GitHub Test fehlgeschlagen: {e}")
        return jsonify({"status": "error", "message": "Verbindung fehlgeschlagen."})
    except Exception as e:
        logger.error(f"GitHub Test Error: {e}")
        return jsonify({"status": "error", "message": str(e)})

@app.route("/api/run_github_backup_now", methods=["POST"])
def run_github_backup_now():
    config = load_config()
    dest = config.get("default_dest")
    if not dest:
        return jsonify({"status": "error", "message": "Kein Zielpfad konfiguriert."})
    
    if current_job_status["active"]:
        return jsonify({"status": "error", "message": "Ein Backup-Prozess läuft bereits."})

    # Da wir dies asynchron machen wollen, starten wir einen Thread
    def _worker():
        global current_job_status
        with backup_lock:
            current_job_status["active"] = True
            current_job_status["progress"] = 10
            current_job_status["step"] = "github"
            current_job_status["message"] = "Starte GitHub Backup..."
            
            try:
                run_github_sync(config, dest, job_status_update=True)
            except Exception as e:
                logger.error(f"GitHub Worker Error: {e}")
                add_event(f"GitHub Fehler: {e}", "error")
                current_job_status["message"] = f"Fehler: {str(e)}"
            finally:
                current_job_status["active"] = False
                current_job_status["progress"] = 100
                add_event("GitHub Backup beendet.", "info")
        
    threading.Thread(target=_worker, daemon=True).start()
    
    return jsonify({"status": "started", "message": "GitHub Backup gestartet."})

@app.route("/api/run_db_backup_now", methods=["POST"])
def run_db_backup_now():
    config = load_config()
    dest = config.get("default_dest")
    if not dest:
        return jsonify({"status": "error", "message": "Kein Zielpfad konfiguriert."})
    
    if current_job_status["active"]:
        return jsonify({"status": "error", "message": "Ein Backup-Prozess läuft bereits."})

    def _worker():
        global current_job_status
        with backup_lock:
            current_job_status["active"] = True
            current_job_status["progress"] = 10
            current_job_status["step"] = "database"
            current_job_status["message"] = "Starte Datenbank Dump..."
            
            try:
                run_db_dump(config, dest, job_status_update=True)
            except Exception as e:
                logger.error(f"DB Worker Error: {e}")
                add_event(f"DB Fehler: {e}", "error")
                current_job_status["message"] = f"Fehler: {str(e)}"
            finally:
                current_job_status["active"] = False
                current_job_status["progress"] = 100
                add_event("Datenbank Dump beendet.", "info")
        
    threading.Thread(target=_worker, daemon=True).start()
    
    return jsonify({"status": "started", "message": "DB Dump gestartet."})



@app.route("/api/run_cloud_backup_now", methods=["POST"])
def run_cloud_backup_now():
    """Startet ein manuelles Cloud-Backup mit separatem Status."""
    data = request.json
    source, dest, comment = data.get("source"), data.get("dest"), data.get("comment", "")
    
    # Check if cloud backup is already running
    if cloud_job_status["active"]:
        return jsonify({"status": "error", "message": "Cloud-Backup läuft bereits."})
        
    # Reset Cloud Logs explicitly to avoid cross-contamination from previous runs
    cloud_job_status["logs"] = []
        
    # Start thread with cloud status target and allowed modules
    task_options = {
        "status_target": "cloud",
        "naming_include_date": data.get("naming_date", True),
        "naming_include_time": data.get("naming_time", True),
        "naming_include_seq": data.get("naming_seq", False)
    }
    
    custom_prefix = data.get("naming_custom") # Can be None/Empty
    
    # Trigger ONLY Cloud module (plus core zip creation)
    thread = threading.Thread(target=run_backup_logic, args=(source, dest, comment, custom_prefix, task_options, ['cloud']))
    thread.start()
    
    return jsonify({"status": "started", "message": "Cloud-Backup im Hintergrund gestartet."})

@app.route("/api/get_cloud_backup_status")
def get_cloud_backup_status():
    return jsonify(cloud_job_status)

@app.route("/api/create_cloud_path", methods=["POST"])
def create_cloud_path():
    """Erstellt den Remote-Pfad falls möglich (z.B. mkdir bei SFTP)."""
    data = request.json
    provider = data.get("provider")
    host = data.get("host")
    user = data.get("user")
    password = data.get("password")
    path = data.get("path")
    port = data.get("port", 22)
    
    if not path:
        return jsonify({"status": "error", "message": "Kein Pfad angegeben."})
        
    if provider == "Local":
        try:
            os.makedirs(path, exist_ok=True)
            return jsonify({"status": "success", "message": "Lokaler Ordner erstellt."})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})

    if provider == "SFTP":
        if not host or not user or not password:
            return jsonify({"status": "error", "message": "Verbindungsdaten fehlen."})
            
        try:
            import paramiko
            
            # Clean Host logic (same as test_cloud_connection)
            host_clean = host.strip().replace("sftp://", "").replace("ssh://", "")
            if "@" in host_clean:
                parts = host_clean.split("@")
                if len(parts) == 2:
                    if not user: user = parts[0]
                    host_clean = parts[1]
            if "/" in host_clean: host_clean = host_clean.split("/")[0]
            
            p = 22
            try: p = int(port)
            except: pass
            
            transport = paramiko.Transport((host_clean, p))
            # Legacy Algos
            sec_opts = transport.get_security_options()
            extra_kex = ('diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group1-sha1')
            extra_ciphers = ('aes128-cbc', '3des-cbc', 'aes256-cbc')
            sec_opts.kex = tuple(list(sec_opts.kex) + [k for k in extra_kex if k not in sec_opts.kex])
            sec_opts.ciphers = tuple(list(sec_opts.ciphers) + [c for c in extra_ciphers if c not in sec_opts.ciphers])
            
            transport.connect(username=user, password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            # Rekursiv erstellen
            # Pfad normalisieren
            path = path.replace("\\", "/")
            if path.startswith("/"): path = path[1:]
            
            parts = path.split("/")
            current = ""
            for part in parts:
                if not part: continue
                current += "/" + part
                try:
                    sftp.stat(current)
                except IOError:
                    # Existiert nicht -> anlegen
                    try:
                        sftp.mkdir(current)
                    except IOError as e:
                        return jsonify({"status": "error", "message": f"Konnte Ordner '{current}' nicht erstellen: {e}"})
            
            sftp.close()
            transport.close()
            return jsonify({"status": "success", "message": "Pfad angelegt."})
            
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})

    return jsonify({"status": "error", "message": "Provider unterstützt keine Ordner-Erstellung oder nicht implementiert."})

@app.route("/api/test_cloud_connection", methods=["POST"])
def test_cloud_connection():
    """Testet die Verbindung zum gewählten Cloud-Provider."""
    data = request.json
    provider = data.get("provider")
    host = data.get("host")
    user = data.get("user")
    password = data.get("password")
    bucket = data.get("bucket")
    port = data.get("port")
    region = data.get("region")
    path = data.get("path")
    
    try:
        if provider == "SFTP":
            if not host or not user or not password:
                return jsonify({"status": "error", "message": "Host, User und Passwort erforderlich."})
            
            try:
                import paramiko
                import socket
                # Debug Logging aktivieren
                try: paramiko.util.log_to_file("sftp_debug.log", level="DEBUG")
                except: pass
            except ImportError:
                return jsonify({"status": "error", "message": "Modul 'paramiko' fehlt."})

            host_clean = host.strip()
            # Handle user@host syntax
            if "@" in host_clean:
                try:
                    parts = host_clean.split("@")
                    if len(parts) == 2:
                        if not user: user = parts[0]
                        host_clean = parts[1]
                except: pass
            
            # Remove protocol and path parts if user pasted a URL
            host_clean = host_clean.replace("sftp://", "").replace("ssh://", "")
            if "/" in host_clean:
                host_clean = host_clean.split("/")[0]

            p = 22
            if port and str(port).strip():
                try: p = int(port)
                except: pass
            
            logger.info(f"SFTP Test (Transport): Host={host_clean}, Port={p}, User={user}")

            transport = None
            sock = None
            try:
                # 1. Socket erstellen mit Timeout (20s)
                sock = socket.create_connection((host_clean, p), timeout=20)
                
                # 2. Transport initialisieren (Low-Level SSH)
                transport = paramiko.Transport(sock)
                
                # --- LEGACY ALGORITHM SUPPORT ---
                try:
                    sec_opts = transport.get_security_options()
                    extra_kex = ('diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group1-sha1')
                    extra_ciphers = ('aes128-cbc', '3des-cbc', 'aes256-cbc')
                    extra_keys = ('ssh-rsa', 'ssh-dss')
                    sec_opts.kex = tuple(list(sec_opts.kex) + [k for k in extra_kex if k not in sec_opts.kex])
                    sec_opts.ciphers = tuple(list(sec_opts.ciphers) + [c for c in extra_ciphers if c not in sec_opts.ciphers])
                    sec_opts.key_types = tuple(list(sec_opts.key_types) + [k for k in extra_keys if k not in sec_opts.key_types])
                except: pass

                # 3. Verbinden
                first_auth_error = None
                
                try:
                    # Explicitly cast password to str to avoid encoding issues
                    transport.connect(username=user.strip(), password=str(password))
                except paramiko.AuthenticationException as ae_pass:
                    first_auth_error = ae_pass
                    
                    # Versuche herauszufinden, was der Server erlaubt
                    allowed_methods = getattr(ae_pass, 'allowed_types', [])
                    
                    # Fallback: Manche Server verlangen Interactive Auth
                    def handler(title, instructions, prompt_list):
                        return [password] * len(prompt_list)
                    try:
                         transport.auth_interactive(user.strip(), handler)
                    except Exception as e_interactive:
                        # Wenn beides fehlschlägt, Fehlermeldung bauen
                        msg = f"Passwort abgelehnt."
                        if allowed_methods:
                            msg += f" (Server erlaubt: {', '.join(allowed_methods)})"
                        
                        msg_fallback = str(e_interactive)
                        if "Bad authentication type" in msg_fallback:
                             # Interactive wird nicht unterstützt
                             raise Exception(f"{msg} Fehler: {str(first_auth_error)}")
                        else:
                             raise Exception(f"{msg} PW-Auth: {str(first_auth_error)}, Interactive: {msg_fallback}")

                # 4. SFTP Session öffnen
                sftp = paramiko.SFTPClient.from_transport(transport)
                
                msg = "SFTP Verbindung OK."
                if path:
                    try: 
                        sftp.stat(path)
                        msg += f" Pfad '{path}' gefunden."
                    except IOError:
                        msg += f" Hinweis: Pfad '{path}' existiert noch nicht (wird bei Backup erstellt)."
                    except Exception as e:
                        msg += f" (Pfad-Check Fehler: {str(e)})"
                
                sftp.close()
                transport.close()
                return jsonify({"status": "success", "message": msg})
                
            except Exception as e:
                return jsonify({"status": "error", "message": f"SFTP Fehler: {str(e)}"})
            finally:
                if transport: transport.close()
                if sock: sock.close()
            
        elif provider == "Dropbox":
            if not password: # Token
                 return jsonify({"status": "error", "message": "Token erforderlich."})
            import dropbox
            try:
                dbx = dropbox.Dropbox(password)
                account = dbx.users_get_current_account()
                return jsonify({"status": "success", "message": f"Dropbox OK: {account.name.display_name}"})
            except Exception as e:
                return jsonify({"status": "error", "message": f"Dropbox Fehler: {str(e)}"})
            
        elif provider == "S3 (Amazon)":
             if not user or not password: # Access Key, Secret
                 return jsonify({"status": "error", "message": "Access Key und Secret erforderlich."})
             import boto3
             try:
                 session = boto3.Session(
                     aws_access_key_id=user,
                     aws_secret_access_key=password,
                     region_name=region if region else None
                 )
                 s3 = session.client('s3')
                 s3.list_buckets()
                 if bucket:
                     try:
                        s3.head_bucket(Bucket=bucket)
                     except:
                        return jsonify({"status": "error", "message": f"Bucket '{bucket}' nicht gefunden oder kein Zugriff."})
                 return jsonify({"status": "success", "message": "S3 Verbindung OK."})
             except Exception as e:
                 return jsonify({"status": "error", "message": f"S3 Fehler: {str(e)}"})
             
        elif provider == "WebDAV":
             if not host:
                 return jsonify({"status": "error", "message": "URL erforderlich."})
             import requests
             auth = None
             if user and password:
                 auth = (user, password)
             
             target_url = host
             if path:
                 # Ensure proper slash handling
                 base = host.rstrip("/")
                 p_clean = path.lstrip("/")
                 target_url = f"{base}/{p_clean}"
                 
             try:
                 # PROPFIND is standard for WebDAV checks
                 resp = requests.request("PROPFIND", target_url, auth=auth, timeout=10)
                 
                 if 200 <= resp.status_code < 300:
                     return jsonify({"status": "success", "message": "WebDAV OK."})
                 elif resp.status_code == 401:
                      return jsonify({"status": "error", "message": "Authentifizierung fehlgeschlagen."})
                 elif resp.status_code == 404:
                      return jsonify({"status": "error", "message": "Pfad nicht gefunden."})
                 else:
                      # Some servers might not support PROPFIND on root without depth header, try HEAD
                      resp2 = requests.head(target_url, auth=auth, timeout=10)
                      if 200 <= resp2.status_code < 300:
                          return jsonify({"status": "success", "message": "WebDAV OK (HEAD)."})
                      
                      return jsonify({"status": "error", "message": f"HTTP {resp.status_code}"})
             except Exception as e:
                 return jsonify({"status": "error", "message": f"WebDAV Fehler: {str(e)}"})
        
        else:
            return jsonify({"status": "error", "message": "Unbekannter Provider."})
            
    except ImportError as ie:
        return jsonify({"status": "error", "message": f"Modul fehlt: {ie.name}. Bitte installieren."})
    except Exception as e:
        logger.error(f"Cloud Test Error: {e}")
        return jsonify({"status": "error", "message": str(e)})

@app.route("/api/start_backup", methods=["POST"])
def start_backup():
    data = request.json
    source, dest, comment = data.get("source"), data.get("dest"), data.get("comment", "")
    task_options = data.get("task_options") # Optional: Naming options from task
    
    if current_job_status["active"]:
        return jsonify({"status": "error", "message": "Backup läuft bereits."})
        
    # Thread starten
    # ISOLATION FIX: Wenn manueller Snapshot (keine task_options), dann KEINE Module (Cloud/GitHub) ausführen.
    # User Request: "beim snappshot soll nur das was in den parametern gespeichert ist ausgeführt werden"
    allowed_modules = None
    if task_options is None:
        allowed_modules = [] # Leere Liste = Keine Module erlaubt (Strict Isolation)
        
    # Fix: Argument order mismatch resolved.
    # run_backup_logic expects: (source, dest, comment, custom_filename_prefix, task_options, allowed_modules)
    thread = threading.Thread(target=run_backup_logic, args=(source, dest, comment, None, task_options, allowed_modules))
    thread.start()
    
    return jsonify({"status": "started", "message": "Backup im Hintergrund gestartet."})

@app.route("/api/get_backup_status")
def get_backup_status():
    return jsonify(current_job_status)

@app.route("/api/get_events")
def get_events():
    global event_queue
    # Return all events and clear queue (Polling style)
    events = list(event_queue)
    event_queue.clear()
    return jsonify(events)

@app.route("/api/stream")
def stream():
    """Server-Sent Events Endpoint with Keep-Alive."""
    def event_stream():
        messages = sse_announcer.listen()
        try:
            while True:
                try:
                    # Wait for message with timeout to send keep-alive
                    msg = messages.get(timeout=15)
                    yield msg
                except queue.Empty:
                    # Send comment as keep-alive to prevent connection drop
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass # Client disconnected
        except Exception as e:
            logger.error(f"SSE Stream Error: {e}")
        finally:
            sse_announcer.remove_listener(messages)

    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/api/restore_backup", methods=["POST"])
def restore_backup():
    """Rekonstruiert Daten aus einem ZIP-Archiv."""
    data = request.json
    filename, dest, target = data.get("filename"), data.get("dest"), data.get("target")
    
    # Pfad aus Historie ermitteln (falls vorhanden)
    history = get_history_from_db()
    entry = next((h for h in history if h['filename'] == filename), None)
    
    archive_full_path = None
    if entry and entry.get("path") and os.path.exists(entry["path"]):
        archive_full_path = entry["path"]
    else:
        # Fallback auf übergebenen Dest-Pfad
        archive_full_path = os.path.join(dest, filename)

    # Intelligente Zielpfad-Korrektur für Einzeldatei/Multi-File Szenarien
    if target:
        # Wenn Pipe enthalten oder Pfad eine Datei ist -> Nimm das Elternverzeichnis
        if "|" in target or (os.path.exists(target) and os.path.isfile(target)):
            first_path = target.split("|")[0].strip()
            # Wenn der Pfad existiert (Datei), nimm dirname. Wenn nicht, rate dirname.
            if os.path.exists(first_path) and os.path.isfile(first_path):
                target = os.path.dirname(first_path)
            elif not os.path.exists(first_path):
                # Versuche Pfadstruktur zu erhalten
                target = os.path.dirname(first_path)

    try:
        # archive_full_path ist bereits berechnet
        if not os.path.exists(archive_full_path):
            return jsonify({"status": "error", "message": "Archiv nicht gefunden."})
            
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
    
    if not filename:
        return jsonify({"status": "error"})
        
    try:
        # Pfad aus Historie ermitteln (SQLite)
        history = get_history_from_db()
        entry = next((h for h in history if h['filename'] == filename), None)
        
        path_to_delete = None
        if entry and entry.get("path"):
             path_to_delete = entry["path"]
        else:
             # Fallback
             if dest: path_to_delete = os.path.join(dest, filename)

        if path_to_delete and os.path.exists(path_to_delete):
            try:
                os.remove(path_to_delete)
            except OSError as e:
                logger.error(f"Konnte Datei nicht löschen: {e}")
            
        delete_history_entry_from_db(filename)
        
        # Broadcast Deletion Event
        try:
            sse_announcer.announce({
                "message": f"Backup gelöscht: {filename}", 
                "type": "info"
            }, event_type="log")
        except: pass
        
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Löschfehler: {e}")
        return jsonify({"status": "error"})

@app.route("/api/clear_history", methods=["POST"])
def clear_history_api():
    """Löscht die gesamte Historie (nur die Einträge, nicht die Dateien)."""
    try:
        # DB leeren
        if clear_history_db():
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "DB Fehler"})
    except Exception as e:
        logger.error(f"Fehler beim Leeren der Historie: {e}")
        return jsonify({"status": "error", "message": str(e)})

scan_state = {"abort": False, "total": 0, "current": 0, "current_file": ""}

@app.route("/api/scan_progress")
def scan_progress_api():
    return jsonify(scan_state)

@app.route("/api/stop_scan", methods=["POST"])
def stop_scan_api():
    scan_state["abort"] = True
    return jsonify({"status": "stopping"})

@app.route("/api/find_duplicates", methods=["POST"])
def find_duplicates_api():
    """Findet redundante Dateien im Quellverzeichnis mit Filtern (Parallelisiert & Smart Skipping)."""
    # Reset State
    scan_state["abort"] = False
    scan_state["total"] = 0
    scan_state["current"] = 0
    scan_state["current_file"] = ""
    
    data = request.json
    path = data.get("path")
    min_size = int(data.get("min_size", 0)) # Bytes
    extensions = data.get("extensions", []) # List of extensions like ['.jpg', '.png']
    
    if not path or not os.path.exists(path):
        return jsonify([])
        
    # --- Phase 1: Fast Scan & Size Grouping ---
    # Sammelt alle Dateien und gruppiert sie nach Größe.
    # Dateien mit einzigartiger Größe können keine Duplikate sein (Smart Skipping).
    
    size_groups = defaultdict(list)
    total_files_count = 0
    
    try:
        # Sequenzieller Scan (schnell für Metadaten)
        for root, _, files in os.walk(path):
            if scan_state["abort"]: return jsonify({"status": "aborted"})
            
            for f in files:
                # Filter Extension
                if extensions:
                    _, ext = os.path.splitext(f)
                    if ext.lower() not in extensions:
                        continue
                        
                fpath = os.path.join(root, f)
                try:
                    fsize = os.path.getsize(fpath)
                    
                    # Filter Size
                    if fsize < min_size:
                        continue
                        
                    size_groups[fsize].append(fpath)
                    total_files_count += 1
                except: pass
        
        # Nur Gruppen mit > 1 Datei behalten
        candidate_groups = {s: paths for s, paths in size_groups.items() if len(paths) > 1}
        
        # Flatten candidates for parallel processing
        candidate_files = []
        for s, paths in candidate_groups.items():
            candidate_files.extend(paths)
            
        # Update Total für Fortschrittsanzeige (nur Kandidaten werden gehasht)
        scan_state["total"] = len(candidate_files)
        scan_state["current"] = 0
        
    except Exception as e:
        logger.error(f"Scan Error Phase 1: {e}")
        return jsonify([])

    # --- Phase 2: Parallel Hashing with Smart Skipping (Size + Mtime) ---
    file_hashes = {} # path -> hash
    file_mtimes = {} # path -> mtime
    
    # Files to actually hash (Representatives)
    files_to_hash = []
    
    # Map for Smart Skipping: (size, mtime) -> [list of paths]
    # We will hash one from the list and assign to all
    smart_groups = defaultdict(list)
    
    try:
        # Group by Size + Mtime
        for size, paths in candidate_groups.items():
            for p in paths:
                try:
                    m = os.path.getmtime(p)
                    smart_groups[(size, m)].append(p)
                    file_mtimes[p] = m
                except: pass
        
        # Determine representatives
        hash_jobs = {} # path -> (size, mtime)
        
        for (size, mtime), paths in smart_groups.items():
            # Pick first one as representative
            rep = paths[0]
            files_to_hash.append(rep)
            hash_jobs[rep] = (size, mtime)
            
        # Update Total for Progress (only actual hashes)
        scan_state["total"] = len(files_to_hash)
        scan_state["current"] = 0
        
        # Parallel Execution
        # Use BLAKE2b for speed as requested
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(calculate_hash, f, "blake2b"): f for f in files_to_hash}
            
            for future in concurrent.futures.as_completed(futures):
                fpath = futures[future]
                if scan_state["abort"]: 
                    executor.shutdown(wait=False, cancel_futures=True)
                    return jsonify({"status": "aborted"})
                    
                try:
                    h = future.result()
                    scan_state["current"] += 1
                    scan_state["current_file"] = os.path.basename(fpath)
                    
                    if h and h != "HASH_ERROR":
                        # Assign hash to ALL files in the same Size+Mtime group
                        size, mtime = hash_jobs[fpath]
                        group_paths = smart_groups[(size, mtime)]
                        
                        for p in group_paths:
                            file_hashes[p] = h
                except Exception as ex:
                    logger.error(f"Hash Error {fpath}: {ex}")

    except Exception as e:
        logger.error(f"Scan Error Phase 2: {e}")
        
    # --- Phase 3: Group by Hash ---
    hashes = defaultdict(list)
    for fpath, h in file_hashes.items():
        hashes[h].append({"path": fpath, "mtime": file_mtimes[fpath]})
        
    redundant = []
    for h, file_objs in hashes.items():
        if len(file_objs) > 1:
            try: size = os.path.getsize(file_objs[0]["path"])
            except: size = 0
            
            # Sort files by mtime (newest first)
            file_objs.sort(key=lambda x: x["mtime"], reverse=True)
            
            redundant.append({"files": file_objs, "size": size})
    
    # Sort groups by wasted space (descending)
    redundant.sort(key=lambda x: x["size"] * (len(x["files"]) - 1), reverse=True)
            
    return jsonify(redundant)

@app.route("/api/delete_file", methods=["POST"])
def delete_file_api():
    """Löscht eine beliebige Datei (für Duplikat-Bereinigung)."""
    path = request.json.get("path")
    if not path or not os.path.exists(path):
        return jsonify({"status": "error", "message": "Datei nicht gefunden"})
    try:
        os.remove(path)
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Delete File Error: {e}")
        return jsonify({"status": "error", "message": str(e)})

startup_tasks_checked = False

@app.route("/api/get_startup_tasks")
def get_startup_tasks():
    global startup_tasks_checked
    if startup_tasks_checked:
        return jsonify({"tasks": []})
    
    config = load_config()
    tasks = config.get("tasks", [])
    active_tasks = [t for t in tasks if t.get("active", True)]
    
    startup_tasks_checked = True 
    
    return jsonify({"tasks": [t.get("name", "Unnamed") for t in active_tasks]})

@app.route("/api/run_startup_tasks", methods=["POST"])
def run_startup_tasks():
    try:
        config = load_config()
        tasks = config.get("tasks", [])
        active_tasks = [t for t in tasks if t.get("active", True)]
        
        def run_tasks_bg():
            tasks_updated = False
            # Wir laden config nochmal frisch im Thread, um sicher zu gehen
            thread_config = load_config()
            thread_tasks = thread_config.get("tasks", [])
            
            for t_idx, t in enumerate(active_tasks):
                t_source = t.get("source")
                t_dest = t.get("dest")
                t_name = t.get("name", "Unnamed Task")
                t_id = t.get("id")
                
                if t_source and t_dest:
                     while is_backup_locked():
                         time.sleep(1)
                     
                     # Prepare Task Options
                     task_opts = {
                         "naming_include_date": t.get("naming_include_date", True),
                         "naming_include_time": t.get("naming_include_time", True),
                         "naming_include_seq": t.get("naming_include_seq", False)
                     }
                     res = run_backup_logic(t_source, t_dest, f"Task: {t_name}", custom_filename_prefix=t_name, task_options=task_opts)
                     if res.get("status") == "success":
                         # Update last_run in thread_tasks
                         for tt in thread_tasks:
                             if tt.get("id") == t_id:
                                 tt["last_run"] = time.time()
                                 tasks_updated = True
                                 break
            
            if tasks_updated:
                thread_config["tasks"] = thread_tasks
                save_config(thread_config)
            
            # Auto-Shutdown Check Removed
        
        threading.Thread(target=run_tasks_bg, daemon=True).start()
        return jsonify({"status": "started"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == "__main__":
    args = sys.argv[1:]
    lang = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("--lang="):
            lang = arg.split("=", 1)[1].strip().lower()
        elif arg in ("--lang", "--language", "-l") and i + 1 < len(args):
            lang = args[i + 1].strip().lower()
            i += 1
        i += 1
    if lang in ("de", "en"):
        CURRENT_LANG = lang

    # Ensure system files exist
    ensure_files_exist()

    # Check Runtime Environment (User Request: PyPy Performance)
    is_pypy = "__pypy__" in sys.builtin_module_names
    runtime_name = "PyPy" if is_pypy else "CPython"
    logger.info(f"System Runtime: {runtime_name} ({sys.version.split()[0]})")
    if is_pypy:
        print(f"Optimierte Laufzeitumgebung erkannt: {runtime_name} (High Performance Mode)")

    # Port-Check und dynamische Zuweisung
    target_port = 5000
    
    # Prüfe ob Port 5000 belegt ist
    import socket # Lazy Load
    import webbrowser # Lazy Load

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
            import tkinter as tk # Lazy Load
            from tkinter import messagebox # Lazy Load
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
    
    # Load language from config
    try:
        cfg = load_config()
        if "language" in cfg:
             CURRENT_LANG = cfg["language"]
             logger.info(f"Loaded language from config: {CURRENT_LANG}")
    except Exception as e:
        logger.error(f"Failed to load language from config: {e}")

    # Start Scheduler Thread
    scheduler_thread = threading.Thread(target=auto_backup_scheduler, daemon=True)
    scheduler_thread.start()
    
    # Start Webbrowser
    webbrowser.open(f"http://127.0.0.1:{target_port}")
    
    # Produktions-WSGI-Server (waitress) für Endanwender
    # Threading bleibt wichtig, damit Requests (z.B. Cancel) während eines laufenden Backups angenommen werden.
    try:
        from waitress import serve
        serve(app, host="127.0.0.1", port=target_port, threads=8)
    except Exception as e:
        logger.error(f"Fehler beim Starten des WSGI-Servers (waitress): {e}")
        # Fallback: Flask-Server mit Threading
        app.run(port=target_port, debug=False, threaded=True)
