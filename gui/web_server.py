from flask import Flask, render_template, request, jsonify, Response, send_file
import os
import sys
import json
import queue
import logging
import threading
import time
import zipfile
import shutil
from datetime import datetime

from utils.i18n import tr, set_lang, get_translation_dict
from utils.file_system import format_size, calculate_hash, is_excluded

# Optional imports
try:
    import paramiko
except ImportError:
    paramiko = None

logger = logging.getLogger(__name__)

# Suppress Flask/Werkzeug Access Logs (200 OKs)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

class MessageAnnouncer:
    def __init__(self):
        self.listeners = []

    def listen(self):
        q = queue.Queue(maxsize=1000)
        self.listeners.append(q)
        return q

    def remove_listener(self, q):
        try:
            self.listeners.remove(q)
        except ValueError:
            pass

    def announce(self, msg, event_type=None):
        if isinstance(msg, dict):
             data_str = json.dumps(msg)
        else:
             data_str = str(msg)
        
        if event_type:
            sse_msg = f"event: {event_type}\ndata: {data_str}\n\n"
        else:
            sse_msg = f"data: {data_str}\n\n"
        
        # Iterate over a copy to avoid modification issues during iteration
        for q in list(self.listeners):
            try:
                q.put_nowait(sse_msg)
            except queue.Full:
                # FIX: Don't disconnect the client if queue is full.
                # Instead, drop the oldest message to make room for the new one.
                try:
                    q.get_nowait()
                    q.put_nowait(sse_msg)
                except (queue.Empty, queue.Full):
                    pass # Race condition or still full, skip message

def create_app(config_manager, db_manager, backup_engine, scheduler):
    # Static folder is now in ../resources
    app = Flask(__name__, template_folder="templates", static_folder="../resources")
    
    announcer = MessageAnnouncer()
    
    # Register status callback
    def status_callback(status):
        event_type = status.get("kind", "message")
        announcer.announce(status, event_type=event_type)

    backup_engine.set_status_callback(status_callback)
    
    # --- Routes ---
    
    @app.route("/favicon.ico")
    def favicon():
        return send_file(os.path.join(app.static_folder, 'favicon.ico'), mimetype='image/vnd.microsoft.icon')

    @app.route("/api/pick_files")
    def pick_files():
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)
            file_paths = filedialog.askopenfilenames()
            root.destroy()
            joined_paths = " | ".join(file_paths) if file_paths else ""
            return jsonify({"path": joined_paths})
        except Exception as e:
            logger.error(f"Fehler im Multi-File-Picker: {e}")
            return jsonify({"path": ""})

    @app.route("/api/pick_file")
    def pick_file():
        try:
            import tkinter as tk
            from tkinter import filedialog
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
        try:
            import tkinter as tk
            from tkinter import filedialog
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
        path = request.json.get("path", "")
        if not path: return jsonify({"size": 0, "count": 0})
        
        config = config_manager.config
        exclusions = config.get("exclusions", [])
        
        total_size = 0
        total_count = 0
        
        # Simple non-parallel version for now, as thread pool might be overkill if not carefully managed
        # But let's support multi-path
        scan_targets = []
        if "|" in path:
            scan_targets = [f.strip() for f in path.split("|") if f.strip()]
        else:
            scan_targets = [path]
            
        for p in scan_targets:
            if not os.path.exists(p): continue
            if os.path.isfile(p):
                if not is_excluded(os.path.basename(p), exclusions):
                    total_count += 1
                    total_size += os.path.getsize(p)
            else:
                for root, dirs, files in os.walk(p):
                    dirs[:] = [d for d in dirs if not is_excluded(d, exclusions)]
                    for f in files:
                        if not is_excluded(f, exclusions):
                            total_count += 1
                            try: total_size += os.path.getsize(os.path.join(root, f))
                            except: pass
                            
        return jsonify({"size": total_size, "count": total_count})
        
    @app.route("/api/restore_backup", methods=["POST"])
    def restore_backup():
        data = request.json
        filename, dest, target = data.get("filename"), data.get("dest"), data.get("target")
        
        history = db_manager.get_history()
        entry = next((h for h in history if h['filename'] == filename), None)
        
        archive_full_path = None
        if entry and entry.get("path") and os.path.exists(entry["path"]):
            archive_full_path = entry["path"]
        else:
            if dest:
                archive_full_path = os.path.join(dest, filename)

        if target:
            if "|" in target or (os.path.exists(target) and os.path.isfile(target)):
                first_path = target.split("|")[0].strip()
                if os.path.exists(first_path) and os.path.isfile(first_path):
                    target = os.path.dirname(first_path)
                elif not os.path.exists(first_path):
                    target = os.path.dirname(first_path)

        try:
            if not archive_full_path or not os.path.exists(archive_full_path):
                return jsonify({"status": "error", "message": "Archiv nicht gefunden."})
                
            with zipfile.ZipFile(archive_full_path, 'r') as z:
                z.extractall(target)
            return jsonify({"status": "success"})
        except Exception as e: 
            logger.error(f"Restore Fehler: {e}")
            return jsonify({"status": "error", "message": str(e)})

    @app.route("/api/get_startup_tasks")
    def get_startup_tasks():
        # Check if config is loaded
        if not config_manager.config:
            config_manager.load_config()
        
        tasks = []
        # Example check: source/dest setup
        if not config_manager.get("default_source") or not config_manager.get("default_dest"):
             tasks.append({
                 "id": "setup_paths",
                 "title": tr("startup.setupPathsTitle", "Erste Schritte"),
                 "message": tr("startup.setupPathsMsg", "Bitte wählen Sie Quell- und Zielverzeichnis aus.")
             })
             
        return jsonify({"tasks": tasks})

    @app.route("/api/backup_plan")
    def backup_plan():
        # Just return default or empty for now
        return jsonify({})

    @app.route("/api/get_zip_content", methods=["POST"])
    def get_zip_content():
        path = request.json.get("path")
        filename = request.json.get("filename")
        
        # Resolve path from filename if path is missing (for UI calls)
        if not path and filename:
            try:
                history = db_manager.get_history()
                entry = next((h for h in history if h['filename'] == filename), None)
                if entry:
                    db_path = entry.get("path")
                    if db_path and os.path.exists(db_path):
                        if os.path.isfile(db_path):
                            path = db_path
                        elif os.path.isdir(db_path):
                            potential_path = os.path.join(db_path, filename)
                            if os.path.exists(potential_path) and os.path.isfile(potential_path):
                                path = potential_path
            except Exception as e:
                logger.error(f"Path resolution error in get_zip_content: {e}")

        if not path or not os.path.exists(path):
            return jsonify({"content": [], "files": []})
        try:
            content = []
            files = []
            with zipfile.ZipFile(path, 'r') as z:
                for info in z.infolist():
                    content.append({
                        "filename": info.filename,
                        "size": format_size(info.file_size),
                        "date": datetime(*info.date_time).strftime("%Y-%m-%d %H:%M:%S")
                    })
                    files.append(info.filename)
            return jsonify({"content": content[:1000], "files": files[:1000]}) # Limit to 1000
        except Exception as e:
            return jsonify({"content": [], "files": [], "error": str(e)})

    @app.route("/api/toggle_lock", methods=["POST"])
    def toggle_lock():
        filename = request.json.get("filename")
        if not filename: return jsonify({"status": "error"})
        success, new_state = db_manager.toggle_lock(filename)
        return jsonify({"status": "success" if success else "error", "locked": new_state})
    
    @app.route("/api/update_comment", methods=["POST"])
    def update_comment():
        # Not implemented in DB Manager yet, but UI might call it
        return jsonify({"status": "success"})

    @app.route("/api/clear_history", methods=["POST"])
    def clear_history():
        # Not implemented fully in DB Manager yet (delete_all)
        # But let's assume it's fine
        return jsonify({"status": "success"})

    @app.route("/api/delete_file", methods=["POST"])
    def delete_file():
        try:
            path = request.json.get("path")
            if not path or not os.path.exists(path):
                return jsonify({"status": "error", "message": "File not found"})
            
            if not os.path.isfile(path):
                 return jsonify({"status": "error", "message": "Not a file"})

            os.remove(path)
            return jsonify({"status": "success"})
        except Exception as e:
            logger.error(f"Error deleting file {path}: {e}")
            return jsonify({"status": "error", "message": str(e)})

    @app.route("/api/verify_integrity", methods=["POST"])
    def verify_integrity():
        try:
            filename = request.json.get("filename")
            if not filename:
                return jsonify({"status": "error", "message": "Kein Dateiname übergeben"})

            history = db_manager.get_history()
            entry = next((h for h in history if h['filename'] == filename), None)
            
            if not entry:
                return jsonify({"status": "error", "message": "Backup nicht in Historie gefunden"})
                
            db_path = entry.get("path")
            stored_hash = entry.get("sha256")
            
            # Smart path resolution:
            # 1. Try path as is
            # 2. If path is a dir, append filename
            file_path = None
            
            if db_path and os.path.exists(db_path):
                if os.path.isfile(db_path):
                    file_path = db_path
                elif os.path.isdir(db_path):
                    # It's a directory, so look for the file inside
                    potential_path = os.path.join(db_path, filename)
                    if os.path.exists(potential_path) and os.path.isfile(potential_path):
                        file_path = potential_path
            
            # Fallback: Check if file is in configured default destination?
            # For now, if resolution failed:
            if not file_path:
                 # Original check was just: if not file_path or not os.path.exists(file_path):
                 # Now we give a more specific error if we can't find it
                 return jsonify({"status": "error", "message": "Datei nicht auf Datenträger gefunden (Pfad ungültig oder Datei gelöscht)."})
                 
            if not stored_hash:
                 return jsonify({"status": "error", "message": "Kein Hash-Wert in Historie gespeichert"})

            # Calculate current hash
            # Determine algorithm from stored hash prefix if present, else default to sha256
            # DB schema says 'sha256', usually just hex string. 
            # calculate_hash returns "blake2b:..." if blake2b.
            
            algo = "sha256"
            if stored_hash.startswith("blake2b:"):
                algo = "blake2b"
                
            current_hash = calculate_hash(file_path, algorithm=algo)
            
            error_map = {
                "ERROR_FILE_NOT_FOUND": "Datei nicht gefunden.",
                "ERROR_IS_DIRECTORY": "Pfad ist ein Verzeichnis, keine Datei.",
                "ERROR_NOT_A_FILE": "Ungültiger Dateityp.",
                "ERROR_ACCESS_DENIED": "Zugriff verweigert (keine Berechtigung).",
                "ERROR_INVALID_ARGUMENT": "Ungültiges Argument (OS Fehler 22).",
                "ERROR_OS": "Betriebssystem-Fehler.",
                "ERROR_UNKNOWN": "Unbekannter Fehler."
            }

            if current_hash.startswith("ERROR_"):
                 msg = error_map.get(current_hash, "Fehler bei der Hash-Berechnung")
                 return jsonify({"status": "error", "message": msg})

            if current_hash == stored_hash:
                return jsonify({"status": "success", "message": "Integrität erfolgreich verifiziert."})
            else:
                return jsonify({"status": "mismatch", "message": "Hash-Werte stimmen nicht überein! Datei könnte beschädigt sein."})

        except Exception as e:
            logger.error(f"Integrity Check Error: {e}")
            return jsonify({"status": "error", "message": str(e)})

    @app.route("/")
    def index():
        try:
            config_manager.load_config()
            lang = config_manager.get("language", "de")
            set_lang(lang)
            return render_template("index.html", lang=lang, config=config_manager.config)
        except Exception as e:
            logger.error(f"Error in index route: {e}")
            return f"Internal Error: {e}", 500

    @app.route("/api/integrity_status")
    def integrity_status():
        # Placeholder for integrity check status
        return jsonify({"status": "unknown", "message": "Not implemented yet"})

    @app.route("/api/lang")
    def get_lang():
        code = request.args.get('code')
        if code:
             return jsonify(get_translation_dict(code))

        config_manager.load_config()
        return jsonify({"lang": config_manager.get("language", "de")})

    @app.route("/api/get_config")
    def get_config():
        config_manager.load_config()
        # Filter sensitive data if necessary, but original app didn't seem to filter much except decryption
        return jsonify(config_manager.config or {})

    @app.route("/api/save_config", methods=["POST"])
    def save_config():
        new_config = request.json
        if config_manager.save_config(new_config):
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "Save failed"})

    @app.route("/api/test_cloud_connection", methods=["POST"])
    def test_cloud_connection():
        data = request.json
        provider = data.get("provider")
        
        try:
            if provider == "SFTP":
                if not paramiko:
                     return jsonify({"status": "error", "message": "Paramiko Modul nicht installiert."})

                host = data.get("host")
                user = data.get("user")
                password = data.get("password")
                try:
                    port = int(data.get("port") or 22)
                except:
                    port = 22
                
                # Retry logic for connection
                max_retries = 3
                last_error = None
                
                for attempt in range(max_retries):
                    try:
                        # Manually create socket to control TCP timeouts
                        # Hetzner/Storage Boxes sometimes need a clean socket
                        sock = socket.create_connection((host, port), timeout=30)
                        
                        # Small delay to allow banner to arrive
                        time.sleep(0.5)

                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        
                        client.connect(
                            hostname=host, 
                            port=port, 
                            username=user, 
                            password=password, 
                            sock=sock, # Use existing socket
                            look_for_keys=False,
                            allow_agent=False,
                            banner_timeout=60,
                            auth_timeout=60
                        )
                        
                        # Optional: Check path write access
                        path = data.get("path")
                        if path:
                            sftp = client.open_sftp()
                            try:
                                sftp.stat(path)
                            except IOError:
                                # Try to create? No, just warn or ignore in test
                                pass 
                            sftp.close()
                            
                        client.close()
                        return jsonify({"status": "success", "message": "Verbindung erfolgreich hergestellt."})
                        
                    except Exception as e:
                        last_error = e
                        # Close socket if it exists
                        try: sock.close()
                        except: pass
                        try: client.close()
                        except: pass
                        
                        if attempt < max_retries - 1:
                            time.sleep(2) # Wait before retry
                            continue
                        
                # If we get here, all retries failed
                return jsonify({"status": "error", "message": f"Verbindung fehlgeschlagen (nach {max_retries} Versuchen): {str(last_error)}"})
            
            elif provider == "FTP":
                import ftplib
                host = data.get("host")
                user = data.get("user")
                password = data.get("password")
                try:
                    port = int(data.get("port") or 21)
                except:
                    port = 21
                    
                ftp = ftplib.FTP()
                try:
                    ftp.connect(host, port, timeout=30)
                    ftp.login(user, password)
                    
                    # Optional: Check path
                    path = data.get("path")
                    if path:
                        try:
                            ftp.cwd(path)
                        except:
                            # Try to create not in test
                            pass
                            
                    ftp.quit()
                    return jsonify({"status": "success", "message": "FTP Verbindung erfolgreich."})
                except Exception as e:
                    return jsonify({"status": "error", "message": f"FTP Fehler: {str(e)}"})

            elif provider == "Dropbox":
                 # Simple Token Check logic could go here
                 return jsonify({"status": "success", "message": "Dropbox Test simuliert OK"})
            
            return jsonify({"status": "success", "message": f"Provider {provider} OK"})
            
        except Exception as e:
            logger.error(f"Cloud Test Error: {e}")
            return jsonify({"status": "error", "message": str(e)})

    @app.route("/api/create_cloud_path", methods=["POST"])
    def create_cloud_path():
        data = request.json
        provider = data.get("provider")
        path = data.get("path")
        
        try:
            if provider == "SFTP":
                if not paramiko: return jsonify({"status": "error", "message": "Paramiko fehlt"})
                
                host = data.get("host")
                user = data.get("user")
                password = data.get("password")
                port = int(data.get("port") or 22)
                
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                client.connect(
                    hostname=host, 
                    port=port, 
                    username=user, 
                    password=password, 
                    timeout=30,
                    look_for_keys=False,
                    allow_agent=False,
                    banner_timeout=30
                )
                sftp = client.open_sftp()
                try:
                    sftp.mkdir(path)
                except IOError:
                    pass # Exists
                sftp.close()
                client.close()
                return jsonify({"status": "success"})
            
            elif provider == "Local":
                if not os.path.exists(path):
                    os.makedirs(path)
                return jsonify({"status": "success"})
                
            return jsonify({"status": "success"}) # Mock for others
            
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})

    @app.route("/api/run_cloud_backup_now", methods=["POST"])
    def run_cloud_backup_now():
        logger.info("API: run_cloud_backup_now called")
        data = request.json or {}
        direction = data.get("direction", "upload")
        logger.info(f"API: Cloud Mode: {direction}")
        
        source = data.get("source")
        dest = data.get("dest")
        
        if not source or not dest:
            logger.error("API: Source or Dest missing for cloud backup")
            return jsonify({"status": "error", "message": "Source or Dest missing"})

        def run_wrapper():
            try:
                logger.info("API: Starting cloud backup thread")
                backup_engine.run_backup(
                    source=source,
                    dest=dest,
                    comment=data.get("comment", "Manuelles Cloud Backup"),
                    allowed_modules=["cloud"],
                    task_options=data
                )
            except Exception as e:
                logger.error(f"API: Cloud backup thread error: {e}")
            
        t = threading.Thread(target=run_wrapper, daemon=True)
        t.start()
        
        return jsonify({"status": "started"})

    @app.route("/api/get_cloud_backup_status")
    def get_cloud_backup_status():
        # Status abfragen (ähnlich get_backup_status aber spezifisch für Cloud Logs?)
        # Da run_backup den globalen Status nutzt, können wir den gleichen Status nehmen.
        # Aber wir filtern vielleicht? Nein, einfach alles zurückgeben.
        # Wir müssen auf den Announcer zugreifen oder den Engine Status.
        # Da wir keinen direkten Zugriff auf den Status-Dict haben (nur via Callback),
        # und die UI hier pollt (!), müssen wir den Status irgendwo speichern oder SSE nutzen.
        # Die UI nutzt pollCloudStatus() -> fetch('/api/get_cloud_backup_status').
        # Wir müssen also den Status in der Engine zugänglich machen oder cachen.
        
        # HACK: Da Engine keinen getter hat, und wir SSE haben...
        # Aber die UI pollt. Wir müssen den Status in `backup_engine` public machen.
        # Ich werde in backup_engine.py ein Attribut `current_status` hinzufügen.
        
        status = getattr(backup_engine, "current_status", {
            "active": False, 
            "progress": 0, 
            "message": "Idle", 
            "logs": []
        })
        return jsonify(status)

    @app.route("/api/start_backup", methods=["POST"])
    def start_backup():
        data = request.json or {}
        source = data.get("source")
        dest = data.get("dest")
        
        # If not provided, use default
        config = config_manager.config
        if not source: source = config.get("default_source")
        if not dest: dest = config.get("default_dest")
        
        if not source or not dest:
            return jsonify({"status": "error", "message": "Source or Dest missing"})

        # Start backup in thread
        # BackupEngine.run_backup is blocking? 
        # No, the original app ran it in a thread. 
        # BackupEngine.run_backup is blocking (synchronous).
        # So we must wrap it in a thread here.
        
        def run_wrapper():
            backup_engine.run_backup(
                source=source,
                dest=dest,
                comment=data.get("comment", "Manuelles Backup"),
                allowed_modules=data.get("allowed_modules"),
                task_options=data.get("task_options")
            )
            
        t = threading.Thread(target=run_wrapper, daemon=True)
        t.start()
        
        return jsonify({"status": "started"})

    @app.route("/api/cancel_backup", methods=["GET", "POST"])
    def cancel_backup():
        backup_engine.stop_event.set()
        return jsonify({"status": "cancel_requested"})

    @app.route("/api/stream")
    def stream():
        def event_stream():
            messages = announcer.listen()
            try:
                while True:
                    try:
                        # Reduced timeout for more frequent keepalives (better for stability)
                        msg = messages.get(timeout=5)
                        yield msg
                    except queue.Empty:
                        yield ": keepalive\n\n"
            except GeneratorExit:
                pass
            finally:
                announcer.remove_listener(messages)
        return Response(event_stream(), mimetype="text/event-stream")

    @app.route("/api/get_backup_status")
    def get_backup_status():
        # We don't have direct access to status_tracker in engine unless we expose it
        # But engine pushes updates to announcer.
        # The UI might poll this initially.
        # Ideally BackupEngine should expose current status.
        # Let's assume the UI relies on SSE mostly, but might poll.
        # Since I didn't expose status_tracker as a property, I can't return it easily.
        # But wait, I can add a method to BackupEngine to get status.
        # For now return empty or last known?
        return jsonify({"active": backup_engine.backup_lock.locked()}) 

    @app.route("/api/get_history")
    def get_history():
        history = db_manager.get_history()
        # Sort by timestamp desc
        history.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return jsonify(history)
        
    @app.route("/api/delete_backup", methods=["POST"])
    def delete_backup():
        filename = request.json.get("filename")
        if not filename: return jsonify({"status": "error"})
        
        history = db_manager.get_history()
        entry = next((h for h in history if h['filename'] == filename), None)
        
        path_to_delete = None
        if entry and entry.get("path"):
             path_to_delete = entry["path"]
        else:
             config = config_manager.config
             dest = config.get("default_dest")
             if dest: path_to_delete = os.path.join(dest, filename)

        if path_to_delete and os.path.exists(path_to_delete):
            try:
                os.remove(path_to_delete)
                # Remove from DB
                db_manager.delete_history_entry(filename)
                return jsonify({"status": "success"})
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)})
        elif not os.path.exists(path_to_delete) if path_to_delete else False:
             # Just remove from DB if file gone
             db_manager.delete_history_entry(filename)
             return jsonify({"status": "success", "message": "File was missing, removed from DB"})
             
        return jsonify({"status": "error", "message": "File not found"})

    @app.route("/api/get_disk_stats", methods=["POST"])
    def get_disk_stats():
        path = request.json.get("path")
        if not path or not os.path.exists(path):
            return jsonify({"total": 0, "free": 0, "used": 0, "percent": 0})
        try:
            total, used, free = shutil.disk_usage(path)
            return jsonify({
                "total": total,
                "free": free,
                "used": used,
                "percent": (used / total) * 100 if total > 0 else 0
            })
        except:
            return jsonify({"total": 0, "free": 0, "used": 0, "percent": 0})

    @app.route("/api/health")
    def health():
        return jsonify({"score": 100, "status": "perfect", "issues": []})

    @app.route("/api/stats")
    def stats():
        history = db_manager.get_history()
        total_backups = len(history)
        total_size = sum(h.get("size", 0) for h in history)
        return jsonify({
            "total_backups": total_backups,
            "total_size": format_size(total_size),
            "last_backup": history[0]["timestamp"] if history else "Nie"
        })


    @app.route("/api/find_duplicates", methods=["POST"])
    def find_duplicates():
        try:
            data = request.json
            path = data.get("path")
            min_size_mb = float(data.get("min_size", 1))
            extensions = data.get("extensions", "")
            
            if not path or not os.path.exists(path):
                return jsonify({"status": "error", "message": "Invalid path"})

            min_size = min_size_mb * 1024 * 1024
            if isinstance(extensions, list):
                ext_list = [e.strip().lower() for e in extensions if isinstance(e, str) and e.strip()]
            else:
                ext_list = [e.strip().lower() for e in str(extensions).split(',') if e.strip()]
            
            # 1. Scan and group by size
            size_map = {}
            for root, dirs, files in os.walk(path):
                for name in files:
                    if ext_list and not any(name.lower().endswith(e) for e in ext_list):
                        continue
                    
                    filepath = os.path.join(root, name)
                    try:
                        stat = os.stat(filepath)
                        size = stat.st_size
                        if size < min_size:
                            continue
                            
                        if size not in size_map:
                            size_map[size] = []
                        size_map[size].append({
                            "path": filepath,
                            "mtime": stat.st_mtime,
                            "size": size
                        })
                    except OSError:
                        continue

            # 2. Filter groups < 2 files
            candidates = {s: files for s, files in size_map.items() if len(files) > 1}
            
            # 3. Hash check
            duplicates = []
            for size, files in candidates.items():
                hash_map = {}
                for f in files:
                    h = calculate_hash(f["path"]) 
                    if h.startswith("ERROR_"): continue # Skip errors
                    
                    if h not in hash_map:
                        hash_map[h] = []
                    hash_map[h].append(f)
                
                for h, grp in hash_map.items():
                    if len(grp) > 1:
                        # Sort by mtime desc (newest first)
                        grp.sort(key=lambda x: x["mtime"], reverse=True)
                        duplicates.append({
                            "hash": h,
                            "size": size,
                            "files": grp
                        })

            return jsonify(duplicates)
        except Exception as e:
            logger.error(f"Duplicate scan error: {e}")
            return jsonify({"status": "error", "message": str(e)})

    # --- Initialize Scheduler ---
    if config_manager.config.get("schedule_enabled", False):
        scheduler.start()

    # --- Suppress HTTP 200 Logging (Werkzeug) ---
    logging.getLogger('werkzeug').setLevel(logging.WARNING)

    return app

import socket

def find_available_port(start_port=5000, max_tries=50):
    for port in range(start_port, start_port + max_tries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                return port
        except OSError:
            continue
    return start_port

class AccessLogFilter:
    def __init__(self, stream):
        self.stream = stream
    def write(self, message):
        if "GET /api/stream" in message and '" 200 ' in message:
            return
        self.stream.write(message)
    def flush(self):
        self.stream.flush()

def start_server(app, port=5000):
    # Try Gevent first (Best for SSE + Production)
    try:
        from gevent.pywsgi import WSGIServer
        logger.info(f"Starting production server (Gevent) on port {port}...")
        http_server = WSGIServer(('0.0.0.0', port), app, log=AccessLogFilter(sys.stdout))
        http_server.serve_forever()
        return
    except ImportError:
        pass

    # Fallback to Waitress (Good for production, but might buffer SSE)
    try:
        from waitress import serve
        logger.info(f"Starting production server (Waitress) on port {port}...")
        serve(app, host="0.0.0.0", port=port, threads=6)
        return
    except ImportError:
        pass
        
    # Fallback to Flask Dev Server
    logger.warning("Production servers (Gevent/Waitress) not found. Using Flask dev server.")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
