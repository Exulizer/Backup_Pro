import os
import shutil
import zipfile
import time
import datetime
import logging
import threading
import stat
from datetime import datetime
import json

from config.settings_manager import ConfigManager
from core.database import DatabaseManager
from utils.file_system import format_size, is_excluded, calculate_hash
from utils.i18n import tr

logger = logging.getLogger(__name__)

def remove_readonly(func, path, excinfo):
    """
    Helper for shutil.rmtree to remove read-only files (common on Windows).
    """
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass

# Optional Cloud Modules
try:
    import paramiko
except ImportError:
    paramiko = None

try:
    import requests
except ImportError:
    requests = None

try:
    import boto3
except ImportError:
    boto3 = None

try:
    import dropbox
    from dropbox.files import WriteMode
except ImportError:
    dropbox = None

import concurrent.futures

class BackupEngine:
    def __init__(self, config_manager: ConfigManager, db_manager: DatabaseManager):
        self.config_manager = config_manager
        self.db_manager = db_manager
        self.backup_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.pause_event.set() # Initially running (not paused)
        self.global_status_callback = None
        self.current_status = {} # Public status for polling

    def set_status_callback(self, callback):
        self.global_status_callback = callback

    def run_backup(self, source, dest, comment="Automatisches Backup", custom_filename_prefix=None, task_options=None, allowed_modules=None, status_callback=None):
        """
        Haupt-Backup-Logik.
        status_callback: function(status_dict) called on updates.
        """
        # Use provided callback or global one
        callback = status_callback if status_callback else self.global_status_callback

        # Clear stop event at the start of a new run
        self.stop_event.clear()

        if not self.backup_lock.acquire(blocking=False):
            logger.warning("Backup läuft bereits. Abgelehnt.")
            return {"status": "error", "message": "Backup läuft bereits."}

        # Initialize status tracker
        status_tracker = {
            "active": True,
            "progress": 0,
            "step": "init",
            "message": "",
            "logs": [],
            "abort_requested": False,
            "result": None
        }

        def log_status(msg, type="info", updates=None):
            try:
                timestamp = datetime.now().strftime("%H:%M:%S")
                if updates:
                    status_tracker.update(updates)
                
                # Check for abort
                if self.stop_event.is_set():
                    status_tracker["abort_requested"] = True

                prefix = ""
                if allowed_modules:
                    prefix = f"[{'|'.join(allowed_modules).upper()}] "
                
                entry = None
                if msg:
                    entry = f"[{timestamp}] {prefix}[{type.upper()}] {msg}"
                    if "logs" not in status_tracker:
                        status_tracker["logs"] = []
                    status_tracker["logs"].append(entry)
                    if type == "error":
                        logger.error(msg)
                    elif type == "warning":
                        logger.warning(msg)
                    else:
                        logger.info(msg)

                if callback:
                    status_payload = {
                        "kind": "status",  # Changed from status_update to status for frontend compatibility
                        "log_entry": entry,
                        "active": status_tracker.get("active"),
                        "progress": status_tracker.get("progress"),
                        "step": status_tracker.get("step"),
                        "message": status_tracker.get("message"),
                        "logs": status_tracker.get("logs"),
                        "result": status_tracker.get("result")
                    }
                    self.current_status = status_payload # Update public status
                    callback(status_payload)
            except Exception as e:
                logger.error(f"Error in log_status: {e}")

        try:
            self.stop_event.clear()
            job_name = comment if comment else "Manuelles Backup"
            log_status(tr("backup.validating", f"Initialisiere: {job_name}..."), updates={"job_name": job_name})

            # Load Config
            config = self.config_manager.config.copy() # Copy to allow runtime overrides
            if task_options:
                config.update(task_options)
            
            # Map UI keys to Config keys if needed
            if "naming_custom" in config: config["naming_custom_text"] = config["naming_custom"]
            if "naming_date" in config: config["naming_include_date"] = config["naming_date"]
            if "naming_time" in config: config["naming_include_time"] = config["naming_time"]
            if "naming_seq" in config: config["naming_include_seq"] = config["naming_seq"]

            # Map Cloud Zip Download if not explicitly set
            if "cloud_zip_download" in config and "zip_download" not in config:
                config["zip_download"] = config["cloud_zip_download"]

            # --- Check Direction ---
            # If task_options has 'direction' or config has 'cloud_direction'
            direction = "upload"
            if task_options and task_options.get("direction"):
                direction = task_options.get("direction")
            elif config.get("cloud_direction"):
                direction = config.get("cloud_direction")

            # Strict Isolation: If direction is Download, NEVER proceed to standard backup logic.
            # This applies to both manual triggers (allowed_modules=['cloud']) AND automated backups if misconfigured.
            if direction == "download":
                if allowed_modules and "cloud" in allowed_modules:
                    # --- Cloud Download Mode (Manual/Isolated) ---
                    log_status(tr("backup.startDownload", "Starte Cloud Download (Restore)..."), "info")
                    try:
                        dl_stats = self.run_cloud_download(config, dest, log_status)
                        
                        # Add History Entry for Download
                        self.db_manager.add_history_entry(
                            filename=os.path.basename(dl_stats["path"]),
                            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            size=dl_stats["size"],
                            sha256="", 
                            path=dl_stats["path"],
                            source_path=config.get("cloud_target_path", "Cloud"),
                            comment="Cloud Download",
                            file_count=dl_stats["files"],
                            source_size=dl_stats["size"]
                        )
                        
                        log_status(tr("backup.downloadSuccess", "Cloud Download erfolgreich."), "success", updates={"active": False, "progress": 100, "step": "done", "result": {"status": "success", "message": "Download finished"}})
                        return {"status": "success", "message": "Download finished"}
                    except Exception as e:
                        log_status(f"Cloud Download Fehler: {e}", "error", updates={"active": False, "step": "error"})
                        return {"status": "error", "message": str(e)}
                else:
                    # If this is a standard scheduled backup but direction is set to Download,
                    # we should probably LOG A WARNING and SKIP the Cloud part, proceeding with local backup ONLY.
                    # Or we should respect "Download" as "Restore to Backup Folder" (dangerous).
                    # Safest approach: If it's a scheduled backup (allowed_modules=None) and direction=Download, 
                    # we treat it as "Local Backup Only" and disable Cloud Upload to prevent overwriting cloud data or downloading unwanted files.
                    log_status("WARNUNG: Cloud-Richtung ist auf 'Download' gestellt. Cloud-Upload wird für dieses Backup übersprungen.", "warning")
                    # Temporarily disable cloud sync for this run to avoid uploading
                    if config.get("cloud_sync_enabled"):
                        config["cloud_sync_enabled"] = False

            # --- Validation ---
            log_status(tr("backup.validating", "Validiere Pfade..."), "debug")
            is_multi_file = "|" in source
            
            scan_paths = []
            if is_multi_file:
                scan_paths = [p.strip() for p in source.split("|") if p.strip()]
                if not any(os.path.exists(p) for p in scan_paths):
                    raise Exception(tr("backup.noValidFiles", "FEHLER: Keine der ausgewählten Dateien existiert."))
            else:
                if not os.path.exists(source):
                     raise Exception(tr("backup.sourceMissing", "FEHLER: Quellpfad existiert nicht: {path}", path=source))
                scan_paths = [source]

            if not os.path.exists(dest):
                try:
                    log_status(tr("backup.creatingDest", "Erstelle Zielverzeichnis: {path}", path=dest), "info")
                    os.makedirs(dest)
                except Exception as e:
                    raise Exception(tr("backup.destCreateFail", "FEHLER: Zielpfad konnte nicht erstellt werden: {path}", path=dest))

            # --- Free Space Check ---
            try:
                _, _, free_space = shutil.disk_usage(dest)
                if free_space < (500 * 1024 * 1024):
                    log_status(tr("backup.lowSpace", "WARNUNG: Nur noch {size} MB Speicherplatz!", size=f"{free_space/1024/1024:.1f}"), "warning")
            except:
                pass

            # --- Filename Generation ---
            now = datetime.now()
            custom_text = config.get("naming_custom_text", "backup")
            if custom_filename_prefix:
                custom_text = custom_filename_prefix
            
            inc_date = config.get("naming_include_date", True)
            inc_time = config.get("naming_include_time", True)
            inc_seq = config.get("naming_include_seq", False)
            seq_num = config.get("naming_seq_counter", 1)

            name_parts = []
            if custom_text: name_parts.append(custom_text)
            if inc_date: name_parts.append(now.strftime("%Y-%m-%d"))
            if inc_time: name_parts.append(now.strftime("%H-%M-%S"))
            if inc_seq: name_parts.append(f"{seq_num:03d}")
            if not name_parts: name_parts.append(f"backup_{now.strftime('%Y-%m-%d_%H-%M-%S')}")

            zip_filename = "_".join(name_parts) + ".zip"
            zip_path = os.path.join(dest, zip_filename)

            # --- Archiving ---
            log_status(tr("backup.analyzing", "Analysiere Dateistruktur (Parallel)..."), "info", updates={"step": "archiving", "progress": 5})
            
            # File Scanning with Progress (Parallelized)
            files_to_backup = []
            total_size = 0
            exclusions = [x.strip() for x in config.get("exclusions", "").split(",") if x.strip()]

            last_scan_update = time.time()
            scanned_count = 0
            scan_lock = threading.Lock()

            def process_directory(path, root_path):
                nonlocal total_size, scanned_count, last_scan_update
                local_entries = []
                subdirs = []
                
                try:
                    with os.scandir(path) as it:
                        for entry in it:
                            if self.stop_event.is_set(): return [], []
                            
                            if is_excluded(entry.name, exclusions):
                                continue
                                
                            if entry.is_file():
                                try:
                                    f_size = entry.stat().st_size
                                    rel_path = os.path.relpath(entry.path, root_path)
                                    local_entries.append((entry.path, rel_path, f_size))
                                except OSError:
                                    pass
                            elif entry.is_dir():
                                subdirs.append((entry.path, root_path))
                except OSError as e:
                    logger.warning(f"Zugriff verweigert auf {path}: {e}")
                
                return local_entries, subdirs

            # Use ThreadPool for scanning
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                futures = []
                
                # Initial tasks
                for path in scan_paths:
                    if os.path.isfile(path):
                         with scan_lock:
                            files_to_backup.append((path, os.path.basename(path)))
                            total_size += os.path.getsize(path)
                            scanned_count += 1
                    else:
                        futures.append(executor.submit(process_directory, path, path))
                
                while futures:
                    if self.stop_event.is_set(): raise Exception("Benutzerabbruch")
                    
                    # Wait for first to complete
                    done, not_done = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                    futures = list(not_done)
                    
                    for future in done:
                        try:
                            entries, subdirs = future.result()
                            
                            with scan_lock:
                                for p, rp, s in entries:
                                    files_to_backup.append((p, rp))
                                    total_size += s
                                    scanned_count += 1
                                    
                                # Update status occasionally
                                current_time = time.time()
                                if current_time - last_scan_update > 0.5:
                                    last_scan_update = current_time
                                    log_status(None, updates={"message": tr("backup.analyzingCount", "Analysiere... {count} Dateien gefunden", count=scanned_count)})
                            
                            # Add new tasks
                            for sd_path, sd_root in subdirs:
                                futures.append(executor.submit(process_directory, sd_path, sd_root))
                                
                        except Exception as e:
                            logger.error(f"Scan error: {e}")

            log_status(tr("backup.startZip", "Starte Komprimierung ({count} Dateien, {size})...", count=len(files_to_backup), size=format_size(total_size)), "info")
            
            processed_size = 0
            last_pct = 0
            
            comp_level = int(config.get("compression_level", 3))
            compression = zipfile.ZIP_DEFLATED
            
            with zipfile.ZipFile(zip_path, 'w', compression=compression, compresslevel=comp_level) as zipf:
                for src_path, arcname in files_to_backup:
                    if self.stop_event.is_set(): raise Exception("Benutzerabbruch")
                    
                    f_size = os.path.getsize(src_path)
                    
                    # Optimize: Use standard write for files < 10MB for speed
                    if f_size < 10 * 1024 * 1024:
                         zipf.write(src_path, arcname)
                    else:
                         # Use chunked write for large files to allow cancellation
                         self.write_file_to_zip_chunked(zipf, src_path, arcname, self.stop_event)
                    
                    processed_size += f_size
                    pct = int((processed_size / total_size) * 100) if total_size > 0 else 100
                    
                    # Update progress every 1%
                    if pct > last_pct:
                        last_pct = pct
                        log_status(None, updates={"progress": 5 + int(pct * 0.85)}) # Scale to 90%

            log_status(tr("backup.zipCreated", "Archiv erstellt: {name}", name=zip_filename), "success", updates={"progress": 90})
            zip_size = os.path.getsize(zip_path)

            # --- Hashing ---
            log_status("Berechne Checksumme...", "info")
            sha = calculate_hash(zip_path)

            # --- Database ---
            self.db_manager.add_history_entry(
                filename=zip_filename,
                timestamp=now.strftime("%Y-%m-%d %H:%M:%S"),
                size=zip_size,
                sha256=sha,
                path=dest,
                source_path=source,
                comment=comment,
                file_count=len(files_to_backup),
                source_size=total_size
            )

            # --- Retention ---
            if config.get("retention_count", 10) > 0:
                 self.apply_retention(dest, config.get("retention_count", 10))

            # --- Cloud Upload ---
            if config.get("cloud_sync_enabled", False) and (not allowed_modules or "cloud" in allowed_modules):
                 self.run_cloud_upload(config, zip_path, zip_filename, log_status)

            log_status(tr("backup.success", "Backup erfolgreich beendet. Größe: {size}", size=format_size(zip_size)), "success", updates={"active": False, "progress": 100, "step": "done", "result": {"status": "success", "file": zip_filename}})
            
            return {"status": "success", "file": zip_filename, "sha256": sha}

        except Exception as e:
            if "Benutzerabbruch" in str(e):
                log_status(tr("backup.userAbortShort", "Abgebrochen durch Benutzer."), "warning", updates={"active": False, "step": "aborted"})
                # Cleanup
                if 'zip_path' in locals() and os.path.exists(zip_path):
                    try: os.remove(zip_path)
                    except: pass
                return {"status": "aborted", "message": "Benutzerabbruch"}
            
            log_status(f"Fehler: {str(e)}", "error", updates={"active": False, "step": "error"})
            return {"status": "error", "message": str(e)}
        finally:
            self.backup_lock.release()

    def write_file_to_zip_chunked(self, zip_file, source_path, arcname, stop_event, chunk_size=16*1024*1024):
        """
        Writes a file to the zip archive in chunks to allow cancellation checks.
        Optimized chunk size for better throughput.
        """
        if stop_event.is_set(): raise Exception("Benutzerabbruch")
        
        try:
            zinfo = zipfile.ZipInfo.from_file(source_path, arcname)
            zinfo.compress_type = zip_file.compression
            
            with zip_file.open(zinfo, 'w') as dest:
                with open(source_path, 'rb') as src:
                    while True:
                        if stop_event.is_set(): raise Exception("Benutzerabbruch")
                        chunk = src.read(chunk_size)
                        if not chunk: break
                        dest.write(chunk)
        except Exception as e:
            if "Benutzerabbruch" in str(e): raise
            raise Exception(f"Fehler beim chunked write: {e}")

    def apply_retention(self, dest_path, limit):
        # Implementation of retention logic (similar to original)
        # Needs to interact with DB to check locked status
        try:
            history = self.db_manager.get_history() # Need to implement this in DatabaseManager
            locked_filenames = {h['filename'] for h in history if h.get('locked', 0)}
            
            files = [f for f in os.listdir(dest_path) if f.endswith(".zip") and "backup" in f] # Simple filter
            files.sort() # Chronological if naming convention is kept
            
            deletable = [f for f in files if f not in locked_filenames]
            
            while len(deletable) > limit:
                to_delete = deletable.pop(0)
                try:
                    os.remove(os.path.join(dest_path, to_delete))
                    self.db_manager.delete_history_entry(filename=to_delete) # Need implement
                    logger.info(f"Retention: Deleted {to_delete}")
                except Exception as e:
                    logger.error(f"Retention Error: {e}")
        except Exception as e:
            logger.error(f"Retention Logic Error: {e}")

    def run_cloud_download(self, config, local_dest, log_callback):
        """
        Downloads files from Cloud to Local Dest.
        Supports optional Zipping via config['zip_download'].
        """
        provider = config.get("cloud_provider", "SFTP")
        zip_download = config.get("zip_download", False)
        
        # Determine actual download target
        download_dest = local_dest
        temp_dir = None
        
        dl_count = 0
        dl_size = 0
        final_path = local_dest
        
        if zip_download:
            temp_dir = os.path.join(local_dest, ".temp_cloud_download")
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, onerror=remove_readonly)
            os.makedirs(temp_dir)
            download_dest = temp_dir
            log_callback(f"Download-Modus: ZIP (Temporär: {temp_dir})", "info")
        else:
            log_callback("Download-Modus: RAW (Dateien direkt)", "info")
            
        log_callback(f"Starte Cloud Download ({provider})...", "info", updates={"step": "cloud_download"})
        
        try:
            try:
                if provider == "SFTP":
                    if not paramiko: raise Exception("Paramiko Modul fehlt.")
                    host = config.get("cloud_host")
                    user = config.get("cloud_user")
                    password = config.get("cloud_password")
                    port = int(config.get("cloud_port", 22))
                    remote_path = config.get("cloud_target_path", "/backups")
                    
                    log_callback(f"SFTP: Verbinde zu {host}:{port}...", "info")
                    
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    # Retry logic for connection
                    for attempt in range(3):
                        try:
                            import socket
                            sock = socket.create_connection((host, port), timeout=30)
                            client.connect(host, port, user, password, sock=sock, look_for_keys=False, allow_agent=False)
                            break
                        except Exception as e:
                            if attempt == 2: raise e
                            time.sleep(2)

                    sftp = client.open_sftp()
                    
                    # Check if remote_path is file or dir
                    try:
                        attr = sftp.stat(remote_path)
                        is_dir = str(attr).startswith('d')
                    except IOError:
                        raise Exception(f"Remote Pfad nicht gefunden: {remote_path}")

                    if not os.path.exists(download_dest):
                        os.makedirs(download_dest)

                    if not is_dir:
                        # Single file
                        local_file = os.path.join(download_dest, os.path.basename(remote_path))
                        log_callback(f"SFTP: Downloade Datei {remote_path}...", "info", updates={"message": f"Downloading {os.path.basename(remote_path)}...", "progress": 10})
                        sftp.get(remote_path, local_file)
                        dl_count += 1
                        dl_size += os.path.getsize(local_file)
                        log_callback(f"SFTP: Datei geladen.", "info", updates={"progress": 40 if zip_download else 95})
                    else:
                        # Directory - Recursive Download
                        log_callback(f"SFTP: Downloade Verzeichnis {remote_path}...", "info", updates={"message": "Downloading Directory...", "progress": 10})
                        
                        current_progress = 10.0
                        
                        def download_dir(rem_dir, loc_dir):
                            nonlocal dl_count, dl_size, current_progress
                            if not os.path.exists(loc_dir):
                                os.makedirs(loc_dir)
                            for entry in sftp.listdir_attr(rem_dir):
                                rem_path = rem_dir + "/" + entry.filename
                                loc_path = os.path.join(loc_dir, entry.filename)
                                if str(entry).startswith('d'):
                                    download_dir(rem_path, loc_path)
                                else:
                                    if self.stop_event.is_set(): raise Exception("Abbruch")
                                    
                                    # Asymptotic Progress Calculation based on file count
                                    # This ensures it keeps moving even with thousands of files
                                    # Download Phase: 10% -> 80% (if zip) or 95% (if raw)
                                    start_prog = 10.0
                                    max_dl_prog = 80.0 if zip_download else 95.0
                                    prog_range = max_dl_prog - start_prog
                                    
                                    # Formula: start + range * (1 - 1 / (1 + k * count))
                                    # k=0.005 means 50% of range at 200 files, 83% at 1000 files, 98% at 10000 files
                                    k_factor = 0.005 
                                    
                                    current_progress = start_prog + prog_range * (1 - 1 / (1 + k_factor * dl_count))
                                    
                                    log_callback(f"Geladen: {entry.filename}", "info", updates={"message": f"Download: {entry.filename}", "progress": int(current_progress)})
                                    sftp.get(rem_path, loc_path)
                                    dl_count += 1
                                    dl_size += os.path.getsize(loc_path)
                        
                        download_dir(remote_path, download_dest)

                    sftp.close()
                    client.close()
                    
                elif provider == "FTP":
                    import ftplib
                    host = config.get("cloud_host")
                    user = config.get("cloud_user")
                    password = config.get("cloud_password")
                    port = int(config.get("cloud_port", 21))
                    remote_path = config.get("cloud_target_path", "/backups")
                    
                    log_callback(f"FTP: Verbinde zu {host}:{port}...", "info", updates={"message": "Connecting FTP...", "progress": 5})
                    ftp = ftplib.FTP()
                    ftp.connect(host, port, timeout=30)
                    ftp.login(user, password)
                    
                    if not os.path.exists(download_dest):
                        os.makedirs(download_dest)
                        
                    # Check if file or dir? FTP is tricky. assume dir if no extension, or try cwd
                    is_dir = False
                    try:
                        ftp.cwd(remote_path)
                        is_dir = True
                    except:
                        is_dir = False
                    
                    if not is_dir:
                        # File
                        local_file = os.path.join(download_dest, os.path.basename(remote_path))
                        log_callback(f"FTP: Downloade Datei {remote_path}...", "info", updates={"message": f"Downloading {os.path.basename(remote_path)}...", "progress": 10})
                        with open(local_file, 'wb') as f:
                            ftp.retrbinary(f"RETR {remote_path}", f.write)
                        dl_count += 1
                        dl_size += os.path.getsize(local_file)
                        log_callback(f"FTP: Datei geladen.", "info", updates={"progress": 40 if zip_download else 95})
                    else:
                        # Dir
                        log_callback(f"FTP: Downloade Ordner {remote_path}...", "info", updates={"message": "Downloading Directory...", "progress": 10})
                        # Simple non-recursive for now or shallow
                        filenames = ftp.nlst()
                        current_progress = 10.0
                        
                        for fname in filenames:
                            if self.stop_event.is_set(): raise Exception("Abbruch")
                            local_f = os.path.join(download_dest, fname)
                            try:
                                # Asymptotic Progress Calculation based on file count
                                start_prog = 10.0
                                max_dl_prog = 80.0 if zip_download else 95.0
                                prog_range = max_dl_prog - start_prog
                                k_factor = 0.005 
                                
                                current_progress = start_prog + prog_range * (1 - 1 / (1 + k_factor * dl_count))
                                
                                log_callback(f"Geladen: {fname}", "info", updates={"message": f"Download: {fname}", "progress": int(current_progress)})
                                with open(local_f, 'wb') as f:
                                    ftp.retrbinary(f"RETR {fname}", f.write)
                                dl_count += 1
                                dl_size += os.path.getsize(local_f)
                            except:
                                pass # Skip subdirs in simple mode
                    
                    ftp.quit()
                    
                # --- Zip Logic ---
                if zip_download and temp_dir:
                    log_callback("Analysiere Dateien für ZIP...", "info", updates={"message": "Preparing Zip...", "progress": 10})
                    
                    # 1. Count total files
                    total_files_to_zip = 0
                    files_list = []
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            files_list.append(os.path.join(root, file))
                    total_files_to_zip = len(files_list)

                    log_callback(f"Erstelle ZIP-Archiv ({total_files_to_zip} Dateien)...", "info", updates={"message": "Zipping...", "progress": 80})
                    
                    now = datetime.now()
                    custom_text = config.get("naming_custom_text", "cloud_restore")
                    # Clean filename
                    custom_text = "".join([c for c in custom_text if c.isalnum() or c in ('-', '_')])
                    
                    zip_name = f"{custom_text}_{now.strftime('%Y-%m-%d_%H-%M-%S')}.zip"
                    zip_path = os.path.join(local_dest, zip_name)
                    
                    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        for idx, file_path in enumerate(files_list):
                             arcname = os.path.relpath(file_path, temp_dir)
                             zipf.write(file_path, arcname)
                             
                             # Update Progress (80% -> 95%)
                             pct = int(((idx + 1) / total_files_to_zip) * 15) + 80 
                             if idx % 5 == 0 or idx == total_files_to_zip - 1:
                                 log_callback(None, "info", updates={"message": f"Zipping: {os.path.basename(file_path)}", "progress": pct})
                                
                    log_callback(f"ZIP erstellt: {zip_name}", "success", updates={"progress": 95, "message": "Zip Created"})
                    final_path = zip_path
                    dl_size = os.path.getsize(zip_path) # Update size to zip size
                    dl_count = 1 # Update count to 1 (the zip file)
                    
                log_callback("Cloud Download erfolgreich.", "success", updates={"progress": 95, "message": "Done"})
                return {"files": dl_count, "size": dl_size, "path": final_path}
                
            except Exception as e:
                log_callback(f"Cloud Download Fehler: {e}", "error")
                raise e
        finally:

            # Robust Cleanup of Temp Directory
            if temp_dir and os.path.exists(temp_dir):
                log_callback("Bereinige temporäre Dateien...", "debug")
                for i in range(5): # Try 5 times
                    try:
                        # 1. Clear attributes (Windows specific) to handle hidden/system files like .gitignore
                        if os.name == 'nt':
                            # Use subprocess to avoid console window popping up if possible, or just os.system
                            # attrib -R -S -H /S /D "path\*"
                            os.system(f'attrib -R -S -H /S /D "{temp_dir}\\*" >nul 2>&1')
                        
                        # 2. Try Python delete
                        shutil.rmtree(temp_dir, onerror=remove_readonly)
                        
                        if not os.path.exists(temp_dir): break
                    except Exception:
                        pass
                        
                    # 3. Force Shell Delete if still exists (Windows)
                    if os.path.exists(temp_dir) and os.name == 'nt':
                        os.system(f'rmdir /s /q "{temp_dir}" >nul 2>&1')
                    
                    if not os.path.exists(temp_dir): break
                    
                    time.sleep(1)
                
                # Final check
                if os.path.exists(temp_dir):
                      log_callback("WARNUNG: Konnte temporären Ordner nicht vollständig entfernen.", "warning")

    def run_cloud_upload(self, config, zip_path, zip_filename, log_callback):
        provider = config.get("cloud_provider", "SFTP")
        log_callback(f"Starte Cloud Upload ({provider})...", "info", updates={"step": "cloud"})
        
        try:
            if provider == "SFTP":
                if not paramiko: raise Exception("Paramiko Modul fehlt.")
                host = config.get("cloud_host")
                user = config.get("cloud_user")
                password = config.get("cloud_password")
                port = int(config.get("cloud_port", 22))
                remote_path = config.get("cloud_target_path", "/backups")
                
                log_callback(f"SFTP: Verbinde zu {host}:{port} als {user}...", "info")
                
                # Retry Logic
                max_retries = 3
                last_error = None
                
                for attempt in range(max_retries):
                    client = None
                    sock = None
                    try:
                        # Use SSHClient for better compatibility and AutoAddPolicy
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        
                        # Manually create socket to control TCP timeouts
                        import socket
                        sock = socket.create_connection((host, port), timeout=60)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                        # Small delay to allow banner to arrive (Hetzner fix)
                        time.sleep(0.5)

                        client.connect(
                            hostname=host, 
                            port=port, 
                            username=user, 
                            password=password, 
                            sock=sock,
                            look_for_keys=False,
                            allow_agent=False,
                            banner_timeout=60,
                            auth_timeout=60
                        )
                        log_callback("SFTP: SSH Verbindung hergestellt.", "info")
                        
                        sftp = client.open_sftp()
                        log_callback("SFTP: Kanal geöffnet.", "info")
                        
                        try: 
                            sftp.mkdir(remote_path)
                        except: 
                            pass # Assume exists
                        
                        remote_file = f"{remote_path}/{zip_filename}".replace("//", "/")
                        file_size = os.path.getsize(zip_path)
                        log_callback(f"SFTP: Starte Upload von {zip_filename} ({file_size} bytes) nach {remote_file}...", "info")
                        
                        # Progress callback for SFTP
                        def sftp_progress(transferred, total):
                            pct = int((transferred / total) * 100)
                            if pct > 0 and pct % 25 == 0 and pct < 100:
                                 pass

                        sftp.put(zip_path, remote_file, callback=sftp_progress)
                        log_callback("SFTP: Upload erfolgreich.", "success")
                        
                        sftp.close()
                        client.close()
                        return # Success!
                        
                    except Exception as e:
                        last_error = e
                        log_callback(f"SFTP Versuch {attempt+1}/{max_retries} fehlgeschlagen: {str(e)}", "warning")
                        try: 
                            if sftp: sftp.close()
                        except: pass
                        try: 
                            if client: client.close()
                        except: pass
                        try:
                            if sock: sock.close()
                        except: pass
                        
                        if attempt < max_retries - 1:
                            time.sleep(2)
                            continue
                
                # If loop finishes without return, it failed
                raise Exception(f"SFTP Upload fehlgeschlagen nach {max_retries} Versuchen. Letzter Fehler: {str(last_error)}")
                
            elif provider == "FTP":
                import ftplib
                host = config.get("cloud_host")
                user = config.get("cloud_user")
                password = config.get("cloud_password")
                port = int(config.get("cloud_port", 21))
                remote_path = config.get("cloud_target_path", "/backups")
                
                log_callback(f"FTP: Verbinde zu {host}:{port} als {user}...", "info")
                
                ftp = ftplib.FTP()
                try:
                    ftp.connect(host, port, timeout=30)
                    ftp.login(user, password)
                    log_callback("FTP: Eingeloggt.", "info")
                    
                    try:
                        ftp.cwd(remote_path)
                    except:
                        try:
                            ftp.mkd(remote_path)
                            ftp.cwd(remote_path)
                        except:
                            log_callback(f"FTP: Konnte Verzeichnis {remote_path} nicht erstellen/wechseln. Nutze Root.", "warning")
                    
                    file_size = os.path.getsize(zip_path)
                    log_callback(f"FTP: Starte Upload ({file_size} bytes)...", "info")
                    
                    with open(zip_path, 'rb') as f:
                        ftp.storbinary(f'STOR {zip_filename}', f)
                        
                    ftp.quit()
                    log_callback("FTP: Upload erfolgreich.", "success")
                except Exception as e:
                    log_callback(f"FTP Fehler: {e}", "error")
                    raise e

            elif provider == "Dropbox":
                if not dropbox: raise Exception("Dropbox Modul fehlt.")
                token = config.get("cloud_password") # Using password field for token
                dbx = dropbox.Dropbox(token)
                with open(zip_path, "rb") as f:
                    dbx.files_upload(f.read(), f"/{zip_filename}", mode=WriteMode("overwrite"))
                    
            # Add other providers (S3, WebDAV) similarly...
            
            log_callback(f"Cloud Upload ({provider}) erfolgreich.", "success")
            
        except Exception as e:
            log_callback(f"Cloud Upload Fehler: {e}", "error")
