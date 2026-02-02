import os
import time
import json
import errno
import hashlib
import fnmatch
import logging

logger = logging.getLogger(__name__)

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

def is_excluded(item_name, exclusions):
    """Prüft, ob eine Datei oder ein Ordner von der Sicherung ausgeschlossen werden soll."""
    if not exclusions:
        return False
    for pattern in exclusions:
        if fnmatch.fnmatch(item_name, pattern) or pattern in item_name:
            return True
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
            return "ERROR_FILE_NOT_FOUND"
        
        # Ignoriere Verzeichnisse oder spezielle Links
        if os.path.isdir(file_path):
            return "ERROR_IS_DIRECTORY"
            
        if not os.path.isfile(file_path):
            return "ERROR_NOT_A_FILE"

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
        
    except PermissionError:
        return "ERROR_ACCESS_DENIED"
    except OSError as e:
        # Errno 22 = Invalid Argument (häufig bei OneDrive "Online Only" Dateien oder zu langen Pfaden)
        if e.errno == 22:
            return "ERROR_INVALID_ARGUMENT" 
        logger.error(f"OS Fehler beim Hashen für {file_path}: {e}")
        return "ERROR_OS"
    except Exception as e:
        logger.error(f"Fehler beim Berechnen des Hashes für {file_path}: {e}")
        return "ERROR_UNKNOWN"

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
