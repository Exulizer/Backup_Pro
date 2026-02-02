import logging
import json
import sys
import os

# --- Log Filtering & Formatting ---

class JSONFormatter(logging.Formatter):
    """Formatiert Logs als JSON-Zeilen für maschinelle Verarbeitung."""
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno
        }
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)

class EndpointFilter(logging.Filter):
    """Filtert erfolgreiche Status-Abfragen aus dem Log, um Spam zu vermeiden."""
    def filter(self, record):
        msg = record.getMessage()
        # Unterdrücke 200 OK Logs für Polling-/SSE-Endpunkte
        ignored_endpoints = [
            "/api/get_backup_status",
            "/api/get_events",
            "/api/get_cloud_backup_status",
            "/api/scan_progress",
            "/api/stream",
            "/api/stats",
            "/api/health",
            "/api/integrity_status",
            "/api/get_config",
            "/api/backup_plan",
            "/api/get_history",
            "/api/get_startup_tasks",
            "/api/get_disk_stats"
        ]
        if any(endpoint in msg for endpoint in ignored_endpoints) and " 200 " in msg:
            return False
        # Unterdrücke harmlose Disconnect-Logs für /api/stream (SSE schließt/verbindet oft neu)
        if "/api/stream" in msg and "Client disconnected while serving" in msg:
            return False
        return True

def setup_logging(log_file_path, debug_mode=False):
    """Konfiguriert das Logging System."""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG) # Root muss alles durchlassen, Handler filtern dann
    
    # Remove existing handlers to avoid duplicates on reload
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # 1. Console Handler (Normaler Text, gefiltert, INFO)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    console_handler.addFilter(EndpointFilter()) # Filter NUR für Konsole
    
    # 2. File Handler (JSON, ungefiltert, DEBUG)
    file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(JSONFormatter())
    # Kein Filter -> Schreibt ALLES (inkl. Polling Spam) für Debugging

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    return logging.getLogger(__name__)
