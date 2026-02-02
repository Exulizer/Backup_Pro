import json
import os
import threading
import logging

logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self, config_path):
        self.config_path = config_path
        self.lock = threading.Lock()
        self.config = {}
        self.last_mtime = 0
        self.load_config()

    def load_config(self):
        """Lädt die Konfiguration aus der Datei, nur wenn sie geändert wurde."""
        with self.lock:
            if os.path.exists(self.config_path):
                try:
                    current_mtime = os.path.getmtime(self.config_path)
                    if current_mtime == self.last_mtime:
                        return self.config
                    
                    with open(self.config_path, 'r', encoding='utf-8') as f:
                        self.config = json.load(f)
                    
                    self.last_mtime = current_mtime
                    logger.debug(f"Konfiguration geladen: {self.config_path}")
                except Exception as e:
                    logger.error(f"Fehler beim Laden der Konfiguration: {e}")
                    # Keep old config in case of read error? Or reset?
                    # Original behavior was reset, but maybe keeping old is safer?
                    # sticking to original behavior for now but ensuring valid dict
                    if not self.config: self.config = {}
            else:
                if self.last_mtime != 0: # Only log warning if it disappeared
                     logger.warning(f"Konfigurationsdatei nicht gefunden: {self.config_path}")
                self.config = {}
                self.last_mtime = 0
            return self.config

    def save_config(self, new_config=None):
        """Speichert die aktuelle Konfiguration in die Datei."""
        with self.lock:
            try:
                if new_config:
                    self.config.update(new_config)
                
                # Ensure directory exists
                os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
                
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    json.dump(self.config, f, indent=4, ensure_ascii=False)
                logger.info("Konfiguration gespeichert.")
                return True
            except Exception as e:
                logger.error(f"Fehler beim Speichern der Konfiguration: {e}")
                return False

    def get(self, key, default=None):
        """Thread-safe getter."""
        with self.lock:
            return self.config.get(key, default)

    def set(self, key, value):
        """Thread-safe setter (saves automatically)."""
        with self.lock:
            self.config[key] = value
        self.save_config()

    def update(self, new_data):
        """Aktualisiert mehrere Werte gleichzeitig."""
        with self.lock:
            self.config.update(new_data)
        self.save_config()
