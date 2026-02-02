import time
import threading
import logging
from datetime import datetime

from config.settings_manager import ConfigManager
from core.backup_engine import BackupEngine
from utils.i18n import tr

logger = logging.getLogger(__name__)

class BackupScheduler:
    def __init__(self, config_manager: ConfigManager, backup_engine: BackupEngine):
        self.config_manager = config_manager
        self.backup_engine = backup_engine
        self.stop_event = threading.Event()
        self.thread = None
        self.last_global_run = time.time()

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run_loop, daemon=True, name="BackupScheduler")
        self.thread.start()
        logger.info("BackupScheduler gestartet.")

    def stop(self):
        if self.thread:
            self.stop_event.set()
            self.thread.join(timeout=5)
            logger.info("BackupScheduler gestoppt.")

    def _run_loop(self):
        # Initial delay
        time.sleep(3)
        
        while not self.stop_event.is_set():
            try:
                self._check_and_run()
            except Exception as e:
                logger.error(f"Fehler im Scheduler Loop: {e}")
            
            # Wait for 10 seconds or until stopped
            if self.stop_event.wait(10):
                break

    def _check_and_run(self):
        # Reload config to get latest settings
        self.config_manager.load_config()
        config = self.config_manager.config
        
        # 1. Global Auto Backup
        if config.get("auto_backup_enabled", False):
            interval_min = config.get("auto_interval", 0)
            if interval_min > 0:
                interval_sec = interval_min * 60
                if time.time() - self.last_global_run >= interval_sec:
                    if self.backup_engine.backup_lock.locked():
                        logger.debug("Auto-Backup deferred: Backup läuft bereits.")
                    else:
                        logger.info("Globales Auto-Backup fällig.")
                        self._run_global_backup(config)
                        self.last_global_run = time.time()

        # 2. Task Specific Backup
        tasks = config.get("tasks", [])
        tasks_modified = False
        current_time = time.time()

        for task in tasks:
            if not task.get("active", True): continue
            
            interval = int(task.get("interval", 0))
            if interval <= 0: continue
            
            last_run = float(task.get("last_run", 0))
            if current_time - last_run >= interval * 60:
                if self.backup_engine.backup_lock.locked():
                     logger.debug(f"Task '{task.get('name')}' deferred: Backup läuft bereits.")
                     continue
                
                logger.info(f"Task Auto-Backup: '{task.get('name')}' fällig.")
                if self._run_task_backup(task):
                    task["last_run"] = current_time
                    tasks_modified = True

        if tasks_modified:
            self.config_manager.save_config(config)

    def _run_global_backup(self, config):
        source = config.get("default_source")
        dest = config.get("default_dest")
        if source and dest:
            self.backup_engine.run_backup(
                source=source,
                dest=dest,
                comment="System Auto-Snapshot"
            )

    def _run_task_backup(self, task):
        source = task.get("source")
        dest = task.get("dest")
        name = task.get("name", "Unnamed Task")
        
        if source and dest:
            task_opts = {
                "naming_include_date": task.get("naming_include_date", True),
                "naming_include_time": task.get("naming_include_time", True),
                "naming_include_seq": task.get("naming_include_seq", False)
            }
            res = self.backup_engine.run_backup(
                source=source,
                dest=dest,
                comment=f"Task: {name}",
                custom_filename_prefix=name,
                task_options=task_opts
            )
            return res.get("status") == "success"
        return False
