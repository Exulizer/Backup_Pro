import sys
import os
import time

# Print immediate feedback
print("Initializing Backup Pro v8 core components...")

# Monkey patch for Gevent (must be before other imports)
try:
    from gevent import monkey
    monkey.patch_all()
except ImportError:
    pass

import threading
import logging
import webbrowser
import time

# Ensure we can import from local modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config.settings_manager import ConfigManager
from core.database import DatabaseManager
from core.backup_engine import BackupEngine
from core.scheduler import BackupScheduler
from gui.web_server import create_app, start_server, find_available_port
from utils.logger import setup_logging
from utils.i18n import init_translator

def main():
    # Init Components
    base_dir = os.path.dirname(os.path.abspath(__file__))
    setup_logging(os.path.join(base_dir, "backup_pro.log"))
    logger = logging.getLogger("Main")
    logger.info("Starting Backup Pro v8...")

    init_translator(base_dir)
    
    config_manager = ConfigManager(os.path.join(base_dir, "config", "backup_config.json"))
    db_manager = DatabaseManager(os.path.join(base_dir, "backup.db"))
    
    backup_engine = BackupEngine(config_manager, db_manager)
    scheduler = BackupScheduler(config_manager, backup_engine)
    
    # Start Scheduler
    scheduler.start()
    
    # Create Web App
    app = create_app(config_manager, db_manager, backup_engine, scheduler)
    
    # Find available port
    port = find_available_port(5000)
    
    # Start Browser (delayed)
    def open_browser():
        time.sleep(0.5)  # Reduced wait time
        webbrowser.open(f"http://127.0.0.1:{port}")
    
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Start Server
    logger.info(f"Starting Web Server on port {port}...")
    try:
        start_server(app, port=port)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        scheduler.stop()

if __name__ == "__main__":
    main()
