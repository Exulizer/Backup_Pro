import os
import json
import sqlite3
import sys
from datetime import datetime

# Konfiguration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "backup_history.db")
CONFIG_FILE = os.path.join(BASE_DIR, "backup_config.json")

def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"ERROR: Config file '{CONFIG_FILE}' not found.")
        return None
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"ERROR: Could not read config file: {e}")
        return None

def get_db_connection():
    if not os.path.exists(DB_FILE):
        print(f"ERROR: Database '{DB_FILE}' not found.")
        return None
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"ERROR: Could not connect to database: {e}")
        return None

def check_integrity():
    print("=== Backup Integrity Checker v1.0 ===")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # 1. Load Config
    config = load_config()
    if not config:
        return

    backup_path = config.get("default_dest")
    if not backup_path:
        print("WARNING: No 'default_dest' configured in backup_config.json.")
        # Try to guess or ask? For now just stop if critical info missing
        # But maybe we can still check absolute paths in DB.
    else:
        print(f"Configured Backup Path: {backup_path}")
        if not os.path.exists(backup_path):
            print(f"ERROR: Backup path does not exist on disk!")
            return

    # 2. Load DB History
    conn = get_db_connection()
    if not conn:
        return

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM history")
        rows = cursor.fetchall()
        db_entries = [dict(row) for row in rows]
    except Exception as e:
        print(f"ERROR: Could not query history table: {e}")
        conn.close()
        return

    print(f"Found {len(db_entries)} entries in Database.\n")

    # Stats
    missing_files = []
    orphaned_files = []
    valid_entries = 0

    # 3. Check DB -> Disk (Completeness)
    # Map filenames to entries for reverse check
    db_filenames = set()

    print("--- Checking DB Entries against Disk ---")
    for entry in db_entries:
        filename = entry.get('filename')
        db_filenames.add(filename)
        
        stored_path = entry.get('path')
        
        # Determine expected path
        actual_path = None
        if stored_path and os.path.exists(stored_path):
            actual_path = stored_path
        elif backup_path:
            # Fallback to default dir
            candidate = os.path.join(backup_path, filename)
            if os.path.exists(candidate):
                actual_path = candidate
        
        if actual_path:
            valid_entries += 1
            # Optional: Check size match?
            # size_on_disk = os.path.getsize(actual_path)
            # if size_on_disk != entry['size']:
            #     print(f"  [SIZE MISMATCH] {filename}: DB={entry['size']}, Disk={size_on_disk}")
        else:
            print(f"  [MISSING] {filename} (Expected at: {stored_path or 'Default Dir'})")
            missing_files.append(entry)

    # 4. Check Disk -> DB (Orphans)
    if backup_path and os.path.exists(backup_path):
        print("\n--- Checking Disk Files against DB ---")
        try:
            files = os.listdir(backup_path)
            # Filter for backup files (assuming zip and prefix from config if possible, but let's just check all zips)
            # A stricter check would use naming_custom_text
            
            for f in files:
                if f.lower().endswith(".zip"):
                    if f not in db_filenames:
                        print(f"  [ORPHAN] {f} (Found on disk, not in DB)")
                        orphaned_files.append(f)
        except Exception as e:
            print(f"ERROR listing directory: {e}")

    # Summary
    print("\n=== Summary ===")
    print(f"Total DB Entries: {len(db_entries)}")
    print(f"Verified Files:   {valid_entries}")
    print(f"Missing Files:    {len(missing_files)}")
    print(f"Orphaned Files:   {len(orphaned_files)}")

    if not missing_files and not orphaned_files:
        print("\nSUCCESS: Database and Filesystem are perfectly in sync.")
    else:
        print("\nWARNING: Inconsistencies found.")

    conn.close()

if __name__ == "__main__":
    check_integrity()
    input("\nDrücken Sie Enter zum Beenden...")
