import sqlite3
import os
import json
import logging

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialisiert die SQLite-Datenbank."""
        try:
            conn = sqlite3.connect(self.db_path)
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
                locked INTEGER DEFAULT 0,
                source_size INTEGER DEFAULT 0
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

            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Datenbank-Initialisierungsfehler: {e}")

    def get_history(self):
        try:
            conn = sqlite3.connect(self.db_path)
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

    def add_history_entry(self, **kwargs):
        """Fügt einen Eintrag in die Historie ein. Akzeptiert kwargs."""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('''INSERT INTO history 
                (filename, timestamp, size, sha256, path, source_path, comment, file_count, locked, source_size)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                (
                    kwargs.get("filename", ""),
                    kwargs.get("timestamp", ""),
                    kwargs.get("size", 0),
                    kwargs.get("sha256", ""),
                    kwargs.get("path", ""),
                    kwargs.get("source_path", ""),
                    kwargs.get("comment", ""),
                    kwargs.get("file_count", 0),
                    1 if kwargs.get("locked") else 0,
                    kwargs.get("source_size", 0)
                )
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"DB Write Error: {e}")

    def delete_history_entry(self, filename):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("DELETE FROM history WHERE filename = ?", (filename,))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"DB Delete Error: {e}")
            return False

    def delete_entry(self, filename):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("DELETE FROM history WHERE filename = ?", (filename,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"DB Delete Error: {e}")
            return False

    def toggle_lock(self, filename):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            c.execute("SELECT locked FROM history WHERE filename = ?", (filename,))
            row = c.fetchone()
            
            if row:
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
