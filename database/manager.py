import sqlite3
import json
from datetime import datetime
from config import DB_PATH

class DBManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        cursor = self.conn.cursor()
        
        # Self-Monitoring: Run integrity check on startup
        try:
            cursor.execute("PRAGMA integrity_check")
            if cursor.fetchone()[0] != "ok":
                logger.error("Database integrity compromised! Attempting repair...")
                cursor.execute("PRAGMA vacuum")
        except Exception as e:
            logger.critical(f"Database error during integrity check: {e}")

        # Reputation Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reputation (
                sha256 TEXT PRIMARY KEY,
                level INTEGER,
                score REAL,
                last_updated TIMESTAMP,
                source TEXT
            )
        """)
        # Alerts Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                message TEXT,
                details TEXT,
                severity TEXT
            )
        """)
        # Scan History Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT,
                sha256 TEXT,
                verdict TEXT,
                timestamp TIMESTAMP
            )
        """)
        # Hosts Table (Fleet Management)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                uuid TEXT PRIMARY KEY,
                hostname TEXT,
                ip_address TEXT,
                status TEXT,
                last_seen TIMESTAMP,
                is_isolated INTEGER DEFAULT 0
            )
        """)
        self.conn.commit()

    def add_alert(self, message, details=None, severity="INFO"):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO alerts (timestamp, message, details, severity) VALUES (?, ?, ?, ?)",
            (datetime.now().isoformat(), message, json.dumps(details or {}), severity)
        )
        self.conn.commit()

    def get_alerts(self, limit=100):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def update_reputation(self, sha256, level, score, source):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO reputation (sha256, level, score, last_updated, source) VALUES (?, ?, ?, ?, ?)",
            (sha256, level, score, datetime.now().isoformat(), source)
        )
        self.conn.commit()

    def get_reputation(self, sha256):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM reputation WHERE sha256 = ?", (sha256,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def register_host(self, uuid, hostname, ip_address):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO hosts (uuid, hostname, ip_address, status, last_seen) VALUES (?, ?, ?, ?, ?)",
            (uuid, hostname, ip_address, "ONLINE", datetime.now().isoformat())
        )
        self.conn.commit()

    def update_host_status(self, uuid, status):
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE hosts SET status = ?, last_seen = ? WHERE uuid = ?",
            (status, datetime.now().isoformat(), uuid)
        )
        self.conn.commit()

    def set_isolation(self, uuid, is_isolated):
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE hosts SET is_isolated = ? WHERE uuid = ?",
            (1 if is_isolated else 0, uuid)
        )
        self.conn.commit()

    def get_hosts(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM hosts")
        return [dict(row) for row in cursor.fetchall()]
