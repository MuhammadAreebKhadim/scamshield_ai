import json
import sqlite3
from typing import List, Optional, Dict, Any
from pathlib import Path
from backend.database.models import ScanRecord, UserProfile, DashboardStats

DB_DIR = Path(__file__).resolve().parent
SQLITE_PATH = DB_DIR / "scamshield.db"

class DatabaseManager:
    def __init__(self):
        self._init_sqlite()

    def _init_sqlite(self):
        conn = sqlite3.connect(SQLITE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                user_id TEXT,
                user_email TEXT,
                input_type TEXT,
                input_summary TEXT,
                input_data TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                is_threat_confirmed INTEGER,
                indicators TEXT,
                threat_intelligence TEXT,
                ai_analysis TEXT,
                recommendations TEXT,
                score_breakdown TEXT,
                created_at TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                name TEXT,
                picture TEXT,
                created_at TEXT
            )
        """)
        # Purge any legacy mock/demo scans
        cursor.execute("DELETE FROM scans WHERE user_id = 'system'")
        conn.commit()
        conn.close()

    def save_scan(self, scan: ScanRecord) -> ScanRecord:
        conn = sqlite3.connect(SQLITE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO scans (
                scan_id, user_id, user_email, input_type, input_summary, input_data,
                risk_score, risk_level, is_threat_confirmed, indicators, threat_intelligence,
                ai_analysis, recommendations, score_breakdown, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan.scan_id,
            scan.user_id,
            scan.user_email,
            scan.input_type,
            scan.input_summary,
            json.dumps(scan.input_data),
            scan.risk_score,
            scan.risk_level,
            1 if scan.is_threat_confirmed else 0,
            json.dumps(scan.indicators),
            json.dumps(scan.threat_intelligence),
            json.dumps(scan.ai_analysis),
            json.dumps(scan.recommendations),
            json.dumps(scan.score_breakdown),
            scan.created_at
        ))
        conn.commit()
        conn.close()
        return scan

    def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        conn = sqlite3.connect(SQLITE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return self._row_to_scan(row)

    def get_recent_scans(self, limit: int = 50, user_id: Optional[str] = None) -> List[ScanRecord]:
        conn = sqlite3.connect(SQLITE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if user_id and user_id != "anonymous":
            cursor.execute("""
                SELECT * FROM scans 
                WHERE LOWER(user_id) = LOWER(?) OR LOWER(user_email) = LOWER(?) 
                ORDER BY created_at DESC LIMIT ?
            """, (user_id, user_id, limit))
        else:
            cursor.execute("""
                SELECT * FROM scans 
                WHERE user_id = 'anonymous' OR user_id IS NULL OR user_id = ''
                ORDER BY created_at DESC LIMIT ?
            """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_scan(r) for r in rows]

    def get_dashboard_stats(self, user_id: Optional[str] = None) -> DashboardStats:
        conn = sqlite3.connect(SQLITE_PATH)
        cursor = conn.cursor()

        if user_id and user_id != "anonymous":
            cursor.execute("SELECT COUNT(*) FROM scans WHERE LOWER(user_id) = LOWER(?) OR LOWER(user_email) = LOWER(?)", (user_id, user_id))
            total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM scans WHERE (LOWER(user_id) = LOWER(?) OR LOWER(user_email) = LOWER(?)) AND risk_level = 'HIGH'", (user_id, user_id))
            high = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM scans WHERE (LOWER(user_id) = LOWER(?) OR LOWER(user_email) = LOWER(?)) AND risk_level = 'SUSPICIOUS'", (user_id, user_id))
            suspicious = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM scans WHERE (LOWER(user_id) = LOWER(?) OR LOWER(user_email) = LOWER(?)) AND risk_level = 'CAUTION'", (user_id, user_id))
            caution = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM scans WHERE (LOWER(user_id) = LOWER(?) OR LOWER(user_email) = LOWER(?)) AND risk_level = 'LOW'", (user_id, user_id))
            safe = cursor.fetchone()[0]

            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE LOWER(user_id) = LOWER(?) OR LOWER(user_email) = LOWER(?) ORDER BY created_at DESC LIMIT 10", (user_id, user_id))
            recent = [self._row_to_scan(r).to_dict() for r in cursor.fetchall()]

            cursor.execute("SELECT input_type, COUNT(*) FROM scans WHERE LOWER(user_id) = LOWER(?) OR LOWER(user_email) = LOWER(?) GROUP BY input_type", (user_id, user_id))
            type_counts = dict(cursor.fetchall())
        else:
            cursor.execute("SELECT COUNT(*) FROM scans WHERE user_id = 'anonymous' OR user_id IS NULL OR user_id = ''")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM scans WHERE (user_id = 'anonymous' OR user_id IS NULL OR user_id = '') AND risk_level = 'HIGH'")
            high = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM scans WHERE (user_id = 'anonymous' OR user_id IS NULL OR user_id = '') AND risk_level = 'SUSPICIOUS'")
            suspicious = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM scans WHERE (user_id = 'anonymous' OR user_id IS NULL OR user_id = '') AND risk_level = 'CAUTION'")
            caution = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM scans WHERE (user_id = 'anonymous' OR user_id IS NULL OR user_id = '') AND risk_level = 'LOW'")
            safe = cursor.fetchone()[0]

            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE user_id = 'anonymous' OR user_id IS NULL OR user_id = '' ORDER BY created_at DESC LIMIT 10")
            recent = [self._row_to_scan(r).to_dict() for r in cursor.fetchall()]

            cursor.execute("SELECT input_type, COUNT(*) FROM scans WHERE user_id = 'anonymous' OR user_id IS NULL OR user_id = '' GROUP BY input_type")
            type_counts = dict(cursor.fetchall())
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 10")
            recent = [self._row_to_scan(r).to_dict() for r in cursor.fetchall()]

            cursor.execute("SELECT input_type, COUNT(*) FROM scans GROUP BY input_type")
            type_counts = dict(cursor.fetchall())

        categories = {
            "Phishing & Suspicious URLs": type_counts.get("url", 0),
            "Email & Message Forensics": type_counts.get("message", 0),
            "Recruitment Verifications": type_counts.get("job", 0),
            "High-Risk Critical Alerts": high,
            "Verified Safe": safe
        }

        conn.close()
        return DashboardStats(
            total_scans=total,
            high_risk_detections=high,
            suspicious_detections=suspicious,
            caution_detections=caution,
            safe_detections=safe,
            recent_scans=recent,
            threat_categories=categories
        )

    def save_user(self, user: UserProfile) -> UserProfile:
        conn = sqlite3.connect(SQLITE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO users (user_id, email, name, picture, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user.user_id, user.email, user.name, user.picture, user.created_at))
        conn.commit()
        conn.close()
        return user

    def get_user_by_email(self, email: str) -> Optional[UserProfile]:
        conn = sqlite3.connect(SQLITE_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        return UserProfile(
            user_id=row["user_id"],
            email=row["email"],
            name=row["name"],
            picture=row["picture"],
            created_at=row["created_at"]
        )

    def _row_to_scan(self, row) -> ScanRecord:
        return ScanRecord(
            scan_id=row["scan_id"],
            user_id=row["user_id"],
            user_email=row["user_email"],
            input_type=row["input_type"],
            input_summary=row["input_summary"],
            input_data=json.loads(row["input_data"]) if row["input_data"] else {},
            risk_score=row["risk_score"],
            risk_level=row["risk_level"],
            is_threat_confirmed=bool(row["is_threat_confirmed"]),
            indicators=json.loads(row["indicators"]) if row["indicators"] else [],
            threat_intelligence=json.loads(row["threat_intelligence"]) if row["threat_intelligence"] else {},
            ai_analysis=json.loads(row["ai_analysis"]) if row["ai_analysis"] else {},
            recommendations=json.loads(row["recommendations"]) if row["recommendations"] else [],
            score_breakdown=json.loads(row["score_breakdown"]) if row["score_breakdown"] else {},
            created_at=row["created_at"]
        )

db = DatabaseManager()
