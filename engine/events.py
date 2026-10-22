"""
AI AYFAM — Persistent Event Store Engine
مخزن الأحداث الدائم — جدول الأحداث الموتونونية مع السلسلة المترابطة لمنع التلاعب
"""

import os
import time
import sqlite3
import hashlib
import json
from typing import List, Dict, Any, Optional

DB_PATH = "/var/lib/ayfam/events.db" if os.geteuid() == 0 else os.path.expanduser("~/.ayfam/events.db")

class EventStore:
    """مخزن أحداث أمني محمي بحشوة تسلسلية مترابطة لمنع التلاعب بالتقارير والسجلات."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    wall_time REAL NOT NULL,
                    mono_time REAL NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    details TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    row_hash TEXT NOT NULL
                )
            """)
            conn.commit()

    def _get_last_hash(self) -> str:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("SELECT row_hash FROM events ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            return row[0] if row else "GENESIS_AYFAM_EVENT_CHAIN"

    def record_event(
        self,
        source: str,
        event_type: str,
        subject: str,
        details: str = "",
        severity: str = "info",
        fingerprint: Optional[str] = None,
    ) -> int:
        wall_t = time.time()
        mono_t = time.monotonic()
        fp = fingerprint or hashlib.sha256(f"{source}:{event_type}:{subject}".encode("utf-8")).hexdigest()[:16]

        prev_hash = self._get_last_hash()
        data_str = f"{wall_t}:{mono_t}:{source}:{event_type}:{subject}:{details}:{severity}:{fp}:{prev_hash}"
        row_hash = hashlib.sha256(data_str.encode("utf-8")).hexdigest()

        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("""
                INSERT INTO events (wall_time, mono_time, source, event_type, subject, details, severity, fingerprint, prev_hash, row_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (wall_t, mono_t, source, event_type, subject, details, severity, fp, prev_hash, row_hash))
            conn.commit()
            return cur.lastrowid

    def verify_chain_integrity(self) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("SELECT wall_time, mono_time, source, event_type, subject, details, severity, fingerprint, prev_hash, row_hash FROM events ORDER BY id ASC")
            rows = cur.fetchall()

        expected_prev = "GENESIS_AYFAM_EVENT_CHAIN"
        for row in rows:
            w_time, m_time, src, ev_type, subj, det, sev, fp, p_hash, r_hash = row
            if p_hash != expected_prev:
                return False

            data_str = f"{w_time}:{m_time}:{src}:{ev_type}:{subj}:{det}:{sev}:{fp}:{p_hash}"
            calc_hash = hashlib.sha256(data_str.encode("utf-8")).hexdigest()
            if calc_hash != r_hash:
                return False

            expected_prev = r_hash
        return True

    def query_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        events = []
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("""
                SELECT id, wall_time, mono_time, source, event_type, subject, details, severity, fingerprint
                FROM events ORDER BY id DESC LIMIT ?
            """, (limit,))
            for r in cur.fetchall():
                events.append({
                    "id": r[0],
                    "wall_time": r[1],
                    "mono_time": r[2],
                    "source": r[3],
                    "event_type": r[4],
                    "subject": r[5],
                    "details": r[6],
                    "severity": r[7],
                    "fingerprint": r[8],
                })
        return events

    def apply_retention_policy(self, max_days: int = 30):
        cutoff = time.time() - (max_days * 86400)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM events WHERE wall_time < ?", (cutoff,))
            conn.commit()


class EventSource:
    """واجهة مصادر الأحداث اللحظية الموحدة."""

    def start(self):
        pass

    def stop(self):
        pass

    def yield_events(self):
        yield from []
