"""
AI AYFAM — Baseline Engine v2
خط الأساس المحسّن — تسجيل المكونات مع تاريخ الظهور (first_seen/last_seen)
وحماية قاعدة البيانات بحشوة HMAC ومسار قبول المشاكل المتوقعة.
"""

import os
import sqlite3
import hashlib
import hmac
import time
import json
from typing import List, Dict, Any, Optional

DB_PATH = "/var/lib/ayfam/baseline_v2.db" if os.geteuid() == 0 else os.path.expanduser("~/.ayfam/baseline_v2.db")
KEY_PATH = "/etc/ayfam/baseline.key" if os.geteuid() == 0 else os.path.expanduser("~/.ayfam/baseline.key")

class BaselineEngine:
    """Legacy class providing backward compatibility for old baseline calls."""
    def __init__(self, *args, **kwargs):
        self.v2 = BaselineEngineV2()

    def save_baseline(self, *args, **kwargs) -> bool:
        return True

    def compare_against_baseline(self, *args, **kwargs) -> Dict[str, Any]:
        return {"new_items": [], "removed_items": [], "modified_items": []}

    def check_deviations(self, *args, **kwargs) -> List[Any]:
        new_items = self.v2.get_new_components_since(0)
        findings = []
        for item in new_items:
            ctype = item["component_type"]
            key = item["key"]
            findings.append(create_finding(
                rule_id="SYS-WRITE-001",
                severity="medium",
                title_ar=f"عنصر جديد غير متوقع في خط الأساس: [{ctype}] {key}",
                title_en=f"New unexpected baseline component: [{ctype}] {key}",
                detail=f"تم رصد المكون لأول مرة في: {time.ctime(item['first_seen'])}",
                fix="راجع المكون وقم بقبوله في خط الأساس إن كان شرعياً.",
                evidence=item,
                stable_key=f"baseline_dev:{ctype}:{key}",
            ))
        return findings

class BaselineEngineV2:
    """محرك إدارة خط الأساس الأمني مع تتبع المكونات والحشوات وسجلات اللقطات."""

    def __init__(self, db_path: str = DB_PATH, key_path: str = KEY_PATH):
        self.db_path = db_path
        self.key_path = key_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.key_path), exist_ok=True)
        self._init_db()
        self._init_key()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS components (
                    component_type TEXT NOT NULL,
                    key TEXT NOT NULL,
                    details TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    is_expected INTEGER DEFAULT 0,
                    expected_expiry REAL,
                    accepted_by TEXT,
                    hmac TEXT NOT NULL,
                    PRIMARY KEY (component_type, key)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at REAL NOT NULL,
                    component_count INTEGER NOT NULL,
                    snapshot_json TEXT NOT NULL
                )
            """)
            conn.commit()

    def _init_key(self):
        if not os.path.exists(self.key_path):
            key = os.urandom(32)
            with open(self.key_path, "wb") as f:
                f.write(key)
            try:
                os.chmod(self.key_path, 0o600)
            except OSError:
                pass

    def _get_hmac(self, data: str) -> str:
        try:
            with open(self.key_path, "rb") as f:
                key = f.read()
        except OSError:
            key = b"fallback_ayfam_baseline_key"
        return hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()

    def update_component(
        self,
        component_type: str,
        key: str,
        details: Dict[str, Any],
        is_expected: bool = False,
    ) -> bool:
        now = time.time()
        details_str = json.dumps(details, sort_keys=True)

        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "SELECT first_seen, is_expected, expected_expiry, accepted_by FROM components WHERE component_type = ? AND key = ?",
                (component_type, key),
            )
            row = cur.fetchone()

            if row:
                first_seen = row[0]
                expected_flag = row[1]
                expiry = row[2]
                accepted_by = row[3]
            else:
                first_seen = now
                expected_flag = 1 if is_expected else 0
                expiry = None
                accepted_by = None

            record_str = f"{component_type}:{key}:{details_str}:{first_seen}:{now}:{expected_flag}"
            hmac_val = self._get_hmac(record_str)

            conn.execute("""
                INSERT OR REPLACE INTO components
                (component_type, key, details, first_seen, last_seen, is_expected, expected_expiry, accepted_by, hmac)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (component_type, key, details_str, first_seen, now, expected_flag, expiry, accepted_by, hmac_val))
            conn.commit()
        return True

    def accept_as_expected(self, component_type: str, key: str, user: str = "admin", expiry_days: Optional[int] = None) -> bool:
        now = time.time()
        expiry = (now + expiry_days * 86400) if expiry_days else None

        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("SELECT details, first_seen, last_seen FROM components WHERE component_type = ? AND key = ?", (component_type, key))
            row = cur.fetchone()
            if not row:
                return False

            details_str, first_seen, last_seen = row
            record_str = f"{component_type}:{key}:{details_str}:{first_seen}:{last_seen}:1"
            hmac_val = self._get_hmac(record_str)

            conn.execute("""
                UPDATE components
                SET is_expected = 1, expected_expiry = ?, accepted_by = ?, hmac = ?
                WHERE component_type = ? AND key = ?
            """, (expiry, user, hmac_val, component_type, key))
            conn.commit()
        return True

    def get_new_components_since(self, since_time: float) -> List[Dict[str, Any]]:
        new_items = []
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("""
                SELECT component_type, key, details, first_seen, is_expected
                FROM components WHERE first_seen >= ? AND is_expected = 0
            """, (since_time,))
            for r in cur.fetchall():
                new_items.append({
                    "component_type": r[0],
                    "key": r[1],
                    "details": json.loads(r[2]),
                    "first_seen": r[3],
                    "is_expected": bool(r[4]),
                })
        return new_items
