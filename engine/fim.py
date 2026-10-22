"""
AI AYFAM — File Integrity Monitoring (FIM) Engine
محرك سلامة الملفات — بناء خط الأساس لحشوات SHA-256 والتحقق منها مع التوقيع والتحقق عبر dpkg
"""

import os
import sqlite3
import hashlib
import hmac
import subprocess
import logging
from typing import List, Dict, Any, Optional
from engine.rules_registry import create_finding
from engine.finding import Finding

DB_PATH = "/var/lib/ayfam/fim_baseline.db" if os.geteuid() == 0 else os.path.expanduser("~/.ayfam/fim_baseline.db")
KEY_PATH = "/etc/ayfam/fim.key" if os.geteuid() == 0 else os.path.expanduser("~/.ayfam/fim.key")

FIM_MONITORED_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d",
    "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d",
    "/etc/pam.d", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
    "/etc/systemd/system", "/lib/systemd/system",
    "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/crontab",
    os.path.expanduser("~/.ssh/authorized_keys"),
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
]

class FileIntegrityMonitor:
    """محرك مراقبة سلامة وتكامل الملفات والمجموعات التنفيذية."""

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
                CREATE TABLE IF NOT EXISTS baseline (
                    path TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    mtime REAL NOT NULL,
                    size INTEGER NOT NULL,
                    hmac TEXT NOT NULL
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
            key = b"fallback_ayfam_fim_key"
        return hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()

    def _hash_file(self, filepath: str) -> Optional[tuple]:
        try:
            st = os.lstat(filepath)
            if os.path.islink(filepath) or not (st.st_mode & 0o100000):
                return None

            # Read sha256
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            digest = h.hexdigest()
            return digest, st.st_mtime, st.st_size
        except Exception:
            return None

    def build_baseline(self, paths: Optional[List[str]] = None) -> int:
        target_paths = paths or FIM_MONITORED_PATHS
        count = 0
        with sqlite3.connect(self.db_path) as conn:
            for target in target_paths:
                if os.path.isfile(target):
                    file_list = [target]
                elif os.path.isdir(target):
                    file_list = []
                    for root, _, files in os.walk(target, followlinks=False):
                        for f in files:
                            file_list.append(os.path.join(root, f))
                else:
                    continue

                for fpath in file_list:
                    res = self._hash_file(fpath)
                    if not res:
                        continue
                    sha256, mtime, size = res
                    hmac_val = self._get_hmac(f"{fpath}:{sha256}:{size}")
                    conn.execute("""
                        INSERT OR REPLACE INTO baseline (path, sha256, mtime, size, hmac)
                        VALUES (?, ?, ?, ?, ?)
                    """, (fpath, sha256, mtime, size, hmac_val))
                    count += 1
            conn.commit()
        return count

    def verify_baseline(self) -> List[Finding]:
        findings = []
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT path, sha256, mtime, size, hmac FROM baseline")
            rows = cursor.fetchall()

        for fpath, orig_sha, orig_mtime, orig_size, orig_hmac in rows:
            # Verify HMAC of DB record
            expected_record_hmac = self._get_hmac(f"{fpath}:{orig_sha}:{orig_size}")
            if not hmac.compare_digest(orig_hmac, expected_record_hmac):
                findings.append(create_finding(
                    "SYS-WRITE-001",
                    severity="critical",
                    title_ar=f"التلاعب بقاعدة بيانات خط الأساس FIM: {fpath}",
                    title_en=f"FIM baseline database tampering detected: {fpath}",
                    detail="سجل خط الأساس تم التلاعب به بصورة غير مصرح بها.",
                    fix="أعد بناء خط الأساس: ayfam --build-fim-baseline",
                    stable_key=fpath,
                ))
                continue

            if not os.path.exists(fpath):
                findings.append(create_finding(
                    "SYS-WRITE-001",
                    severity="high",
                    title_ar=f"حذف ملف نظام محمي من خط الأساس: {fpath}",
                    title_en=f"Protected file removed from baseline: {fpath}",
                    detail=f"الملف {fpath} كان محدوماً في خط الأساس ولكنه حُذف الآن.",
                    fix=f"استرجع الملف {fpath} من النسخ الاحتياطية أو الحزمة الأصلية.",
                    stable_key=fpath,
                ))
                continue

            current_res = self._hash_file(fpath)
            if not current_res:
                continue

            cur_sha, cur_mtime, cur_size = current_res
            if cur_sha != orig_sha:
                findings.append(create_finding(
                    "SYS-WRITE-001",
                    severity="critical",
                    title_ar=f"تغيير غير مصرح به في ملف النظام: {fpath}",
                    title_en=f"Unauthorized file integrity change detected: {fpath}",
                    detail=f"تغيرت حشوة SHA256 للملف.\nسابقاً: {orig_sha[:16]}...\nحالياً: {cur_sha[:16]}...",
                    fix=f"تحقق من سبب تعديل {fpath} واسترجعه إن لم تكن أنت من عدّله.",
                    evidence={"path": fpath, "orig_sha": orig_sha, "cur_sha": cur_sha},
                    stable_key=fpath,
                ))

        return findings

    def check_dpkg_verify(self) -> List[Finding]:
        findings = []
        try:
            from utils import safe_exec
            r = safe_exec.run(["dpkg", "--verify"], timeout=60, check_binary=False)
            if r.ok and r.stdout:
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if not line or len(line) < 12:
                        continue
                    # Format: ??5??????  c /etc/something or ??5??????    /usr/bin/something
                    parts = line.split()
                    flags = parts[0]
                    fpath = parts[-1]
                    if "5" in flags and not flags.startswith("??5?c"):  # Digest mismatch and not a conffile
                        findings.append(create_finding(
                            "SYS-WRITE-001",
                            severity="high",
                            title_ar=f"تعديل ملف تنفيذي تابع لحزمة رسمية: {fpath}",
                            title_en=f"Modified package-owned binary: {fpath}",
                            detail=f"فحص dpkg --verify كشف عن تعديل حشوة الملف المملوك للحزمة.",
                            fix=f"أعد تثبيت الحزمة الأصلية: sudo apt-get --reinstall install $(dpkg -S '{fpath}' | cut -d: -f1)",
                            evidence={"path": fpath, "dpkg_line": line},
                            stable_key=fpath,
                        ))
        except Exception as e:
            logging.debug(f"dpkg verify error: {e}")
        return findings
