"""
AI AYFAM — Multi-Source Log Reader & Normalizer
قراءة السجلات المتعددة المصادر والمؤرخ زمنيًا مع التطهير الدقيق
"""

import os
import re
import json
import ipaddress
import subprocess
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from utils import safe_exec

def sanitize_log_text(text: str, max_len: int = 500) -> str:
    """تطهير النصوص القادمة من السجلات (أسماء مستخدمين، مضيفين، مدخلات) لمنع ReDoS وحقن النصوص."""
    if not text:
        return ""
    # Truncate adversarial long lines
    cleaned = text[:max_len]
    # Remove control characters except newlines/tabs
    cleaned = "".join(ch for ch in cleaned if ch == "\n" or ch == "\t" or 32 <= ord(ch) < 127 or ord(ch) > 160)
    return cleaned.strip()

def parse_ip_address(text: str) -> Optional[str]:
    """استخراج والتحقق من صحة عنوان IP من نص السجل عبر ipaddress."""
    m = re.search(r"from\s+([0-9a-fA-F:\.]+)|rhost=([0-9a-fA-F:\.]+)|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|([0-9a-fA-F:]+:[0-9a-fA-F:]+)", text)
    if m:
        ip_str = next((g for g in m.groups() if g), None)
        if ip_str:
            try:
                ip_obj = ipaddress.ip_address(ip_str.strip())
                return str(ip_obj)
            except ValueError:
                pass
    return None

class LogSourceReader:
    """مستكشف وقارئ السجلات من journalctl والسجلات النصية."""

    def __init__(self, cursor_file: Optional[str] = None):
        self.cursor_file = cursor_file or os.path.expanduser("~/.ayfam/journal_cursor.txt")
        os.makedirs(os.path.dirname(self.cursor_file), exist_ok=True)

    def read_journal_json(self, since: str = "-7d", limit: int = 3000) -> List[Dict[str, Any]]:
        events = []
        cmd = ["journalctl", "-o", "json", "-n", str(limit), "--no-pager"]
        if since:
            cmd.extend(["--since", since])

        if os.path.exists(self.cursor_file):
            try:
                with open(self.cursor_file, "r") as f:
                    cursor = f.read().strip()
                    if cursor:
                        cmd.extend(["--after-cursor", cursor])
            except Exception:
                pass

        res = safe_exec.run(cmd, timeout=30, check_binary=False)
        if not res.ok or not res.stdout:
            return events

        last_cursor = None
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                cursor = data.get("__CURSOR")
                if cursor:
                    last_cursor = cursor

                msg = sanitize_log_text(data.get("MESSAGE", ""))
                syslog_id = data.get("SYSLOG_IDENTIFIER", "") or data.get("_COMM", "")
                ts_micro = int(data.get("__REALTIME_TIMESTAMP", 0))
                ts_sec = ts_micro / 1000000.0 if ts_micro else datetime.now(timezone.utc).timestamp()

                events.append({
                    "timestamp": ts_sec,
                    "service": syslog_id,
                    "message": msg,
                    "raw": line[:1000],
                    "ip": parse_ip_address(msg),
                    "source": "journald",
                })
            except Exception:
                continue

        if last_cursor:
            try:
                with open(self.cursor_file, "w") as f:
                    f.write(last_cursor)
            except Exception:
                pass

        return events

    def read_file_logs(self, log_path: str = "/var/log/auth.log", limit: int = 3000) -> List[Dict[str, Any]]:
        events = []
        if not os.path.exists(log_path):
            return events

        res = safe_exec.run(["tail", "-n", str(limit), log_path], timeout=15)
        if not res.ok or not res.stdout:
            return events

        current_year = datetime.now().year
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            msg = sanitize_log_text(line)
            # Standard syslog date format: Oct 22 14:05:01
            m_date = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?: (.*)$", line)
            if m_date:
                date_str, host, service, log_msg = m_date.groups()
                try:
                    dt = datetime.strptime(f"{current_year} {date_str}", "%Y %b %d %H:%M:%S")
                    ts = dt.timestamp()
                except ValueError:
                    ts = datetime.now().timestamp()

                events.append({
                    "timestamp": ts,
                    "service": service,
                    "message": sanitize_log_text(log_msg),
                    "raw": msg,
                    "ip": parse_ip_address(log_msg),
                    "source": log_path,
                })
        return events
