"""
AI AYFAM v6 — Behavioral Baseline & Anomaly Engine
محرك خط الأساس السلوكي — يتعلم الحالة الطبيعية للنظام (المستخدمين، المنافذ، المهام)،
ويكتشف أي شذوذ أو اختراق جديد ينحرف عن السلوك المعتمد.
"""

import os
import json
import sqlite3
from typing import Dict, List, Any, Optional
from engine.finding import Finding
from engine.sysreader import SystemReader

class BaselineEngine:
    def __init__(self, db_path: str = None, sys_reader: Optional[SystemReader] = None):
        self.db_path = db_path or os.path.expanduser("~/.ayfam/brain.db")
        self.sys = sys_reader or SystemReader()
        self._init_table()

    def _init_table(self):
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                CREATE TABLE IF NOT EXISTS system_baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    component TEXT NOT NULL UNIQUE,
                    snapshot_data TEXT NOT NULL,
                    updated_at TEXT DEFAULT (datetime('now'))
                );
                """)
        except Exception:
            pass

    def capture_current_state(self) -> Dict[str, Any]:
        """التقاط بصمة شاملة للحالة الراهنة للنظام."""
        # 1. المستخدمين
        passwd_content = self.sys.read_text("/etc/passwd")
        users = set()
        for line in passwd_content.splitlines():
            parts = line.split(":")
            if len(parts) >= 3:
                users.add(f"{parts[0]}:{parts[2]}")

        # 2. المنافذ المستمعة
        ok, out, _ = self.sys.run_cmd(["ss", "-tulpn"])
        ports = set()
        if ok:
            for line in out.splitlines():
                if "LISTEN" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        ports.add(parts[4])

        # 3. ملفات SUID الحالية
        ok_suid, suid_out, _ = self.sys.run_cmd(["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "-perm", "-4000"])
        suid_files = set(suid_out.splitlines()) if ok_suid else set()

        return {
            "users": sorted(list(users)),
            "listening_ports": sorted(list(ports)),
            "suid_files": sorted(list(suid_files)),
        }

    def save_baseline(self) -> bool:
        """حفظ أو تحديث خط الأساس في قاعدة البيانات كحالة موثوقة."""
        state = self.capture_current_state()
        try:
            with sqlite3.connect(self.db_path) as conn:
                for comp, data in state.items():
                    conn.execute("""
                    INSERT INTO system_baselines (component, snapshot_data, updated_at)
                    VALUES (?, ?, datetime('now'))
                    ON CONFLICT(component) DO UPDATE SET
                    snapshot_data=excluded.snapshot_data, updated_at=excluded.updated_at;
                    """, (comp, json.dumps(data)))
            return True
        except Exception:
            return False

    def check_deviations(self) -> List[Finding]:
        """مقارنة حالة النظام الحالية بخط الأساس الموثوق لكشف أي شذوذ."""
        findings = []
        current = self.capture_current_state()
        baseline = {}

        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute("SELECT component, snapshot_data FROM system_baselines").fetchall()
                for comp, data in rows:
                    baseline[comp] = set(json.loads(data))
        except Exception:
            return findings

        if not baseline:
            findings.append(Finding(
                severity="info",
                title="لم يتم تسجيل خط أساس للنظام بعد",
                detail="قم بتشغيل: ayfam --baseline-learn ليتعلم الوكيل الحالة الطبيعية الموثوقة لنظامك.",
                fix="python3 main.py --baseline-learn",
                category="baseline",
            ))
            return findings

        # 1. كشف مستخدمين جدد
        base_users = baseline.get("users", set())
        cur_users = set(current.get("users", []))
        new_users = cur_users - base_users
        if new_users:
            findings.append(Finding(
                severity="critical",
                title=f"🚨 رصد مستخدمين جدد غير موجودين في خط الأساس: {', '.join(list(new_users)[:3])}",
                detail=f"تم إنشاء حسابات مستخدمين جديدة بعد حفظ خط الأساس الموثوق للنظام: {list(new_users)}",
                fix="تحقق من شرعية المستخدمين أو احذفهم: sudo userdel <username>",
                category="anomaly_identity",
                tags=["new_user", "persistence"],
                attack_ids=["T1136.001"],
            ))

        # 2. كشف منافذ استماع جديدة
        base_ports = baseline.get("listening_ports", set())
        cur_ports = set(current.get("listening_ports", []))
        new_ports = cur_ports - base_ports
        if new_ports:
            findings.append(Finding(
                severity="high",
                title=f"⚠️ منافذ استماع شبكية جديدة ظهرت فجأة: {', '.join(list(new_ports)[:4])}",
                detail=f"تم رصد فتح خدمات استماع جديدة لم تكن موجودة في السلوك الطبيعي للنظام: {list(new_ports)}",
                fix="افحص العمليات المرتبطة بالمنافذ وأغلقها إن لم تكن مصرحة.",
                category="anomaly_network",
                tags=["new_port", "backdoor"],
                attack_ids=["T1571"],
            ))

        # 3. كشف ملفات SUID جديدة
        base_suid = baseline.get("suid_files", set())
        cur_suid = set(current.get("suid_files", []))
        new_suid = cur_suid - base_suid
        if new_suid:
            findings.append(Finding(
                severity="critical",
                title=f"🚨 ملفات امتيازات SUID جديدة لم تكن موجودة سابقاً: {', '.join(list(new_suid)[:2])}",
                detail=f"ظهور ملفات SUID جديدة يعتبر مؤشراً قوياً على محاولة تثبيت آلية تصعيد صلاحيات.",
                fix=f"أزل صلاحية SUID فوراً: sudo chmod u-s {list(new_suid)[0]}",
                category="anomaly_privilege",
                tags=["suid_anomaly", "privesc"],
                attack_ids=["T1548.001"],
            ))

        return findings
