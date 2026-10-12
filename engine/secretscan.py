"""
AI AYFAM v5 — Secret Scanner & Shannon Entropy Engine
كاشف الأسرار والمفاتيح المسربة — يعتمد على تحليل إنتروبيا شانون (Shannon Entropy)
والتوقيعات الدقيقة، مع حجب الأسرار تلقائياً في التقارير لمنع تسريبها.
"""

import math
import os
import re
from typing import List, Tuple, Optional
from engine.finding import Finding
from engine.sysreader import SystemReader

class SecretScanner:
    def __init__(self, sys_reader: Optional[SystemReader] = None):
        self.sys = sys_reader or SystemReader()

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """حساب درجة عشوائية النص (إنتروبيا شانون). المفاتيح المشفرة عادة > 4.5."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def mask_secret(secret: str) -> str:
        s = secret.strip()
        if len(s) <= 8:
            return "***"
        return f"{s[:4]}...{s[-4:]}"

    def scan_path(self, root_path: str, max_files: int = 500) -> List[Finding]:
        findings = []
        if not self.sys.exists(root_path):
            return findings

        # أنماط المفاتيح المعروفة
        PATTERNS = [
            (re.compile(r"-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----"), "مفتاح خاص غير مشفر (SSH/RSA Private Key)", "critical"),
            (re.compile(r"\bghp_[A-Za-z0-9_]{36}\b"), "رمز وصول GitHub الشخصي (GitHub Personal Token)", "critical"),
            (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "مفتاح وصول AWS Access Key", "critical"),
            (re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b"), "رمز مصادقة Slack Token", "high"),
            (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\b"), "رمز JSON Web Token (JWT)", "medium"),
            (re.compile(r"(?:api_key|apikey|secret|password)\s*[:=]\s*['\"]([^'\"]{16,})['\"]", re.I), "كلمة مرور أو مفتاح API مكشوف", "high"),
        ]

        # جمع الملفات
        files_to_check = []
        if self.sys.is_file(root_path):
            files_to_check = [root_path]
        else:
            for root, dirs, files in os.walk(root_path):
                # استبعاد مجلدات الكاش والبيئات الافتراضية
                dirs[:] = [d for d in dirs if d not in (".git", ".venv", "venv", "node_modules", "__pycache__")]
                for fname in files:
                    lower_name = fname.lower()
                    key_named = lower_name in {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "authorized_keys"}
                    if key_named or lower_name.endswith((".py", ".env", ".json", ".yaml", ".yml", ".sh", ".conf", ".txt", ".history", ".pem", ".key", ".crt")):
                        files_to_check.append(os.path.join(root, fname))
                    if len(files_to_check) >= max_files:
                        break
                if len(files_to_check) >= max_files:
                    break

        for fpath in files_to_check:
            content = self.sys.read_text(fpath)
            if not content:
                continue

            for idx, line in enumerate(content.splitlines(), 1):
                # 1. مطابقة التوقيعات
                for pat, label, sev in PATTERNS:
                    m = pat.search(line)
                    if m:
                        secret_val = m.group(1) if m.groups() else m.group(0)
                        masked = self.mask_secret(secret_val)
                        findings.append(Finding(
                            severity=sev,
                            title=f"كشف سر حساس: {label} في {os.path.basename(fpath)}:{idx}",
                            detail=f"الملف: {fpath}\nالقيمة المحجوبة: {masked}",
                            fix=f"انقل السر من {fpath} إلى متغيرات البيئة المحمية أو مدير الأسرار.",
                            category="secrets",
                            tags=["secrets", "credential_leak"],
                            attack_ids=["T1552.001"],
                            effort="low",
                        ))
                        break
        return findings
