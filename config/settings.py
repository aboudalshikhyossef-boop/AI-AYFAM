"""
AI AYFAM - Settings & Configuration Manager

ملاحظة أمنية: هذا الملف يخزّن أسراراً حساسة (github_token, shodan_key).
لذلك نفرض صلاحيات 0600 على الملف و0700 على المجلد عند كل إنشاء/حفظ،
حتى لا يقدر أي مستخدم آخر على نفس الجهاز على قراءتها.
"""

import os
import json
import stat
from pathlib import Path


CONFIG_DIR = Path.home() / ".ayfam"
CONFIG_FILE = CONFIG_DIR / "config.json"
_SECRET_KEYS = ("github_token", "shodan_key", "abuseipdb_key", "nvd_api_key", "vulners_key", "gemini_api_key")

DEFAULT_SETTINGS = {
    "language": "ar",
    "github_token": "",
    "shodan_key": "",
    # مفاتيح اختيارية بالكامل — كل مصدر بحث/CVE في tools/web.py يعمل بدونها
    # بمصادر مجانية لا تحتاج مفتاحاً، وإن وُجد المفتاح يُستخدَم لتحسين الدقة
    # أو رفع حد الطلبات (rate limit) فقط. لا شيء يتوقف عن العمل بدونها.
    "abuseipdb_key": "",   # يرفع فحص سمعة IP من تخمين استضافة/VPN إلى بيانات إساءة فعلية
    "nvd_api_key": "",     # يرفع حد NVD من 5 طلبات/30ث إلى 50 طلب/30ث
    "vulners_key": "",     # غير مُستخدَم حالياً — محجوز لتوسعة مستقبلية
    "gemini_api_key": "",  # Gemini Developer API — يُستخدم فقط لجلب CTI عام
    "auto_fix": False,
    "report_dir": str(Path.home() / "ayfam-reports"),
    "cve_cache_hours": 6,
    "max_scan_threads": 50,
    "trusted_networks": [],
    "version": "1.0.0",
}


class Settings:
    def __init__(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self._harden_permissions()
        Path(str(Path.home() / "ayfam-reports")).mkdir(parents=True, exist_ok=True)
        self._data = {**DEFAULT_SETTINGS}
        self._load()

    def _harden_permissions(self):
        """يفرض 0700 على مجلد الإعدادات و0600 على ملف الإعدادات، ويصلح أي
        صلاحيات مفتوحة كانت موجودة من إصدار سابق (defense in depth)."""
        try:
            os.chmod(CONFIG_DIR, stat.S_IRWXU)  # 0700 — المالك فقط
        except OSError:
            pass
        if CONFIG_FILE.exists():
            try:
                os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0600
            except OSError:
                pass

    def _load(self):
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                    self._data.update(saved)
            except (json.JSONDecodeError, OSError) as e:
                # Don't silently lose user config (including github_token).
                # Back up the bad file so the user can recover it manually.
                import shutil, sys
                backup = CONFIG_FILE.with_suffix(".json.corrupt")
                try:
                    shutil.copy2(CONFIG_FILE, backup)
                    os.chmod(backup, stat.S_IRUSR | stat.S_IWUSR)  # 0600 — قد تحوي أسراراً
                except Exception:
                    backup = None
                print(f"[CONFIG] Failed to load {CONFIG_FILE}: {e}", file=sys.stderr)
                if backup:
                    print(f"[CONFIG] Corrupt file backed up to {backup}", file=sys.stderr)

    def _save(self):
        # افتح بصلاحيات 0600 منذ اللحظة الأولى (os.open) بدلاً من إنشاء
        # الملف بصلاحيات افتراضية ثم تقييدها لاحقاً — يمنع نافذة زمنية
        # قصيرة يكون فيها الملف قابلاً للقراءة من الجميع.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(CONFIG_FILE, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self._data, f, ensure_ascii=False, indent=2)

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        self._data[key] = value
        self._save()

    def all(self):
        display = {**self._data}
        for key in _SECRET_KEYS:
            v = display.get(key)
            if v:
                display[key] = (v[:8] + "..." + v[-4:]) if len(v) > 12 else "***"
        return display
