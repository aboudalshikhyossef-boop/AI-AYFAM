"""
AI AYFAM - Settings & Configuration Manager

ملاحظة أمنية: هذا الملف يخزّن أسراراً حساسة (github_token, shodan_key).
لذلك نفرض صلاحيات 0600 على الملف و0700 على المجلد عند كل إنشاء/حفظ،
حتى لا يقدر أي مستخدم آخر على نفس الجهاز على قراءتها.
"""

import os
import json
import stat
import tempfile
from pathlib import Path
from config.version import APP_VERSION
from config.model_defaults import OPENAI_DEFAULT_MODEL
from engine.gemini_rate_limit import DEFAULT_GEMINI_MODEL

try:
    from dotenv import load_dotenv
except ImportError:  # optional at import time; preflight reports it when missing
    load_dotenv = None

try:
    import keyring
except ImportError:  # optional: secure file storage remains the fallback
    keyring = None


PROJECT_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
if load_dotenv is not None:
    # Explicit environment variables always win over the project file.
    load_dotenv(PROJECT_ENV_FILE, override=False)


CONFIG_DIR = Path.home() / ".ayfam"
CONFIG_FILE = CONFIG_DIR / "config.json"
_SECRET_KEYS = ("github_token", "shodan_key", "abuseipdb_key", "nvd_api_key", "vulners_key", "gemini_api_key", "openai_api_key", "google_cse_key")
_KEYRING_SERVICE = "ai-ayfam"

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
    "openai_api_key": "",  # OpenAI API — يُستخدم للمساعد الأمني الاختياري
    "google_cse_key": "",  # Google Programmable Search (اختياري): نتائج Google مباشرة بدل التأسيس عبر Gemini
    "google_cse_cx": "f5fbcd40fda484bc7",   # معرّف محرك البحث المخصص (cx)
    "ai_provider": "auto",  # auto | openai | gemini | local
    "openai_model": OPENAI_DEFAULT_MODEL,
    "gemini_model": DEFAULT_GEMINI_MODEL,
    "auto_fix": False,
    "sound_ux": False,
    "sound_profile": "soft",
    "dark_mode": True,
    "report_dir": str(Path.home() / "ayfam-reports"),
    "cve_cache_hours": 6,
    "max_scan_threads": 50,
    "trusted_networks": [],
    "version": APP_VERSION,
}

_BOOLEAN_SETTINGS = {"auto_fix", "sound_ux", "dark_mode"}
_POSITIVE_INTEGER_SETTINGS = {
    "cve_cache_hours": (1, 24 * 30),
    "max_scan_threads": (1, 256),
}
_STRING_SETTINGS = {
    "github_token", "shodan_key", "abuseipdb_key", "nvd_api_key",
    "vulners_key", "gemini_api_key", "openai_api_key", "google_cse_key",
    "google_cse_cx", "openai_model", "gemini_model", "sound_profile",
}
_ALLOWED_VALUES = {
    "language": {"ar", "en"},
    "ai_provider": {"auto", "openai", "gemini", "local"},
    "sound_profile": {"soft", "tactical", "silent"},
}


class Settings:
    def __init__(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self._harden_permissions()
        self._data = {**DEFAULT_SETTINGS}
        self._load()
        Path(self._data["report_dir"]).expanduser().mkdir(parents=True, exist_ok=True)

    def _harden_permissions(self):
        """يفرض 0700 على مجلد الإعدادات و0600 على ملف الإعدادات، ويصلح أي
        صلاحيات مفتوحة كانت موجودة من إصدار سابق (defense in depth)."""
        try:
            if CONFIG_DIR.exists() and CONFIG_DIR.is_symlink():
                raise OSError("configuration directory must not be a symlink")
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            os.chmod(CONFIG_DIR, stat.S_IRWXU)  # 0700 — المالك فقط
        except OSError:
            pass
        if CONFIG_FILE.exists():
            try:
                os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0600
            except OSError:
                pass

    def _load(self):
        if CONFIG_FILE.exists() and CONFIG_FILE.is_symlink():
            raise OSError("configuration file must not be a symlink")
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                    if not isinstance(saved, dict):
                        raise ValueError("configuration root must be an object")
                    self._data.update(saved)
            except (json.JSONDecodeError, OSError, ValueError, TypeError) as e:
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
        self._validate_data()
        self._load_keyring_secrets()

    def _load_keyring_secrets(self) -> None:
        """Prefer desktop keyring values without making keyring mandatory/headless-hostile."""
        if keyring is None:
            return
        for name in _SECRET_KEYS:
            try:
                value = keyring.get_password(_KEYRING_SERVICE, name)
            except Exception:
                value = None
            if value:
                self._data[name] = value

    def _save_keyring_secrets(self) -> set[str]:
        """Store available secrets in the user's keyring and return successful keys."""
        stored = set()
        if keyring is None:
            return stored
        for name in _SECRET_KEYS:
            value = self._data.get(name, "")
            if not value:
                # Empty means explicit deletion, not retaining an old keyring value.
                try:
                    existing = keyring.get_password(_KEYRING_SERVICE, name)
                except Exception:
                    # A missing/unavailable backend is valid on headless systems.
                    # In that case there is no usable keyring value to restore.
                    continue
                if existing:
                    try:
                        keyring.delete_password(_KEYRING_SERVICE, name)
                    except Exception as exc:
                        raise RuntimeError(f"Unable to delete keyring entry for {name}") from exc
                continue
            try:
                keyring.set_password(_KEYRING_SERVICE, name, value)
                stored.add(name)
            except Exception as exc:
                raise RuntimeError(f"Unable to store keyring entry for {name}") from exc
        return stored

    def _validate_data(self) -> None:
        """Restore invalid known values to safe defaults without blocking startup."""
        import sys

        for key in _BOOLEAN_SETTINGS:
            value = self._data.get(key)
            if not isinstance(value, bool):
                self._data[key] = DEFAULT_SETTINGS[key]
                print(f"[CONFIG] Ignoring invalid boolean setting: {key}", file=sys.stderr)

        for key, (minimum, maximum) in _POSITIVE_INTEGER_SETTINGS.items():
            value = self._data.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                self._data[key] = DEFAULT_SETTINGS[key]
                print(f"[CONFIG] Ignoring invalid integer setting: {key}", file=sys.stderr)

        for key in _STRING_SETTINGS:
            value = self._data.get(key)
            if not isinstance(value, str):
                self._data[key] = DEFAULT_SETTINGS[key]
                print(f"[CONFIG] Ignoring invalid string setting: {key}", file=sys.stderr)

        for key, allowed in _ALLOWED_VALUES.items():
            if self._data.get(key) not in allowed:
                self._data[key] = DEFAULT_SETTINGS[key]
                print(f"[CONFIG] Ignoring invalid value for setting: {key}", file=sys.stderr)

        report_dir = self._data.get("report_dir")
        if not isinstance(report_dir, str) or not report_dir.strip():
            self._data["report_dir"] = DEFAULT_SETTINGS["report_dir"]
            print("[CONFIG] Ignoring invalid setting: report_dir", file=sys.stderr)

        trusted_networks = self._data.get("trusted_networks")
        if not isinstance(trusted_networks, list) or not all(isinstance(item, str) for item in trusted_networks):
            self._data["trusted_networks"] = list(DEFAULT_SETTINGS["trusted_networks"])
            print("[CONFIG] Ignoring invalid setting: trusted_networks", file=sys.stderr)

        self._data["version"] = APP_VERSION

    def _save(self):
        # افتح بصلاحيات 0600 منذ اللحظة الأولى (os.open) بدلاً من إنشاء
        # الملف بصلاحيات افتراضية ثم تقييدها لاحقاً — يمنع نافذة زمنية
        # قصيرة يكون فيها الملف قابلاً للقراءة من الجميع.
        if CONFIG_FILE.is_symlink():
            raise OSError("configuration file must not be a symlink")
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        stored_secrets = self._save_keyring_secrets()
        payload = {**self._data}
        for name in stored_secrets:
            payload[name] = ""
        fd, temp_name = tempfile.mkstemp(prefix=".config.", dir=CONFIG_DIR, text=True)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_name, CONFIG_FILE)
            os.chmod(CONFIG_FILE, 0o600)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

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
