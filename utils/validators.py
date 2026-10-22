"""
AI AYFAM - Central Input Validators
طبقة تحقق مركزية إلزامية

القاعدة: أي قيمة (IP, hostname, PID, اسم واجهة, مسار ملف...) تأتي من
المستخدم، من قراءة USB/ADB، أو من أي مصدر خارجي غير موثوق — يجب أن تمر
من دالة تحقق هنا *قبل* أن تُستخدم في بناء أي أمر نظام.

كل دالة تُرجع Tuple[bool, str]:
  (True,  القيمة_النظيفة)   إذا كانت صالحة
  (False, رسالة_خطأ)        إذا كانت غير صالحة
"""

import ipaddress
import os
import re
import stat

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_PORT_RANGE_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")
_ADB_SERIAL_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_ANDROID_PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
_PROTECTED_PATHS = {
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64",
    "/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var",
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh/sshd_config",
    "/etc/resolv.conf",
}


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_hostname(value: str) -> bool:
    return bool(value) and bool(_HOSTNAME_RE.match(value))


def validate_scan_target(value: str):
    """هدف فحص شبكي: يجب أن يكون IP صالح أو hostname صالح — لا شيء آخر."""
    if not value or not isinstance(value, str):
        return False, "هدف الفحص فارغ / Scan target is empty"
    value = value.strip()
    if is_valid_ip(value) or is_valid_hostname(value):
        return True, value
    return False, f"هدف غير صالح (يجب IP أو hostname فقط): '{value}'"


def validate_port_range(value: str):
    if not value or not _PORT_RANGE_RE.match(value.strip()):
        return False, f"نطاق منافذ غير صالح (مثال صحيح: 1-1024): '{value}'"
    v = value.strip()
    parts = v.split("-")
    start, end = int(parts[0]), int(parts[-1])
    if not (0 <= start <= 65535 and 0 <= end <= 65535 and start <= end):
        return False, "نطاق المنافذ يجب أن يكون بين 0 و 65535 (والبداية ≤ النهاية)"
    if end - start > 20000:
        return False, "نطاق المنافذ كبير جداً (الحد الأقصى 20000 منفذ بالمرة الواحدة)"
    return True, v


def validate_interface(value: str):
    if not value or not _IFACE_RE.match(value.strip()):
        return False, f"اسم واجهة شبكة/بلوتوث غير صالح: '{value}'"
    return True, value.strip()


def validate_pid(value: str):
    v = (value or "").strip()
    if not v.isdigit():
        return False, f"PID يجب أن يكون رقماً: '{value}'"
    pid = int(v)
    if pid <= 1:
        return False, "لا يُسمح بإنهاء PID 1 (init/systemd) — قد يعطّل النظام بالكامل"
    if pid == os.getpid():
        return False, "لا يمكن للتطبيق إنهاء عملية AI AYFAM نفسها"
    return True, v


def validate_ip_for_fix(value: str):
    v = (value or "").strip()
    if not is_valid_ip(v):
        return False, f"عنوان IP غير صالح: '{value}'"
    # Never allow banning loopback / broadcast — that's self-lockout, not security.
    try:
        ip_obj = ipaddress.ip_address(v)
        if ip_obj.is_loopback:
            return False, "لا يمكن حظر عنوان loopback (127.0.0.1) — سيقطع الوكيل نفسه"
    except ValueError:
        pass
    return True, v


def validate_safe_path(value: str, must_be_absolute: bool = True):
    """تحقق من مسار ملف مع حظر جذور وملفات النظام الحرجة."""
    v = (value or "").strip()
    if not v or "\x00" in v:
        return False, f"مسار غير صالح: '{value}'"
    if ".." in v.split(os.sep):
        return False, f"مسار يحتوي على '..' مرفوض لأسباب أمنية: '{value}'"
    if must_be_absolute and not os.path.isabs(v):
        return False, f"يجب أن يكون المسار مطلقاً: '{value}'"
    normalized = os.path.normpath(v)
    if normalized in _PROTECTED_PATHS:
        return False, f"المسار محمي ولا يُسمح بتعديله تلقائياً: '{normalized}'"
    return True, v


def validate_adb_serial(value: str):
    if not value or not _ADB_SERIAL_RE.match(value.strip()):
        return False, f"رقم تسلسلي غير صالح لجهاز Android: '{value}'"
    return True, value.strip()


def validate_android_package(value: str):
    v = (value or "").strip()
    if not v or not _ANDROID_PKG_RE.match(v):
        return False, f"اسم حزمة Android غير صالح (مثال: com.example.app): '{value}'"
    return True, v


def validate_ssid(value):
    v = value if value is not None else ""
    if not v or len(v.encode("utf-8", "ignore")) > 32 or any(ord(c) < 0x20 for c in v):
        return False, "اسم شبكة WiFi (SSID) غير صالح أو فارغ"
    return True, v


def validate_wifi_password(value):
    v = value or ""
    if v and (len(v) < 8 or len(v) > 63 or any(ord(c) < 0x20 for c in v)):
        return False, "كلمة مرور WiFi يجب أن تكون 8-63 حرفاً بدون رموز تحكم"
    return True, v


def validate_device_path(value: str):
    v = (value or "").strip()
    if not v.startswith("/dev/") or ".." in v or "\x00" in v:
        return False, f"مسار جهاز غير صالح: '{value}'"
    if os.path.exists(v):
        try:
            st = os.stat(v)
            if not stat.S_ISBLK(st.st_mode) and not stat.S_ISCHR(st.st_mode):
                return False, f"المسار ليس جهاز كتلة أو محرفي صالح: '{value}'"
        except OSError as exc:
            return False, f"فشل التحقق من نوع الجهاز: {exc}"
    return True, v


def validate_mountpoint(value: str):
    v = (value or "").strip()
    ok, res = validate_safe_path(v, must_be_absolute=True)
    if not ok:
        return ok, res
    return True, v
