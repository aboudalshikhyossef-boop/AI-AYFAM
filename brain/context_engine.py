"""
AI AYFAM — Context Engine
يفهم بيئته بنسبة 100%: من المستخدم، ما المتصل، ما يعمل
"""

import os
import pwd
import socket
import platform
from datetime import datetime

from utils import safe_exec


def _run(cmd, timeout=10):
    """⚠️ لأوامر shell ثابتة فقط — جميع الاستدعاءات في هذا الملف نصوص ثابتة
    100% بدون أي متغيّر مُدرَج، وهو أمر تم التحقق منه بمراجعة كل موضع استخدام."""
    return safe_exec.run_trusted_shell(cmd, timeout=timeout).stdout


class ContextEngine:
    # كاش على مستوى الفئة (class-level) — IP العام يُجلب مرة واحدة فقط لكل
    # عمر العملية، وليس في كل refresh()، لتفادي تأخير 3-6 ثوانٍ متكرر.
    _public_ip_cache = None
    _public_ip_fetched = False

    def __init__(self):
        self._cache = {}
        self._session_start = datetime.now()
        self.refresh()

    def _cached_public_ip(self) -> str:
        """يجلب عنوان IP العام مرة واحدة فقط لكل عمر العملية (session).
        الفشل يُخزَّن مؤقتاً أيضاً حتى لا تتكرر محاولة بطيئة في كل استدعاء
        إن كان الاتصال بالإنترنت معطلاً أو بطيئاً."""
        if ContextEngine._public_ip_fetched:
            return ContextEngine._public_ip_cache or ""
        ContextEngine._public_ip_fetched = True
        try:
            import requests
            r = requests.get("https://api.ipify.org?format=json", timeout=3)
            if r.status_code == 200:
                ip = r.json().get("ip", "") or ""
                ContextEngine._public_ip_cache = ip
                return ip
        except Exception:
            pass
        ContextEngine._public_ip_cache = ""
        return ""

    def refresh(self):
        """يجمع معلومات البيئة الكاملة"""
        self._cache = {
            "user":          self._get_user_context(),
            "system":        self._get_system_context(),
            "network":       self._get_network_context(),
            "devices":       self._get_device_context(),
            "security":      self._get_security_context(),
            "session_start": self._session_start.isoformat(),
        }

    # ─── User Context ────────────────────────────────────────────────────────
    def _get_user_context(self) -> dict:
        uid = os.getuid()
        try:
            pw = pwd.getpwuid(uid)
            username = pw.pw_name
            home = pw.pw_dir
        except Exception:
            username = os.environ.get("USER", "unknown")
            home = os.path.expanduser("~")

        is_root = (uid == 0)
        has_sudo = False
        sudo_groups = []

        groups_out = _run("groups")
        sudo_groups = [g for g in groups_out.split() if g in ("sudo", "wheel", "admin")]
        has_sudo = bool(sudo_groups) or is_root

        # Logged-in users
        who_out = _run("who")
        logged_users = []
        for line in who_out.split("\n"):
            if line.strip():
                parts = line.split()
                if parts:
                    logged_users.append(parts[0])

        # Last logins
        last_out = _run("last -n 5 --time-format iso 2>/dev/null || last -n 5 2>/dev/null")
        last_logins = []
        for line in last_out.split("\n")[:5]:
            if line.strip() and "wtmp" not in line:
                last_logins.append(line.strip())

        return {
            "username": username,
            "uid": uid,
            "home": home,
            "is_root": is_root,
            "has_sudo": has_sudo,
            "sudo_groups": sudo_groups,
            "role": "ROOT / مدير جذر" if is_root else ("SUDO / مدير" if has_sudo else "USER / مستخدم عادي"),
            "logged_users": list(set(logged_users)),
            "last_logins": last_logins[:3],
        }

    # ─── System Context ──────────────────────────────────────────────────────
    def _get_system_context(self) -> dict:
        hostname = socket.gethostname()
        kernel   = _run("uname -r")
        arch     = _run("uname -m")
        uptime   = _run("uptime -p 2>/dev/null || uptime")

        # OS detection
        os_name = "Linux"
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME"):
                        os_name = line.split("=")[1].strip().strip('"')
                        break
        except Exception:
            os_name = platform.platform()

        # Resources
        mem_out = _run("free -h 2>/dev/null | awk 'NR==2{print $2, $3, $4}'")
        mem_parts = mem_out.split()
        cpu_out = _run("nproc 2>/dev/null")
        load_out = _run("uptime | awk -F'load average:' '{print $2}'")
        disk_out = _run("df -h / 2>/dev/null | awk 'NR==2{print $2, $3, $5}'")

        return {
            "hostname": hostname,
            "os": os_name,
            "kernel": kernel,
            "arch": arch,
            "uptime": uptime,
            "cpu_cores": cpu_out or "?",
            "load": load_out.strip() if load_out else "?",
            "memory": {"total": mem_parts[0] if len(mem_parts) > 0 else "?",
                       "used":  mem_parts[1] if len(mem_parts) > 1 else "?",
                       "free":  mem_parts[2] if len(mem_parts) > 2 else "?"},
            "disk_root": disk_out or "?",
        }

    # ─── Network Context ─────────────────────────────────────────────────────
    def _get_network_context(self) -> dict:
        # Interfaces
        ip_out = _run("ip -o addr show 2>/dev/null | awk '{print $2, $4}'")
        interfaces = {}
        for line in ip_out.split("\n"):
            parts = line.split()
            if len(parts) >= 2:
                iface = parts[0]
                addr  = parts[1]
                if iface not in ("lo",):
                    interfaces[iface] = addr

        # Default gateway
        gw = _run("ip route show default 2>/dev/null | awk '{print $3}' | head -1")

        # Public IP — lazy / cached per process to avoid 3-6s startup delay on every refresh.
        # Only fetch once per agent lifetime; users can force-refresh via update_intel.
        public_ip = self._cached_public_ip()

        # DNS
        dns_out = _run("cat /etc/resolv.conf 2>/dev/null | grep nameserver | awk '{print $2}'")
        dns = [d for d in dns_out.split("\n") if d.strip()]

        # Firewall
        ufw_out = _run("ufw status 2>/dev/null | head -1")
        fw_enabled = "active" in ufw_out.lower() or "نشط" in ufw_out.lower()

        # Active connections count
        conns_count = _run("ss -tn state established 2>/dev/null | tail -n +2 | wc -l")

        return {
            "interfaces": interfaces,
            "gateway": gw or "?",
            "public_ip": public_ip or "غير متاح",
            "dns": dns[:3],
            "firewall_active": fw_enabled,
            "active_connections": conns_count or "0",
        }

    # ─── Device Context ──────────────────────────────────────────────────────
    def _get_device_context(self) -> dict:
        # USB devices (fast)
        lsusb_out = _run("lsusb 2>/dev/null")
        usb_devices = []
        for line in lsusb_out.split("\n"):
            if line.strip() and "Bus" in line:
                usb_devices.append(line.strip())

        # Mounted removable media
        mounts_out = _run("findmnt -t vfat,ntfs,exfat -o TARGET,SOURCE,FSTYPE --noheadings 2>/dev/null")
        removable = []
        for line in mounts_out.split("\n"):
            if line.strip():
                removable.append(line.strip())

        # Bluetooth
        bt_out = _run("hciconfig 2>/dev/null | grep -E 'hci|UP|DOWN'")
        bluetooth_on = "UP" in bt_out

        # WiFi adapters
        wifi_out = _run("iw dev 2>/dev/null | grep Interface | awk '{print $2}'")
        wifi_adapters = [w for w in wifi_out.split("\n") if w.strip()]

        # ADB phones
        adb_out = _run("adb devices 2>/dev/null | tail -n +2")
        phones = []
        for line in adb_out.split("\n"):
            if line.strip() and "\t" in line:
                serial, status = line.split("\t")
                phones.append({"serial": serial.strip(), "status": status.strip()})

        return {
            "usb_count": len(usb_devices),
            "usb_devices": usb_devices[:5],
            "removable_media": removable,
            "bluetooth": bluetooth_on,
            "wifi_adapters": wifi_adapters,
            "android_phones": phones,
        }

    # ─── Security Context ────────────────────────────────────────────────────
    def _get_security_context(self) -> dict:
        # Open ports count
        ports_out = _run("ss -tulpn 2>/dev/null | tail -n +2 | wc -l")

        # Failed login attempts
        failed_logins = _run("grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0")
        try:
            failed_count = int(failed_logins)
        except Exception:
            failed_count = 0

        # Last reboot
        reboot_out = _run("last reboot 2>/dev/null | head -1")

        # Running services count
        services_out = _run("systemctl list-units --state=running --type=service --no-legend 2>/dev/null | wc -l")

        # Pending updates
        updates_out = _run("apt list --upgradable 2>/dev/null | grep -c upgradable 2>/dev/null || echo 0")
        try:
            pending_updates = int(updates_out) - 1  # subtract header
        except Exception:
            pending_updates = 0

        return {
            "open_ports_count": ports_out or "?",
            "failed_login_attempts": failed_count,
            "last_reboot": reboot_out.split()[:5] if reboot_out else ["?"],
            "running_services": services_out or "?",
            "pending_updates": max(0, pending_updates),
            "threat_level": self._calc_threat_level(failed_count, pending_updates),
        }

    def update_threat_level(self, findings: list) -> str:
        """تحديث مستوى التهديد المعروض من نتائج الفحص الحقيقية، وليس فقط من السجلات."""
        critical = sum(1 for f in findings if str(f.get("severity","")).lower() == "critical")
        high = sum(1 for f in findings if str(f.get("severity","")).lower() == "high")
        medium = sum(1 for f in findings if str(f.get("severity","")).lower() == "medium")
        if critical >= 1:
            level = "CRITICAL"
        elif high >= 3:
            level = "CRITICAL"
        elif high >= 1:
            level = "HIGH"
        elif medium >= 3:
            level = "HIGH"
        elif medium >= 1:
            level = "MEDIUM"
        else:
            level = "LOW"
        self._cache.setdefault("security", {})["threat_level"] = level
        return level

    def _calc_threat_level(self, failed_logins: int, pending_updates: int) -> str:
        if failed_logins > 50 or pending_updates > 30:
            return "CRITICAL"
        elif failed_logins > 10 or pending_updates > 10:
            return "HIGH"
        elif failed_logins > 0 or pending_updates > 5:
            return "MEDIUM"
        else:
            return "LOW"

    # ─── Public API ──────────────────────────────────────────────────────────
    @property
    def user(self) -> dict:
        return self._cache.get("user", {})

    @property
    def system(self) -> dict:
        return self._cache.get("system", {})

    @property
    def network(self) -> dict:
        return self._cache.get("network", {})

    @property
    def devices(self) -> dict:
        return self._cache.get("devices", {})

    @property
    def security(self) -> dict:
        return self._cache.get("security", {})

    def summary(self) -> dict:
        return self._cache

    def threat_level(self) -> str:
        return self._cache.get("security", {}).get("threat_level", "UNKNOWN")

    def who_am_i(self) -> str:
        u = self.user
        s = self.system
        return (
            f"أنا AI AYFAM — وكيل أمن سيبراني ذكي.\n"
            f"أعمل على: {s.get('hostname','?')} [{s.get('os','Linux')}]\n"
            f"المستخدم الحالي: {u.get('username','?')} — {u.get('role','?')}\n"
            f"وقت الجلسة: {self._session_start.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"مستوى التهديد الحالي: {self.threat_level()}\n"
            f"أجهزة USB متصلة: {self.devices.get('usb_count', 0)}\n"
            f"جدار الحماية: {'🟢 نشط' if self.network.get('firewall_active') else '🔴 معطَّل'}\n"
            f"اتصالات نشطة: {self.network.get('active_connections', '?')}"
        )

    @classmethod
    def sanitize_privacy_data(cls, text: str, hostname: str = "", username: str = "") -> str:
        """
        طبقة تمويه وتعمية حماية الخصوصية قبل إرسال النص إلى مزودات AI الخارجية (Gemini).
        تستبدل اسم الجهاز واسم المستخدم برمزين عامين [HOST] و [USER]، مع تعمية مسارات /home/<user>.
        """
        if not text:
            return ""

        # Auto-detect hostname if not provided
        if not hostname:
            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = ""

        # Auto-detect username if not provided
        if not username:
            try:
                username = pwd.getpwuid(os.getuid()).pw_name
            except Exception:
                username = os.environ.get("USER", "")

        result = text
        if hostname and len(hostname) > 1:
            result = result.replace(hostname, "[HOST]")

        if username and len(username) > 1:
            # Mask user's home directory pattern /home/username
            home_path = f"/home/{username}"
            result = result.replace(home_path, "/home/[USER]")
            result = result.replace(username, "[USER]")

        return result
