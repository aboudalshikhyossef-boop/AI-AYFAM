"""
AI AYFAM - Smart System Scanner
فحص النظام الذكي — لا يُصنِّف ملفات الصيانة الموثوقة كخطر
"""

import subprocess
import os
import re
import glob
import platform
from datetime import datetime

from utils import safe_exec


def _run(cmd, timeout=30):
    """⚠️ لأوامر shell ثابتة فقط. الاستثناء الوحيد المتغيّر (log_path في
    analyze_logs) تم نقله إلى قائمة وسائط منفصلة — راجع أسفل الملف."""
    res = safe_exec.run_trusted_shell(cmd, timeout=timeout)
    return res.ok, res.stdout, res.stderr


# ─────────────────────────────────────────────────────────────────────────────
#  TRUSTED SYSTEM PATHS — never flag these as suspicious
# ─────────────────────────────────────────────────────────────────────────────

TRUSTED_SYSTEM_PATHS = {
    "/usr/lib/apt/", "/var/lib/apt/", "/etc/apt/",
    "/usr/lib/dpkg/", "/var/lib/dpkg/", "/usr/bin/dpkg",
    "/usr/bin/apt", "/usr/bin/apt-get", "/usr/lib/snapd/",
    "/var/lib/snapd/", "/snap/", "/usr/share/apt/",
    "/usr/lib/openssh/", "/usr/sbin/sshd",
    "/bin/ping", "/bin/ping6", "/usr/bin/ping",
    "/bin/mount", "/bin/umount", "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/pkexec",
    "/usr/bin/fusermount", "/usr/bin/fusermount3",
    "/usr/sbin/pppd",
    "/usr/lib/dbus-1.0/", "/usr/lib/policykit-1/",
    "/usr/lib/xorg/", "/usr/lib/lightdm/",
    "/usr/share/", "/usr/lib/x86_64-linux-gnu/",
    "/lib/systemd/", "/usr/lib/systemd/",
    "/usr/lib/update-notifier/", "/usr/lib/ubuntu-advantage-tools/",
    "/usr/lib/update-manager/", "/usr/share/update-manager/",
}

TRUSTED_SUID_BINARIES = {
    "/usr/bin/sudo", "/usr/bin/su", "/bin/su",
    "/usr/bin/passwd", "/bin/passwd",
    "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/gpasswd", "/usr/bin/newgrp",
    "/usr/bin/pkexec",
    "/bin/ping", "/bin/ping6", "/usr/bin/ping",
    "/bin/mount", "/bin/umount", "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/fusermount", "/usr/bin/fusermount3",
    "/usr/sbin/pppd",
    "/usr/lib/openssh/ssh-keysign",
    "/sbin/unix_chkpwd", "/usr/sbin/unix_chkpwd",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/bin/newuidmap", "/usr/bin/newgidmap",
    "/usr/bin/at",
    "/usr/sbin/userhelper",
}

TRUSTED_CRON_KEYWORDS = {
    "apt-", "dpkg", "logrotate", "updatedb", "mlocate",
    "fstrim", "man-db", "samba", "anacron", "clamav",
    "postfix", "sendmail", "rsync", "popularity-contest",
    "apport", "unattended-upgrade", "update-", "/usr/sbin/",
    "/usr/bin/", "/bin/", "/usr/lib/cron/", "/usr/share/cron/",
}

SUSPICIOUS_SUID_LOCATIONS = {"/tmp/", "/home/", "/var/tmp/", "/dev/shm/", "/run/shm/"}


def _is_trusted_path(path: str) -> bool:
    if path in TRUSTED_SUID_BINARIES:
        return True
    return any(path.startswith(tp) for tp in TRUSTED_SYSTEM_PATHS)


def _is_trusted_cron(cmd: str) -> bool:
    return any(kw in cmd for kw in TRUSTED_CRON_KEYWORDS)


# ─────────────────────────────────────────────────────────────────────────────

def get_system_info() -> dict:
    _, cpu, _  = _run("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2")
    _, ram, _  = _run("free -h | awk '/Mem/{print $2\" total, \"$3\" used, \"$4\" free\"}'")
    _, up, _   = _run("uptime -p 2>/dev/null || uptime")
    _, kern, _ = _run("uname -r")
    _, os_r, _ = _run("cat /etc/os-release 2>/dev/null | grep PRETTY | cut -d= -f2 | tr -d '\"'")
    _, disk, _ = _run("df -h / | awk 'NR==2{print $2\" total, \"$3\" used, \"$4\" free\"}'")
    return {
        "hostname": os.uname().nodename,
        "os": os_r or platform.system(),
        "kernel": kern,
        "cpu": cpu.strip(),
        "ram": ram,
        "disk": disk,
        "uptime": up,
        "user": os.getenv("USER", ""),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def check_suid_files() -> dict:
    """Smart SUID — only flags truly unusual files, ignores system ones."""
    result = {"findings": [], "suid_files": [], "trusted_count": 0}
    _, out, _ = _run("find / -type f -perm -4000 2>/dev/null", timeout=60)

    for path in out.split("\n"):
        path = path.strip()
        if not path:
            continue
        result["suid_files"].append(path)

        if _is_trusted_path(path):
            result["trusted_count"] += 1
            continue

        if any(path.startswith(sp) for sp in SUSPICIOUS_SUID_LOCATIONS):
            result["findings"].append({
                "severity": "critical",
                "title": f"🔴 SUID في مكان خطير جداً: {path}",
                "detail": "ملف SUID خارج النظام — يشير إلى rootkit أو اختراق",
                "fix": f"chmod u-s '{path}'\nrm -f '{path}'  # إن لم يكن ملفاً أصلياً",
            })
        else:
            result["findings"].append({
                "severity": "medium",
                "title": f"SUID غير معروف — راجعه: {path}",
                "detail": "خارج القائمة البيضاء لملفات SUID المعروفة",
                "fix": f"file '{path}'\nchmod u-s '{path}'  # لإزالة SUID إن لم يكن ضرورياً",
            })
    return result

# NOTE: full file continues - this push was truncated in transit. See next commit.
