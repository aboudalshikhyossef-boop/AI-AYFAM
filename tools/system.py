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
from engine.rules_registry import create_finding


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
            result["findings"].append(create_finding(
                "SYS-SUID-001",
                severity="critical",
                title_ar=f"🔴 SUID في مكان خطير جداً: {path}",
                detail="ملف SUID خارج النظام — يشير إلى rootkit أو اختراق",
                fix=f"chmod u-s '{path}'\nrm -f '{path}'  # إن لم يكن ملفاً أصلياً",
                evidence={"path": path},
                stable_key=path,
            ))
        else:
            result["findings"].append(create_finding(
                "SYS-SUID-001",
                severity="medium",
                title_ar=f"SUID غير معروف — راجعه: {path}",
                detail="خارج القائمة البيضاء لملفات SUID المعروفة",
                fix=f"file '{path}'\nchmod u-s '{path}'  # لإزالة SUID إن لم يكن ضرورياً",
                evidence={"path": path},
                stable_key=path,
            ))
    return result


def check_crontabs() -> dict:
    """Smart cron — only flags truly suspicious jobs."""
    result = {"findings": [], "jobs": []}
    sources = [
        ("crontab -l 2>/dev/null", "user cron"),
        ("sudo crontab -l 2>/dev/null", "root cron"),
        ("cat /etc/crontab 2>/dev/null", "/etc/crontab"),
    ]
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
                 "/var/spool/cron/crontabs"]
    for d in cron_dirs:
        if os.path.isdir(d):
            try:
                for entry in os.listdir(d):
                    fpath = os.path.join(d, entry)
                    if os.path.isfile(fpath) and not os.path.islink(fpath):
                        # Use safe_exec.run to safely read files without shell globbing/interpolation
                        sources.append((fpath, d))
            except OSError:
                pass

    dangerous_patterns = [
        (r"(nc|ncat|netcat)\s+-[eln]", "Netcat reverse shell"),
        (r"bash\s+-i\s+>&",            "Bash reverse shell"),
        (r"/dev/tcp/",                 "/dev/tcp shell"),
        (r"base64\s+-d.*\|.*sh",       "Encoded payload exec"),
        (r"wget\s+http.*\|.*sh",       "Download & exec"),
        (r"curl\s+http.*\|.*sh",       "Download & exec"),
        (r"python.*-c.*socket",        "Python socket shell"),
        (r"chmod\s+777\s+/",           "chmod 777 on root"),
    ]

    seen = set()
    for cmd_str_or_path, source in sources:
        if cmd_str_or_path.startswith("/") and os.path.isfile(cmd_str_or_path):
            r = safe_exec.run(["cat", cmd_str_or_path], timeout=10)
            out = r.stdout
        else:
            _, out, _ = _run(cmd_str_or_path, timeout=10)
        for line in out.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or len(line) < 8 or line in seen:
                continue
            seen.add(line)
            if _is_trusted_cron(line):
                result["jobs"].append({"source": source, "job": line, "trusted": True})
                continue
            result["jobs"].append({"source": source, "job": line, "trusted": False})
            for pattern, desc in dangerous_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    result["findings"].append(create_finding(
                        "NET-SUSP-PROC",
                        severity="critical",
                        title_ar=f"🔴 Cron خبيث ({desc}): {source}",
                        detail=f"السطر: {line[:200]}",
                        fix="احذف فوراً: crontab -e",
                        evidence={"source": source, "line": line},
                        stable_key=line,
                    ))
                    break
            else:
                if any(kw in line for kw in ["/tmp/", "/dev/shm", "chmod 777", "suid"]):
                    result["findings"].append(create_finding(
                        "NET-SUSP-PROC",
                        severity="high",
                        title_ar=f"Cron مشبوه من {source}: {line[:60]}",
                        detail=f"الأمر: {line[:200]}",
                        fix="راجع: crontab -e",
                        evidence={"source": source, "line": line},
                        stable_key=line,
                    ))
    return result


def check_running_processes() -> dict:
    result = {"findings": [], "processes": []}
    _, out, _ = _run("ps aux --no-header 2>/dev/null | head -100")
    suspicious_keywords = {
        "nc -l":             ("critical", "Netcat listener — باب خلفي محتمل"),
        "ncat -l":           ("critical", "Ncat listener"),
        "python -m http.server": ("medium", "Python HTTP server نشط"),
        "php -S":            ("medium", "PHP server نشط"),
        "meterpreter":       ("critical", "Meterpreter — إطار اختراق!"),
        "mimikatz":          ("critical", "Mimikatz — سرقة بيانات!"),
        "/tmp/./":           ("high",     "عملية تعمل من /tmp"),
    }
    for line in out.split("\n"):
        if not line.strip():
            continue
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        user, pid, cpu = parts[0], parts[1], parts[2]
        cmd = parts[10]
        result["processes"].append({"user": user, "pid": pid, "cmd": cmd[:80]})
        for kw, (sev, desc) in suspicious_keywords.items():
            if kw in cmd:
                result["findings"].append(create_finding(
                    "NET-SUSP-PROC",
                    severity=sev,
                    title_ar=f"عملية مشبوهة: {desc} (PID:{pid})",
                    detail=f"User: {user} | CMD: {cmd[:150]}",
                    fix=f"sudo kill -9 {pid}",
                    evidence={"pid": pid, "user": user, "cmd": cmd},
                    stable_key=f"{user}:{cmd.split()[0]}",
                ))
                break
        try:
            if float(cpu) > 95 and not any(
                t in cmd for t in ("Xorg", "compiz", "gnome", "kde", "systemd", "kworker")
            ):
                result["findings"].append(create_finding(
                    "NET-SUSP-PROC",
                    severity="medium",
                    title_ar=f"استهلاك CPU مرتفع: {cmd[:50]} ({cpu}%)",
                    detail=f"PID:{pid} | User:{user}",
                    fix=f"sudo strace -p {pid} 2>&1 | head -10",
                    evidence={"pid": pid, "cpu": cpu},
                    stable_key=f"{user}:{cmd.split()[0]}",
                ))
        except ValueError:
            pass
    return result


def check_users_and_groups() -> dict:
    result = {"findings": [], "users": [], "sudo_users": []}
    _, out, _ = _run("cat /etc/passwd")
    current_user = os.getenv("USER", "")
    for line in out.split("\n"):
        parts = line.split(":")
        if len(parts) < 7:
            continue
        user, uid, shell = parts[0], parts[2], parts[6]
        uid_int = int(uid) if uid.isdigit() else 9999
        result["users"].append({"user": user, "uid": uid, "shell": shell})
        if uid_int == 0 and user != "root":
            result["findings"].append(create_finding(
                "SYS-USER-ROOT0",
                severity="critical",
                title_ar=f"🔴 مستخدم بـ UID=0 غير root: {user}",
                detail="يمتلك صلاحيات root كاملة!",
                fix=f"sudo userdel {user}",
                evidence={"user": user, "uid": uid},
                stable_key=user,
            ))
        elif uid_int >= 1000 and uid_int != 65534 and shell not in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin", "") and user != current_user:
            result["findings"].append(create_finding(
                "SYS-USER-SHELL",
                severity="info",
                title_ar=f"مستخدم بصلاحية تسجيل دخول: {user} (UID:{uid})",
                detail=f"Shell: {shell}",
                fix=f"إن لم يكن ضرورياً: sudo usermod -s /usr/sbin/nologin {user}",
                evidence={"user": user, "uid": uid},
                stable_key=user,
            ))
    _, sudo_out, _ = _run("getent group sudo wheel admin 2>/dev/null")
    for line in sudo_out.split("\n"):
        parts = line.split(":")
        if len(parts) >= 4 and parts[3]:
            for m in parts[3].split(","):
                m = m.strip()
                if m:
                    result["sudo_users"].append(m)
                    result["findings"].append(create_finding(
                        "SYS-USER-SUDO",
                        severity="info",
                        title_ar=f"مستخدم sudo: {m} (مجموعة: {parts[0]})",
                        detail="تأكد أن فقط المستخدمين الموثوقين في sudo",
                        fix="",
                        evidence={"user": m, "group": parts[0]},
                        stable_key=m,
                    ))
    return result


def check_ssh_config() -> dict:
    result = {"findings": [], "config": {}}
    for fpath in glob.glob("/etc/ssh/sshd_config") + glob.glob("/etc/ssh/sshd_config.d/*.conf"):
        try:
            with open(fpath) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        result["config"][parts[0].lower()] = parts[1]
        except Exception:
            continue
    cfg = result["config"]
    if cfg.get("permitrootlogin", "").lower() not in ("no", "prohibit-password", "forced-commands-only"):
        result["findings"].append(create_finding(
            "SSH-ROOT-001",
            severity="high",
            title_ar="SSH يسمح بدخول root مباشر!",
            detail=f"PermitRootLogin = {cfg.get('permitrootlogin','default')}",
            fix="PermitRootLogin no\nsudo systemctl restart ssh",
            stable_key="permitrootlogin",
        ))
    if cfg.get("passwordauthentication", "yes").lower() == "yes":
        result["findings"].append(create_finding(
            "SSH-PASS-001",
            severity="medium",
            title_ar="SSH يقبل كلمات المرور — استخدم SSH keys",
            detail="PasswordAuthentication yes",
            fix="PasswordAuthentication no  # في /etc/ssh/sshd_config",
            stable_key="passwordauth",
        ))
    if cfg.get("port", "22") == "22":
        result["findings"].append(create_finding(
            "SSH-PORT-001",
            severity="low",
            title_ar="SSH على المنفذ الافتراضي 22",
            detail="تغيير المنفذ يقلل Brute Force التلقائي",
            fix="Port 2222  # في /etc/ssh/sshd_config",
            stable_key="sshport",
        ))
    return result


def check_world_writable() -> dict:
    result = {"findings": [], "files": []}
    _, out, _ = _run(
        "find /etc /usr/bin /usr/sbin /bin /sbin -type f -perm -o+w 2>/dev/null | head -20",
        timeout=30
    )
    for path in out.split("\n"):
        path = path.strip()
        if not path:
            continue
        result["files"].append(path)
        sev = "critical" if any(path.startswith(p) for p in ["/etc/", "/usr/bin/", "/bin/"]) else "high"
        result["findings"].append(create_finding(
            "SYS-WRITE-001",
            severity=sev,
            title_ar=f"ملف نظام قابل للكتابة من الجميع: {path}",
            detail="تصعيد الصلاحيات محتمل!",
            fix=f"sudo chmod o-w '{path}'",
            evidence={"path": path},
            stable_key=path,
        ))
    return result


def get_installed_packages_vulnerabilities() -> dict:
    result = {"findings": [], "updates_available": 0}
    _, updates, _ = _run("apt-get -s upgrade 2>/dev/null | grep -c 'Inst '", timeout=30)
    try:
        count = int(updates.strip())
        result["updates_available"] = count
        if count > 0:
            sev = "high" if count > 20 else "medium" if count > 5 else "low"
            result["findings"].append(create_finding(
                "SYS-UPDATE-001",
                severity=sev,
                title_ar=f"تحديثات معلّقة: {count} حزمة",
                detail="بعض التحديثات قد تشمل إصلاحات أمنية",
                fix="sudo apt-get update && sudo apt-get upgrade -y",
                evidence={"count": count},
                stable_key="pending_updates",
            ))
    except ValueError:
        pass
    _, sec_upd, _ = _run("apt-get -s upgrade 2>/dev/null | grep -i 'security' | wc -l", timeout=30)
    try:
        sec_count = int(sec_upd.strip())
        if sec_count > 0:
            result["findings"].append(create_finding(
                "SYS-UPDATE-001",
                severity="high",
                title_ar=f"تحديثات أمنية معلّقة: {sec_count} حزمة",
                detail="تحديثات تتضمن إصلاحات أمنية",
                fix="sudo apt-get update && sudo apt-get upgrade -y",
                evidence={"count": sec_count},
                stable_key="pending_sec_updates",
            ))
    except ValueError:
        pass
    return result


# حزم حسّاسة أمنياً يستحق التحقق من CVE مرتبطة بها تحديداً عند وجود تحديث
# معلّق لها — قائمة مقصودة (وليست كل الحزم) لتفادي عشرات طلبات الشبكة لكل
# فحص نظام. القائمة تغطي الخدمات الشبكية والمصادقة والقواعد الأساسية الأكثر
# استهدافاً فعلياً في تقارير CVE/CISA KEV.
SECURITY_CRITICAL_PACKAGES = (
    "openssh-server", "openssh-client", "openssl", "libssl", "sudo", "curl",
    "wget", "nginx", "apache2", "samba", "smbclient", "bash", "python3",
    "php", "mysql-server", "mariadb-server", "postgresql", "sqlite3",
    "glibc", "systemd", "polkit", "docker", "containerd", "gnupg", "git",
    "grub", "cups", "avahi", "dbus", "networkmanager",
)


def list_upgradable_security_packages() -> dict:
    """
    يعيد أسماء الحزم القابلة للترقية حالياً والتي تقع ضمن قائمة الحزم
    الحسّاسة أمنياً (SECURITY_CRITICAL_PACKAGES) — دون أي اتصال بالإنترنت هنا.
    طبقة أعلى (core/agent.py) تُطابق هذه الأسماء مع CISA KEV/NVD عبر tools/web.py
    لإنتاج نتائج "ربط تلقائي بين فحص النظام وقاعدة CVE". الفصل مقصود: system.py
    يبقى بلا اتصال شبكي، وweb.py هو الوحيد الذي يتحدث مع الإنترنت.
    """
    result = {"packages": []}
    _, out, _ = _run("apt list --upgradable 2>/dev/null", timeout=30)
    seen = set()
    for line in out.split("\n"):
        line = line.strip()
        if "/" not in line or "upgradable from" not in line:
            continue
        pkg_field = line.split("/", 1)[0].strip()
        base_name = pkg_field.split(":")[0].lower()  # يزيل لاحقة العمارة مثل :amd64
        installed = ""
        marker = "upgradable from:"
        if marker in line:
            installed = line.split(marker, 1)[1].strip(" []")
        for watched in SECURITY_CRITICAL_PACKAGES:
            if watched in base_name and base_name not in seen:
                seen.add(base_name)
                result["packages"].append({
                    "package": base_name,
                    "version": installed,
                    "raw_line": line,
                })
                break
    return result


def _read_log_sources() -> tuple[list[str], list[dict]]:
    """يقرأ سجلات المصادقة من الملفات ثم journald، ويُبلغ عن كل مصدر (قُرئ / مرفوض / غير موجود)."""
    lines, sources = [], []
    for log_path in ("/var/log/auth.log", "/var/log/auth.log.1", "/var/log/secure", "/var/log/syslog"):
        if not os.path.exists(log_path):
            continue
        res = safe_exec.run(["tail", "-n", "3000", log_path])
        if res.ok and res.stdout:
            chunk = res.stdout.split("\n")
            lines.extend(chunk)
            sources.append({"source": log_path, "status": "read", "lines": len(chunk)})
        else:
            denied = "denied" in (res.stderr or "").lower() or "permission" in (res.stderr or "").lower()
            sources.append({"source": log_path, "status": "denied" if denied else "empty", "lines": 0})
    if not any(s["status"] == "read" for s in sources):
        res = safe_exec.run(["journalctl", "-u", "ssh", "-u", "sshd", "-t", "sudo", "--since", "-7d", "-n", "3000", "--no-pager", "-o", "short"], timeout=20)
        text = res.stdout or ""
        if res.ok and text and "No entries" not in text and "-- No" not in text[:20]:
            chunk = text.split("\n")
            lines.extend(chunk)
            sources.append({"source": "journalctl (7 أيام)", "status": "read", "lines": len(chunk)})
        else:
            denied = "not seeing messages" in (res.stderr or "") or "permission" in (res.stderr or "").lower()
            sources.append({"source": "journalctl", "status": "denied" if denied else "empty", "lines": 0})
    return lines, sources


def analyze_logs() -> dict:
    from engine.logforensics import LogForensicsEngine
    engine = LogForensicsEngine()
    findings = engine.analyze_all_logs(window_minutes=1440)
    return {
        "findings": findings,
        "brute_force_ips": {},
        "failed_logins": 0,
        "successful_root_logins": 0,
        "sources": [{"source": "journald / auth.log", "status": "read", "lines": len(findings)}],
        "invalid_users": {},
        "sudo_failures": 0,
        "new_users": [],
    }
