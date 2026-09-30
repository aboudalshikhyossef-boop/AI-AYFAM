"""
AI AYFAM - Auto-Fix Engine
محرك الإصلاح التلقائي للمشاكل الأمنية

كل دالة هنا قد تُستدعى بمدخلات حرة يكتبها المستخدم مباشرة في وضع المحادثة
(IP, PID, مسار ملف...) — لذلك كل دالة تتحقق من مدخلاتها عبر utils.validators
*قبل* أي تنفيذ، وتنفّذ الأوامر عبر utils.safe_exec بدون shell=True إطلاقاً.
"""

import os
from datetime import datetime

from utils import safe_exec, validators


def _backup_file(path):
    if not os.path.exists(path):
        return None
    backup = f"{path}.ayfam_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    res = safe_exec.run(["cp", "--", path, backup], sudo=True)
    return backup if res.ok else None


FIX_REGISTRY = {}


def register_fix(fix_id):
    def decorator(fn):
        FIX_REGISTRY[fix_id] = fn
        return fn
    return decorator


@register_fix("enable_firewall")
def fix_enable_firewall():
    steps = []
    r1 = safe_exec.run(["ufw", "enable"], sudo=True, input_data="y\n")
    steps.append({"cmd": "ufw enable", "ok": r1.ok, "out": r1.stdout, "err": r1.stderr})
    r2 = safe_exec.run(["ufw", "default", "deny", "incoming"], sudo=True)
    steps.append({"cmd": "ufw default deny incoming", "ok": r2.ok, "out": r2.stdout})
    r3 = safe_exec.run(["ufw", "default", "allow", "outgoing"], sudo=True)
    steps.append({"cmd": "ufw default allow outgoing", "ok": r3.ok, "out": r3.stdout})
    r4 = safe_exec.run(["ufw", "allow", "22/tcp"], sudo=True)
    steps.append({"cmd": "ufw allow 22/tcp (SSH)", "ok": r4.ok, "out": r4.stdout})
    return {"success": all(s["ok"] for s in steps[:2]), "steps": steps}


@register_fix("disable_root_ssh")
def fix_disable_root_ssh():
    config = "/etc/ssh/sshd_config"
    backup = _backup_file(config)
    steps = [{"cmd": f"backup to {backup}", "ok": bool(backup)}]
    r1 = safe_exec.run(["sed", "-i", "s/^PermitRootLogin.*/PermitRootLogin no/", config], sudo=True)
    ok = r1.ok
    if ok:
        # تأكد أن السطر موجود فعلاً (sed لا يضيف سطراً جديداً إن لم يجد تطابقاً)
        check = safe_exec.run(["grep", "-q", "^PermitRootLogin no", config], sudo=True)
        if not check.ok:
            r1b = safe_exec.write_file_privileged(config, "PermitRootLogin no\n", append=True)
            ok = r1b.ok
    steps.append({"cmd": "Set PermitRootLogin no", "ok": ok, "out": r1.stdout, "err": r1.stderr})
    r2 = safe_exec.run(["systemctl", "restart", "sshd"], sudo=True)
    steps.append({"cmd": "restart sshd", "ok": r2.ok, "out": r2.stdout})
    return {"success": ok, "steps": steps, "backup": backup}


@register_fix("remove_suid")
def fix_remove_suid(filepath: str):
    ok_path, path_or_err = validators.validate_safe_path(filepath)
    if not ok_path:
        return {"success": False, "error": path_or_err}
    filepath = path_or_err
    if not os.path.exists(filepath):
        return {"success": False, "error": f"الملف غير موجود: {filepath}"}
    backup = _backup_file(filepath)
    r = safe_exec.run(["chmod", "u-s", "--", filepath], sudo=True)
    return {"success": r.ok, "steps": [{"cmd": f"chmod u-s {filepath}", "ok": r.ok, "out": r.stdout, "err": r.stderr}], "backup": backup}


@register_fix("ban_ip")
def fix_ban_ip(ip: str):
    ok_ip, ip_or_err = validators.validate_ip_for_fix(ip)
    if not ok_ip:
        return {"success": False, "error": ip_or_err}
    ip = ip_or_err
    steps = []
    r1 = safe_exec.run(["ufw", "deny", "from", ip], sudo=True)
    steps.append({"cmd": f"ufw deny from {ip}", "ok": r1.ok, "out": r1.stdout})
    r2 = safe_exec.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], sudo=True)
    steps.append({"cmd": f"iptables block {ip}", "ok": r2.ok, "out": r2.stdout})
    r3 = safe_exec.run(["fail2ban-client", "set", "sshd", "banip", ip], sudo=True, check_binary=False)
    steps.append({"cmd": f"fail2ban ban {ip}", "ok": r3.ok, "out": r3.stdout})
    return {"success": r1.ok or r2.ok, "steps": steps}


@register_fix("update_system")
def fix_update_system():
    steps = []
    r1 = safe_exec.run(["apt-get", "update", "-y"], sudo=True, timeout=120)
    steps.append({"cmd": "apt-get update", "ok": r1.ok, "out": r1.stdout[:200]})
    r2 = safe_exec.run(["apt-get", "upgrade", "-y"], sudo=True, timeout=300)
    steps.append({"cmd": "apt-get upgrade", "ok": r2.ok, "out": r2.stdout[:200]})
    return {"success": r1.ok and r2.ok, "steps": steps}


@register_fix("kill_process")
def fix_kill_process(pid: str):
    ok_pid, pid_or_err = validators.validate_pid(pid)
    if not ok_pid:
        return {"success": False, "error": pid_or_err}
    pid = pid_or_err
    r = safe_exec.run(["kill", "-9", "--", pid], sudo=True)
    return {"success": r.ok, "steps": [{"cmd": f"kill -9 {pid}", "ok": r.ok, "out": r.stdout, "err": r.stderr}]}


@register_fix("disable_ssh_password_auth")
def fix_disable_ssh_password_auth():
    config = "/etc/ssh/sshd_config"
    backup = _backup_file(config)
    r1 = safe_exec.run(["sed", "-i", "s/^PasswordAuthentication.*/PasswordAuthentication no/", config], sudo=True)
    ok = r1.ok
    if ok:
        check = safe_exec.run(["grep", "-q", "^PasswordAuthentication no", config], sudo=True)
        if not check.ok:
            r1b = safe_exec.write_file_privileged(config, "PasswordAuthentication no\n", append=True)
            ok = r1b.ok
    r2 = safe_exec.run(["systemctl", "restart", "sshd"], sudo=True)
    return {"success": ok, "steps": [{"cmd": "disable password auth", "ok": ok}, {"cmd": "restart sshd", "ok": r2.ok}], "backup": backup}


@register_fix("remove_autorun")
def fix_remove_autorun(filepath: str):
    ok_path, path_or_err = validators.validate_safe_path(filepath)
    if not ok_path:
        return {"success": False, "error": path_or_err}
    filepath = path_or_err
    backup = _backup_file(filepath)
    r = safe_exec.remove_path_privileged(filepath)
    return {"success": r.ok, "steps": [{"cmd": f"rm -f -- {filepath}", "ok": r.ok, "out": r.stdout, "err": r.stderr}], "backup": backup}


@register_fix("restrict_world_writable")
def fix_restrict_world_writable(filepath: str):
    ok_path, path_or_err = validators.validate_safe_path(filepath)
    if not ok_path:
        return {"success": False, "error": path_or_err}
    filepath = path_or_err
    r = safe_exec.run(["chmod", "o-w", "--", filepath], sudo=True)
    return {"success": r.ok, "steps": [{"cmd": f"chmod o-w {filepath}", "ok": r.ok, "out": r.stdout, "err": r.stderr}]}


@register_fix("setup_fail2ban")
def fix_setup_fail2ban():
    steps = []
    r1 = safe_exec.run(["apt-get", "install", "-y", "fail2ban"], sudo=True, timeout=120)
    steps.append({"cmd": "install fail2ban", "ok": r1.ok, "out": r1.stdout[:100]})
    jail_config = (
        "[DEFAULT]\nbantime  = 3600\nfindtime  = 600\nmaxretry = 5\n\n"
        "[sshd]\nenabled = true\nport    = ssh\nfilter  = sshd\n"
        "logpath = %(sshd_log)s\nmaxretry = 3\n"
    )
    r2 = safe_exec.write_file_privileged("/etc/fail2ban/jail.local", jail_config)
    steps.append({"cmd": "configure fail2ban", "ok": r2.ok})
    r3 = safe_exec.run(["systemctl", "enable", "--now", "fail2ban"], sudo=True)
    steps.append({"cmd": "enable fail2ban", "ok": r3.ok, "out": r3.stdout})
    return {"success": r1.ok and r3.ok, "steps": steps}


@register_fix("change_dns")
def fix_change_dns(dns1: str = "1.1.1.1", dns2: str = "1.0.0.1"):
    for label, val in (("dns1", dns1), ("dns2", dns2)):
        if not validators.is_valid_ip(val):
            return {"success": False, "error": f"عنوان DNS غير صالح ({label}): {val}"}
    backup = _backup_file("/etc/resolv.conf")
    content = f"nameserver {dns1}\nnameserver {dns2}\n"
    r = safe_exec.write_file_privileged("/etc/resolv.conf", content)
    return {"success": r.ok, "steps": [{"cmd": f"set DNS to {dns1}, {dns2}", "ok": r.ok}], "backup": backup}


def apply_fix(fix_id: str, **kwargs) -> dict:
    if fix_id not in FIX_REGISTRY:
        return {"success": False, "error": f"Fix '{fix_id}' not found. Available: {list(FIX_REGISTRY.keys())}"}
    fn = FIX_REGISTRY[fix_id]
    try:
        result = fn(**kwargs) if kwargs else fn()
        return result
    except Exception as e:
        return {"success": False, "error": str(e)}


def list_available_fixes():
    return list(FIX_REGISTRY.keys())
