"""
AI AYFAM - Auto-Fix Engine
محرك الإصلاح التلقائي للمشاكل الأمنية

كل دالة هنا قد تُستدعى بمدخلات حرة يكتبها المستخدم مباشرة في وضع المحادثة
(IP, PID, مسار ملف...) — لذلك كل دالة تتحقق من مدخلاتها عبر utils.validators
*قبل* أي تنفيذ، وتنفّذ الأوامر عبر utils.safe_exec بدون shell=True إطلاقاً.
"""

import os
import re
from datetime import datetime

from utils import safe_exec, validators


def _backup_file(path):
    if not os.path.exists(path):
        return None
    backup = f"{path}.ayfam_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    res = safe_exec.run(["cp", "--", path, backup], sudo=True)
    return backup if res.ok else None


def _validate_sshd_config(config: str) -> bool:
    result = safe_exec.run(["sshd", "-t", "-f", config], sudo=True, check_binary=False)
    return result.ok


def _set_global_sshd_option(config: str, option: str, value: str):
    """Set an sshd option before the first Match block, preserving the file."""
    script = (
        "import re,sys; p=sys.argv[1]; option=sys.argv[2]; value=sys.argv[3]; "
        "lines=open(p,encoding='utf-8').read().splitlines(True); "
        "match=next((i for i,x in enumerate(lines) if re.match(r'^\\s*Match\\s',x,re.I)),len(lines)); "
        "pat=re.compile(r'^\\s*#?\\s*'+re.escape(option)+r'(\\s|$)',re.I); "
        "changed=False; out=[]; "
        "\nfor i,x in enumerate(lines):\n"
        "  if i < match and pat.match(x):\n"
        "    out.append(option+' '+value+'\\n'); changed=True\n"
        "  else: out.append(x)\n"
        "if not changed: out.insert(match, option+' '+value+'\\n')\n"
        "open(p,'w',encoding='utf-8').writelines(out)"
    )
    return safe_exec.run(["python3", "-c", script, config, option, value], sudo=True)


def _restore_backup(config: str, backup: str | None) -> bool:
    if not backup:
        return False
    return safe_exec.run(["cp", "--", backup, config], sudo=True).ok


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
    return {"success": all(s["ok"] for s in steps), "steps": steps}


@register_fix("disable_root_ssh")
def fix_disable_root_ssh():
    config = "/etc/ssh/sshd_config"
    backup = _backup_file(config)
    steps = [{"cmd": f"backup to {backup}", "ok": bool(backup)}]
    r1 = _set_global_sshd_option(config, "PermitRootLogin", "no")
    steps.append({"cmd": "Set PermitRootLogin no", "ok": r1.ok, "out": r1.stdout, "err": r1.stderr})
    if not r1.ok or not _validate_sshd_config(config):
        _restore_backup(config, backup)
        return {"success": False, "steps": steps + [{"cmd": "validate sshd config", "ok": False}], "backup": backup}
    r2 = safe_exec.run(["systemctl", "restart", "sshd"], sudo=True)
    steps.append({"cmd": "restart sshd", "ok": r2.ok, "out": r2.stdout})
    if not r2.ok:
        _restore_backup(config, backup)
    return {"success": r2.ok, "steps": steps, "backup": backup}


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
    r2 = safe_exec.run(["apt-get", "upgrade", "-y"], sudo=True, timeout=1800)
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
    authorized_keys = os.path.expanduser("~/.ssh/authorized_keys")
    if not os.path.isfile(authorized_keys):
        return {"success": False, "error": "تم الإلغاء: لا يوجد ~/.ssh/authorized_keys؛ قد تفقد الوصول إلى SSH", "backup": backup}
    r1 = _set_global_sshd_option(config, "PasswordAuthentication", "no")
    steps = [{"cmd": "disable password auth", "ok": r1.ok}]
    if not r1.ok or not _validate_sshd_config(config):
        _restore_backup(config, backup)
        steps.append({"cmd": "validate sshd config", "ok": False})
        return {"success": False, "steps": steps, "backup": backup}
    r2 = safe_exec.run(["systemctl", "restart", "sshd"], sudo=True)
    steps.append({"cmd": "restart sshd", "ok": r2.ok})
    if not r2.ok:
        _restore_backup(config, backup)
    return {"success": r2.ok, "steps": steps, "backup": backup}


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
    if safe_exec.run(["resolvectl", "status"], check_binary=False).ok:
        interfaces = safe_exec.run(["resolvectl", "dns"], check_binary=False)
        if not interfaces.ok:
            return {"success": False, "error": "تعذر اكتشاف واجهة DNS عبر resolvectl"}
        iface_names = re.findall(r"^([^\s:]+):", interfaces.stdout, flags=re.MULTILINE)
        iface = next((name for name in iface_names if name != "Global"), "")
        if not iface:
            return {"success": False, "error": "لم يُعثر على واجهة شبكة لتغيير DNS"}
        r = safe_exec.run(["resolvectl", "dns", iface, dns1, dns2], sudo=True)
        return {"success": r.ok, "steps": [{"cmd": f"resolvectl dns {iface}", "ok": r.ok}], "persistent": False}
    return {"success": False, "error": "resolvectl غير متاح؛ لم تتم الكتابة فوق /etc/resolv.conf"}


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
