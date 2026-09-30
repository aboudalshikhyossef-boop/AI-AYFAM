"""
AI AYFAM v5 — Threat Hunter & Persistence Detection
محرك صيد التهديدات المتقدم — يكتشف محاولات الاختراق الخفية، الأبواب الخلفية،
ملفات preload، ومفاتيح SSH الدخيلة، والعمليات التي تعمل من ملفات تنفيذية محذوفة.
"""

import os
import re
from typing import List, Optional
from engine.finding import Finding
from engine.sysreader import SystemReader

class ThreatHunter:
    def __init__(self, sys_reader: Optional[SystemReader] = None):
        self.sys = sys_reader or SystemReader()

    def hunt_all(self) -> List[Finding]:
        findings = []
        findings.extend(self.check_ld_preload())
        findings.extend(self.check_deleted_exe_processes())
        findings.extend(self.check_authorized_keys())
        findings.extend(self.check_shell_profiles())
        findings.extend(self.check_suspicious_cron_scripts())
        return findings

    def check_ld_preload(self) -> List[Finding]:
        findings = []
        preload_file = "/etc/ld.so.preload"
        if self.sys.exists(preload_file):
            content = self.sys.read_text(preload_file).strip()
            if content:
                findings.append(Finding(
                    severity="critical",
                    title="🚨 رصد مكتبة مشتركة محقونة في /etc/ld.so.preload",
                    detail=f"الملف يحتوي على: '{content}'. هذا مؤشر كلاسيكي لـ Userland Rootkit يعترض نداءات النظام.",
                    fix=f"sudo rm -f {preload_file} # وافحص المكتبة المذكورة فوراً",
                    category="persistence",
                    tags=["rootkit", "ld_preload", "stealth"],
                    attack_ids=["T1574.006"],
                    confidence=1.0,
                ))
        return findings

    def check_deleted_exe_processes(self) -> List[Finding]:
        """كشف العمليات التي تعمل حالياً من ملف تنفيذي تم حذفه من القرص."""
        findings = []
        proc_dir = "/proc"
        if not self.sys.is_dir(proc_dir):
            return findings

        for pid in self.sys.listdir(proc_dir):
            if not pid.isdigit() or pid == "1":
                continue
            exe_link = f"/proc/{pid}/exe"
            try:
                # التحقق إن كان الرابط يشير إلى (deleted)
                dest = os.readlink(exe_link) if hasattr(os, "readlink") else ""
                if "(deleted)" in dest:
                    cmdline = self.sys.read_text(f"/proc/{pid}/cmdline").replace("\x00", " ")
                    findings.append(Finding(
                        severity="high",
                        title=f"عملية تعمل من ملف محذوف: PID {pid} ({dest})",
                        detail=f"العملية تستمر بالعمل في الذاكرة بعد حذف ملفها من القرص.\nالأمر: {cmdline[:120]}",
                        fix=f"sudo kill -9 {pid}",
                        category="evasion",
                        tags=["deleted_binary", "in_memory", "malware"],
                        attack_ids=["T1059.004", "T1070.004"],
                    ))
            except Exception:
                continue
        return findings

    def check_authorized_keys(self) -> List[Finding]:
        """فحص مفاتيح SSH المصرح بها وكشف الحقن أو المفاتيح المقيدة المريبة."""
        findings = []
        auth_keys_pattern = "/home/*/.ssh/authorized_keys"
        all_keys = self.sys.glob(auth_keys_pattern) + ["/root/.ssh/authorized_keys"]

        for kfile in all_keys:
            if not self.sys.is_file(kfile):
                continue
            content = self.sys.read_text(kfile)
            for idx, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # كشف الأوامر المحقونة في مفتاح SSH (ForceCommand injection)
                if line.startswith("command=") and any(sh in line for sh in ("sh", "bash", "curl", "nc")):
                    findings.append(Finding(
                        severity="critical",
                        title=f"🚨 أمر إجباري مشبوه داخل مفتاح SSH: {kfile}:{idx}",
                        detail=f"السطر يحتوي على أمر مقيد قد يكون باباً خلفياً: {line[:100]}",
                        fix=f"راجع السطر واحذفه من {kfile}",
                        category="persistence",
                        tags=["ssh_backdoor", "authorized_keys"],
                        attack_ids=["T1098.004"],
                    ))
        return findings

    def check_shell_profiles(self) -> List[Finding]:
        """فحص ملفات تشغيل الطرفية بحثاً عن سكريبتات تحميل تلقائي أو reverse shells."""
        findings = []
        targets = ["/etc/profile", "/etc/bash.bashrc"] + self.sys.glob("/home/*/.bashrc") + self.sys.glob("/home/*/.profile")

        suspicious_patterns = [
            (r"(curl|wget)\s+[^\n|]+\|\s*(sh|bash)", "تحميل وتنفيذ فوري عبر الشيل"),
            (r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+", "اتصال عكسي مباشر عبر /dev/tcp"),
            (r"base64\s+-d.*\|.*(sh|bash)", "تنفيذ حمولة مشفرة base64"),
        ]

        for target in targets:
            if not self.sys.is_file(target):
                continue
            text = self.sys.read_text(target)
            for pat, desc in suspicious_patterns:
                if re.search(pat, text):
                    findings.append(Finding(
                        severity="critical",
                        title=f"🚨 نمط باب خلفي في ملف تشغيل الشيل: {target}",
                        detail=f"تم رصد: {desc}",
                        fix=f"افحص الملف {target} فوراً وأزل السطر الخبيث.",
                        category="persistence",
                        tags=["shell_backdoor", "persistence"],
                        attack_ids=["T1546.004"],
                    ))
        return findings

    def check_suspicious_cron_scripts(self) -> List[Finding]:
        findings = []
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly"]
        for cdir in cron_dirs:
            if not self.sys.is_dir(cdir):
                continue
            for fname in self.sys.listdir(cdir):
                fpath = os.path.join(cdir, fname)
                if not self.sys.is_file(fpath):
                    continue
                content = self.sys.read_text(fpath)
                if any(x in content for x in ("/tmp/", "/dev/shm", "nc -e", "bash -i")):
                    findings.append(Finding(
                        severity="high",
                        title=f"مهمة مجدولة (Cron) تشغل مسارات مشبوهة: {fpath}",
                        detail=f"السكريبت يشغل ملفات من /tmp أو ينفذ أوامر شبكية غير مألوفة.",
                        fix=f"راجع محتوى {fpath} وتأكد من شرعيته.",
                        category="persistence",
                        tags=["cron", "persistence"],
                        attack_ids=["T1053.003"],
                    ))
        return findings
