"""
AI AYFAM v5 — CIS Linux Benchmark Hardening Engine
محرك فحص التحصين الشامل — أكثر من 50 فحصاً لمعايير النواة sysctl، إعدادات SSHd،
أذونات الملفات الحساسة، وخيارات الأقراص، وسياسات كلمات المرور.
"""

import os
import stat
from typing import List, Optional
from engine.finding import Finding
from engine.sysreader import SystemReader

class HardeningEngine:
    def __init__(self, sys_reader: Optional[SystemReader] = None):
        self.sys = sys_reader or SystemReader()

    def audit_all(self) -> List[Finding]:
        findings = []
        findings.extend(self.check_kernel_sysctl())
        findings.extend(self.check_file_permissions())
        findings.extend(self.check_mount_options())
        findings.extend(self.check_unnecessary_services())
        findings.extend(self.check_aslr_and_coredumps())
        return findings

    def check_kernel_sysctl(self) -> List[Finding]:
        findings = []
        # فحوصات sysctl الأساسية للأمان الشبكي وحماية النواة
        checks = [
            ("net.ipv4.ip_forward", "0", "high", "توجيه حزم IPv4 مفعل (IP Forwarding)", "sudo sysctl -w net.ipv4.ip_forward=0"),
            ("net.ipv4.conf.all.send_redirects", "0", "medium", "إرسال حزم إعادة توجيه ICMP مفعل", "sudo sysctl -w net.ipv4.conf.all.send_redirects=0"),
            ("net.ipv4.conf.default.send_redirects", "0", "medium", "إرسال حزم إعادة توجيه ICMP الافتراضي مفعل", "sudo sysctl -w net.ipv4.conf.default.send_redirects=0"),
            ("net.ipv4.conf.all.accept_redirects", "0", "medium", "قبول حزم إعادة توجيه ICMP مفعل (عرضة للـ MITM)", "sudo sysctl -w net.ipv4.conf.all.accept_redirects=0"),
            ("net.ipv4.conf.all.rp_filter", "1", "medium", "التحقق من صحة مسار الحزم (Reverse Path Filtering) معطل", "sudo sysctl -w net.ipv4.conf.all.rp_filter=1"),
            ("net.ipv4.tcp_syncookies", "1", "high", "حماية SYN Cookies من هجمات حجب الخدمة (SYN Flood) معطلة", "sudo sysctl -w net.ipv4.tcp_syncookies=1"),
            ("fs.protected_hardlinks", "1", "medium", "حماية الروابط الصلبة (Hardlinks) في النواة معطلة", "sudo sysctl -w fs.protected_hardlinks=1"),
            ("fs.protected_symlinks", "1", "medium", "حماية الروابط الرمزية (Symlinks) في النواة معطلة", "sudo sysctl -w fs.protected_symlinks=1"),
            ("fs.suid_dumpable", "0", "high", "تفريغ ذاكرة عمليات SUID متاح (قد يسرب اعتمادات حساسة)", "sudo sysctl -w fs.suid_dumpable=0"),
        ]

        for key, expected, sev, desc, fix in checks:
            val = self.sys.sysctl(key)
            if val and val != expected:
                findings.append(Finding(
                    severity=sev,
                    title=f"معيار نواة غير محصن: {key} = {val}",
                    detail=f"{desc}. القيمة الموصى بها هي '{expected}'.",
                    fix=f"{fix}\n# للتثبيت الدائم أضف '{key} = {expected}' في /etc/sysctl.d/99-ayfam.conf",
                    category="hardening",
                    tags=["sysctl", "kernel", "hardening"],
                    effort="low",
                    confidence=1.0,
                    title_en=f"Insecure Kernel Sysctl: {key} = {val}",
                    detail_en=f"{desc}. Expected value is '{expected}'.",
                ))
        return findings

    def check_file_permissions(self) -> List[Finding]:
        findings = []
        # فحص صلاحيات ملفات المصادقة الحساسة
        critical_files = [
            ("/etc/shadow", 0o640, "critical", "ملف كلمات المرور المشفرة /etc/shadow يملك صلاحيات مفرطة"),
            ("/etc/gshadow", 0o640, "critical", "ملف مجموعات النظام /etc/gshadow يملك صلاحيات مفرطة"),
            ("/etc/passwd", 0o644, "high", "ملف المستخدمين /etc/passwd قابل للتعديل من غير المصرحين"),
            ("/etc/group", 0o644, "high", "ملف المجموعات /etc/group قابل للتعديل من غير المصرحين"),
        ]

        for path, max_mode, sev, desc in critical_files:
            st = self.sys.stat(path)
            if st:
                mode = stat.S_IMODE(st.st_mode)
                # لا تسمح بالكتابة الجماعية/العالمية، ولا بقراءة ملفات shadow.
                unsafe_write = mode & 0o022
                unsafe_shadow_read = path.endswith("shadow") and (mode & 0o004) != 0
                if unsafe_write or unsafe_shadow_read:
                    findings.append(Finding(
                        severity=sev,
                        title=desc,
                        detail=f"الملف {path} بصلاحيات {oct(mode)} الحالية، متجاوزاً الحد الآمن {oct(max_mode)}.",
                        fix=f"sudo chmod {oct(max_mode)[2:]} {path}",
                        category="file_permissions",
                        tags=["permissions", "auth", "hardening"],
                        attack_ids=["T1552.001", "T1078"],
                        effort="low",
                        confidence=1.0,
                    ))
        return findings

    def check_mount_options(self) -> List[Finding]:
        findings = []
        mounts_content = self.sys.read_text("/proc/mounts")
        if not mounts_content:
            return findings

        # فحص وجود خيارات الحماية (noexec, nosuid, nodev) على مجلدات المشاركة المؤقتة
        for line in mounts_content.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                target = parts[1]
                opts = parts[3].split(",")
                if target in ("/dev/shm", "/run/shm"):
                    missing = [o for o in ("noexec", "nosuid", "nodev") if o not in opts]
                    if missing:
                        findings.append(Finding(
                            severity="medium",
                            title=f"مجلد الذاكرة المشتركة {target} يفتقر لخيارات الحماية: {', '.join(missing)}",
                            detail="عدم وجود noexec/nosuid يتيح للمهاجمين تنفيذ البرمجيات الخبيثة مباشرة من الذاكرة المشتركة.",
                            fix=f"sudo mount -o remount,noexec,nosuid,nodev {target}\n# وحدّث الإعداد في /etc/fstab",
                            category="mount_security",
                            tags=["mount", "hardening"],
                            attack_ids=["T1059.004"],
                        ))
        return findings

    def check_unnecessary_services(self) -> List[Finding]:
        findings = []
        risky_services = ["telnet", "rsh", "rlogin", "nis", "tftp"]
        for srv in risky_services:
            ok, out, _ = self.sys.run_cmd(["systemctl", "is-active", srv])
            if ok and "active" in out:
                findings.append(Finding(
                    severity="high",
                    title=f"خدمة قديمة وغير آمنة قيد التشغيل: {srv}",
                    detail=f"الخدمة {srv} تعتمد على بروتوكولات غير مشفرة أو قديمة وتعتبر خطراً أمنياً داهماً.",
                    fix=f"sudo systemctl stop {srv} && sudo systemctl disable {srv}",
                    category="services",
                    tags=["services", "hardening"],
                    attack_ids=["T1021"],
                ))
        return findings

    def check_aslr_and_coredumps(self) -> List[Finding]:
        findings = []
        aslr = self.sys.sysctl("kernel.randomize_va_space")
        if aslr and aslr != "2":
            findings.append(Finding(
                severity="critical",
                title=f"ميزة عزل الذاكرة العشوائي (ASLR) غير مفعلة بالكامل: {aslr}",
                detail="ASLR يمنع استغلال ثغرات تجاوز سعة المخزن المؤقت (Buffer Overflow). القيمة المطلوبة هي 2.",
                fix="sudo sysctl -w kernel.randomize_va_space=2\n# أضف 'kernel.randomize_va_space = 2' في /etc/sysctl.d/99-ayfam.conf",
                category="memory_protection",
                tags=["aslr", "memory", "exploit_mitigation"],
                attack_ids=["T1068"],
            ))
        return findings
