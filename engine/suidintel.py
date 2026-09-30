"""
AI AYFAM v5 — GTFOBins & SUID Intelligence Engine
تحليل ذكي لملفات SUID والامتيازات — يربط الملفات التنفيذية بمتجهات كسر الصلاحيات
الحقيقية من مشروع GTFOBins بدون إنترنت.
"""

import os
from typing import List, Dict, Any, Optional
from engine.finding import Finding
from engine.sysreader import SystemReader

# قاعدة معرفة محلية مدمجة بأخطر ملفات GTFOBins الشائعة وآليات استغلالها
GTFOBINS_CORE = {
    "bash": {"suid": "bash -p", "desc": "تشغيل شيل فوري بصلاحيات root"},
    "sh": {"suid": "sh -p", "desc": "تشغيل شيل فوري بصلاحيات root"},
    "python": {"suid": "python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'", "desc": "تنفيذ كود بايثون كـ root"},
    "python3": {"suid": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'", "desc": "تنفيذ كود بايثون كـ root"},
    "perl": {"suid": "perl -e 'exec \"/bin/sh\";'", "desc": "تنفيذ كود بيرل كـ root"},
    "ruby": {"suid": "ruby -e 'exec \"/bin/sh\"'", "desc": "تنفيذ كود روبي كـ root"},
    "find": {"suid": "find . -exec /bin/sh -p \\; -quit", "desc": "تنفيذ أوامر عبر وسيط -exec"},
    "vim": {"suid": "vim -c ':!/bin/sh'", "desc": "الهروب من المحرر إلى شيل root"},
    "vi": {"suid": "vi -c ':!/bin/sh'", "desc": "الهروب من المحرر إلى شيل root"},
    "nano": {"suid": "nano (قراءة/تعديل ملفات النظام الحساسة)", "desc": "تعديل /etc/passwd أو /etc/shadow مباشرة"},
    "nmap": {"suid": "nmap --interactive", "desc": "استغلال الوضع التفاعلي القديم لتشغيل أوامر"},
    "awk": {"suid": "awk 'BEGIN {system(\"/bin/sh\")}'", "desc": "تنفيذ دوال النظام في AWK"},
    "gdb": {"suid": "gdb -nx -ex '!sh' -ex quit", "desc": "تشغيل أوامر من داخل مصحح الأخطاء"},
    "cp": {"suid": "cp /etc/shadow /tmp/shadow", "desc": "نسخ وقراءة أي ملف محمي"},
    "mv": {"suid": "mv /tmp/evil_passwd /etc/passwd", "desc": "استبدال ملفات النظام الحساسة"},
    "less": {"suid": "!/bin/sh داخل less", "desc": "الهروب من مستعرض النصوص إلى الشيل"},
    "more": {"suid": "!/bin/sh داخل more", "desc": "الهروب من مستعرض النصوص إلى الشيل"},
    "env": {"suid": "env /bin/sh -p", "desc": "تشغيل بيئة تنفيذ جديدة بصلاحيات كاملة"},
    "tar": {"suid": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh", "desc": "تنفيذ أوامر بنقاط الفحص"},
    "zip": {"suid": "zip /tmp/x.zip /etc/shadow", "desc": "ضغط واستخراج الملفات الحساسة"},
    "strace": {"suid": "strace -o /dev/null /bin/sh -p", "desc": "تتبع واستدعاء شيل ذو امتيازات"},
    "pkexec": {"suid": "PwnKit (CVE-2021-4034)", "desc": "ثغرة تصعيد صلاحيات معروفة في Polkit"},
    "date": {"suid": "date -f /etc/shadow", "desc": "قراءة أسطر من ملفات النظام الحساسة"},
    "systemctl": {"suid": "systemctl (خدمة مخصصة)", "desc": "إنشاء خدمة بنمط root وتنفيذها"},
}

class SuidIntelligence:
    def __init__(self, sys_reader: Optional[SystemReader] = None):
        self.sys = sys_reader or SystemReader()

    def audit_suid(self, suid_paths: List[str]) -> List[Finding]:
        findings = []
        for path in suid_paths:
            binary = os.path.basename(path).lower()
            if binary in GTFOBINS_CORE:
                info = GTFOBINS_CORE[binary]
                findings.append(Finding(
                    severity="critical",
                    title=f"⚠️ ملف SUID عالي الخطورة موثق في GTFOBins: {path}",
                    detail=f"الملف التنفيذي '{binary}' يملك صلاحية SUID ويمكن استغلاله لتصعيد الصلاحيات (Privilege Escalation).\n"
                           f"المتجه: {info['desc']}\nمثال الاستغلال: {info['suid']}",
                    fix=f"sudo chmod u-s {path}",
                    category="privilege_escalation",
                    tags=["suid", "gtfobins", "privesc"],
                    attack_ids=["T1548.001"],
                    effort="low",
                    risk_of_fix="low",
                    confidence=1.0,
                    title_en=f"Critical GTFOBins SUID Binary: {path}",
                    detail_en=f"Binary '{binary}' has SUID bit set and is a known GTFOBins privilege escalation vector.",
                ))
        return findings
