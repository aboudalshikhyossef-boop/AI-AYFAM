#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}[*] جاري بناء محرك خط الأساس السلوكي والتكيف الذاتي (Phase 3)...${NC}"

# ==============================================================================
# 1. engine/baseline.py
# ==============================================================================
cat << 'BEOF' > engine/baseline.py
"""
AI AYFAM v6 — Behavioral Baseline & Anomaly Engine
محرك خط الأساس السلوكي — يتعلم الحالة الطبيعية للنظام (المستخدمين، المنافذ، المهام)،
ويكتشف أي شذوذ أو اختراق جديد ينحرف عن السلوك المعتمد.
"""

import os
import json
import sqlite3
from typing import Dict, List, Any, Optional
from engine.finding import Finding
from engine.sysreader import SystemReader

class BaselineEngine:
    def __init__(self, db_path: str = None, sys_reader: Optional[SystemReader] = None):
        self.db_path = db_path or os.path.expanduser("~/.ayfam/brain.db")
        self.sys = sys_reader or SystemReader()
        self._init_table()

    def _init_table(self):
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                CREATE TABLE IF NOT EXISTS system_baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    component TEXT NOT NULL UNIQUE,
                    snapshot_data TEXT NOT NULL,
                    updated_at TEXT DEFAULT (datetime('now'))
                );
                """)
        except Exception:
            pass

    def capture_current_state(self) -> Dict[str, Any]:
        """التقاط بصمة شاملة للحالة الراهنة للنظام."""
        # 1. المستخدمين
        passwd_content = self.sys.read_text("/etc/passwd")
        users = set()
        for line in passwd_content.splitlines():
            parts = line.split(":")
            if len(parts) >= 3:
                users.add(f"{parts[0]}:{parts[2]}")

        # 2. المنافذ المستمعة
        ok, out, _ = self.sys.run_cmd(["ss", "-tulpn"])
        ports = set()
        if ok:
            for line in out.splitlines():
                if "LISTEN" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        ports.add(parts[4])

        # 3. ملفات SUID الحالية
        ok_suid, suid_out, _ = self.sys.run_cmd(["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "-perm", "-4000"])
        suid_files = set(suid_out.splitlines()) if ok_suid else set()

        return {
            "users": sorted(list(users)),
            "listening_ports": sorted(list(ports)),
            "suid_files": sorted(list(suid_files)),
        }

    def save_baseline(self) -> bool:
        """حفظ أو تحديث خط الأساس في قاعدة البيانات كحالة موثوقة."""
        state = self.capture_current_state()
        try:
            with sqlite3.connect(self.db_path) as conn:
                for comp, data in state.items():
                    conn.execute("""
                    INSERT INTO system_baselines (component, snapshot_data, updated_at)
                    VALUES (?, ?, datetime('now'))
                    ON CONFLICT(component) DO UPDATE SET
                    snapshot_data=excluded.snapshot_data, updated_at=excluded.updated_at;
                    """, (comp, json.dumps(data)))
            return True
        except Exception:
            return False

    def check_deviations(self) -> List[Finding]:
        """مقارنة حالة النظام الحالية بخط الأساس الموثوق لكشف أي شذوذ."""
        findings = []
        current = self.capture_current_state()
        baseline = {}

        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute("SELECT component, snapshot_data FROM system_baselines").fetchall()
                for comp, data in rows:
                    baseline[comp] = set(json.loads(data))
        except Exception:
            return findings

        if not baseline:
            findings.append(Finding(
                severity="info",
                title="لم يتم تسجيل خط أساس للنظام بعد",
                detail="قم بتشغيل: ayfam --baseline-learn ليتعلم الوكيل الحالة الطبيعية الموثوقة لنظامك.",
                fix="python3 main.py --baseline-learn",
                category="baseline",
            ))
            return findings

        # 1. كشف مستخدمين جدد
        base_users = baseline.get("users", set())
        cur_users = set(current.get("users", []))
        new_users = cur_users - base_users
        if new_users:
            findings.append(Finding(
                severity="critical",
                title=f"🚨 رصد مستخدمين جدد غير موجودين في خط الأساس: {', '.join(list(new_users)[:3])}",
                detail=f"تم إنشاء حسابات مستخدمين جديدة بعد حفظ خط الأساس الموثوق للنظام: {list(new_users)}",
                fix="تحقق من شرعية المستخدمين أو احذفهم: sudo userdel <username>",
                category="anomaly_identity",
                tags=["new_user", "persistence"],
                attack_ids=["T1136.001"],
            ))

        # 2. كشف منافذ استماع جديدة
        base_ports = baseline.get("listening_ports", set())
        cur_ports = set(current.get("listening_ports", []))
        new_ports = cur_ports - base_ports
        if new_ports:
            findings.append(Finding(
                severity="high",
                title=f"⚠️ منافذ استماع شبكية جديدة ظهرت فجأة: {', '.join(list(new_ports)[:4])}",
                detail=f"تم رصد فتح خدمات استماع جديدة لم تكن موجودة في السلوك الطبيعي للنظام: {list(new_ports)}",
                fix="افحص العمليات المرتبطة بالمنافذ وأغلقها إن لم تكن مصرحة.",
                category="anomaly_network",
                tags=["new_port", "backdoor"],
                attack_ids=["T1571"],
            ))

        # 3. كشف ملفات SUID جديدة
        base_suid = baseline.get("suid_files", set())
        cur_suid = set(current.get("suid_files", []))
        new_suid = cur_suid - base_suid
        if new_suid:
            findings.append(Finding(
                severity="critical",
                title=f"🚨 ملفات امتيازات SUID جديدة لم تكن موجودة سابقاً: {', '.join(list(new_suid)[:2])}",
                detail=f"ظهور ملفات SUID جديدة يعتبر مؤشراً قوياً على محاولة تثبيت آلية تصعيد صلاحيات.",
                fix=f"أزل صلاحية SUID فوراً: sudo chmod u-s {list(new_suid)[0]}",
                category="anomaly_privilege",
                tags=["suid_anomaly", "privesc"],
                attack_ids=["T1548.001"],
            ))

        return findings
BEOF

# ==============================================================================
# 2. engine/autoreactor.py
# ==============================================================================
cat << 'AEOF' > engine/autoreactor.py
"""
AI AYFAM v6 — Auto-Reactor & Rule Synthesizer
محرك الاستجابة التلقائية وتوليد القواعد — يحلل الهجمات المرصودة ويولد قواعد حماية
فورية لـ UFW و iptables و auditd لتصليب النظام ديناميكياً.
"""

from typing import List, Dict, Any
from engine.finding import Finding

class AutoReactor:
    @staticmethod
    def synthesize_rules(findings: List[Finding]) -> List[Dict[str, str]]:
        """توليد قواعد حماية جاهزة للتطبيق التلقائي بناءً على التهديدات المرصودة."""
        rules = []

        for f in findings:
            tags = f.get("tags", [])
            title = f.get("title", "")
            detail = f.get("detail", "")

            # 1. هجمات القوة الغاشمة والتخمين -> قواعد حظر فورية
            if "brute_force" in tags or "brute_force_success" in tags or "password_spraying" in tags:
                import re
                ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", title + " " + detail)
                for ip in set(ips):
                    if not ip.startswith(("127.", "0.0")):
                        rules.append({
                            "type": "FIREWALL_BLOCK",
                            "desc": f"حظر IP المهاجم {ip} في جدار الحماية",
                            "cmd": f"sudo ufw insert 1 deny from {ip}",
                        })

            # 2. خدمات غير محمية مكشوفة -> قواعد تقييد
            if "exposed_port" in tags or "exposed_service" in tags:
                import re
                ports = re.findall(r"منفذ\s+(\d+)", title)
                for port in ports:
                    rules.append({
                        "type": "PORT_RESTRICTION",
                        "desc": f"إغلاق المنفذ المكشوف {port} عن الخارج",
                        "cmd": f"sudo ufw deny {port}/tcp",
                    })

            # 3. ملفات امتيازات خطيرة -> إزالة SUID
            if "suid" in tags or "suid_anomaly" in tags:
                import re
                paths = re.findall(r"(/[\w\.-]+(?:/[\w\.-]+)+)", title + " " + detail)
                for p in paths:
                    if os.path.exists(p):
                        rules.append({
                            "type": "PRIVILEGE_STRIP",
                            "desc": f"إزالة صلاحية SUID من الملف {p}",
                            "cmd": f"sudo chmod u-s {p}",
                        })

        return rules
AEOF

# ==============================================================================
# 3. تحديث core/agent_v5.py لدمج وظائف Phase 3
# ==============================================================================
cat << 'V5EOF' > core/agent_v5.py
"""
AI AYFAM v6 — Agent V6 Capabilities Mixin
وحدة التكامل الشاملة:
- الفحص العميق (CIS Benchmark)
- ترسانة Lynis و YARA و Chkrootkit
- الحارس النشط (Active Sentinel)
- خطط العمل والمكتبة (Playbooks)
- خط الأساس السلوكي وكشف الشذوذ (Baseline & Anomaly)
- التوليد التلقائي لقواعد الحماية (Auto-Reactor)
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
from engine.baseline import BaselineEngine
from engine.autoreactor import AutoReactor
from tools.arsenal import SecurityArsenal
from reports.html_report import generate_interactive_html


class AgentV5Mixin:
    def _run_baseline_learn_cli(self):
        """التقاط وحفظ خط الأساس السلوكي للنظام."""
        self.ui.section(self._t("🧠 بناء خط الأساس السلوكي للنظام (Behavioral Baseline)", "🧠 Learning System Behavioral Baseline"))
        engine = BaselineEngine()
        with self.ui.spinner(self._t("حفظ البصمة الموثوقة للمستخدمين، المنافذ، والملفات...", "Capturing baseline snapshot...")):
            ok = engine.save_baseline()
        if ok:
            self.ui.success(self._t("✅ تم حفظ خط الأساس بنجاح! سيعتمد الوكيل هذه الحالة كمرجع للسلوك الطبيعي.", "Baseline captured successfully."))
        else:
            self.ui.error(self._t("تعذر حفظ خط الأساس في قاعدة البيانات.", "Failed to save baseline."))

    def _run_baseline_check_cli(self):
        """مقارنة حالة النظام بخط الأساس لكشف أي شذوذ."""
        self.ui.section(self._t("🔍 فحص انحرافات وشذوذ النظام عن خط الأساس", "🔍 Checking Baseline Deviations & Anomalies"))
        engine = BaselineEngine()
        with self.ui.spinner(self._t("مقارنة الحالة الحالية بالبصمة المعتمدة...", "Analyzing deviations...")):
            findings = engine.check_deviations()

        if findings:
            for f in findings:
                self.ui.print_finding(f["severity"], f["title"], f.get("detail", ""), f.get("fix", ""))
        else:
            self.ui.success(self._t("🟢 النظام متطابق تماماً مع خط الأساس ولا توجد أي انحرافات مريبة.", "System is compliant with baseline."))
        return findings

    def _run_synthesize_rules_cli(self):
        """توليد قواعد حماية وجدار ناري بناءً على التهديدات المرصودة."""
        self.ui.section(self._t("🛡️ التوليد التلقائي لقواعد الحماية (Auto-Rule Synthesis)", "🛡️ Synthesizing Defensive Rules"))
        if not self._last_findings:
            self.ui.warning(self._t("شغّل فحصاً أولاً لرصد التهديدات وتوليد قواعد لها.", "Run a scan first."))
            return
        rules = AutoReactor.synthesize_rules(self._last_findings)
        if rules:
            self.ui.info(self._t(f"تم توليد {len(rules)} قواعد دفاعية موصى بها:", f"Synthesized {len(rules)} recommended rules:"))
            for r in rules:
                self.ui.raw(f"  • [{r['type']}] {r['desc']}\n    [cyan]{r['cmd']}[/cyan]")
        else:
            self.ui.info(self._t("لم تظهر تهديدات نشطة تتطلب توليد قواعد حظر جديدة.", "No active threats requiring new rules."))

    def _show_playbook_cli(self, topic: str):
        self.ui.section(self._t(f"📖 خطة العمل الأمنية (Security Playbook): {topic}", f"📖 Security Playbook: {topic}"))
        from brain.playbook_engine import PlaybookEngine
        engine = PlaybookEngine(kb=self.kb)
        pb = engine.generate_playbook(topic)

        if pb.get("total_commands", 0) == 0:
            msg_ar = f"لم أجد أوامر كافية لـ '{topic}' في الكتب المفهرسة حالياً. يمكنك تغذية الأداة بكتاب عبر: ayfam --learn <path>"
            msg_en = f"No specific commands found for '{topic}' in ingested books. Ingest via: ayfam --learn <path>"
            self.ui.warning(self._t(msg_ar, msg_en))
            return

        total = pb["total_commands"]
        self.ui.info(self._t(f"تم تجميع {total} أمراً موثقاً من مراجعك ومكتبتك:", f"Extracted {total} documented commands:"))

        for stage_name, steps in pb.get("stages", {}).items():
            if steps:
                self.ui.subsection(stage_name)
                for s in steps:
                    cmd_text = s.get("cmd", "")
                    book_name = s.get("book", "")
                    page_num = s.get("page", "")
                    self.ui.raw(f"  $ {cmd_text}\n    [dim]— المصدر: «{book_name}» ({page_num})[/dim]")

    def _run_deep_audit(self):
        self.ui.section(self._t("🛡️ فحص التحصين المتقدم (CIS Benchmark & Hardening)", "🛡️ Deep Hardening Audit"))
        findings = []

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
                broken = cp["broken_techniques_count"]
                cmd_fix = cp["fix_cmd"]
                self.ui.info(f"  • أمر يكسر {broken} تقنيات هجوم: [cyan]{cmd_fix}[/cyan]")

        self._last_findings = findings
        return findings

    def _run_lynis_cli(self):
        self.ui.section(self._t("🔍 فحص وتدقيق النظام بأداة Lynis القياسية", "🔍 Lynis System Security Audit"))
        arsenal = SecurityArsenal()
        with self.ui.spinner(self._t("جاري تشغيل Lynis وتحليل النتائج...", "Running Lynis audit...")):
            res = arsenal.run_lynis_audit()

        if res.get("hardening_index"):
            idx = res["hardening_index"]
            self.ui.success(self._t(f"مؤشر التحصين (Hardening Index): {idx}/100", f"Hardening Index: {idx}/100"))

        for f in res.get("findings", []):
            self.ui.print_finding(f["severity"], f["title"], f.get("detail", ""), f.get("fix", ""))

    def _run_yara_cli(self, target_path: str = "."):
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
        self.ui.section(self._t("🕵️ فحص الجذور الخفية (Rootkit Hunter)", "🕵️ Rootkit Detection Scan"))
        arsenal = SecurityArsenal()
        with self.ui.spinner(self._t("فحص النواة والبرمجيات المتسللة...", "Scanning kernel and system...")):
            findings = arsenal.check_rootkits()

        for f in findings:
            self.ui.print_finding(f["severity"], f["title"], f.get("detail", ""), f.get("fix", ""))

    def _run_sentinel_cli(self):
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
V5EOF

# ==============================================================================
# 4. تحديث main.py لربط خيارات Phase 3
# ==============================================================================
python3 -c '
with open("main.py", "r", encoding="utf-8") as f:
    code = f.read()

if "--baseline-learn" not in code:
    code = code.replace(
        "parser.add_argument(\"--audit\", action=\"store_true\", help=\"فحص تحصين شامل بنمط CIS\")",
        "parser.add_argument(\"--audit\", action=\"store_true\", help=\"فحص تحصين شامل بنمط CIS\")\n"
        "    parser.add_argument(\"--baseline-learn\", action=\"store_true\", help=\"التقاط وحفظ خط الأساس السلوكي للنظام\")\n"
        "    parser.add_argument(\"--baseline-check\", action=\"store_true\", help=\"كشف شذوذ النظام بالمقارنة بخط الأساس\")\n"
        "    parser.add_argument(\"--synthesize-rules\", action=\"store_true\", help=\"توليد قواعد جدار ناري وحماية تلقائية\")"
    )
    code = code.replace(
        "elif args.playbook:\n            agent._show_playbook_cli(args.playbook)",
        "elif args.baseline_learn:\n            agent._run_baseline_learn_cli()\n"
        "        elif args.baseline_check:\n            agent._run_baseline_check_cli()\n"
        "        elif args.synthesize_rules:\n            agent._run_synthesize_rules_cli()\n"
        "        elif args.playbook:\n            agent._show_playbook_cli(args.playbook)"
    )
    with open("main.py", "w", encoding="utf-8") as f:
        f.write(code)
    print("  [✓] main.py updated with Phase 3 CLI flags.")
'

# ==============================================================================
# 5. اختبارات Phase 3
# ==============================================================================
cat << 'TEOF' > tests/test_baseline.py
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.baseline import BaselineEngine
from engine.sysreader import FakeSystem
from engine.autoreactor import AutoReactor
from engine.finding import Finding

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

print("\n[1] Baseline Engine Snapshot & Learning")
tmp_db = tempfile.mktemp(suffix=".db")
fake_sys = FakeSystem(
    files={"/etc/passwd": "root:x:0:0::/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash"}
)
be = BaselineEngine(db_path=tmp_db, sys_reader=fake_sys)
ok = be.save_baseline()
check("baseline saved to SQLite", ok is True)

# محاكاة إنشاء مستخدم مشبوه جديد
fake_sys.files["/etc/passwd"] += "\nhacker:x:0:0::/root:/bin/bash"
findings = be.check_deviations()
check("detects unauthorized new user anomaly", len(findings) > 0)
check("severity is critical for new UID 0 user", any(f["severity"] == "critical" for f in findings))

print("\n[2] Auto-Reactor Rule Synthesizer")
test_finding = Finding(
    severity="critical",
    title="هجوم Brute Force من 198.51.100.22",
    detail="تفاصيل المحاولات المتكررة من 198.51.100.22",
    tags=["brute_force"],
)
rules = AutoReactor.synthesize_rules([test_finding])
check("synthesizes firewall rule", len(rules) > 0)
check("rule targets attacker IP", "198.51.100.22" in rules[0]["cmd"])

print(f"\n{'='*50}\nTOTAL PHASE 3 TESTS: {passed} passed, {failed} failed\n{'='*50}")
if os.path.exists(tmp_db):
    os.remove(tmp_db)
sys.exit(1 if failed else 0)
TEOF

python3 -m py_compile $(find engine/ tools/ core/ brain/ -name "*.py")
python3 tests/test_baseline.py

echo -e "\n${GREEN}======================================================================"
echo -e "  🎉  تمت ترقية محرك خط الأساس السلوكي والتكيف الذاتي بنجاح تام!"
echo -e "======================================================================${NC}"
echo -e "الأوامر الجديدة الجاهزة الآن للاستخدام:"
echo -e "  ${YELLOW}python3 main.py --baseline-learn${NC}    → حفظ سلوك وبصمة النظام الطبيعية كمرجع"
echo -e "  ${YELLOW}python3 main.py --baseline-check${NC}    → كشف أي شذوذ، تلاعب، أو مستخدمين جدد"
echo -e "  ${YELLOW}python3 main.py --synthesize-rules${NC}  → توليد قواعد حماية فورية للجدار الناري"
echo ""
