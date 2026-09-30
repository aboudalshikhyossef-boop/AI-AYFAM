#!/usr/bin/env bash
set -e

# 1. كتابة ملف core/agent_v5.py كاملاً وبطريقة برمجية نظيفة وصحيحة 100%
cat << 'V5EOF' > core/agent_v5.py
"""
AI AYFAM v6 — Agent V6 Capabilities Mixin
وحدة التكامل وتوسيع قدرات الوكيل — تشمل الفحص العميق، ترسانة Lynis و YARA،
الحارس النشط، كشف الأسرار، وخطط العمل الأمنية (Security Playbooks).
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
    def _show_playbook_cli(self, topic: str):
        """عرض خطة عمل أمنية مهيكلة مستخرجة من الكتب."""
        self.ui.section(self._t(f"📖 خطة العمل الأمنية (Security Playbook): {topic}", f"📖 Security Playbook: {topic}"))
        from brain.playbook_engine import PlaybookEngine
        engine = PlaybookEngine(kb=self.kb)
        pb = engine.generate_playbook(topic)

        if pb.get("total_commands", 0) == 0:
            msg_ar = f"لم أجد أوامر كافية لـ '{topic}' في الكتب المفهرسة حالياً. يمكنك تغذية الأداة بكتاب عبر: ayfam --learn <path>"
            msg_en = f"No specific commands found for '{topic}' in ingested books. You can ingest books via: ayfam --learn <path>"
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
        """تشغيل فحص التحصين الشامل CIS Benchmark وصيد التهديدات."""
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
                broken = cp["broken_techniques_count"]
                cmd_fix = cp["fix_cmd"]
                self.ui.info(f"  • أمر يكسر {broken} تقنيات هجوم: [cyan]{cmd_fix}[/cyan]")

        self._last_findings = findings
        return findings

    def _run_lynis_cli(self):
        """تشغيل أداة Lynis العالمية المدمجة."""
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
V5EOF

echo "[*] فحص سلامة الأكواد برمجياً..."
python3 -m py_compile core/agent_v5.py
python3 -m py_compile brain/playbook_engine.py

echo "[*] تشغيل اختبار خطط العمل (Playbook Test)..."
python3 tests/test_playbook.py

echo "[✓] تم تصحيح الخطأ وتثبيت المرحلة 2 بنجاح تام!"
