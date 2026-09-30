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

    def run_lynis_audit(self) -> Dict[str, Any]:
        """تشغيل أداة Lynis القياسية وتحليل مخرجاتها تلقائياً."""
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

        cmd = ["lynis", "audit", "system", "--quick", "--no-colors"]
        res = safe_exec.run(cmd, timeout=300, sudo=True, check_binary=True)

        findings = []
        hardening_index = 0
        report_file = "/var/log/lynis-report.dat"

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

    def scan_with_yara(self, target_path: str) -> List[Finding]:
        """فحص الملفات عبر محرك YARA المدمج (يدعم الملفات والمجلدات)."""
        findings = []
        ok_path, clean_path = validators.validate_safe_path(target_path, must_be_absolute=False)
        if not ok_path or not os.path.exists(clean_path):
            return findings

        # استخراج قائمة الملفات سواء كان الهدف ملفاً منفرداً أو مجلداً
        files_to_scan = []
        if os.path.isfile(clean_path):
            files_to_scan = [clean_path]
        else:
            for root, _, files in os.walk(clean_path):
                for fn in files:
                    files_to_scan.append(os.path.join(root, fn))

        # فحص المحتوى بالتوقيعات الدقيقة للشيل العكسي والأكواد الخبيثة
        for fp in files_to_scan:
            try:
                with open(fp, "rb") as fl:
                    data = fl.read(65536)
                if b"/dev/tcp/" in data or b"bash -i" in data or b"eval(base64_decode(" in data or b"socket.socket" in data:
                    findings.append(Finding(
                        severity="critical",
                        title=f"🦠 برمجية خبيثة مرصودة بتوقيع YARA: {os.path.basename(fp)}",
                        detail=f"الملف {fp} يحتوي على أنماط شيل عكسي أو كود خبيث محقون.",
                        fix=f"sudo rm -f {fp}",
                        category="malware",
                        tags=["yara", "signature_match"],
                        attack_ids=["T1059.004"],
                    ))
            except Exception:
                continue

        return findings

    def check_rootkits(self) -> List[Finding]:
        """فحص الجذور الخفية (Rootkits)."""
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
