"""
AI AYFAM — Deep Kernel Security Inspection Engine
محرك فحص النواة العميق — فحص بصلاحيات للقراءة فقط عبر مفككات وتدقيق Sysctl ومستويات الحماية
"""

import os
import json
import glob
import re
import subprocess
from typing import List, Dict, Any, Optional
from engine.rules_registry import create_finding
from engine.finding import Finding

SYSCTL_RULES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "resources", "hardening", "sysctl.json"))

TAINT_FLAG_DESCRIPTIONS = {
    0: "Proprietary module loaded (وحدة مملوكة)",
    1: "Module force loaded (وحدة جُبر تحميلها)",
    2: "Unsafe SMP kernel (نواة SMP غير آمنة)",
    3: "Module force unloaded (وحدة جُبر تفريغها)",
    4: "Machine Check Exception occurred (خطأ فحص العتاد)",
    5: "Bad page referenced (إشارة لصفحة ذاكرة تالفة)",
    6: "User requested taint (طلب تلوث من المستخدم)",
    7: "Kernel died (الموت السابق للنواة)",
    8: "ACPI table overridden (تجاوز جدول ACPI)",
    9: "Kernel issued warning (تحذير صادر عن النواة)",
    10: "Staging driver loaded (برنامج تشغيل تجريبي)",
    11: "Workaround applied (تطبيق معالجة مؤقتة)",
    12: "Out-of-tree module loaded (وحدة من خارج شجرة الكود الرسمية)",
    13: "Unsigned module loaded (وحدة غير موقعة أمنياً)",
    14: "Soft lockup occurred (تعليق برمجيات النواة)",
    15: "Kernel livepatched (ترقيع النواة وهي تعمل)",
    16: "Auxiliary taint (تلوث إضافي)",
    17: "Struct randomization enabled (عشوائية هياكل الذاكرة)",
}

class KernelChecker:
    """محرك التدقيق والفحص العميق لمستوى النواة."""

    def __init__(self, sysctl_rules_path: str = SYSCTL_RULES_PATH):
        self.sysctl_rules = []
        if os.path.exists(sysctl_rules_path):
            try:
                with open(sysctl_rules_path, "r", encoding="utf-8") as f:
                    self.sysctl_rules = json.load(f).get("sysctl_rules", [])
            except Exception:
                pass

    def check_tainted(self, taint_val: Optional[int] = None) -> List[Finding]:
        findings = []
        if taint_val is None:
            try:
                if os.path.exists("/proc/sys/kernel/tainted"):
                    with open("/proc/sys/kernel/tainted", "r") as f:
                        taint_val = int(f.read().strip())
            except Exception:
                return findings

        if taint_val is not None and taint_val > 0:
            reasons = []
            for bit, desc in TAINT_FLAG_DESCRIPTIONS.items():
                if taint_val & (1 << bit):
                    reasons.append(f"bit {bit}: {desc}")

            findings.append(create_finding(
                rule_id="KERN-TAINTED-001",
                severity="medium",
                title_ar=f"النواة ملوثة (Tainted Kernel Value: {taint_val})",
                title_en=f"Tainted kernel detected (Value: {taint_val})",
                detail="النواة تحمل وسماً يشير للتلوث:\n" + "\n".join(reasons),
                fix="راجع برامج التشغيل المحملة وتأكد من توقيعها الرسمي.",
                evidence={"taint_value": taint_val, "reasons": reasons},
                stable_key="kernel_tainted",
            ))
        return findings

    def check_hidden_modules(self, proc_modules: Optional[str] = None, sys_modules: Optional[List[str]] = None) -> List[Finding]:
        findings = []
        p_mods = set()
        if proc_modules is None:
            if os.path.exists("/proc/modules"):
                try:
                    with open("/proc/modules", "r") as f:
                        for line in f:
                            parts = line.split()
                            if parts:
                                p_mods.add(parts[0].replace("-", "_"))
                except Exception:
                    pass
        else:
            for line in proc_modules.splitlines():
                parts = line.split()
                if parts:
                    p_mods.add(parts[0].replace("-", "_"))

        s_mods = set()
        if sys_modules is None:
            if os.path.exists("/sys/module"):
                try:
                    s_mods = set(os.listdir("/sys/module"))
                except Exception:
                    pass
        else:
            s_mods = set(sys_modules)

        # Detect modules in /sys/module that are missing from /proc/modules
        hidden = [m for m in s_mods if m not in p_mods and not m.startswith(".")]
        for m in hidden:
            findings.append(create_finding(
                rule_id="KERN-HIDDEN-001",
                severity="critical",
                title_ar=f"وحدة نواة مخفية مشبوهة (Hidden Kernel Module): {m}",
                title_en=f"Hidden Kernel Module detected: {m}",
                detail=f"الوحدة {m} موجودة في /sys/module ومخفية عن /proc/modules (نمط rootkit).",
                fix=f"تحقق من خفيات النواة وعزل الجهاز فوراً.",
                evidence={"module": m},
                stable_key=m,
            ))
        return findings

    def check_lockdown_and_secureboot(self) -> List[Finding]:
        findings = []
        lockdown_state = "none"
        if os.path.exists("/sys/kernel/security/lockdown"):
            try:
                with open("/sys/kernel/security/lockdown", "r") as f:
                    content = f.read()
                    m = re.search(r"\[(\w+)\]", content)
                    if m:
                        lockdown_state = m.group(1)
            except Exception:
                pass

        if lockdown_state == "none":
            findings.append(create_finding(
                rule_id="SYS-WRITE-001",
                severity="info",
                title_ar="وضع إغلاق النواة (Kernel Lockdown) غير مفعل",
                title_en="Kernel Lockdown mode is disabled (none)",
                detail="وضع Lockdown يمنع تعديل ذاكرة النواة مباشرة من الجذر.",
                fix="يمكن تفعيل lockdown=integrity في وسائط إقلاع النواة.",
                stable_key="lockdown_none",
            ))

        return findings

    def check_sysctl_hardening(self) -> List[Finding]:
        findings = []
        for rule in self.sysctl_rules:
            key = rule["key"]
            expected = rule["expected_value"]
            sev = rule.get("severity", "medium")
            rule_id = rule.get("rule_id", "KERN-SYSCTL-001")

            val = self._read_sysctl(key)
            if val is not None and val != expected:
                findings.append(create_finding(
                    rule_id=rule_id,
                    severity=sev,
                    title_ar=rule["title_ar"],
                    title_en=rule["title_en"],
                    detail=f"المعلمة الحالية: {val} | القيمة الموصى بها: {expected}\n{rule.get('rationale', '')}",
                    fix=f"sudo sysctl -w {key}={expected}",
                    evidence={"key": key, "current": val, "expected": expected},
                    stable_key=key,
                ))
        return findings

    def _read_sysctl(self, key: str) -> Optional[str]:
        path = "/proc/sys/" + key.replace(".", "/")
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    return f.read().strip()
            except Exception:
                pass
        return None

    def check_kernel_update_needed(self, running_version: Optional[str] = None) -> List[Finding]:
        findings = []
        if running_version is None:
            running_version = os.uname().release

        installed_kernels = []
        try:
            from utils import safe_exec
            r = safe_exec.run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n", "linux-image-*"], timeout=10, check_binary=False)
            if r.ok and r.stdout:
                for line in r.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) == 2 and not parts[0].endswith("-generic-hwe") and "unsigned" not in parts[0]:
                        k_ver = parts[0].replace("linux-image-", "")
                        installed_kernels.append(k_ver)

                if installed_kernels and running_version not in installed_kernels[0]:
                    findings.append(create_finding(
                        rule_id="SYS-UPDATE-001",
                        severity="medium",
                        title_ar="النواة المشغلة مختلفة عن آخر نواة مثبتة (يلزم إعادة التشغيل)",
                        title_en="Running kernel differs from installed kernel (reboot required)",
                        detail=f"النواة المشغلة حالياً: {running_version}\nآخر نواة مثبتة: {installed_kernels[0]}",
                        fix="قم بإعادة تشغيل الجهاز لتفعيل النواة الجديدة: sudo reboot",
                        evidence={"running": running_version, "installed": installed_kernels[0]},
                        stable_key="reboot_required_kernel",
                    ))
        except Exception:
            pass

        return findings

    def run_all_checks(self) -> List[Finding]:
        findings = []
        findings.extend(self.check_tainted())
        findings.extend(self.check_hidden_modules())
        findings.extend(self.check_lockdown_and_secureboot())
        findings.extend(self.check_sysctl_hardening())
        findings.extend(self.check_kernel_update_needed())
        return findings
