"""
AI AYFAM — Deterministic Explanation & False-Positive Suppression Engine
طبقة الشرح الثنائي اللغة وقواعد كبت التنبيهات الإيجابية الكاذبة
"""

import time
import os
import json
from typing import List, Dict, Any, Optional
from engine.finding import Finding
from engine.rules_registry import get_rule

SUPPRESSION_FILE = os.path.expanduser("~/.ayfam/suppressions.json")

class ExplanationEngine:
    """طبقة صياغة الشرح المكون من ستة أركان والتحكم في كبت النتائج."""

    def __init__(self, suppression_file: str = SUPPRESSION_FILE):
        self.suppression_file = suppression_file
        os.makedirs(os.path.dirname(self.suppression_file), exist_ok=True)
        self.suppressions = self._load_suppressions()

    def _load_suppressions(self) -> Dict[str, Dict[str, Any]]:
        if os.path.exists(self.suppression_file):
            try:
                with open(self.suppression_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_suppressions(self):
        try:
            with open(self.suppression_file, "w", encoding="utf-8") as f:
                json.dump(self.suppressions, f, indent=2)
        except Exception:
            pass

    def add_suppression(self, rule_id: str, fingerprint: Optional[str] = None, expiry_days: int = 30, reason: str = "User approved"):
        expiry = time.time() + (expiry_days * 86400)
        key = f"{rule_id}:{fingerprint}" if fingerprint else rule_id
        self.suppressions[key] = {
            "rule_id": rule_id,
            "fingerprint": fingerprint,
            "expiry": expiry,
            "reason": reason,
        }
        self._save_suppressions()

    def is_suppressed(self, finding: Finding) -> bool:
        now = time.time()
        rule_key = finding.rule_id
        fp_key = f"{finding.rule_id}:{finding.fingerprint}"

        for k in (fp_key, rule_key):
            if k in self.suppressions:
                rule_supp = self.suppressions[k]
                if now < rule_supp.get("expiry", 0):
                    return True
                else:
                    # Expired suppression
                    del self.suppressions[k]
                    self._save_suppressions()
        return False

    def explain(self, finding: Finding, lang: str = "ar") -> Dict[str, str]:
        rule = get_rule(finding.rule_id)
        sev = finding.severity.upper()

        if lang == "ar":
            return {
                "what": f"[{sev}] {finding.title}",
                "why_it_matters": finding.detail or rule.get("rationale", "هذه المشكلة قد تتيح للمهاجم الوصول أو تصعيد الصلاحيات."),
                "evidence": json.dumps(finding.get("evidence", {}), ensure_ascii=False, indent=2),
                "confidence": f"{int(finding.get('confidence', 1.0) * 100)}%",
                "what_to_do": finding.fix or rule.get("fix_template", "اتبع إجراءات تحصين النظام."),
                "risk_of_fixing": finding.get("risk_of_fix", "منخفضة (low)"),
            }
        else:
            return {
                "what": f"[{sev}] {finding.title_en or finding.title}",
                "why_it_matters": finding.get("detail_en") or finding.detail or "May allow initial access or privilege escalation.",
                "evidence": json.dumps(finding.get("evidence", {}), indent=2),
                "confidence": f"{int(finding.get('confidence', 1.0) * 100)}%",
                "what_to_do": finding.fix or rule.get("fix_template", "Follow system hardening guidelines."),
                "risk_of_fixing": finding.get("risk_of_fix", "low"),
            }
