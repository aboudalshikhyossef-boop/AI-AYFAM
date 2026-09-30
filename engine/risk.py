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
