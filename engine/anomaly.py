"""
AI AYFAM — Anomaly & Statistical Trend Engine
محرك كشف الشذوذ والتوقع الاستدلالي — الإحصائيات المتدحرجة وتوقع الخطوة الهجومية التالية
"""

import math
from typing import List, Dict, Any, Optional

class AnomalyEngine:
    """محرك الحسابات الإحصائية المتدحرجة وكشف الشذوذ وتوقع التكتيك التالي."""

    @staticmethod
    def calculate_ewma(data: List[float], alpha: float = 0.3) -> float:
        """حساب المتوسط المتحرك الموزون أسياً (EWMA)."""
        if not data:
            return 0.0
        ewma = data[0]
        for val in data[1:]:
            ewma = alpha * val + (1 - alpha) * ewma
        return ewma

    @staticmethod
    def calculate_z_score(value: float, mean: float, std_dev: float) -> float:
        if std_dev <= 0.0001:
            return 0.0
        return (value - mean) / std_dev

    @staticmethod
    def predict_likely_next_step(observed_attack_ids: List[str]) -> Dict[str, Any]:
        """توقع استدلالي للخطوة الهجومية التالية بناءً على تكتيكات MITRE ATT&CK المرصودة."""
        tactic_progression = {
            "T1110": {"next_tactic": "Privilege Escalation", "likely_technique": "T1548.001 (SUID Execution)", "confidence": 0.75},
            "T1190": {"next_tactic": "Persistence", "likely_technique": "T1053.003 (Cron Persistence)", "confidence": 0.80},
            "T1552.001": {"next_tactic": "Credential Abuse / Defense Evasion", "likely_technique": "T1078 (Valid Accounts)", "confidence": 0.85},
            "T1059": {"next_tactic": "Exfiltration / C2", "likely_technique": "T1071 (Application Layer Protocol)", "confidence": 0.70},
        }

        for att_id in observed_attack_ids:
            for key, pred in tactic_progression.items():
                if key in att_id:
                    return {
                        "is_heuristic": True,
                        "observed_technique": att_id,
                        "likely_next_tactic": pred["next_tactic"],
                        "likely_technique": pred["likely_technique"],
                        "confidence": pred["confidence"],
                        "disclaimer": "Heuristic prediction based on MITRE ATT&CK progression patterns. Certainty is not guaranteed.",
                    }

        return {
            "is_heuristic": True,
            "observed_technique": "None",
            "likely_next_tactic": "Reconnaissance / Initial Access",
            "likely_technique": "T1595 (Active Scanning)",
            "confidence": 0.50,
            "disclaimer": "Default baseline heuristic expectation.",
        }
