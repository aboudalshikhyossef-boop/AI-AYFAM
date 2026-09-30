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
