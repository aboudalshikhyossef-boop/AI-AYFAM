"""
AI AYFAM v5 — Normalized Finding Data Model
نموذج النتائج الموحد — متوافق كلياً مع قواميس dict السابقة، مع دعم معرّفات القواعد الثابتة
(rule_id)، البصمات المقارنة (fingerprint)، ووسوم ATT&CK.
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
        rule_id: str = "GENERIC-001",
        stable_key: Optional[str] = None,
        fingerprint: Optional[str] = None,
        **kwargs,
    ):
        sev_clean = (severity or "info").lower()
        if sev_clean not in SEVERITY_WEIGHTS:
            sev_clean = "info"

        # حساب البصمة fingerprint والمُعرّف id
        rule_clean = rule_id or "GENERIC-001"
        ev_dict = evidence or {}

        if not fingerprint:
            key_part = stable_key or ""
            if not key_part and ev_dict:
                # استخراج جزء ثابت مفتاحي من الأدلة إذا لم يُمرّر
                key_part = str(ev_dict.get("path") or ev_dict.get("ip") or ev_dict.get("port") or ev_dict.get("service") or ev_dict.get("pid") or "")
            if not key_part:
                key_part = title
            fp_material = f"{rule_clean}:{key_part}"
            fingerprint = hashlib.sha256(fp_material.encode("utf-8")).hexdigest()[:16]

        fid = fingerprint

        super().__init__(
            id=fid,
            fingerprint=fingerprint,
            rule_id=rule_clean,
            severity=sev_clean,
            title=title,
            detail=detail,
            fix=fix,
            category=category,
            tags=tags or [],
            attack_ids=attack_ids or [],
            evidence=ev_dict,
            fix_cmds=fix_cmds or ([fix] if fix and "\n" not in fix and not fix.startswith("#") else []),
            effort=effort,
            risk_of_fix=risk_of_fix,
            confidence=confidence,
            title_en=title_en or title,
            detail_en=detail_en or detail,
            score=int(SEVERITY_WEIGHTS.get(sev_clean, 2) * confidence),
            **kwargs,
        )

    @property
    def id(self) -> str:
        return self["id"]

    @property
    def fingerprint(self) -> str:
        return self["fingerprint"]

    @property
    def rule_id(self) -> str:
        return self["rule_id"]

    @property
    def category(self) -> str:
        return self["category"]

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
            rule_id=d.get("rule_id", "GENERIC-001"),
            stable_key=d.get("stable_key"),
            fingerprint=d.get("fingerprint"),
        )
