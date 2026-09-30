"""
AI AYFAM v5 — Statistical Intent Classification & Morphological Preprocessor
مصنف النوايا الإحصائي والمعالج الصرفي العربي الخفيف — يدعم تحليل النوايا المتعددة
في جملة واحدة بدون أي مكتبات ذكاء اصطناعي خارجية.
"""

import re
from typing import List, Tuple

_AR_STRIP_PREFIXES = ("ال", "و", "ف", "ب", "ل")

def clean_arabic_token(word: str) -> str:
    """تنظيف الكلمة من التشكيل، التطويل، والزوائد الشائعة لتعزيز المطابقة الدلالية."""
    w = word.strip()
    # إزالة التشكيل والتطويل
    w = re.sub(r"[\u064B-\u0652\u0640]", "", w)
    # توحيد الحروف
    w = w.translate(str.maketrans("أإآىة", "ااايه"))
    # إزالة بادئة التعريف
    if len(w) > 4 and w.startswith("ال"):
        w = w[2:]
    return w

def split_multi_intent_text(text: str) -> List[str]:
    """تقسيم الأوامر المركبة (مثال: 'افحص الشبكة ثم افحص النظام')."""
    delimiters = [r"\s+ثم\s+", r"\s+و\s+بعدها\s+", r"\s+and\s+then\s+", r"\s+then\s+"]
    pattern = "|".join(delimiters)
    parts = re.split(pattern, text, flags=re.IGNORECASE)
    return [p.strip() for p in parts if p.strip()]
