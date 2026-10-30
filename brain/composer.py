"""Pure local response composer driven by transparent policy weights."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence


@dataclass(frozen=True)
class Evidence:
    text: str
    source: str = "المعرفة المحلية"
    confidence: float = 0.0
    kind: str = "evidence"
    steps: tuple[str, ...] = ()
    examples: tuple[str, ...] = ()


@dataclass(frozen=True)
class Answer:
    text: str
    sections: tuple[str, ...]
    used_weights: Mapping[str, float]
    evidence_count: int
    why: tuple[str, ...]


def _weight(weights: Mapping[str, float], key: str, default: float = 0.5) -> float:
    try:
        value = float(weights.get(key, default))
    except (TypeError, ValueError):
        value = default
    return max(0.0, min(1.5, value))


def compose(plan_weights: Mapping[str, float], evidence: Sequence[Evidence | Mapping], question_type: str,
            *, profile_name: str = "balanced-v1") -> Answer:
    """Compose a response without I/O, network calls, or copied provider text."""
    items = []
    for item in evidence:
        if isinstance(item, Evidence):
            items.append(item)
        else:
            items.append(Evidence(
                text=str(item.get("text", "")), source=str(item.get("source", "المعرفة المحلية")),
                confidence=float(item.get("confidence", 0.0) or 0.0), kind=str(item.get("kind", "evidence")),
                steps=tuple(item.get("steps", ()) or ()), examples=tuple(item.get("examples", ()) or ()),
            ))
    items = [item for item in items if item.text.strip()]
    weights = {key: round(_weight(plan_weights, key), 4) for key in plan_weights}
    if not weights:
        weights = {"question_alignment": 1.0, "evidence_first": 0.9, "structured_response": 0.6,
                   "limitations": 0.8, "source_attribution": 0.8, "confidence_calibration": 0.8}

    sections: list[str] = []
    if _weight(weights, "question_alignment") >= 0.5:
        sections.append(f"السؤال المرتبط ({question_type}): تم ترتيب الإجابة حول الأدلة المطابقة فقط.")

    ordered = sorted(items, key=lambda item: item.confidence, reverse=_weight(weights, "evidence_first") >= 0.5)
    for index, item in enumerate(ordered):
        text = item.text.strip()
        if _weight(weights, "brevity") >= 0.95:
            text = text[:280].rstrip() + ("…" if len(text) > 280 else "")
        label = "الدليل" if _weight(weights, "structured_response") < 0.5 else f"الدليل {index + 1}"
        source = f" — المصدر: {item.source}" if _weight(weights, "source_attribution") >= 0.5 else ""
        sections.append(f"{label}{source}:\n{text}")

    if _weight(weights, "stepwise_reasoning") >= 0.55:
        steps = [step for item in ordered for step in item.steps]
        if steps:
            sections.append("الخطوات المستنتجة:\n" + "\n".join(f"{i + 1}. {step}" for i, step in enumerate(steps[:5])))
    if _weight(weights, "examples") >= 0.55:
        examples = [example for item in ordered for example in item.examples]
        if examples:
            sections.append("مثال مرتبط:\n" + "\n".join(f"- {example}" for example in examples[:3]))
    if _weight(weights, "limitations") >= 0.5:
        sections.append("الحدود: هذا رد مبني على الأدلة المحلية المتاحة، ولا يثبت ما لا يوجد له مصدر.")
    if _weight(weights, "confidence_calibration") >= 0.5:
        confidence = max((item.confidence for item in ordered), default=0.0)
        sections.append(f"درجة الثقة التقريبية في المطابقة: {confidence:.2f}.")

    influential = sorted(((key, value) for key, value in weights.items()), key=lambda pair: pair[1], reverse=True)[:3]
    why = tuple(f"{key}={value:.2f}" for key, value in influential)
    sections.append(
        f"لماذا هذا الرد؟ ملف الأوزان: {profile_name}؛ أهم 3 أوزان مؤثرة: "
        + ", ".join(why) + f"؛ الأدلة المستخدمة: {len(ordered)}."
    )
    return Answer("\n\n".join(sections), tuple(sections), weights, len(ordered), why)
