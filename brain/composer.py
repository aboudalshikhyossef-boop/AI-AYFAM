"""Pure local response composer driven by measured retrieval signals and live policy weights."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Mapping, Sequence


@dataclass(frozen=True)
class Evidence:
    text: str
    source: str = "المعرفة المحلية / Local knowledge"
    retrieval_score: float | None = None
    retrieval_method: str = ""
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


def _optional_score(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        return None
    return round(score, 4)


def compose(
    plan_weights: Mapping[str, float],
    evidence: Sequence[Evidence | Mapping],
    question_type: str,
    *,
    profile_name: str = "balanced-v1",
) -> Answer:
    """Compose supplied references; absent retrieval signals never become numbers."""
    items: list[Evidence] = []
    for item in evidence:
        if isinstance(item, Evidence):
            parsed = item
        else:
            parsed = Evidence(
                text=str(item.get("text", "")),
                source=str(item.get("source", "المعرفة المحلية / Local knowledge")),
                retrieval_score=_optional_score(item.get("retrieval_score")),
                retrieval_method=str(item.get("retrieval_method", "")),
                kind=str(item.get("kind", "evidence")),
                steps=tuple(str(x) for x in (item.get("steps", ()) or ())),
                examples=tuple(str(x) for x in (item.get("examples", ()) or ())),
            )
        if parsed.text.strip():
            items.append(Evidence(
                text=parsed.text,
                source=parsed.source,
                retrieval_score=_optional_score(parsed.retrieval_score),
                retrieval_method=parsed.retrieval_method,
                kind=parsed.kind,
                steps=parsed.steps,
                examples=parsed.examples,
            ))

    keys = (
        "question_alignment", "evidence_first", "source_attribution",
        "stepwise_reasoning", "structured_response", "brevity",
        "examples", "limitations", "retrieval_score_display",
    )
    weights = {key: round(_weight(plan_weights, key), 4) for key in keys}

    sections: list[str] = []
    if weights["question_alignment"] >= 0.5:
        sections.append(
            f"السؤال المرتبط / Related query ({question_type}): "
            "رُتبت المقاطع بحسب إشارات الاسترجاع المتاحة فقط. / "
            "Passages are ordered only by available retrieval signals."
        )

    scored = [item for item in items if item.retrieval_score is not None]
    unscored = [item for item in items if item.retrieval_score is None]
    scored.sort(
        key=lambda item: item.retrieval_score,
        reverse=weights["evidence_first"] >= 0.5,
    )
    ordered = scored + unscored if weights["evidence_first"] >= 0.5 else unscored + scored

    for index, item in enumerate(ordered):
        body = item.text.strip()
        if weights["brevity"] >= 0.95:
            body = body[:280].rstrip() + ("…" if len(body) > 280 else "")
        label = (
            f"الدليل {index + 1} / Evidence {index + 1}"
            if weights["structured_response"] >= 0.5
            else "الدليل / Evidence"
        )
        source = (
            f" — المصدر / Source: {item.source}"
            if weights["source_attribution"] >= 0.5 and item.source.strip()
            else ""
        )
        sections.append(f"{label}{source}:\n{body}")
        if weights["retrieval_score_display"] >= 0.5 and item.retrieval_score is not None:
            method = item.retrieval_method or "retrieval"
            sections.append(
                f"مؤشر دعم الاسترجاع ({method}) / Retrieval support ({method}): "
                f"{item.retrieval_score:.3f}"
            )

    if weights["stepwise_reasoning"] >= 0.55:
        steps = [step for item in ordered for step in item.steps]
        if steps:
            sections.append(
                "خطوات واردة في المصدر / Steps stated in the source:\n"
                + "\n".join(f"{i + 1}. {step}" for i, step in enumerate(steps[:5]))
            )

    if weights["examples"] >= 0.55:
        examples = [example for item in ordered for example in item.examples]
        if examples:
            sections.append(
                "أمثلة واردة في المصدر / Examples stated in the source:\n"
                + "\n".join(f"- {example}" for example in examples[:3])
            )

    if weights["limitations"] >= 0.5:
        sections.append(
            "الحدود / Limitations: هذه المقاطع مراجع محلية ولا تثبت صحة ما لم يرد فيها. / "
            "These are local references; they do not establish claims absent from the sources."
        )

    influential = sorted(weights.items(), key=lambda pair: pair[1], reverse=True)[:3]
    why = tuple(f"{key}={value:.2f}" for key, value in influential)
    return Answer(
        text="\n\n".join(sections),
        sections=tuple(sections),
        used_weights=weights,
        evidence_count=len(ordered),
        why=why,
    )
