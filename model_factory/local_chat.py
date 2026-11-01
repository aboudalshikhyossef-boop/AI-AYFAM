"""Local neural generation plus source-grounded retrieval from AYFAM corpora."""

from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any

from model_factory.active_model import read_active_model_manifest
from model_factory.data import iter_records
from model_factory.inference import LoadedInferenceModel, generate_text, load_inference_model
from model_factory.hardware import HardwareProfile, build_training_plan

_TOKEN_RE = re.compile(r"[\w\u0600-\u06FF]+", re.UNICODE)
_STOP_WORDS = {
    "ما", "ماذا", "كيف", "هل", "هو", "هي", "من", "في", "على", "عن", "الى",
    "إلى", "هذا", "هذه", "ذلك", "تلك", "مع", "لي", "لك", "the", "what",
    "which", "who", "when", "where", "why", "how", "is", "are", "was",
    "were", "and", "or", "of", "to", "in", "on", "for", "a", "an",
}

_CACHE_LOCK = threading.RLock()
_CACHED_MANIFEST_PATH: str | None = None
_CACHED_MANIFEST_MTIME: int | None = None
_CACHED_MODEL: LoadedInferenceModel | None = None


def _terms(text: str) -> set[str]:
    return {
        token.casefold()
        for token in _TOKEN_RE.findall(text)
        if len(token) > 1 and token.casefold() not in _STOP_WORDS
    }


def has_active_local_model() -> bool:
    return read_active_model_manifest() is not None


def _load_active_model(manifest: dict[str, Any]) -> LoadedInferenceModel:
    global _CACHED_MANIFEST_PATH, _CACHED_MANIFEST_MTIME, _CACHED_MODEL
    artifact_path = Path(manifest["artifact_path"]).expanduser()
    stat_result = artifact_path.stat()
    cache_key = str(artifact_path.resolve())
    with _CACHE_LOCK:
        if (
            _CACHED_MODEL is not None
            and _CACHED_MANIFEST_PATH == cache_key
            and _CACHED_MANIFEST_MTIME == stat_result.st_mtime_ns
        ):
            return _CACHED_MODEL
        loaded = load_inference_model(artifact_path, device="cpu")
        try:
            import torch
            profile = HardwareProfile.detect()
            torch.set_num_threads(build_training_plan(profile).num_threads)
        except (ImportError, RuntimeError, ValueError):
            pass
        _CACHED_MANIFEST_PATH = cache_key
        _CACHED_MANIFEST_MTIME = stat_result.st_mtime_ns
        _CACHED_MODEL = loaded
        return loaded


def retrieve_corpus_passages(
    corpus_path: str | Path,
    query: str,
    *,
    limit: int = 2,
    max_chars: int = 520,
) -> list[dict[str, Any]]:
    """Stream the approved corpus and retain only the highest-overlap excerpts."""
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 5:
        raise ValueError("limit must be between 1 and 5")
    query_terms = _terms(query)
    if not query_terms:
        return []

    candidates: list[tuple[float, int, dict[str, Any]]] = []
    for index, record in enumerate(iter_records(corpus_path)):
        text_terms = _terms(record.text)
        if not text_terms:
            continue
        overlap = query_terms & text_terms
        if not overlap:
            continue
        # Reward coverage of the query while mildly penalizing long passages.
        score = len(overlap) / (len(query_terms) ** 0.5 * max(1.0, len(text_terms) ** 0.25))
        item = {
            "title": record.title or record.filename or record.source,
            "source": record.source,
            "page": record.page,
            "chapter": record.chapter,
            "split": record.split,
            "excerpt": record.text[:max_chars].strip(),
            "matched_terms": sorted(overlap),
        }
        candidates.append((score, -index, item))
        candidates.sort(key=lambda row: (row[0], row[1]), reverse=True)
        if len(candidates) > limit:
            candidates.pop()

    return [item for _score, _index, item in candidates]


def answer_with_active_model(
    prompt: str,
    *,
    history: list[tuple[str, str]] | None = None,
    max_new_tokens: int = 40,
) -> dict[str, Any] | None:
    """Generate with the trained checkpoint and attach retrieved book evidence.

    The neural continuation is shown separately from source excerpts: generation
    is not treated as proof that a statement is factually supported by the book.
    """
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")
    manifest = read_active_model_manifest()
    if manifest is None:
        return None

    loaded = _load_active_model(manifest)
    passages = retrieve_corpus_passages(manifest["corpus_path"], prompt, limit=1)
    # The model context is only 128 tokens on the current architecture. Keep the
    # prompt deliberately short so the question and a small evidence fragment
    # survive truncation; display the fuller retrieved passage separately below.
    evidence_hint = ""
    if passages:
        passage = passages[0]
        evidence_hint = (
            f"مرجع: {passage.get('title', '')}، صفحة {passage.get('page') or '؟'}. "
            f"{passage.get('excerpt', '')[:96]}"
        )
    compact_question = prompt.strip()[-240:]
    generation_prompt = (
        f"مرجع مختصر: {evidence_hint}\n"
        f"سؤال: {compact_question}\n"
        "إجابة:"
    )
    generated = generate_text(
        loaded,
        generation_prompt,
        max_new_tokens=max_new_tokens,
        temperature=0.65,
        top_k=32,
        top_p=0.90,
        seed=None,
        stop_on_eos=False,
    )
    return {
        "generated_text": generated.text.strip(),
        "generated_tokens": generated.generated_token_count,
        "prompt_tokens": generated.prompt_token_count,
        "global_step": int(manifest["global_step"]),
        "epochs_completed": int(manifest["epochs_completed"]),
        "model_parameters": int(manifest["model_parameters"]),
        "tokenizer_vocab_size": int(manifest["tokenizer_vocab_size"]),
        "device": loaded.device,
        "artifact_path": manifest["artifact_path"],
        "corpus_fingerprint": manifest["data_fingerprint"],
        "evaluation_split": manifest.get("evaluation_split", "validation/test (held-out)"),
        "evaluation_before": manifest.get("evaluation_before"),
        "evaluation_after": manifest.get("evaluation_after"),
        "validation_before": manifest.get("validation_before"),
        "validation_after": manifest.get("validation_after"),
        "test_before": manifest.get("test_before"),
        "test_after": manifest.get("test_after"),
        "passages": passages,
    }
