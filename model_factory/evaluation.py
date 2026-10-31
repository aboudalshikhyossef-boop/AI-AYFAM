"""Held-out token-weighted evaluation for AI AYFAM model artifacts."""

from __future__ import annotations

import math
from typing import Any, Literal

from model_factory.corpus_tools import validate_prepared_corpus
from model_factory.data import iter_batches
from model_factory.inference import LoadedInferenceModel, _torch

EvaluationSplit = Literal["validation", "test"]


def evaluate_model(
    loaded: LoadedInferenceModel,
    corpus_path: str,
    *,
    split: EvaluationSplit = "test",
    batch_size: int = 1,
    max_batches: int | None = None,
) -> dict[str, Any]:
    """Evaluate token-weighted loss and next-token accuracy on held-out data.

    The corpus is strictly audited and must match the fingerprint recorded in
    the model artifact. Validation/test records are streamed in bounded batches.
    """
    if split not in {"validation", "test"}:
        raise ValueError("evaluation split must be validation or test")
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size <= 0:
        raise ValueError("batch_size must be a positive integer")
    if max_batches is not None and (
        isinstance(max_batches, bool) or not isinstance(max_batches, int) or max_batches <= 0
    ):
        raise ValueError("max_batches must be a positive integer or None")

    report = validate_prepared_corpus(corpus_path, require_held_out=True)
    expected_fingerprint = loaded.source.get("data_fingerprint", "")
    if not expected_fingerprint or report.fingerprint != expected_fingerprint:
        raise ValueError("evaluation corpus fingerprint does not match the model artifact")

    torch = _torch()
    functional = torch.nn.functional
    total_loss = 0.0
    total_correct = 0
    total_tokens = 0
    batches = 0
    was_training = loaded.model.training
    loaded.model.eval()
    try:
        with torch.inference_mode():
            batch_iterator = iter_batches(
                corpus_path,
                loaded.tokenizer,
                split=split,
                block_size=loaded.config.block_size,
                batch_size=batch_size,
                shuffle=False,
            )
            for input_ids, targets in batch_iterator:
                if max_batches is not None and batches >= max_batches:
                    break
                input_ids = input_ids.to(loaded.device)
                targets = targets.to(loaded.device)
                logits = loaded.model(input_ids)["logits"]
                mask = targets.ne(loaded.tokenizer.PAD)
                token_count = int(mask.sum().item())
                if token_count == 0:
                    continue
                summed_loss = functional.cross_entropy(
                    logits.reshape(-1, loaded.config.vocab_size),
                    targets.reshape(-1),
                    ignore_index=loaded.tokenizer.PAD,
                    reduction="sum",
                )
                predictions = logits.argmax(dim=-1)
                correct = int(((predictions == targets) & mask).sum().item())
                total_loss += float(summed_loss.item())
                total_correct += correct
                total_tokens += token_count
                batches += 1
    finally:
        loaded.model.train(was_training)

    if total_tokens == 0:
        raise ValueError(f"{split} split produced no evaluable target tokens")
    average_loss = total_loss / total_tokens
    return {
        "split": split,
        "loss": average_loss,
        "perplexity": math.exp(min(average_loss, 20.0)),
        "perplexity_exponent_capped": average_loss > 20.0,
        "next_token_accuracy": total_correct / total_tokens,
        "correct_tokens": total_correct,
        "tokens_evaluated": total_tokens,
        "batches_evaluated": batches,
        "corpus_fingerprint": report.fingerprint,
    }
