"""Atomic pointer to the locally trained model used by the AYFAM conversation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any

ACTIVE_MODEL_MANIFEST = (
    Path.home() / ".local" / "share" / "ayfam" / "training" / "active-model.json"
)


def read_active_model_manifest(
    path: str | Path | None = None,
) -> dict[str, Any] | None:
    source = Path(path).expanduser() if path is not None else ACTIVE_MODEL_MANIFEST
    if source.is_symlink() or not source.is_file():
        return None
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        return None
    for key in ("artifact_path", "checkpoint_path", "corpus_path", "data_fingerprint"):
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            return None
    artifact = Path(payload["artifact_path"]).expanduser()
    checkpoint = Path(payload["checkpoint_path"]).expanduser()
    corpus = Path(payload["corpus_path"]).expanduser()
    if artifact.is_symlink() or checkpoint.is_symlink() or corpus.is_symlink():
        return None
    if not artifact.is_file() or not checkpoint.is_file() or not corpus.is_file():
        return None
    return payload


def write_active_model_manifest(
    path: str | Path,
    *,
    artifact_path: str | Path,
    checkpoint_path: str | Path,
    corpus_path: str | Path,
    tokenizer_path: str | Path | None,
    data_fingerprint: str,
    global_step: int,
    model_parameters: int,
    tokenizer_vocab_size: int,
    epochs_completed: int,
    evaluation_split: str,
    evaluation_before: dict[str, float] | None,
    evaluation_after: dict[str, float] | None,
    validation_before: dict[str, float] | None,
    validation_after: dict[str, float] | None,
    test_before: dict[str, float] | None,
    test_after: dict[str, float] | None,
) -> Path:
    destination = Path(path).expanduser()
    artifact = Path(artifact_path).expanduser()
    checkpoint = Path(checkpoint_path).expanduser()
    corpus = Path(corpus_path).expanduser()
    for candidate, label in (
        (artifact, "artifact"),
        (checkpoint, "checkpoint"),
        (corpus, "corpus"),
    ):
        if candidate.is_symlink() or not candidate.is_file():
            raise OSError(f"active model {label} must be an existing regular file")

    payload: dict[str, Any] = {
        "schema_version": 1,
        "artifact_path": str(artifact.resolve()),
        "checkpoint_path": str(checkpoint.resolve()),
        "corpus_path": str(corpus.resolve()),
        "tokenizer_path": str(Path(tokenizer_path).expanduser().resolve()) if tokenizer_path is not None else "",
        "data_fingerprint": data_fingerprint,
        "global_step": int(global_step),
        "model_parameters": int(model_parameters),
        "tokenizer_vocab_size": int(tokenizer_vocab_size),
        "epochs_completed": int(epochs_completed),
        "evaluation_split": str(evaluation_split),
        "evaluation_before": evaluation_before,
        "evaluation_after": evaluation_after,
        "validation_before": validation_before,
        "validation_after": validation_after,
        "test_before": test_before,
        "test_after": test_after,
    }
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.is_symlink():
        raise OSError("active model manifest must not be a symbolic link")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".ayfam-active-model-",
        suffix=".json",
        dir=destination.parent,
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return destination
