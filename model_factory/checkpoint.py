"""Atomic, versioned and resumable training checkpoints."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import platform
import tempfile
from typing import Any

from model_factory.tokenizer import ByteBPETokenizer, ByteTokenizer

CHECKPOINT_SCHEMA_VERSION = 1


def _torch():
    try:
        import torch
    except ImportError as exc:
        raise RuntimeError(
            "PyTorch is optional. Install requirements-training.txt to use checkpoints."
        ) from exc
    return torch


def save_checkpoint(path: str | Path, trainer, tokenizer: ByteTokenizer | ByteBPETokenizer) -> Path:
    torch = _torch()
    destination = Path(path).expanduser()
    if destination.is_symlink():
        raise OSError("checkpoint destination must not be a symlink")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model_config": trainer.model.config.to_dict(),
        "tokenizer_config": tokenizer.to_dict(),
        "model_state": trainer.model.state_dict(),
        "optimizer_state": trainer.optimizer.state_dict(),
        "global_step": int(trainer.global_step),
        "data_fingerprint": trainer.data_fingerprint,
        "training_config": trainer.config.to_dict(),
        "torch_rng_state": torch.get_rng_state(),
        "torch_cuda_rng_states": (
            torch.cuda.get_rng_state_all() if torch.cuda.is_available() else []
        ),
        "metadata": {
            "python": platform.python_version(),
            "torch": str(torch.__version__),
            "platform": platform.platform(),
            "device": str(trainer.device),
            "hardware": trainer.hardware_profile.to_dict(),
        },
    }
    fd, temporary_name = tempfile.mkstemp(prefix=".ayfam-checkpoint-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            torch.save(payload, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
        try:
            directory_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
    return destination


def load_checkpoint(
    path: str | Path,
    trainer,
    tokenizer: ByteTokenizer | ByteBPETokenizer,
    *,
    expected_data_fingerprint: str | None = None,
) -> dict[str, Any]:
    torch = _torch()
    source = Path(path).expanduser()
    if source.is_symlink():
        raise OSError("checkpoint source must not be a symlink")
    # weights_only=True prevents arbitrary Python object construction from checkpoint files.
    payload = torch.load(source, map_location="cpu", weights_only=True)
    if not isinstance(payload, dict) or payload.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        raise ValueError("unsupported or invalid checkpoint schema")
    if payload.get("model_config") != trainer.model.config.to_dict():
        raise ValueError("checkpoint model configuration does not match the current model")
    if payload.get("tokenizer_config") != tokenizer.to_dict():
        raise ValueError("checkpoint tokenizer does not match the current tokenizer")
    saved_training = payload.get("training_config")
    if not isinstance(saved_training, dict):
        raise ValueError("checkpoint training configuration is missing or invalid")
    current_training = trainer.config.to_dict()
    for key in ("learning_rate", "weight_decay", "gradient_clip_norm", "warmup_steps"):
        if saved_training.get(key) != current_training.get(key):
            raise ValueError(f"checkpoint training setting {key} does not match")
    saved_effective_batch = (
        saved_training.get("batch_size", 0)
        * saved_training.get("gradient_accumulation_steps", 0)
    )
    current_effective_batch = (
        current_training.get("batch_size", 0)
        * current_training.get("gradient_accumulation_steps", 0)
    )
    if saved_effective_batch != current_effective_batch:
        raise ValueError("checkpoint effective batch size does not match the current training plan")
    saved_fingerprint = payload.get("data_fingerprint", "")
    required_fingerprint = expected_data_fingerprint or trainer.data_fingerprint
    if required_fingerprint and saved_fingerprint != required_fingerprint:
        raise ValueError("checkpoint corpus fingerprint does not match the current corpus")
    if not isinstance(payload.get("global_step"), int) or payload["global_step"] < 0:
        raise ValueError("checkpoint global_step is invalid")
    trainer.model.load_state_dict(payload["model_state"], strict=True)
    trainer.optimizer.load_state_dict(payload["optimizer_state"])
    trainer.global_step = payload["global_step"]
    trainer.data_fingerprint = saved_fingerprint
    if isinstance(payload.get("torch_rng_state"), torch.Tensor):
        torch.set_rng_state(payload["torch_rng_state"].cpu())
    cuda_rng_states = payload.get("torch_cuda_rng_states", [])
    if torch.cuda.is_available() and isinstance(cuda_rng_states, list) and cuda_rng_states:
        if len(cuda_rng_states) == torch.cuda.device_count():
            torch.cuda.set_rng_state_all([state.cpu() for state in cuda_rng_states])
    return {
        "global_step": trainer.global_step,
        "data_fingerprint": saved_fingerprint,
        "metadata": payload.get("metadata", {}),
        "created_at": payload.get("created_at", ""),
    }
