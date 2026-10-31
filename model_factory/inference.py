"""Safe model-only export, loading and autoregressive text generation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import math
import os
from pathlib import Path
import platform
import tempfile
from typing import Any

from model_factory.config import ModelConfig
from model_factory.tokenizer import ByteBPETokenizer, ByteTokenizer, tokenizer_from_dict

INFERENCE_ARTIFACT_SCHEMA_VERSION = 1
MAX_GENERATION_TOKENS = 8_192


def _torch():
    try:
        import torch
    except ImportError as exc:
        raise RuntimeError(
            "PyTorch is optional. Install requirements-training.txt to use local inference."
        ) from exc
    return torch


def _atomic_torch_save(payload: dict[str, Any], destination: Path) -> None:
    if destination.is_symlink():
        raise OSError("model artifact destination must not be a symlink")
    destination.parent.mkdir(parents=True, exist_ok=True)
    torch = _torch()
    fd, temporary_name = tempfile.mkstemp(
        prefix=".ayfam-model-", suffix=".tmp", dir=destination.parent
    )
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


def _read_weights_only(path: str | Path) -> dict[str, Any]:
    torch = _torch()
    source = Path(path).expanduser()
    if source.is_symlink():
        raise OSError("model file must not be a symlink")
    payload = torch.load(source, map_location="cpu", weights_only=True)
    if not isinstance(payload, dict):
        raise ValueError("model file must contain a JSON-like checkpoint mapping")
    return payload


def _build_model(config_payload: object, tokenizer_payload: object, state: object):
    torch = _torch()
    from model_factory.architecture import AYFAMTransformer

    if not isinstance(config_payload, dict) or not isinstance(tokenizer_payload, dict):
        raise ValueError("model or tokenizer configuration is missing or invalid")
    config = ModelConfig.from_dict(config_payload)
    tokenizer = tokenizer_from_dict(tokenizer_payload)
    if config.vocab_size != tokenizer.vocab_size:
        raise ValueError("model vocabulary size does not match the selected tokenizer")
    if config.pad_token_id != tokenizer.PAD or config.eos_token_id != tokenizer.EOS:
        raise ValueError("model special-token IDs do not match the selected tokenizer")
    if not isinstance(state, dict) or not state:
        raise ValueError("model state dictionary is missing or empty")
    if any(not isinstance(value, torch.Tensor) for value in state.values()):
        raise ValueError("model state dictionary contains non-tensor values")
    model = AYFAMTransformer(config)
    try:
        model.load_state_dict(state, strict=True)
    except (RuntimeError, TypeError) as exc:
        raise ValueError("model state dictionary does not match its architecture") from exc
    return model, tokenizer, config


def export_inference_artifact(
    checkpoint_path: str | Path,
    output_path: str | Path,
) -> Path:
    """Extract model weights and tokenizer from a training checkpoint.

    Optimizer state and training-only tensors are deliberately omitted from the
    exported artifact, making subsequent local inference loads substantially lighter.
    """
    source = Path(checkpoint_path).expanduser()
    destination = Path(output_path).expanduser()
    if source.is_symlink() or destination.is_symlink():
        raise OSError("checkpoint and model artifact paths must not be symlinks")
    if source.resolve() == destination.resolve():
        raise ValueError("input checkpoint and output artifact must be different files")

    payload = _read_weights_only(source)
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported or invalid training checkpoint schema")
    model, tokenizer, config = _build_model(
        payload.get("model_config"),
        payload.get("tokenizer_config"),
        payload.get("model_state"),
    )
    del tokenizer
    torch = _torch()
    state = {
        key: value.detach().to(device="cpu").contiguous().clone()
        for key, value in model.state_dict().items()
    }
    source_info = {
        "global_step": payload.get("global_step", 0),
        "created_at": payload.get("created_at", ""),
        "data_fingerprint": payload.get("data_fingerprint", ""),
    }
    if (
        isinstance(source_info["global_step"], bool)
        or not isinstance(source_info["global_step"], int)
        or source_info["global_step"] < 0
    ):
        raise ValueError("training checkpoint global_step is invalid")
    if not isinstance(source_info["data_fingerprint"], str):
        raise ValueError("training checkpoint data fingerprint is invalid")

    artifact = {
        "artifact_schema_version": INFERENCE_ARTIFACT_SCHEMA_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "model_config": config.to_dict(),
        "tokenizer_config": payload["tokenizer_config"],
        "model_state": state,
        "source": source_info,
        "metadata": {
            "python": platform.python_version(),
            "torch": str(torch.__version__),
            "parameter_count": sum(parameter.numel() for parameter in model.parameters()),
        },
    }
    _atomic_torch_save(artifact, destination)
    return destination


@dataclass(frozen=True)
class LoadedInferenceModel:
    model: Any
    tokenizer: ByteTokenizer | ByteBPETokenizer
    config: ModelConfig
    metadata: dict[str, Any]
    source: dict[str, Any]
    device: str


def resolve_device(device: str = "auto") -> str:
    if device not in {"auto", "cpu", "cuda"}:
        raise ValueError("device must be auto, cpu, or cuda")
    torch = _torch()
    if device == "auto":
        return "cuda" if torch.cuda.is_available() else "cpu"
    if device == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA was requested but is not available in this PyTorch build")
    return device


def load_inference_model(
    artifact_path: str | Path,
    *,
    device: str = "auto",
) -> LoadedInferenceModel:
    """Load a compact model-only artifact without constructing an optimizer."""
    payload = _read_weights_only(artifact_path)
    if payload.get("artifact_schema_version") != INFERENCE_ARTIFACT_SCHEMA_VERSION:
        raise ValueError("unsupported or invalid inference artifact schema")
    model, tokenizer, config = _build_model(
        payload.get("model_config"),
        payload.get("tokenizer_config"),
        payload.get("model_state"),
    )
    source = payload.get("source")
    metadata = payload.get("metadata")
    if not isinstance(source, dict) or not isinstance(metadata, dict):
        raise ValueError("inference artifact metadata is missing or invalid")
    step = source.get("global_step")
    fingerprint = source.get("data_fingerprint")
    if isinstance(step, bool) or not isinstance(step, int) or step < 0:
        raise ValueError("inference artifact source step is invalid")
    if not isinstance(fingerprint, str):
        raise ValueError("inference artifact corpus fingerprint is invalid")
    selected_device = resolve_device(device)
    model.to(selected_device)
    model.eval()
    return LoadedInferenceModel(
        model=model,
        tokenizer=tokenizer,
        config=config,
        metadata=dict(metadata),
        source=dict(source),
        device=selected_device,
    )


@dataclass(frozen=True)
class GenerationResult:
    text: str
    generated_token_ids: tuple[int, ...]
    prompt_token_count: int
    generated_token_count: int
    stopped_on_eos: bool


def generate_text(
    loaded: LoadedInferenceModel,
    prompt: str,
    *,
    max_new_tokens: int = 64,
    temperature: float = 0.8,
    top_k: int | None = 40,
    top_p: float | None = 0.9,
    seed: int | None = 42,
    stop_on_eos: bool = True,
) -> GenerationResult:
    """Generate one continuation while leaving the caller's global RNG untouched."""
    torch = _torch()
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")
    if isinstance(max_new_tokens, bool) or not isinstance(max_new_tokens, int):
        raise ValueError("max_new_tokens must be an integer")
    if not 0 <= max_new_tokens <= MAX_GENERATION_TOKENS:
        raise ValueError(f"max_new_tokens must be between 0 and {MAX_GENERATION_TOKENS}")
    if isinstance(temperature, bool) or not isinstance(temperature, (int, float)):
        raise ValueError("temperature must be a finite number greater than or equal to zero")
    if not math.isfinite(float(temperature)) or temperature < 0:
        raise ValueError("temperature must be a finite number greater than or equal to zero")
    if top_k is not None and (
        isinstance(top_k, bool) or not isinstance(top_k, int) or top_k <= 0
    ):
        raise ValueError("top_k must be a positive integer or None")
    if top_p is not None and (
        isinstance(top_p, bool)
        or not isinstance(top_p, (int, float))
        or not math.isfinite(float(top_p))
        or not 0.0 < top_p <= 1.0
    ):
        raise ValueError("top_p must be in the range (0, 1] or None")
    if seed is not None and (isinstance(seed, bool) or not isinstance(seed, int)):
        raise ValueError("seed must be an integer or None")
    if not isinstance(stop_on_eos, bool):
        raise ValueError("stop_on_eos must be a boolean")

    encoded = loaded.tokenizer.encode(prompt, add_bos=True)
    encoded = encoded[-loaded.config.block_size :]
    input_ids = torch.tensor([encoded], dtype=torch.long, device=loaded.device)
    generated = input_ids
    produced: list[int] = []
    stopped_on_eos = False
    eos_id = loaded.tokenizer.EOS
    generator = None
    if seed is not None:
        generator = torch.Generator(device=loaded.device)
        generator.manual_seed(seed)

    was_training = loaded.model.training
    loaded.model.eval()
    try:
        with torch.inference_mode():
            for _ in range(max_new_tokens):
                context = generated[:, -loaded.config.block_size :]
                logits = loaded.model(context)["logits"][:, -1, :].clone()
                # Special control tokens are not meaningful free-form output.
                for token_id in (loaded.tokenizer.PAD, loaded.tokenizer.BOS, loaded.tokenizer.UNK):
                    logits[:, token_id] = float("-inf")

                if temperature == 0:
                    next_token = torch.argmax(logits, dim=-1, keepdim=True)
                else:
                    logits = logits / float(temperature)
                    if top_k is not None:
                        count = min(top_k, logits.shape[-1])
                        threshold = torch.topk(logits, count, dim=-1).values[:, -1, None]
                        logits = logits.masked_fill(logits < threshold, float("-inf"))
                    if top_p is not None and top_p < 1.0:
                        sorted_logits, sorted_indices = torch.sort(logits, descending=True, dim=-1)
                        cumulative = torch.softmax(sorted_logits, dim=-1).cumsum(dim=-1)
                        remove = cumulative > float(top_p)
                        remove[:, 1:] = remove[:, :-1].clone()
                        remove[:, 0] = False
                        remove_indices = torch.zeros_like(remove).scatter(
                            1, sorted_indices, remove
                        )
                        logits = logits.masked_fill(remove_indices, float("-inf"))
                    probabilities = torch.softmax(logits, dim=-1)
                    if not bool(torch.isfinite(probabilities).all()):
                        raise FloatingPointError("sampling probabilities became non-finite")
                    next_token = torch.multinomial(
                        probabilities, num_samples=1, generator=generator
                    )
                token_id = int(next_token.item())
                produced.append(token_id)
                generated = torch.cat((generated, next_token), dim=1)
                if stop_on_eos and token_id == eos_id:
                    stopped_on_eos = True
                    break
    finally:
        loaded.model.train(was_training)

    return GenerationResult(
        text=loaded.tokenizer.decode(produced),
        generated_token_ids=tuple(produced),
        prompt_token_count=len(encoded),
        generated_token_count=len(produced),
        stopped_on_eos=stopped_on_eos,
    )
