"""Repeatable, low-impact inference benchmarks for AI AYFAM artifacts."""

from __future__ import annotations

import os
import platform
import sys
import time
from typing import Any

from model_factory.inference import LoadedInferenceModel, generate_text, _torch


def _peak_rss_mb() -> float | None:
    try:
        import resource
        value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        # Linux and the BSDs report KiB; macOS reports bytes.
        return value / (1024 * 1024 if sys.platform == "darwin" else 1024)
    except (ImportError, OSError, ValueError):
        try:
            import psutil
            return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
        except (ImportError, OSError):
            return None


def benchmark_model(
    loaded: LoadedInferenceModel,
    *,
    batch_size: int = 1,
    sequence_length: int | None = None,
    warmup_iterations: int = 2,
    iterations: int = 10,
    generation_tokens: int = 16,
    threads: int | None = None,
) -> dict[str, Any]:
    """Measure forward throughput, greedy generation speed and process memory."""
    torch = _torch()
    for name, value in (
        ("batch_size", batch_size),
        ("iterations", iterations),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if isinstance(warmup_iterations, bool) or not isinstance(warmup_iterations, int) or warmup_iterations < 0:
        raise ValueError("warmup_iterations must be a non-negative integer")
    if isinstance(generation_tokens, bool) or not isinstance(generation_tokens, int) or not 0 <= generation_tokens <= 2_048:
        raise ValueError("generation_tokens must be between 0 and 2048")
    if threads is not None and (
        isinstance(threads, bool) or not isinstance(threads, int) or threads <= 0
    ):
        raise ValueError("threads must be a positive integer or None")

    length = loaded.config.block_size if sequence_length is None else sequence_length
    if isinstance(length, bool) or not isinstance(length, int) or not 1 <= length <= loaded.config.block_size:
        raise ValueError("sequence_length must be within the model context length")

    previous_threads = torch.get_num_threads()
    selected_threads = previous_threads if threads is None else threads
    device = loaded.model.token_embedding.weight.device
    model_was_training = loaded.model.training
    try:
        torch.set_num_threads(selected_threads)
        inputs = torch.randint(
            low=0,
            high=min(256, loaded.config.vocab_size),
            size=(batch_size, length),
            dtype=torch.long,
            device=device,
        )
        loaded.model.eval()
        if device.type == "cuda":
            torch.cuda.reset_peak_memory_stats(device)
        with torch.inference_mode():
            for _ in range(warmup_iterations):
                loaded.model(inputs)
            if device.type == "cuda":
                torch.cuda.synchronize(device)
            started = time.perf_counter()
            for _ in range(iterations):
                loaded.model(inputs)
            if device.type == "cuda":
                torch.cuda.synchronize(device)
            forward_seconds = max(time.perf_counter() - started, 1e-12)

            generation_seconds = 0.0
            generated_tokens = 0
            if generation_tokens:
                generation_prompt = "AI AYFAM"
                if device.type == "cuda":
                    torch.cuda.synchronize(device)
                started = time.perf_counter()
                generated = generate_text(
                    loaded,
                    generation_prompt,
                    max_new_tokens=generation_tokens,
                    temperature=0.0,
                    top_k=None,
                    top_p=None,
                    seed=0,
                    stop_on_eos=False,
                )
                if device.type == "cuda":
                    torch.cuda.synchronize(device)
                generation_seconds = max(time.perf_counter() - started, 1e-12)
                generated_tokens = generated.generated_token_count
    finally:
        loaded.model.train(model_was_training)
        torch.set_num_threads(previous_threads)

    peak_cuda_mb = None
    if device.type == "cuda":
        peak_cuda_mb = torch.cuda.max_memory_allocated(device) / (1024 * 1024)
    processed_tokens = batch_size * length * iterations
    return {
        "device": str(device),
        "torch_version": str(torch.__version__),
        "platform": platform.platform(),
        "model_parameters": loaded.model.parameter_count(),
        "model_vocab_size": loaded.config.vocab_size,
        "context_length": loaded.config.block_size,
        "batch_size": batch_size,
        "sequence_length": length,
        "threads": selected_threads,
        "warmup_iterations": warmup_iterations,
        "iterations": iterations,
        "forward_seconds": forward_seconds,
        "forward_tokens": processed_tokens,
        "forward_tokens_per_second": processed_tokens / forward_seconds,
        "generation_seconds": generation_seconds,
        "generated_tokens": generated_tokens,
        "generation_tokens_per_second": (
            generated_tokens / generation_seconds if generated_tokens else 0.0
        ),
        "peak_process_rss_mb": _peak_rss_mb(),
        "peak_cuda_allocated_mb": peak_cuda_mb,
    }
