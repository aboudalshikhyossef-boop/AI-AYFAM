"""Shared Gemini quota guard and canonical model defaults."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Callable, Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Linux is the supported runtime
    fcntl = None

DEFAULT_MIN_INTERVAL = 30.0
DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"
# Retained as metadata for older callers; explicit choices are never rewritten.
LEGACY_GEMINI_MODELS = frozenset({
    "gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-flash-latest",
})


def gemini_model_name(value: str | None) -> str:
    """Preserve an explicit selection; use the default only for an empty value."""
    model = str(value or "").strip()
    return model.removeprefix("models/") if model else DEFAULT_GEMINI_MODEL


def _interval() -> float:
    raw = os.getenv("AYFAM_GEMINI_MIN_INTERVAL", str(DEFAULT_MIN_INTERVAL))
    try:
        return max(0.0, float(raw))
    except ValueError:
        return DEFAULT_MIN_INTERVAL


def _state_path(api_key: str) -> Path:
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:20]
    directory = Path(os.getenv("AYFAM_STATE_DIR", str(Path.home() / ".ayfam"))).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"gemini-rate-{digest}.json"


def _cancelled(cancel_event: Any) -> bool:
    if cancel_event is None:
        return False
    is_set = getattr(cancel_event, "is_set", None)
    if callable(is_set):
        return bool(is_set())
    return bool(cancel_event()) if callable(cancel_event) else bool(cancel_event)


def wait_for_slot(
    api_key: str,
    *,
    timeout: float | None = None,
    cancel_event: Any = None,
    on_wait: Callable[[float], None] | None = None,
    clock: Callable[[], float] = time.time,
    sleeper: Callable[[float], None] = time.sleep,
    poll_interval: float = 0.2,
) -> float:
    """Reserve a shared request slot without sleeping while holding the file lock.

    Waiting is cancellable, reports the remaining delay through on_wait, and
    honours one total timeout budget. The persisted timestamp keeps the quota
    guard shared by concurrent threads/processes using the same key.
    """
    key = str(api_key or "")
    if not key:
        raise ValueError("Gemini API key is required")
    started = time.monotonic()
    budget = None if timeout is None else max(0.0, float(timeout))
    path = _state_path(key)
    lock_path = path.with_suffix(".lock")
    interval = _interval()
    last_reported_second = -1
    while True:
        if _cancelled(cancel_event):
            raise InterruptedError("Gemini slot wait was cancelled")
        elapsed = time.monotonic() - started
        if budget is not None and elapsed >= budget:
            raise TimeoutError("Gemini slot wait exceeded total timeout")
        remaining = 0.0
        # The critical section only reads/updates the timestamp. It never sleeps.
        with lock_path.open("a+", encoding="utf-8") as lock:
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                try:
                    state = json.loads(path.read_text(encoding="utf-8"))
                    last = float(state.get("last_request", 0.0))
                except (OSError, ValueError, TypeError, json.JSONDecodeError):
                    last = 0.0
                now = clock()
                remaining = max(0.0, interval - (now - last)) if last else 0.0
                if remaining <= 0:
                    path.write_text(json.dumps({"last_request": now}), encoding="utf-8")
                    return max(0.0, time.monotonic() - started)
            finally:
                if fcntl is not None:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        elapsed = time.monotonic() - started
        if budget is not None:
            remaining_budget = budget - elapsed
            if remaining_budget <= 0 or remaining > remaining_budget:
                raise TimeoutError("Gemini slot wait exceeded total timeout")
        if on_wait:
            remaining_second = int(remaining + 0.999)
            if remaining_second != last_reported_second:
                on_wait(remaining)
                last_reported_second = remaining_second
        delay = min(max(0.01, float(poll_interval)), remaining)
        if budget is not None:
            delay = min(delay, max(0.0, budget - elapsed))
        if delay <= 0:
            raise TimeoutError("Gemini slot wait exceeded total timeout")
        sleeper(delay)


def compact_text(value: str, limit: int = 4000) -> str:
    """Normalize whitespace and cap outbound prompt text before tokenization."""
    return " ".join(str(value or "").split())[:limit]
