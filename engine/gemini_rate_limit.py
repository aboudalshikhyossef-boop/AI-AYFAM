"""Shared Gemini quota guard.

The guard is process-safe: all Gemini callers use one lock/timestamp file under
~/.ayfam, so the 30-second spacing also applies when the GUI, CLI, and search
workers run at the same time. The first request is immediate; later requests
sleep until the minimum interval has elapsed.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Callable

try:
    import fcntl
except ImportError:  # pragma: no cover - Linux is the supported runtime
    fcntl = None

DEFAULT_MIN_INTERVAL = 30.0


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


def wait_for_slot(api_key: str, *, clock: Callable[[], float] = time.time,
                  sleeper: Callable[[float], None] = time.sleep) -> float:
    """Reserve the next Gemini slot and return the seconds waited.

    A file lock is held while reading, waiting, and writing the timestamp. This
    serializes callers across threads and separate Python processes.
    """
    path = _state_path(api_key)
    lock_path = path.with_suffix(".lock")
    interval = _interval()
    started = clock()
    waited = 0.0
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
            remaining = max(0.0, interval - (now - last))
            if remaining:
                sleeper(remaining)
                waited = remaining
            path.write_text(json.dumps({"last_request": clock()}), encoding="utf-8")
        finally:
            if fcntl is not None:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    return waited if waited else max(0.0, clock() - started - interval if interval else 0.0)


def compact_text(value: str, limit: int = 4000) -> str:
    """Normalize whitespace and cap outbound prompt text before tokenization."""
    return " ".join(str(value or "").split())[:limit]
