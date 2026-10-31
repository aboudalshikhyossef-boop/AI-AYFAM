import threading
import time
from pathlib import Path

import pytest

from engine import gemini_rate_limit


FAKE_KEY = "gemini-rate-secret-test-123456789"


def configure_state(monkeypatch, tmp_path, interval="0.05"):
    monkeypatch.setenv("AYFAM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AYFAM_GEMINI_MIN_INTERVAL", interval)


def test_model_name_preserves_explicit_choice():
    assert gemini_rate_limit.gemini_model_name("gemini-2.5-flash") == "gemini-2.5-flash"
    assert gemini_rate_limit.gemini_model_name("gemini-3.8-flash") == "gemini-3.8-flash"
    assert gemini_rate_limit.gemini_model_name("") == gemini_rate_limit.DEFAULT_GEMINI_MODEL


def test_wait_reserves_first_slot_and_reports_wait_time(monkeypatch, tmp_path):
    configure_state(monkeypatch, tmp_path)
    assert gemini_rate_limit.wait_for_slot(FAKE_KEY, timeout=1.0) == 0.0
    reported = []
    started = time.monotonic()
    waited = gemini_rate_limit.wait_for_slot(
        FAKE_KEY,
        timeout=1.0,
        poll_interval=0.005,
        on_wait=reported.append,
    )
    assert waited > 0
    assert reported and all(value > 0 for value in reported)
    assert time.monotonic() - started >= 0.02


def test_wait_never_sleeps_while_holding_file_lock(monkeypatch, tmp_path):
    configure_state(monkeypatch, tmp_path, interval="0.02")
    lock_state = {"held": False}
    if gemini_rate_limit.fcntl is not None:
        original = gemini_rate_limit.fcntl.flock

        def track_lock(fd, operation):
            original(fd, operation)
            lock_state["held"] = bool(operation & gemini_rate_limit.fcntl.LOCK_EX)

        monkeypatch.setattr(gemini_rate_limit.fcntl, "flock", track_lock)

    gemini_rate_limit.wait_for_slot(FAKE_KEY, timeout=1.0)

    def checked_sleep(delay):
        assert lock_state["held"] is False
        time.sleep(min(delay, 0.005))

    gemini_rate_limit.wait_for_slot(
        FAKE_KEY, timeout=1.0, poll_interval=0.005, sleeper=checked_sleep,
    )


def test_wait_can_be_cancelled_and_emits_remaining_time(monkeypatch, tmp_path):
    configure_state(monkeypatch, tmp_path, interval="2")
    gemini_rate_limit.wait_for_slot(FAKE_KEY, timeout=1.0)
    cancel = threading.Event()
    remaining = []

    def cancel_on_sleep(_delay):
        cancel.set()

    with pytest.raises(InterruptedError):
        gemini_rate_limit.wait_for_slot(
            FAKE_KEY,
            timeout=1.0,
            cancel_event=cancel,
            on_wait=remaining.append,
            sleeper=cancel_on_sleep,
            poll_interval=0.01,
        )
    assert remaining and remaining[0] > 0


def test_wait_honours_one_total_timeout(monkeypatch, tmp_path):
    configure_state(monkeypatch, tmp_path, interval="2")
    gemini_rate_limit.wait_for_slot(FAKE_KEY, timeout=1.0)
    with pytest.raises(TimeoutError):
        gemini_rate_limit.wait_for_slot(
            FAKE_KEY, timeout=0.01, sleeper=lambda _delay: None,
        )


def test_persisted_rate_limit_state_does_not_contain_raw_api_key(monkeypatch, tmp_path):
    configure_state(monkeypatch, tmp_path, interval="0")
    gemini_rate_limit.wait_for_slot(FAKE_KEY, timeout=1.0)
    state_files = list(Path(tmp_path).glob("gemini-rate-*.json"))
    assert len(state_files) == 1
    assert FAKE_KEY not in state_files[0].name
    assert FAKE_KEY not in state_files[0].read_text(encoding="utf-8")
