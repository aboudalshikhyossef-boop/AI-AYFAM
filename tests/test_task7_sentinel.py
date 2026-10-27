"""
Unit tests for Task 7 — Persistent Event Store and Real-time Sentinel Monitor
"""

import os
import tempfile
import time
from unittest.mock import MagicMock, patch
import pytest
from engine.events import EventStore, EventSource
from engine.sentinel import SentinelEngine, InotifyEventSource


def test_event_store_persistence_and_tamper_evident_chain():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "events.db")
        store = EventStore(db_path=db_path)

        id1 = store.record_event("inotify", "file_modified", "/etc/passwd", "Modified by user", "critical")
        id2 = store.record_event("proc_diff", "proc_spawned", "/tmp/malicious", "Spawned binary", "high")

        assert id1 == 1
        assert id2 == 2

        # Verify integrity of sequence
        assert store.verify_chain_integrity() is True

        # Tamper with row in DB
        import sqlite3
        with sqlite3.connect(db_path) as conn:
            conn.execute("UPDATE events SET details='Tampered details' WHERE id=1")
            conn.commit()

        # Integrity verification must detect tampering
        assert store.verify_chain_integrity() is False


def test_sentinel_inotify_event_monitoring_mocked():
    source = InotifyEventSource(watch_paths=["/etc/passwd"])
    mock_inotify = MagicMock()
    mock_event = MagicMock()
    mock_event.wd = 1
    mock_event.mask = 2  # MODIFY
    mock_inotify.read.return_value = [mock_event]

    mock_inotify_module = MagicMock()
    mock_inotify_module.INotify.return_value = mock_inotify
    mock_inotify_module.flags.CREATE = 1
    mock_inotify_module.flags.DELETE = 4
    mock_inotify_module.flags.MODIFY = 2

    with patch.dict("sys.modules", {"inotify_simple": mock_inotify_module}), \
         patch("engine.sentinel.INOTIFY_AVAILABLE", True), \
         patch("engine.sentinel.inotify_simple", mock_inotify_module, create=True):
        source.start()
        source.wd_map[1] = "/etc/passwd"
        events = list(source.yield_events())
        source.stop()

        assert len(events) == 1
        assert events[0]["source"] == "inotify"
        assert events[0]["subject"] == "/etc/passwd"
        assert events[0]["event_type"] == "file_modified"
        assert events[0]["severity"] == "critical"


class DummyEventSource(EventSource):
    def __init__(self, events=None):
        self.events = events or []
        self.started = False

    def start(self):
        self.started = True

    def stop(self):
        self.started = False

    def yield_events(self):
        if not self.started:
            return
        while self.events:
            yield self.events.pop(0)


def test_sentinel_engine_idempotent_start():
    engine = SentinelEngine()
    engine.inotify_source = DummyEventSource()

    with patch.object(engine, "_notify"):
        engine.start()
        t1 = engine.thread
        assert t1 is not None
        assert t1.is_alive()

        # Second start call should not spawn a new thread
        engine.start()
        assert engine.thread is t1

        engine.stop()
        assert engine.thread is None


def test_sentinel_engine_stop_and_cleanup():
    engine = SentinelEngine()
    engine.inotify_source = DummyEventSource()

    with patch.object(engine, "_notify"):
        engine.start()
        t = engine.thread
        assert t is not None
        assert t.is_alive()

        engine.stop()
        assert engine.running is False
        assert engine.thread is None
        assert not t.is_alive()


def test_sentinel_engine_restart():
    engine = SentinelEngine()
    engine.inotify_source = DummyEventSource()

    with patch.object(engine, "_notify"):
        engine.start()
        t1 = engine.thread
        assert t1 is not None and t1.is_alive()

        engine.stop()
        assert engine.thread is None

        # Restarting should spawn a new active thread
        engine.start()
        t2 = engine.thread
        assert t2 is not None and t2.is_alive()
        assert t2 != t1

        engine.stop()
        assert engine.thread is None


def test_sentinel_engine_event_processing():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "events.db")
        store = EventStore(db_path=db_path)
        engine = SentinelEngine(store=store)

        sample_event = {
            "source": "inotify",
            "event_type": "file_modified",
            "subject": "/etc/passwd",
            "details": "File event modified on /etc/passwd",
            "severity": "critical",
        }
        mock_source = DummyEventSource([sample_event])
        engine.inotify_source = mock_source

        with patch.object(engine, "_notify") as mock_notify:
            engine.start()
            time.sleep(0.3)
            engine.stop()

            mock_notify.assert_called_with("file_modified", "/etc/passwd")

        events = store.query_recent_events(limit=10)
        assert len(events) == 1
        assert events[0]["source"] == "inotify"
        assert events[0]["event_type"] == "file_modified"
        assert events[0]["subject"] == "/etc/passwd"
        assert events[0]["severity"] == "critical"
