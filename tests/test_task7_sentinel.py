"""
Unit tests for Task 7 — Persistent Event Store and Real-time Sentinel Monitor
"""

import os
import tempfile
import time
import pytest
from engine.events import EventStore
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

def test_sentinel_inotify_event_monitoring():
    with tempfile.TemporaryDirectory() as tmpdir:
        watch_file = os.path.join(tmpdir, "monitored.txt")
        with open(watch_file, "w") as f:
            f.write("initial")

        source = InotifyEventSource(watch_paths=[watch_file])
        source.start()

        # Modify file
        with open(watch_file, "a") as f:
            f.write("modified")

        time.sleep(0.1)
        events = list(source.yield_events())
        source.stop()

        assert len(events) >= 1
        assert events[0]["source"] == "inotify"
        assert events[0]["subject"] == watch_file
