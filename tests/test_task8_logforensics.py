"""
Unit tests for Task 8 — Log Forensics v2 & Multi-source Log Reader
"""

import os
import pytest
from engine.logsource import LogSourceReader, sanitize_log_text, parse_ip_address
from engine.logforensics import LogForensicsEngine

def test_log_sanitization_and_ip_parsing():
    long_line = "Failed password for invalid user " + "A" * 1000 + " from 10.0.0.5"
    sanitized = sanitize_log_text(long_line, max_len=100)
    assert len(sanitized) <= 100

    ip = parse_ip_address("Failed password for root from 192.168.1.100 port 22")
    assert ip == "192.168.1.100"

    invalid_ip = parse_ip_address("Invalid IP 999.999.999.999")
    assert invalid_ip is None

def test_file_log_reader_and_forensics_engine():
    sample_log = os.path.abspath(os.path.join(os.path.dirname(__file__), "data", "sample_auth.log"))
    file_reader = LogSourceReader()
    events = file_reader.read_file_logs(log_path=sample_log)

    assert len(events) >= 6
    assert any(e["ip"] == "192.168.1.50" for e in events)

    # Keep the detector test fixture-only; never invoke the host journal in CI.
    class FixtureReader(LogSourceReader):
        def read_journal_json(self, since="-7d", limit=3000):
            return []

        def read_file_logs(self, log_path="/var/log/auth.log", limit=3000):
            return events

    # Test Forensics Engine on sample
    reader = FixtureReader()
    engine = LogForensicsEngine(reader=reader)
    findings = engine.analyze_all_logs(window_minutes=1000000)

    assert len(findings) >= 1
    rule_ids = [f["rule_id"] for f in findings]
    assert "LOG-SSH-BRUTE" in rule_ids or "SSH-ROOT-001" in rule_ids
