from engine.secretscan import SecretScanner
from engine.sysreader import FakeSystem, SystemReader
from tools.network import _classify_connection, _is_local_ip


def test_ip_classification_uses_ipaddress_for_ipv4_and_ipv6():
    assert _is_local_ip("10.20.30.40")
    assert _is_local_ip("172.31.4.2")
    assert _is_local_ip("192.168.1.2")
    assert _is_local_ip("fd12::1")
    assert _is_local_ip("fe80::1")
    assert _is_local_ip("::ffff:192.168.1.2")
    assert not _is_local_ip("172.32.0.1")
    assert not _is_local_ip("8.8.8.8")


def test_known_process_on_unusual_port_is_not_automatically_trusted():
    result = _classify_connection("tcp", "10.0.0.2:50000", "8.8.8.8:45678",
                                  "ESTAB", 'users:(("python3",pid=123))')
    assert result["trust"] == "unknown"
    assert result["risk"] == "medium"


def test_wildcard_remote_is_not_reported_as_trusted_service():
    result = _classify_connection("tcp", "0.0.0.0:8081", "*:*", "LISTEN", "")
    assert result["trust"] == "unknown"


def test_limited_reader_rejects_oversized_and_binary_files(tmp_path):
    reader = SystemReader()
    oversized = tmp_path / "large.txt"
    oversized.write_bytes(b"x" * 32)
    binary = tmp_path / "binary.txt"
    binary.write_bytes(b"hello\\x00world")
    small = tmp_path / "small.txt"
    small.write_text("safe", encoding="utf-8")
    assert reader.read_text_limited(str(oversized), 16) is None
    assert reader.read_text_limited(str(binary), 32) is None
    assert reader.read_text_limited(str(small), 16) == "safe"


def test_secret_scanner_skips_oversized_fake_file():
    reader = FakeSystem({"/tmp/large.env": "TOKEN=" + "A" * (SecretScanner.MAX_FILE_BYTES + 1)})
    assert SecretScanner(reader).scan_path("/tmp/large.env") == []


def test_secret_scanner_still_detects_and_masks_small_secret():
    reader = FakeSystem({"/tmp/small.env": "password='" + "A" * 24 + "'"})
    findings = SecretScanner(reader).scan_path("/tmp/small.env")
    assert len(findings) == 1
    assert "AAAA...AAAA" in findings[0].detail
    assert "A" * 24 not in findings[0].detail
