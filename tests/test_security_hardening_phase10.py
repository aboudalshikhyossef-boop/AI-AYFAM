"""Tests for Phase 10 Step 3 refactoring and security hardening."""

import os
from unittest.mock import patch, MagicMock
from utils.validators import validate_device_path
from tools.web import is_safe_public_url, fetch_page_content


def test_validate_device_path_block_device_and_non_device():
    # Invalid path without /dev/
    ok, err = validate_device_path("/tmp/not_a_device")
    assert not ok

    # Valid string format but points to regular file (mock stat to avoid /dev permission errors)
    with patch("os.path.exists", return_value=True), \
         patch("os.stat") as mock_stat:
        mock_stat.return_value.st_mode = 0o100644  # Regular file mode S_IFREG
        ok, err = validate_device_path("/dev/fake_disk")
        assert not ok
        assert "ليس جهاز كتلة" in err


def test_fetch_page_content_ssrf_protection():
    # Local loopback blocked
    res = fetch_page_content("http://127.0.0.1/admin")
    assert not res["success"]
    assert "SSRF Protection" in res["error"]

    # Private network blocked
    res = fetch_page_content("http://192.168.1.1/router")
    assert not res["success"]

    # File scheme blocked
    res = fetch_page_content("file:///etc/passwd")
    assert not res["success"]
