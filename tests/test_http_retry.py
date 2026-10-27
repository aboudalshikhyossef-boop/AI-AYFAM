"""
Tests for http_client retry mechanisms, backoff, and timeouts.
"""

from unittest.mock import patch, MagicMock
import pytest
from utils import http_client


def test_http_client_get_retry_success():
    mock_fail = MagicMock()
    mock_fail.status_code = 502

    mock_ok = MagicMock()
    mock_ok.status_code = 200

    with patch("requests.get", side_effect=[mock_fail, mock_ok]) as mock_get:
        resp = http_client.get("https://example.com/test", retries=2)
        assert resp.status_code == 200
        assert mock_get.call_count == 2


def test_http_client_user_agent_header():
    mock_ok = MagicMock()
    mock_ok.status_code = 200

    with patch("requests.get", return_value=mock_ok) as mock_get:
        http_client.get("https://example.com/test")
        args, kwargs = mock_get.call_args
        headers = kwargs.get("headers", {})
        assert "User-Agent" in headers
        assert "AI-AYFAM" in headers["User-Agent"]
