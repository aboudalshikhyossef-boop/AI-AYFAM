"""
Tests for utils.http_client fallback urllib functionality and ResponseWrapper behavior.
"""

import unittest
from unittest.mock import MagicMock, patch
import json

from utils import http_client
from utils.http_client import ResponseWrapper


class TestHTTPClient(unittest.TestCase):

    def setUp(self):
        self.url = "http://example.com/api"

    @patch("utils.http_client.REQUESTS_AVAILABLE", False)
    @patch("urllib.request.urlopen")
    def test_put_fallback_with_json_data(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"status": "updated", "msg": "مرحبا"}).encode("utf-8")
        mock_resp.headers.items.return_value = [("Content-Type", "application/json")]
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        payload = {"name": "اختبار", "active": True}
        resp = http_client.put(self.url, json_data=payload)

        self.assertIsInstance(resp, ResponseWrapper)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.ok)
        self.assertEqual(resp.json(), {"status": "updated", "msg": "مرحبا"})

        # Verify request parameters
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_method(), "PUT")
        self.assertEqual(req.headers.get("Content-type"), "application/json")
        self.assertEqual(req.data, json.dumps(payload).encode("utf-8"))

    @patch("utils.http_client.REQUESTS_AVAILABLE", False)
    @patch("urllib.request.urlopen")
    def test_put_fallback_with_json_keyword(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.read.return_value = b'{"success": true}'
        mock_resp.headers.items.return_value = []
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        payload = {"key": "value_قيم"}
        resp = http_client.put(self.url, json=payload)

        self.assertEqual(resp.status_code, 201)
        self.assertTrue(resp.ok)
        self.assertEqual(resp.json(), {"success": True})

        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_method(), "PUT")
        self.assertEqual(req.headers.get("Content-type"), "application/json")
        self.assertEqual(req.data, json.dumps(payload).encode("utf-8"))

    @patch("utils.http_client.REQUESTS_AVAILABLE", False)
    @patch("urllib.request.urlopen")
    def test_put_fallback_with_raw_bytes_data(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"OK"
        mock_resp.headers.items.return_value = []
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        raw_data = b"raw binary content"
        resp = http_client.put(self.url, data=raw_data)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, "OK")

        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.data, raw_data)

    @patch("utils.http_client.REQUESTS_AVAILABLE", False)
    @patch("urllib.request.urlopen")
    def test_put_fallback_with_dict_data(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"OK"
        mock_resp.headers.items.return_value = []
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        data = {"field": "val"}
        resp = http_client.put(self.url, data=data)

        self.assertEqual(resp.status_code, 200)
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.headers.get("Content-type"), "application/x-www-form-urlencoded")
        self.assertEqual(req.data, b"field=val")

    @patch("utils.http_client.REQUESTS_AVAILABLE", False)
    @patch("urllib.request.urlopen")
    def test_put_fallback_with_str_data(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"OK"
        mock_resp.headers.items.return_value = []
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        str_data = "plain string payload"
        resp = http_client.put(self.url, data=str_data)

        self.assertEqual(resp.status_code, 200)
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.data, b"plain string payload")

    @patch("utils.http_client.REQUESTS_AVAILABLE", False)
    @patch("urllib.request.urlopen")
    def test_put_fallback_http_error(self, mock_urlopen):
        import urllib.error
        from io import BytesIO

        error_headers = {"Content-Type": "application/json"}
        error_body = json.dumps({"error": "not found"}).encode("utf-8")
        http_error = urllib.error.HTTPError(
            self.url, 404, "Not Found", error_headers, BytesIO(error_body)
        )
        mock_urlopen.side_effect = http_error

        resp = http_client.put(self.url, json={"id": 123})

        self.assertEqual(resp.status_code, 404)
        self.assertFalse(resp.ok)
        self.assertEqual(resp.json(), {"error": "not found"})

    @patch("utils.http_client.REQUESTS_AVAILABLE", False)
    @patch("urllib.request.urlopen")
    def test_get_fallback_response_supports_iter_content(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"abcdef"
        mock_resp.headers.items.return_value = []
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        response = http_client.get(self.url, stream=True)
        self.assertEqual(list(response.iter_content(chunk_size=2)), [b"ab", b"cd", b"ef"])

    @patch("utils.http_client.REQUESTS_AVAILABLE", True)
    @patch("utils.http_client.requests")
    def test_put_when_requests_available(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_requests.put.return_value = mock_resp

        payload = {"a": 1}
        resp = http_client.put(self.url, json=payload)

        mock_requests.put.assert_called_once_with(self.url, headers=None, json=payload, data=None, timeout=15.0)
        self.assertEqual(resp, mock_resp)


if __name__ == "__main__":
    unittest.main()
