"""
AI AYFAM — Unified HTTP Client with Standard Library Fallback
يوفر دوال get/post/put متوافقة مع requests حتى في غياب مكتبة requests.
"""

from __future__ import annotations

import json as _json
import urllib.request
import urllib.error
import urllib.parse
from typing import Any, Mapping

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
    REQUESTS_AVAILABLE = False


def _validate_http_url(url: str) -> str:
    """Reject non-web schemes and credential-bearing URLs before urllib access."""
    parsed = urllib.parse.urlsplit(str(url))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only absolute HTTP(S) URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing embedded credentials are not allowed")
    return str(url)


class ResponseWrapper:
    """محاكي لكائن requests.Response باستخدام urllib القياسي."""
    def __init__(self, status_code: int, content: bytes | None = None, headers: Mapping[str, str] | None = None, url: str = "", raw_response: Any = None):
        self.status_code = status_code
        self._content = content
        self._raw_response = raw_response
        self.headers = headers or {}
        self.url = url
        self.ok = 200 <= status_code < 400
        self._closed = False

    @property
    def content(self) -> bytes:
        if self._content is None:
            self._content = b"".join(self.iter_content())
        return self._content

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return _json.loads(self.text)

    def iter_content(self, chunk_size: int = 65536):
        """Read urllib response chunks lazily rather than buffering the whole body."""
        size = max(1, int(chunk_size))
        if self._raw_response is None:
            data = self._content or b""
            for offset in range(0, len(data), size):
                yield data[offset:offset + size]
            return
        try:
            while True:
                chunk = self._raw_response.read(size)
                if not chunk:
                    break
                yield chunk
        finally:
            self.close()

    def close(self) -> None:
        if not self._closed and self._raw_response is not None:
            self._closed = True
            self._raw_response.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()


def _urllib_timeout(timeout: Any) -> float:
    """urllib accepts one float; requests may receive (connect, read)."""
    if isinstance(timeout, (tuple, list)):
        values = [float(value) for value in timeout if value is not None]
        return max(values) if values else 15.0
    try:
        return float(timeout)
    except (TypeError, ValueError):
        return 15.0


def get(url: str, headers: dict | None = None, params: dict | None = None, timeout: float = 15.0, stream: bool = False, **kwargs: Any) -> Any:
    """تنفيذ طلب GET مع دعم requests أو urllib التلقائي."""
    url = _validate_http_url(url)
    if REQUESTS_AVAILABLE:
        return requests.get(url, headers=headers, params=params, timeout=timeout, stream=stream, **kwargs)
    if params:
        query_string = urllib.parse.urlencode(params)
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{query_string}"
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        resp = urllib.request.urlopen(req, timeout=_urllib_timeout(timeout))  # nosec B310 - validated HTTP(S) URL
        if stream:
            return ResponseWrapper(resp.status, None, dict(resp.headers.items()), url, raw_response=resp)
        try:
            return ResponseWrapper(resp.status, resp.read(), dict(resp.headers.items()), url)
        finally:
            resp.close()
    except urllib.error.HTTPError as exc:
        if stream:
            return ResponseWrapper(exc.code, None, dict(exc.headers.items()), url, raw_response=exc)
        return ResponseWrapper(exc.code, exc.read(), dict(exc.headers.items()), url)
    except Exception as exc:
        raise RuntimeError(f"HTTP GET Error ({url}): {exc}") from exc


def _request_body(target_json: Any, data: Any, headers: dict | None) -> tuple[bytes, dict]:
    hdrs = dict(headers or {})
    if target_json is not None:
        hdrs["Content-Type"] = "application/json"
        return _json.dumps(target_json).encode("utf-8"), hdrs
    if isinstance(data, (dict, list)):
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        return urllib.parse.urlencode(data).encode("utf-8"), hdrs
    if isinstance(data, str):
        return data.encode("utf-8"), hdrs
    if isinstance(data, bytes):
        return data, hdrs
    return b"", hdrs


def post(url: str, headers: dict | None = None, json_data: Any = None, data: Any = None, timeout: float = 15.0, json: Any = None, **kwargs: Any) -> Any:
    """تنفيذ طلب POST مع دعم requests أو urllib التلقائي."""
    target_json = json_data if json_data is not None else json
    url = _validate_http_url(url)
    if REQUESTS_AVAILABLE:
        return requests.post(url, headers=headers, json=target_json, data=data, timeout=timeout, **kwargs)
    payload, hdrs = _request_body(target_json, data, headers)
    req = urllib.request.Request(url, data=payload, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_urllib_timeout(timeout)) as resp:  # nosec B310 - URL validated as HTTP(S) above
            return ResponseWrapper(resp.status, resp.read(), dict(resp.headers.items()), url)
    except urllib.error.HTTPError as exc:
        return ResponseWrapper(exc.code, exc.read(), dict(exc.headers.items()), url)
    except Exception as exc:
        raise RuntimeError(f"HTTP POST Error ({url}): {exc}") from exc


def put(url: str, headers: dict | None = None, json_data: Any = None, timeout: float = 15.0, json: Any = None, data: Any = None, **kwargs: Any) -> Any:
    """تنفيذ طلب PUT مع دعم requests أو urllib التلقائي."""
    target_json = json_data if json_data is not None else json
    url = _validate_http_url(url)
    if REQUESTS_AVAILABLE:
        return requests.put(url, headers=headers, json=target_json, data=data, timeout=timeout, **kwargs)
    payload, hdrs = _request_body(target_json, data, headers)
    req = urllib.request.Request(url, data=payload, headers=hdrs, method="PUT")
    try:
        with urllib.request.urlopen(req, timeout=_urllib_timeout(timeout)) as resp:
            return ResponseWrapper(resp.status, resp.read(), dict(resp.headers.items()), url)
    except urllib.error.HTTPError as exc:
        return ResponseWrapper(exc.code, exc.read(), dict(exc.headers.items()), url)
    except Exception as exc:
        raise RuntimeError(f"HTTP PUT Error ({url}): {exc}") from exc
