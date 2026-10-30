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


class ResponseWrapper:
    """محاكي لكائن requests.Response باستخدام urllib القياسي."""
    def __init__(self, status_code: int, content: bytes, headers: Mapping[str, str] | None = None, url: str = ""):
        self.status_code = status_code
        self.content = content
        self.text = content.decode("utf-8", errors="replace")
        self.headers = headers or {}
        self.url = url
        self.ok = 200 <= status_code < 400

    def json(self) -> Any:
        return _json.loads(self.text)


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
    if REQUESTS_AVAILABLE:
        return requests.get(url, headers=headers, params=params, timeout=timeout, stream=stream, **kwargs)
    if params:
        query_string = urllib.parse.urlencode(params)
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{query_string}"
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_urllib_timeout(timeout)) as resp:
            return ResponseWrapper(resp.status, resp.read(), dict(resp.headers.items()), url)
    except urllib.error.HTTPError as exc:
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
    if REQUESTS_AVAILABLE:
        return requests.post(url, headers=headers, json=target_json, data=data, timeout=timeout, **kwargs)
    payload, hdrs = _request_body(target_json, data, headers)
    req = urllib.request.Request(url, data=payload, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_urllib_timeout(timeout)) as resp:
            return ResponseWrapper(resp.status, resp.read(), dict(resp.headers.items()), url)
    except urllib.error.HTTPError as exc:
        return ResponseWrapper(exc.code, exc.read(), dict(exc.headers.items()), url)
    except Exception as exc:
        raise RuntimeError(f"HTTP POST Error ({url}): {exc}") from exc


def put(url: str, headers: dict | None = None, json_data: Any = None, timeout: float = 15.0, json: Any = None, data: Any = None, **kwargs: Any) -> Any:
    """تنفيذ طلب PUT مع دعم requests أو urllib التلقائي."""
    target_json = json_data if json_data is not None else json
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
