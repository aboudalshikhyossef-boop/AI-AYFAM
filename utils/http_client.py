"""
AI AYFAM — Unified HTTP Client with Standard Library Fallback
يوفر دوال get/post/put متوافقة مع requests حتى في غياب مكتبة requests.
"""

from __future__ import annotations

import json
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
        return json.loads(self.text)


def get(url: str, headers: dict | None = None, params: dict | None = None, timeout: float = 15.0, stream: bool = False, **kwargs: Any) -> Any:
    """تنفيذ طلب GET مع دعم requests أو urllib التلقائي."""
    if REQUESTS_AVAILABLE:
        return requests.get(url, headers=headers, params=params, timeout=timeout, stream=stream, **kwargs)

    # Fallback to urllib.request
    if params:
        query_string = urllib.parse.urlencode(params)
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{query_string}"

    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read()
            resp_headers = dict(resp.headers.items())
            return ResponseWrapper(resp.status, content, resp_headers, url)
    except urllib.error.HTTPError as exc:
        content = exc.read()
        return ResponseWrapper(exc.code, content, dict(exc.headers.items()), url)
    except Exception as exc:
        raise RuntimeError(f"HTTP GET Error ({url}): {exc}") from exc


def post(url: str, headers: dict | None = None, json_data: Any = None, data: Any = None, timeout: float = 15.0, json: Any = None, **kwargs: Any) -> Any:
    """تنفيذ طلب POST مع دعم requests أو urllib التلقائي."""
    target_json = json_data if json_data is not None else json
    if REQUESTS_AVAILABLE:
        return requests.post(url, headers=headers, json=target_json, data=data, timeout=timeout, **kwargs)

    hdrs = dict(headers or {})
    payload: bytes = b""
    if target_json is not None:
        payload = __import__("json").dumps(target_json).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    elif isinstance(data, (dict, list)):
        payload = urllib.parse.urlencode(data).encode("utf-8")
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif isinstance(data, str):
        payload = data.encode("utf-8")
    elif isinstance(data, bytes):
        payload = data

    req = urllib.request.Request(url, data=payload, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read()
            return ResponseWrapper(resp.status, content, dict(resp.headers.items()), url)
    except urllib.error.HTTPError as exc:
        content = exc.read()
        return ResponseWrapper(exc.code, content, dict(exc.headers.items()), url)
    except Exception as exc:
        raise RuntimeError(f"HTTP POST Error ({url}): {exc}") from exc


def put(url: str, headers: dict | None = None, json_data: Any = None, timeout: float = 15.0, json: Any = None, data: Any = None, **kwargs: Any) -> Any:
    """تنفيذ طلب PUT مع دعم requests أو urllib التلقائي."""
    target_json = json_data if json_data is not None else json
    if REQUESTS_AVAILABLE:
        return requests.put(url, headers=headers, json=target_json, data=data, timeout=timeout, **kwargs)

    hdrs = dict(headers or {})
    payload = json.dumps(target_json).encode("utf-8") if target_json is not None else (data or b"")
    if target_json is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=payload, headers=hdrs, method="PUT")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read()
            return ResponseWrapper(resp.status, content, dict(resp.headers.items()), url)
    except urllib.error.HTTPError as exc:
        content = exc.read()
        return ResponseWrapper(exc.code, content, dict(exc.headers.items()), url)
    except Exception as exc:
        raise RuntimeError(f"HTTP PUT Error ({url}): {exc}") from exc
