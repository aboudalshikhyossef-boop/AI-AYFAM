"""Offline-safe OpenAI and Gemini adapters with model validation and diagnostics.

Network access is only performed by explicit provider methods. Importing this module
never performs a request. All diagnostics are bilingual and deliberately omit
provider-supplied error strings and credentials.
"""
from __future__ import annotations

import hashlib
import os
import random
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from utils import http_client
from engine.gemini_rate_limit import DEFAULT_GEMINI_MODEL, compact_text, gemini_model_name, wait_for_slot
from brain.context_engine import ContextEngine

OPENAI_DEFAULT_MODEL = "gpt-4o-mini"
OPENAI_MODELS_URL = "https://api.openai.com/v1/models"
GEMINI_MODELS_URL = "https://generativelanguage.googleapis.com/v1beta/models"
OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
MODEL_CACHE_TTL = 60.0
MAX_RETRY_ATTEMPTS = 3
MAX_BACKOFF_SECONDS = 3.0
OPENAI_MAX_OUTPUT_TOKENS = 256
GEMINI_MAX_OUTPUT_TOKENS = 256
CIRCUIT_FAILURE_THRESHOLD = 3
CIRCUIT_COOLDOWN_SECONDS = 60.0

_MESSAGES = {
    "missing_key": (
        "API key is not configured. Add it in settings or the environment.",
        "مفتاح API غير مُعدّ. أضفه في الإعدادات أو متغيرات البيئة.",
        "Set the provider key locally; never paste it into logs or reports.",
        "أضف المفتاح محلياً، ولا تضعه في السجلات أو التقارير.",
        False,
    ),
    "invalid_key": (
        "The API key was rejected (401). Check the key and revoke/replace it if exposed.",
        "رُفض مفتاح API (401). تحقّق من المفتاح وألغِه واستبدله إن كان مكشوفاً.",
        "Create or select a valid key for this provider.",
        "أنشئ مفتاحاً صالحاً لهذا المزوّد أو اختر مفتاحاً صحيحاً.",
        False,
    ),
    "forbidden": (
        "The provider denied access (403). The account or project may lack permission.",
        "رفض المزوّد الوصول (403). قد لا يملك الحساب أو المشروع الصلاحية المطلوبة.",
        "Check project access, account permissions, and API enablement.",
        "تحقّق من صلاحيات المشروع والحساب وتفعيل واجهة API.",
        False,
    ),
    "restricted_key": (
        "The API key is restricted for this endpoint or client (403).",
        "مفتاح API مقيّد لهذا المسار أو العميل (403).",
        "Review key restrictions, allowed APIs, referrers, and IP rules.",
        "راجع قيود المفتاح والواجهات المسموحة وقواعد النطاقات وعناوين IP.",
        False,
    ),
    "model_not_found": (
        "The selected model is not available to this key (404 or absent from the model list).",
        "النموذج المحدد غير متاح لهذا المفتاح (404 أو غير موجود في قائمة النماذج).",
        "Choose an available model explicitly. The saved selection is not changed automatically.",
        "اختر نموذجاً متاحاً يدوياً. لن يتغير اختيارك المحفوظ تلقائياً.",
        False,
    ),
    "rate_limited": (
        "The provider rate limit was reached (429). This is temporary and may be retried.",
        "تم بلوغ حدّ معدل الطلبات (429). الحالة مؤقتة ويمكن إعادة المحاولة.",
        "Wait for the retry window or reduce request frequency.",
        "انتظر انتهاء مهلة إعادة المحاولة أو خفّض وتيرة الطلبات.",
        True,
    ),
    "quota_exhausted": (
        "The provider quota or billing allowance is exhausted. Automatic retry is disabled.",
        "انتهت الحصة أو صلاحية الفوترة لدى المزوّد. أُوقفت إعادة المحاولة التلقائية.",
        "Review API billing, project quota, and account limits.",
        "راجع فوترة API وحصة المشروع وحدود الحساب.",
        False,
    ),
    "server_error": (
        "The provider returned a server error (5xx). A bounded retry may succeed.",
        "أعاد المزوّد خطأ خادم (5xx). قد تنجح إعادة المحاولة المحدودة.",
        "Retry later; check the provider status page if it continues.",
        "أعد المحاولة لاحقاً، وراجع حالة خدمة المزوّد إذا استمر الخلل.",
        True,
    ),
    "timeout": (
        "The provider request timed out.",
        "انتهت مهلة طلب المزوّد.",
        "Check connectivity and retry with a reasonable timeout.",
        "تحقّق من الاتصال وأعد المحاولة بمهلة مناسبة.",
        True,
    ),
    "network/dns": (
        "A network or DNS error prevented the provider request.",
        "منع خطأ في الشبكة أو DNS وصول الطلب إلى المزوّد.",
        "Check internet access, DNS, proxy, and firewall settings.",
        "تحقّق من الإنترنت وDNS والوكيل وإعدادات الجدار الناري.",
        True,
    ),
    "invalid_response": (
        "The provider returned an invalid or structurally incomplete response.",
        "أعاد المزوّد استجابة غير صالحة أو ناقصة البنية.",
        "Retry later; verify endpoint and model compatibility if it persists.",
        "أعد المحاولة لاحقاً، وتحقّق من توافق المسار والنموذج إن استمر الخلل.",
        True,
    ),
    "circuit_open": (
        "This provider is temporarily paused after repeated failures.",
        "أُوقف هذا المزوّد مؤقتاً بعد تكرار الإخفاقات.",
        "Wait for the cooldown period or explicitly test the provider again.",
        "انتظر انتهاء التهدئة أو اختبر المزوّد يدوياً.",
        False,
    ),
}


@dataclass(frozen=True)
class AssistantDiagnostic:
    category: str
    transient: bool
    message_en: str
    message_ar: str
    action_en: str
    action_ar: str
    status_code: int | None = None
    latency_ms: float | None = None

    def render(self) -> str:
        status = f" (HTTP {self.status_code})" if self.status_code else ""
        return (
            f"[{self.category}]{status} {self.message_en}\n"
            f"{self.message_ar}\n"
            f"Action: {self.action_en}\nالإجراء: {self.action_ar}"
        )


class AssistantError(RuntimeError):
    """Typed, secret-safe provider failure."""

    def __init__(self, diagnostic: AssistantDiagnostic, provider: str = ""):
        self.diagnostic = diagnostic
        self.category = diagnostic.category
        self.transient = diagnostic.transient
        self.provider = provider
        super().__init__(diagnostic.render())


def _diagnostic(category: str, status_code: int | None = None, latency_ms: float | None = None) -> AssistantDiagnostic:
    en, ar, action_en, action_ar, transient = _MESSAGES.get(
        category, _MESSAGES["invalid_response"]
    )
    return AssistantDiagnostic(
        category, transient, en, ar, action_en, action_ar, status_code, latency_ms
    )


class AssistantProvider(Protocol):
    name: str
    model: str

    def ask(self, prompt: str, *, system_context: str = "", on_wait: Callable[[float], None] | None = None) -> str:
        ...


@dataclass(frozen=True)
class AssistantConfig:
    provider: str = "auto"
    openai_api_key: str = ""
    openai_model: str = OPENAI_DEFAULT_MODEL
    gemini_api_key: str = ""
    gemini_model: str = DEFAULT_GEMINI_MODEL
    timeout: float = 30.0


@dataclass(frozen=True)
class ModelCatalog:
    provider: str
    models: tuple[str, ...]
    output_limits: Mapping[str, int] = field(default_factory=dict)


_MODEL_CACHE: dict[tuple[str, str], tuple[float, ModelCatalog]] = {}
_MODEL_CACHE_LOCK = threading.Lock()
_CIRCUITS: dict[str, tuple[int, float]] = {}
_CIRCUIT_LOCK = threading.Lock()


def _text(value: Any) -> str:
    return str(value or "").strip()


def resolve_secret(configured: str, *environment_names: str, environ: Mapping[str, str] | None = None) -> str:
    """Prefer environment secrets over values saved in local settings."""
    env = os.environ if environ is None else environ
    for name in environment_names:
        value = _text(env.get(name))
        if value:
            return value
    return _text(configured)


def _effective_setting(configured: str, environment_name: str, default: str = "") -> str:
    return _text(os.environ.get(environment_name)) or _text(configured) or default


def _provider_key(provider: str, api_key: str) -> tuple[str, str]:
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    return provider, digest


def clear_model_cache() -> None:
    """Clear model metadata cache; intended for tests and explicit refresh."""
    with _MODEL_CACHE_LOCK:
        _MODEL_CACHE.clear()


def _response_payload(response: Any) -> Mapping[str, Any] | None:
    try:
        value = response.json()
    except (AttributeError, TypeError, ValueError):
        return None
    return value if isinstance(value, Mapping) else None


def _error_fields(payload: Mapping[str, Any] | None) -> tuple[str, str, str]:
    if not payload:
        return "", "", ""
    error = payload.get("error", payload)
    if not isinstance(error, Mapping):
        return "", "", ""
    code = _text(error.get("code")).lower()
    kind = _text(error.get("type") or error.get("status")).lower()
    message = _text(error.get("message")).lower()
    details = error.get("details", [])
    if isinstance(details, list):
        message += " " + " ".join(
            _text(item.get("quotaId") or item.get("description"))
            for item in details if isinstance(item, Mapping)
        ).lower()
    return code, kind, message


def classify_http_error(provider: str, response: Any, *, latency_ms: float | None = None) -> AssistantDiagnostic:
    status = int(getattr(response, "status_code", 0) or 0)
    code, kind, message = _error_fields(_response_payload(response))
    combined = " ".join((code, kind, message))
    if status == 401:
        category = "invalid_key"
    elif status == 403:
        category = "restricted_key" if any(
            token in combined for token in ("restrict", "api key not valid", "ip address", "referrer", "api_key_service_blocked")
        ) else "forbidden"
    elif status == 404:
        category = "model_not_found"
    elif status == 429:
        exhausted = any(token in combined for token in (
            "insufficient_quota", "billing_hard_limit", "quota_exhausted",
            "exceeded your current quota", "billing limit", "perday", "daily quota",
            "projectspend", "spendper", "monthly quota",
        ))
        category = "quota_exhausted" if exhausted else "rate_limited"
    elif status in (408, 504):
        category = "timeout"
    elif status in (425,) or status == 429:
        category = "rate_limited"
    elif status >= 500:
        category = "server_error"
    else:
        category = "invalid_response"
    return _diagnostic(category, status, latency_ms)


def classify_exception(exc: BaseException, *, latency_ms: float | None = None) -> AssistantDiagnostic:
    if isinstance(exc, (TimeoutError, socket.timeout)):
        category = "timeout"
    elif isinstance(exc, socket.gaierror):
        category = "network/dns"
    elif isinstance(exc, (ConnectionError, OSError)):
        category = "network/dns"
    else:
        # Wrappers may convert timeouts/DNS failures to RuntimeError. Inspect
        # known markers only; never echo provider exception text.
        marker = str(exc).lower()
        if any(token in marker for token in ("timed out", "timeout", "deadline exceeded")):
            category = "timeout"
        elif any(token in marker for token in ("name resolution", "temporary failure in name", "getaddrinfo", "dns")):
            category = "network/dns"
        else:
            category = "network/dns"
    return _diagnostic(category, latency_ms=latency_ms)


def _retry_after(response: Any) -> float:
    try:
        return max(0.0, min(float(response.headers.get("Retry-After", 0)), MAX_BACKOFF_SECONDS))
    except (AttributeError, TypeError, ValueError):
        return 0.0


def _request_with_retry(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str],
    timeout: float,
    provider: str,
    params: Mapping[str, Any] | None = None,
    payload: Mapping[str, Any] | None = None,
) -> Any:
    """Bound all attempts and sleeps by one total timeout budget."""
    started = time.monotonic()
    budget = max(0.1, float(timeout))
    deadline = started + budget
    last_diagnostic = _diagnostic("network/dns")
    for attempt in range(MAX_RETRY_ATTEMPTS):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssistantError(_diagnostic("timeout"), provider)
        request_timeout = max(0.1, min(remaining, budget))
        response = None
        try:
            if method == "get":
                response = http_client.get(
                    url, headers=dict(headers), params=dict(params or {}),
                    timeout=request_timeout,
                )
            else:
                response = http_client.post(
                    url, headers=dict(headers), json_data=dict(payload or {}),
                    timeout=request_timeout,
                )
            status = int(getattr(response, "status_code", 0) or 0)
            if 200 <= status < 300:
                return response
            last_diagnostic = classify_http_error(provider, response)
        except AssistantError:
            raise
        except Exception as exc:
            last_diagnostic = classify_exception(exc)
        if not last_diagnostic.transient or attempt + 1 >= MAX_RETRY_ATTEMPTS:
            raise AssistantError(last_diagnostic, provider)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssistantError(_diagnostic("timeout"), provider)
        retry_after = _retry_after(response) if "response" in locals() and last_diagnostic.category == "rate_limited" else 0.0
        exponential = min(MAX_BACKOFF_SECONDS, 0.25 * (2 ** attempt))
        delay = max(retry_after, exponential) + random.uniform(0.0, 0.15)
        if delay >= remaining:
            raise AssistantError(_diagnostic("timeout"), provider)
        time.sleep(delay)
    raise AssistantError(last_diagnostic, provider)


def _normalize_model(provider: str, model: str) -> str:
    chosen = _text(model)
    if not chosen:
        return DEFAULT_GEMINI_MODEL if provider == "gemini" else OPENAI_DEFAULT_MODEL
    if provider == "gemini":
        return chosen.removeprefix("models/")
    return chosen


def list_available_models(
    provider: str,
    api_key: str,
    *,
    timeout: float = 15.0,
    force: bool = False,
) -> ModelCatalog:
    """List models usable by the configured key; model-list calls do not generate tokens."""
    provider = _text(provider).lower()
    key = _text(api_key)
    if provider not in ("openai", "gemini"):
        raise ValueError("provider must be openai or gemini")
    if not key:
        raise AssistantError(_diagnostic("missing_key"), provider)
    cache_key = _provider_key(provider, key)
    now = time.monotonic()
    with _MODEL_CACHE_LOCK:
        cached = _MODEL_CACHE.get(cache_key)
        if cached and not force and now - cached[0] < MODEL_CACHE_TTL:
            return cached[1]

    if provider == "openai":
        response = _request_with_retry(
            "get", OPENAI_MODELS_URL,
            headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
            timeout=timeout, provider=provider,
        )
        body = _response_payload(response)
        data = body.get("data") if body else None
        if not isinstance(data, list):
            raise AssistantError(_diagnostic("invalid_response"), provider)
        models = tuple(sorted({
            _text(item.get("id")) for item in data
            if isinstance(item, Mapping) and _text(item.get("id"))
        }))
        catalog = ModelCatalog(provider, models)
    else:
        headers = {"x-goog-api-key": key, "Accept": "application/json"}
        models_set: set[str] = set()
        output_limits: dict[str, int] = {}
        page_token = ""
        for _ in range(10):
            params: dict[str, Any] = {"pageSize": 1000}
            if page_token:
                params["pageToken"] = page_token
            response = _request_with_retry(
                "get", GEMINI_MODELS_URL, headers=headers, params=params,
                timeout=timeout, provider=provider,
            )
            body = _response_payload(response)
            rows = body.get("models") if body else None
            if not isinstance(rows, list):
                raise AssistantError(_diagnostic("invalid_response"), provider)
            for item in rows:
                if not isinstance(item, Mapping):
                    continue
                methods = item.get("supportedGenerationMethods", [])
                if isinstance(methods, list) and "generateContent" not in methods:
                    continue
                name = _text(item.get("name")).removeprefix("models/")
                if name:
                    models_set.add(name)
                    try:
                        limit = int(item.get("outputTokenLimit") or 0)
                    except (TypeError, ValueError):
                        limit = 0
                    if limit > 0:
                        output_limits[name] = limit
            page_token = _text(body.get("nextPageToken")) if body else ""
            if not page_token:
                break
        catalog = ModelCatalog(provider, tuple(sorted(models_set)), output_limits)

    if not catalog.models:
        raise AssistantError(_diagnostic("invalid_response"), provider)
    with _MODEL_CACHE_LOCK:
        _MODEL_CACHE[cache_key] = (time.monotonic(), catalog)
    return catalog


def validate_model_access(
    provider: str,
    api_key: str,
    model: str,
    *,
    timeout: float = 15.0,
    force: bool = False,
) -> dict[str, Any]:
    """Validate the key and explicit model selection without a generation request."""
    selected = _normalize_model(provider, model)
    started = time.monotonic()
    catalog = list_available_models(provider, api_key, timeout=timeout, force=force)
    elapsed = (time.monotonic() - started) * 1000
    exists = selected in catalog.models
    suggestion = ""
    if not exists:
        preferred = DEFAULT_GEMINI_MODEL if provider == "gemini" else OPENAI_DEFAULT_MODEL
        suggestion = preferred if preferred in catalog.models else catalog.models[0]
        diagnostic = _diagnostic("model_not_found", 404, elapsed)
        raise AssistantError(
            AssistantDiagnostic(
                diagnostic.category, diagnostic.transient,
                diagnostic.message_en + f" Selected: {selected}. Suggested: {suggestion}.",
                diagnostic.message_ar + f" المحدد: {selected}. البديل المقترح: {suggestion}.",
                diagnostic.action_en, diagnostic.action_ar, 404, elapsed,
            ),
            provider,
        )
    return {
        "provider": provider, "model": selected, "exists": True,
        "models_count": len(catalog.models), "suggestion": suggestion,
        "output_limit": catalog.output_limits.get(selected, 0),
        "latency_ms": round(elapsed, 1), "category": "ok",
    }


def _privacy_safe_inputs(prompt: str, system_context: str) -> tuple[str, str]:
    return (
        compact_text(ContextEngine.sanitize_privacy_data(prompt), 3600),
        compact_text(ContextEngine.sanitize_privacy_data(system_context), 600),
    )


def _extract_openai_text(payload: Any) -> str:
    if not isinstance(payload, Mapping):
        raise ValueError("response root is not an object")
    direct = _text(payload.get("output_text"))
    if direct:
        return direct
    output = payload.get("output")
    if not isinstance(output, list):
        raise ValueError("response output is missing")
    texts: list[str] = []
    for item in output:
        if not isinstance(item, Mapping) or item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if isinstance(part, Mapping) and part.get("type") == "output_text":
                value = _text(part.get("text"))
                if value:
                    texts.append(value)
    if not texts:
        raise ValueError("response contains no output_text message")
    return "\n".join(texts)


def _extract_gemini_text(payload: Any) -> str:
    if not isinstance(payload, Mapping):
        raise ValueError("response root is not an object")
    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or not candidates or not isinstance(candidates[0], Mapping):
        raise ValueError("candidate is missing")
    content = candidates[0].get("content")
    if not isinstance(content, Mapping):
        raise ValueError("candidate content is missing")
    parts = content.get("parts")
    if not isinstance(parts, list):
        raise ValueError("candidate parts are missing")
    texts = [
        _text(part.get("text")) for part in parts
        if isinstance(part, Mapping) and _text(part.get("text"))
    ]
    if not texts:
        raise ValueError("candidate contains no text part")
    return "\n".join(texts)


def _record_provider_success(name: str) -> None:
    with _CIRCUIT_LOCK:
        _CIRCUITS.pop(name, None)


def _record_provider_failure(name: str) -> None:
    with _CIRCUIT_LOCK:
        failures, opened_until = _CIRCUITS.get(name, (0, 0.0))
        failures += 1
        if failures >= CIRCUIT_FAILURE_THRESHOLD:
            opened_until = time.monotonic() + CIRCUIT_COOLDOWN_SECONDS
            failures = 0
        _CIRCUITS[name] = (failures, opened_until)


def provider_circuit_remaining(name: str) -> float:
    with _CIRCUIT_LOCK:
        failures, opened_until = _CIRCUITS.get(name, (0, 0.0))
        remaining = max(0.0, opened_until - time.monotonic())
        if not remaining and opened_until:
            _CIRCUITS.pop(name, None)
        return remaining


def clear_provider_circuits() -> None:
    with _CIRCUIT_LOCK:
        _CIRCUITS.clear()


def fallback_allowed(error: AssistantError) -> bool:
    """Permanent key, access, quota, and selected-model errors do not cascade."""
    return error.category not in {
        "invalid_key", "forbidden", "restricted_key", "model_not_found",
        "quota_exhausted", "missing_key", "circuit_open",
    }


def _circuit_diagnostic(name: str, remaining: float) -> AssistantError:
    base = _diagnostic("circuit_open")
    ar = base.message_ar + f" المدة المتبقية: {remaining:.0f} ثانية."
    en = base.message_en + f" Cooldown remaining: {remaining:.0f}s."
    return AssistantError(
        AssistantDiagnostic(base.category, False, en, ar, base.action_en, base.action_ar),
        name,
    )


class OpenAIAssistant:
    name = "openai"

    def __init__(self, api_key: str, model: str = OPENAI_DEFAULT_MODEL, timeout: float = 30.0):
        self.api_key = _text(api_key)
        self.model = _normalize_model("openai", model)
        self.timeout = float(timeout)
        if not self.api_key:
            raise AssistantError(_diagnostic("missing_key"), self.name)

    def validate(self, *, force: bool = False) -> dict[str, Any]:
        return validate_model_access(self.name, self.api_key, self.model, timeout=self.timeout, force=force)

    def ask(self, prompt: str, *, system_context: str = "", on_wait: Callable[[float], None] | None = None) -> str:
        try:
            answer = self._ask(prompt, system_context=system_context)
        except AssistantError:
            _record_provider_failure(self.name)
            raise
        except Exception as exc:
            _record_provider_failure(self.name)
            raise AssistantError(classify_exception(exc), self.name) from exc
        _record_provider_success(self.name)
        return answer

    def _ask(self, prompt: str, *, system_context: str = "") -> str:
        if not _text(prompt):
            raise AssistantError(_diagnostic("invalid_response"), self.name)
        self.validate()
        prompt, context = _privacy_safe_inputs(prompt, system_context)
        instruction = (
            "You are AI AYFAM, a cybersecurity assistant for Linux Mint and Ubuntu. "
            "Give safe, concise, actionable advice. Never claim a command was executed. "
            "Distinguish observed facts from hypotheses. Answer in the user's language."
            + (f"\nContext: {context}" if context else "")
        )
        input_items = [
            {"role": "system", "content": [{"type": "input_text", "text": instruction}]},
            {"role": "user", "content": [{"type": "input_text", "text": prompt}]},
        ]
        catalog = list_available_models(self.name, self.api_key, timeout=self.timeout)
        max_tokens = catalog.output_limits.get(self.model, OPENAI_MAX_OUTPUT_TOKENS)
        max_tokens = min(OPENAI_MAX_OUTPUT_TOKENS, max_tokens) if max_tokens > 0 else OPENAI_MAX_OUTPUT_TOKENS
        response = _request_with_retry(
            "post", OPENAI_RESPONSES_URL,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            payload={
                "model": self.model,
                "input": input_items,
                "max_output_tokens": max_tokens,
                "store": False,
            },
            timeout=self.timeout, provider=self.name,
        )
        body = _response_payload(response)
        try:
            answer = _extract_openai_text(body)
        except (TypeError, ValueError):
            raise AssistantError(_diagnostic("invalid_response"), self.name)
        if not answer:
            raise AssistantError(_diagnostic("invalid_response"), self.name)
        return answer


class GeminiAssistant:
    name = "gemini"

    def __init__(self, api_key: str, model: str = DEFAULT_GEMINI_MODEL, timeout: float = 30.0):
        self.api_key = _text(api_key)
        self.model = _normalize_model("gemini", model)
        self.timeout = float(timeout)
        if not self.api_key:
            raise AssistantError(_diagnostic("missing_key"), self.name)

    def validate(self, *, force: bool = False) -> dict[str, Any]:
        return validate_model_access(self.name, self.api_key, self.model, timeout=self.timeout, force=force)

    def ask(self, prompt: str, *, system_context: str = "", on_wait: Callable[[float], None] | None = None) -> str:
        try:
            answer = self._ask(prompt, system_context=system_context, on_wait=on_wait)
        except AssistantError:
            _record_provider_failure(self.name)
            raise
        except Exception as exc:
            _record_provider_failure(self.name)
            raise AssistantError(classify_exception(exc), self.name) from exc
        _record_provider_success(self.name)
        return answer

    def _ask(self, prompt: str, *, system_context: str = "", on_wait: Callable[[float], None] | None = None) -> str:
        if not _text(prompt):
            raise AssistantError(_diagnostic("invalid_response"), self.name)
        started = time.monotonic()
        check = validate_model_access(
            self.name, self.api_key, self.model,
            timeout=self.timeout, force=False,
        )
        prompt, context = _privacy_safe_inputs(prompt, system_context)
        instruction = (
            "You are AI AYFAM, a cybersecurity assistant for Linux Mint and Ubuntu. "
            "Give safe, concise, actionable advice. Never claim a command was executed. "
            "Distinguish observed facts from hypotheses. Answer in the user's language."
        )
        if context:
            instruction += f"\nContext: {context}"
        limit = check.get("output_limit") or GEMINI_MAX_OUTPUT_TOKENS
        limit = min(GEMINI_MAX_OUTPUT_TOKENS, int(limit))
        try:
            remaining_before_wait = self.timeout - (time.monotonic() - started)
            if remaining_before_wait <= 0:
                raise TimeoutError("Model validation exceeded request timeout")
            wait_for_slot(
                self.api_key,
                timeout=remaining_before_wait,
                on_wait=on_wait,
            )
        except TimeoutError:
            raise AssistantError(_diagnostic("timeout"), self.name)
        remaining_timeout = self.timeout - (time.monotonic() - started)
        if remaining_timeout <= 0:
            raise AssistantError(_diagnostic("timeout"), self.name)
        response = _request_with_retry(
            "post",
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
            headers={"x-goog-api-key": self.api_key, "Content-Type": "application/json"},
            payload={
                "systemInstruction": {"parts": [{"text": instruction}]},
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                # Temperature is intentionally omitted: model families do not
                # uniformly accept sampling controls.
                "generationConfig": {"maxOutputTokens": limit},
            },
            timeout=remaining_timeout, provider=self.name,
        )
        try:
            answer = _extract_gemini_text(_response_payload(response))
        except (TypeError, ValueError):
            raise AssistantError(_diagnostic("invalid_response"), self.name)
        return answer


def build_providers(config: AssistantConfig) -> tuple[list[AssistantProvider], dict[str, float]]:
    """Build auto-mode providers in order, excluding providers in cooldown."""
    selected = _effective_setting(config.provider, "AI_PROVIDER", "auto").lower()
    openai_key = resolve_secret(config.openai_api_key, "OPENAI_API_KEY")
    gemini_key = resolve_secret(config.gemini_api_key, "GOOGLE_API_KEY", "GEMINI_API_KEY")
    openai_model = _effective_setting(config.openai_model, "OPENAI_MODEL", OPENAI_DEFAULT_MODEL)
    gemini_model = _effective_setting(config.gemini_model, "GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    if selected not in ("auto", "local", "openai", "gemini", ""):
        raise AssistantError(_diagnostic("invalid_response"), selected)
    requested = ("openai", "gemini") if selected in ("auto", "") else (selected,)
    providers: list[AssistantProvider] = []
    paused: dict[str, float] = {}
    for name in requested:
        key = openai_key if name == "openai" else gemini_key
        if not key:
            continue
        remaining = provider_circuit_remaining(name)
        if remaining > 0:
            paused[name] = remaining
            continue
        if name == "openai":
            providers.append(OpenAIAssistant(key, openai_model, config.timeout))
        elif name == "gemini":
            providers.append(GeminiAssistant(key, gemini_model, config.timeout))
    if selected in ("openai", "gemini") and not providers:
        name = selected
        key = openai_key if name == "openai" else gemini_key
        if not key:
            raise AssistantError(_diagnostic("missing_key"), name)
        remaining = provider_circuit_remaining(name)
        if remaining > 0:
            raise _circuit_diagnostic(name, remaining)
    return providers, paused


def build_provider(config: AssistantConfig) -> AssistantProvider | None:
    """Compatibility helper returning the first configured provider."""
    providers, paused = build_providers(config)
    if providers:
        return providers[0]
    if paused:
        name, remaining = next(iter(paused.items()))
        raise _circuit_diagnostic(name, remaining)
    return None


def check_ai_providers(
    settings: Any,
    *,
    environ: Mapping[str, str] | None = None,
    timeout: float = 8.0,
) -> list[dict[str, Any]]:
    """Read-only CLI diagnostics. Never returns or prints the API key itself."""
    env = os.environ if environ is None else environ
    rows: list[dict[str, Any]] = []
    for name, setting_key, model_key, default, env_names in (
        ("openai", "openai_api_key", "openai_model", OPENAI_DEFAULT_MODEL, ("OPENAI_API_KEY",)),
        ("gemini", "gemini_api_key", "gemini_model", DEFAULT_GEMINI_MODEL, ("GOOGLE_API_KEY", "GEMINI_API_KEY")),
    ):
        configured = settings.get(setting_key, "") if hasattr(settings, "get") else ""
        environment_key = next((_text(env.get(item)) for item in env_names if _text(env.get(item))), "")
        key = environment_key or _text(configured)
        source = "environment" if environment_key else ("settings" if key else "missing")
        model = _normalize_model(name, _text(env.get("OPENAI_MODEL" if name == "openai" else "GEMINI_MODEL")) or (
            settings.get(model_key, default) if hasattr(settings, "get") else default
        ))
        started = time.monotonic()
        row: dict[str, Any] = {
            "provider": name, "key_source": source, "model": model,
            "model_available": False, "category": "missing_key" if not key else "unknown",
            "latency_ms": 0.0, "message": "",
        }
        if not key:
            row["message"] = _diagnostic("missing_key").render()
        else:
            try:
                result = validate_model_access(name, key, model, timeout=timeout, force=True)
                row.update({"model_available": True, "category": "ok", "latency_ms": result["latency_ms"]})
                row["message"] = "Model is listed and available for this key. النموذج متاح في قائمة هذا المفتاح."
            except AssistantError as exc:
                row["category"] = exc.category
                row["message"] = str(exc)
                row["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
        rows.append(row)
    return rows
