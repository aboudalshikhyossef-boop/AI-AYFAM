import json
import socket
from unittest.mock import patch

import pytest

from engine.ai_assistant import (
    AssistantConfig,
    AssistantError,
    GeminiAssistant,
    OpenAIAssistant,
    build_provider,
    build_providers,
    clear_model_cache,
    clear_provider_circuits,
    classify_http_error,
    fallback_allowed,
    list_available_models,
    provider_circuit_remaining,
    resolve_secret,
    validate_model_access,
)


FAKE_KEY = "sk-FAKE-KEY-ONLY-0123456789"


class Response:
    def __init__(self, status_code=200, payload=None, headers=None, broken_json=False):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.text = json.dumps(payload) if payload is not None else ""
        self.broken_json = broken_json

    def json(self):
        if self.broken_json:
            raise ValueError("fake malformed JSON")
        return self._payload


def openai_catalog(*models):
    return Response(200, {"data": [{"id": item} for item in models]})


def gemini_catalog(*models):
    return Response(200, {"models": [
        {
            "name": f"models/{name}",
            "supportedGenerationMethods": ["generateContent"],
            "outputTokenLimit": 4096,
        }
        for name in models
    ]})


def openai_output(answer="Secure answer"):
    return Response(200, {
        "status": "completed",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": answer}],
        }],
    })


def gemini_output(answer="Gemini answer"):
    return Response(200, {
        "candidates": [{
            "content": {"parts": [{"text": answer}]},
            "finishReason": "STOP",
        }],
    })


@pytest.fixture(autouse=True)
def reset_provider_state():
    clear_model_cache()
    clear_provider_circuits()
    yield
    clear_model_cache()
    clear_provider_circuits()


def test_environment_secret_wins_over_saved_value():
    assert resolve_secret("saved", "OPENAI_API_KEY", environ={"OPENAI_API_KEY": "env"}) == "env"


def test_auto_provider_prefers_openai_and_preserves_order(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    providers, paused = build_providers(AssistantConfig(
        openai_api_key="openai-test",
        gemini_api_key="gemini-test",
    ))
    assert [provider.name for provider in providers] == ["openai", "gemini"]
    assert paused == {}
    assert isinstance(build_provider(AssistantConfig(openai_api_key="openai-test")), OpenAIAssistant)


def test_explicit_gemini_model_is_never_rewritten():
    provider = GeminiAssistant("gemini-fake", "gemini-2.5-flash")
    assert provider.model == "gemini-2.5-flash"


def test_model_list_cache_and_explicit_model_validation():
    with patch("engine.ai_assistant.http_client.get", return_value=openai_catalog("gpt-4o-mini")) as get:
        first = list_available_models("openai", FAKE_KEY)
        second = list_available_models("openai", FAKE_KEY)
        assert first == second
        assert get.call_count == 1
        assert validate_model_access("openai", FAKE_KEY, "gpt-4o-mini")["exists"] is True


def test_unavailable_model_reports_suggestion_without_replacing_choice():
    with patch("engine.ai_assistant.http_client.get", return_value=gemini_catalog("gemini-3.8-flash")):
        with pytest.raises(AssistantError) as caught:
            validate_model_access("gemini", "gemini-fake", "gemini-user-selected")
    assert caught.value.category == "model_not_found"
    assert "gemini-user-selected" in str(caught.value)
    assert "gemini-3.8-flash" in str(caught.value)
    assert GeminiAssistant("gemini-fake", "gemini-user-selected").model == "gemini-user-selected"


def test_openai_uses_responses_api_output_limit_and_validates_structure():
    with patch("engine.ai_assistant.http_client.get", return_value=openai_catalog("gpt-4o-mini")), \
         patch("engine.ai_assistant.http_client.post", return_value=openai_output()) as post:
        answer = OpenAIAssistant(FAKE_KEY, "gpt-4o-mini").ask("How do I harden SSH?")
    assert answer == "Secure answer"
    assert post.call_args.args[0] == "https://api.openai.com/v1/responses"
    payload = post.call_args.kwargs["json_data"]
    assert payload["model"] == "gpt-4o-mini"
    assert payload["max_output_tokens"] == 256
    assert payload["store"] is False
    assert "temperature" not in payload
    assert FAKE_KEY not in json.dumps(payload)


def test_openai_rejects_invalid_response_shape():
    with patch("engine.ai_assistant.http_client.get", return_value=openai_catalog("gpt-4o-mini")), \
         patch("engine.ai_assistant.http_client.post", return_value=Response(200, {"output": []})):
        with pytest.raises(AssistantError) as caught:
            OpenAIAssistant(FAKE_KEY).ask("hello")
    assert caught.value.category == "invalid_response"
    assert FAKE_KEY not in str(caught.value)


def test_openai_scrubs_private_context_before_transmission():
    response = openai_output("safe")
    with patch("engine.ai_assistant.http_client.get", return_value=openai_catalog("gpt-4o-mini")), \
         patch("engine.ai_assistant.http_client.post", return_value=response) as post, \
         patch("socket.gethostname", return_value="linux-mint-private"), \
         patch("os.getuid", return_value=1000), \
         patch("pwd.getpwuid") as getpwuid:
        getpwuid.return_value.pw_name = "private-user"
        assert OpenAIAssistant(FAKE_KEY).ask(
            "Analyze linux-mint-private for private-user",
            system_context="Host linux-mint-private; user private-user",
        ) == "safe"
    sent = json.dumps(post.call_args.kwargs["json_data"])
    assert "linux-mint-private" not in sent
    assert "private-user" not in sent
    assert FAKE_KEY not in sent


def test_gemini_response_is_parsed_and_uses_bounded_generation():
    with patch("engine.ai_assistant.http_client.get", return_value=gemini_catalog("gemini-3.8-flash")), \
         patch("engine.ai_assistant.http_client.post", return_value=gemini_output()) as post, \
         patch("engine.ai_assistant.wait_for_slot", return_value=0.0):
        answer = GeminiAssistant("gemini-fake").ask("Explain UFW")
    assert answer == "Gemini answer"
    assert post.call_args.args[0].endswith("/models/gemini-3.8-flash:generateContent")
    assert post.call_args.kwargs["headers"]["x-goog-api-key"] == "gemini-fake"
    payload = post.call_args.kwargs["json_data"]
    assert payload["generationConfig"]["maxOutputTokens"] == 256
    assert "temperature" not in payload["generationConfig"]


@pytest.mark.parametrize(
    ("status", "payload", "expected"),
    [
        (401, {"error": {"message": "invalid key"}}, "invalid_key"),
        (403, {"error": {"message": "permission denied"}}, "forbidden"),
        (403, {"error": {"message": "API key restriction blocks this endpoint"}}, "restricted_key"),
        (404, {"error": {"message": "model not found"}}, "model_not_found"),
        (429, {"error": {"code": "rate_limit_exceeded", "message": "slow down"}}, "rate_limited"),
        (429, {"error": {"code": "insufficient_quota", "message": "quota exceeded"}}, "quota_exhausted"),
        (429, {"error": {"status": "RESOURCE_EXHAUSTED", "details": [
            {"quotaId": "ProjectSpendPerTenMinutes"}
        ]}}, "quota_exhausted"),
        (503, {"error": {"message": "server error"}}, "server_error"),
        (408, {"error": {"message": "timeout"}}, "timeout"),
    ],
)
def test_http_categories_are_secret_safe(status, payload, expected):
    diagnostic = classify_http_error("openai", Response(status, payload))
    assert diagnostic.category == expected
    assert FAKE_KEY not in diagnostic.render()


def test_timeout_and_dns_categories_hide_exception_details():
    from engine.ai_assistant import classify_exception

    timeout = classify_exception(TimeoutError(f"timeout {FAKE_KEY}"))
    dns = classify_exception(socket.gaierror(f"DNS failed {FAKE_KEY}"))
    assert timeout.category == "timeout"
    assert dns.category == "network/dns"
    assert FAKE_KEY not in timeout.render()
    assert FAKE_KEY not in dns.render()


def test_malformed_models_json_is_invalid_response_and_secret_is_hidden():
    with patch("engine.ai_assistant.http_client.get", return_value=Response(200, broken_json=True)):
        with pytest.raises(AssistantError) as caught:
            list_available_models("openai", FAKE_KEY, force=True)
    assert caught.value.category == "invalid_response"
    assert FAKE_KEY not in str(caught.value)


def test_invalid_key_and_quota_errors_are_not_retried():
    for response, expected in (
        (Response(401, {"error": {"message": "bad key"}}), "invalid_key"),
        (Response(429, {"error": {"code": "insufficient_quota"}}), "quota_exhausted"),
    ):
        with patch("engine.ai_assistant.http_client.get", return_value=response) as get, \
             patch("engine.ai_assistant.time.sleep") as sleep:
            with pytest.raises(AssistantError) as caught:
                list_available_models("openai", FAKE_KEY, force=True)
        assert caught.value.category == expected
        assert get.call_count == 1
        sleep.assert_not_called()


@pytest.mark.parametrize("temporary", [
    Response(429, {"error": {"code": "rate_limit_exceeded"}}),
    Response(503, {"error": {"message": "temporarily unavailable"}}),
])
def test_temporary_http_errors_are_retried(temporary):
    success = openai_catalog("gpt-4o-mini")
    with patch("engine.ai_assistant.http_client.get", side_effect=[temporary, success]) as get, \
         patch("engine.ai_assistant.time.sleep"), \
         patch("engine.ai_assistant.random.uniform", return_value=0.0):
        result = list_available_models("openai", FAKE_KEY, force=True)
    assert "gpt-4o-mini" in result.models
    assert get.call_count == 2


def test_wrapped_timeout_retries_but_invalid_json_does_not_leak_key():
    with patch("engine.ai_assistant.http_client.get", side_effect=[
        RuntimeError("HTTP GET Error: timed out with " + FAKE_KEY),
        openai_catalog("gpt-4o-mini"),
    ]) as get, patch("engine.ai_assistant.time.sleep"), \
         patch("engine.ai_assistant.random.uniform", return_value=0.0):
        assert "gpt-4o-mini" in list_available_models("openai", FAKE_KEY, force=True).models
    assert get.call_count == 2


def test_circuit_breaker_opens_after_consecutive_failures_and_resets_on_success():
    from engine.ai_assistant import _record_provider_failure, _record_provider_success

    assert provider_circuit_remaining("openai") == 0
    for _ in range(3):
        _record_provider_failure("openai")
    assert provider_circuit_remaining("openai") > 0
    with pytest.raises(AssistantError) as caught:
        build_providers(AssistantConfig(provider="openai", openai_api_key=FAKE_KEY))
    assert caught.value.category == "circuit_open"
    _record_provider_success("openai")
    assert provider_circuit_remaining("openai") == 0


def test_only_nonpermanent_failures_allow_auto_fallback():
    for category in ("network/dns", "timeout", "rate_limited", "server_error", "invalid_response"):
        from engine.ai_assistant import _diagnostic
        assert fallback_allowed(AssistantError(_diagnostic(category)))
    for category in ("invalid_key", "forbidden", "restricted_key", "model_not_found", "quota_exhausted"):
        from engine.ai_assistant import _diagnostic
        assert not fallback_allowed(AssistantError(_diagnostic(category)))
