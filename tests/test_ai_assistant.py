import json
import pytest
from unittest.mock import patch

from engine.ai_assistant import (
    AssistantConfig,
    AssistantError,
    GeminiAssistant,
    OpenAIAssistant,
    build_provider,
    resolve_secret,
)


class Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def test_environment_secret_wins_over_saved_value():
    assert resolve_secret("saved", "OPENAI_API_KEY", environ={"OPENAI_API_KEY": "env"}) == "env"


def test_auto_provider_prefers_openai():
    provider = build_provider(AssistantConfig(openai_api_key="openai", gemini_api_key="gemini"))
    assert isinstance(provider, OpenAIAssistant)


def test_explicit_gemini_provider_wins_when_both_keys_are_configured():
    provider = build_provider(AssistantConfig(
        provider="gemini",
        openai_api_key="openai",
        gemini_api_key="gemini",
    ))
    assert isinstance(provider, GeminiAssistant)


def test_openai_response_is_parsed_without_logging_key():
    response = Response(200, {"choices": [{"message": {"content": "Secure answer"}}]})
    with patch("engine.ai_assistant.http_client.post", return_value=response) as post:
        answer = OpenAIAssistant("secret", "gpt-test").ask("How do I harden SSH?")
    assert answer == "Secure answer"
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer secret"
    assert "secret" not in json.dumps(post.call_args.kwargs["json_data"])
    assert post.call_args.kwargs["json_data"]["model"] == "gpt-test"


def test_environment_selects_provider_and_model(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-env")
    provider = build_provider(AssistantConfig(openai_api_key="saved", openai_model="gpt-saved"))
    assert isinstance(provider, OpenAIAssistant)
    assert provider.model == "gpt-env"


def test_openai_scrubs_private_context_before_transmission():
    response = Response(200, {"choices": [{"message": {"content": "safe"}}]})
    with patch("engine.ai_assistant.http_client.post", return_value=response) as post, \
         patch("socket.gethostname", return_value="linux-mint-dev"), \
         patch("os.getuid", return_value=1000), \
         patch("pwd.getpwuid") as getpwuid:
        getpwuid.return_value.pw_name = "developer"
        assert OpenAIAssistant("secret").ask(
            "Analyze linux-mint-dev for user developer",
            system_context="Context for developer on linux-mint-dev",
        ) == "safe"
    sent = post.call_args.kwargs["json_data"]
    assert "linux-mint-dev" not in str(sent)
    assert "developer" not in str(sent)


def test_transient_openai_failure_is_retried():
    response = Response(200, {"choices": [{"message": {"content": "recovered"}}]})
    with patch("engine.ai_assistant.http_client.post", side_effect=[RuntimeError("temporary"), response]) as post, \
         patch("engine.ai_assistant.time.sleep"):
        assert OpenAIAssistant("secret").ask("hello") == "recovered"
    assert post.call_count == 2


def test_gemini_response_is_parsed():
    response = Response(200, {"candidates": [{"content": {"parts": [{"text": "Gemini answer"}]}}]})
    with patch("engine.ai_assistant.http_client.post", return_value=response) as post, \
         patch("engine.ai_assistant.wait_for_slot"):
        assert GeminiAssistant("secret").ask("Explain UFW") == "Gemini answer"
    assert post.call_args.args[0] == (
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent"
    )
    assert post.call_args.kwargs["headers"]["x-goog-api-key"] == "secret"
    generation_config = post.call_args.kwargs["json_data"]["generationConfig"]
    assert generation_config["maxOutputTokens"] == 2048


def test_gemini_transport_error_is_reported_without_leaking_the_key():
    with patch(
        "engine.ai_assistant.http_client.post",
        side_effect=RuntimeError("request failed using secret-key"),
    ), patch("engine.ai_assistant.wait_for_slot"):
        with pytest.raises(AssistantError, match="Gemini connection failed") as caught:
            GeminiAssistant("secret-key").ask("Explain UFW")
    assert "secret-key" not in str(caught.value)


def test_gemini_combines_all_response_parts():
    response = Response(200, {"candidates": [{"content": {"parts": [
        {"text": "First part."}, {"text": "Second part."}
    ]}}]})
    with patch("engine.ai_assistant.http_client.post", return_value=response), \
         patch("engine.ai_assistant.wait_for_slot"):
        assert GeminiAssistant("secret").ask("Explain UFW") == "First part.\nSecond part."


def test_provider_error_is_actionable():
    response = Response(401, {"error": {"message": "invalid key"}})
    with patch("engine.ai_assistant.http_client.post", return_value=response):
        try:
            OpenAIAssistant("secret").ask("hello")
        except AssistantError as exc:
            assert "invalid key" in str(exc)
        else:
            raise AssertionError("expected AssistantError")
