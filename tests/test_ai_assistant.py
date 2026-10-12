import json
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


def test_openai_response_is_parsed_without_logging_key():
    response = Response(200, {"choices": [{"message": {"content": "Secure answer"}}]})
    with patch("engine.ai_assistant.http_client.post", return_value=response) as post:
        answer = OpenAIAssistant("secret", "gpt-test").ask("How do I harden SSH?")
    assert answer == "Secure answer"
    assert post.call_args.kwargs["headers"]["Authorization"] == "Bearer secret"
    assert "secret" not in json.dumps(post.call_args.kwargs["json_data"])
    assert post.call_args.kwargs["json_data"]["model"] == "gpt-test"


def test_gemini_response_is_parsed():
    response = Response(200, {"candidates": [{"content": {"parts": [{"text": "Gemini answer"}]}}]})
    with patch("engine.ai_assistant.http_client.post", return_value=response):
        assert GeminiAssistant("secret").ask("Explain UFW") == "Gemini answer"


def test_provider_error_is_actionable():
    response = Response(401, {"error": {"message": "invalid key"}})
    with patch("engine.ai_assistant.http_client.post", return_value=response):
        try:
            OpenAIAssistant("secret").ask("hello")
        except AssistantError as exc:
            assert "invalid key" in str(exc)
        else:
            raise AssertionError("expected AssistantError")
