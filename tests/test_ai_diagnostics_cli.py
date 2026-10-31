import sys
from unittest.mock import patch

import main
from engine.ai_assistant import check_ai_providers


class FakeSettings:
    def __init__(self, values):
        self.values = values

    def get(self, key, default=""):
        return self.values.get(key, default)


class Response:
    status_code = 200
    headers = {}

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


def test_check_ai_providers_reports_model_key_source_and_latency_without_secret():
    fake_secret = "sk-FAKE-DIAGNOSTIC-SECRET-0123456789"
    settings = FakeSettings({
        "openai_api_key": "saved-openai-key",
        "openai_model": "gpt-6-luna",
        "gemini_api_key": "saved-gemini-key",
        "gemini_model": "gemini-3.8-flash",
    })
    with patch.dict("os.environ", {}, clear=True), patch(
        "engine.ai_assistant.http_client.get",
        side_effect=[
            Response({"data": [{"id": "gpt-6-luna"}]}),
            Response({"models": [{
                "name": "models/gemini-3.8-flash",
                "supportedGenerationMethods": ["generateContent"],
                "outputTokenLimit": 2048,
            }]}),
        ],
    ) as get:
        rows = check_ai_providers(settings, timeout=1.0)

    assert [row["provider"] for row in rows] == ["openai", "gemini"]
    assert all(row["category"] == "ok" for row in rows)
    assert all(row["model_available"] for row in rows)
    assert all(row["key_source"] == "settings" for row in rows)
    assert all(row["latency_ms"] >= 0 for row in rows)
    assert get.call_count == 2
    assert fake_secret not in repr(rows)


def test_cli_accepts_check_ai_switch(monkeypatch):
    assert main.parse_args(["--check-ai"]).check_ai is True
    monkeypatch.setattr(sys, "argv", ["ayfam", "--check-ai"])
    monkeypatch.setattr(main, "run_ai_diagnostics", lambda: 7)
    assert main.main() == 7


def test_cli_diagnostic_table_does_not_print_api_key(monkeypatch, capsys):
    fake_secret = "sk-FAKE-DIAGNOSTIC-SECRET-0123456789"
    rows = [
        {
            "provider": "openai",
            "key_source": "environment",
            "model": "gpt-6-luna",
            "model_available": True,
            "category": "ok",
            "latency_ms": 12.3,
            "message": "ok",
        },
        {
            "provider": "gemini",
            "key_source": "missing",
            "model": "gemini-3.8-flash",
            "model_available": False,
            "category": "missing_key",
            "latency_ms": 0.0,
            "message": "missing",
        },
    ]
    monkeypatch.setattr("config.settings.Settings", lambda: FakeSettings({}))
    monkeypatch.setattr("engine.ai_assistant.check_ai_providers", lambda *_a, **_k: rows)
    assert main.run_ai_diagnostics() == 0
    output = capsys.readouterr().out
    assert "openai" in output and "gemini" in output
    assert "environment" in output
    assert fake_secret not in output
