from types import SimpleNamespace
from unittest.mock import patch

import pytest

from engine.ai_assistant import AssistantError
from ui.gui_app import QMessageBox, UnifiedCockpitWindow


class Field:
    def __init__(self, value):
        self.value = value

    def text(self):
        return self.value


class Settings:
    def __init__(self):
        self.values = {}

    def get(self, key, default=""):
        return self.values.get(key, default)

    def set(self, key, value):
        self.values[key] = value


class Log:
    def __init__(self):
        self.value = ""

    def setPlainText(self, value):
        self.value = value


def make_window(provider):
    window = SimpleNamespace(
        settings=Settings(),
        settings_log=Log(),
        setting_gemini_key=Field("fake-gemini-key"),
        setting_gemini_model=Field("gemini-2.5-flash"),
        setting_openai_key=Field("fake-openai-key"),
        setting_openai_model=Field("gpt-4o-mini"),
    )
    tasks = []

    def run_background_task(fn, title, preserve_findings=False, result_handler=None):
        tasks.append(title)
        try:
            result = fn()
        except Exception as exc:
            result = exc
        if result_handler:
            result_handler(result)

    window.run_background_task = run_background_task
    window.tr = lambda text: text
    return window, tasks


@pytest.mark.parametrize("provider", ["openai", "gemini"])
def test_provider_setting_failure_does_not_persist_key_or_model(provider, monkeypatch):
    for key in ("OPENAI_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    window, tasks = make_window(provider)
    failure = AssistantError(
        __import__("engine.ai_assistant", fromlist=["_diagnostic"])._diagnostic("invalid_key"),
        provider,
    )
    with patch("engine.ai_assistant.validate_model_access", side_effect=failure):
        UnifiedCockpitWindow._test_ai_provider_settings(window, provider)

    assert len(tasks) == 1
    assert window.settings.values == {}
    assert "invalid_key" in window.settings_log.value
    assert "fake-" not in window.settings_log.value


@pytest.mark.parametrize(
    ("provider", "expected_key", "expected_model"),
    [
        ("openai", "openai_api_key", "openai_model"),
        ("gemini", "gemini_api_key", "gemini_model"),
    ],
)
def test_provider_settings_persist_only_after_successful_model_list(
    provider, expected_key, expected_model, monkeypatch
):
    for key in ("OPENAI_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    window, tasks = make_window(provider)
    result = {
        "category": "ok",
        "exists": True,
        "models_count": 3,
        "latency_ms": 12.5,
    }
    with patch("engine.ai_assistant.validate_model_access", return_value=result), patch(
        "ui.gui_app.QMessageBox.question",
        return_value=QMessageBox.StandardButton.No,
    ):
        UnifiedCockpitWindow._test_ai_provider_settings(window, provider)

    assert len(tasks) == 1
    assert window.settings.values[expected_key] == (
        "fake-openai-key" if provider == "openai" else "fake-gemini-key"
    )
    assert window.settings.values[expected_model] == (
        "gpt-4o-mini" if provider == "openai" else "gemini-2.5-flash"
    )
    assert "12.5 ms" in window.settings_log.value
    assert "fake-" not in window.settings_log.value
