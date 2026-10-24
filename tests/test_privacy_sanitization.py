"""
Unit tests for Privacy Sanitize Data Layer in ContextEngine and Gemini integration
"""

import pytest
from brain.context_engine import ContextEngine
from engine.ai_assistant import GeminiAssistant
from unittest.mock import patch, MagicMock

def test_context_engine_privacy_sanitization():
    raw_text = "Host my-mint-pc has user user_jules running script in /home/user_jules/test.py"
    sanitized = ContextEngine.sanitize_privacy_data(
        raw_text,
        hostname="my-mint-pc",
        username="user_jules"
    )

    assert "my-mint-pc" not in sanitized
    assert "user_jules" not in sanitized
    assert "[HOST]" in sanitized
    assert "[USER]" in sanitized
    assert "/home/[USER]/test.py" in sanitized

def test_gemini_assistant_scrubs_prompt_before_sending():
    assistant = GeminiAssistant(api_key="fake-key")

    mock_post = MagicMock()
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {
        "candidates": [
            {"content": {"parts": [{"text": "Filtered response"}]}}
        ]
    }

    with patch("utils.http_client.post", mock_post), \
         patch("engine.ai_assistant.wait_for_slot"):

        with patch("socket.gethostname", return_value="linux-mint-dev"), \
             patch("os.getuid", return_value=1000), \
             patch("pwd.getpwuid", return_value=MagicMock(pw_name="developer")):
            res = assistant.ask(
                prompt="Analyze system linux-mint-dev for user developer",
                system_context="Context for developer on linux-mint-dev"
            )

        assert res == "Filtered response"
        call_args = mock_post.call_args[1]["json_data"]

        sys_inst = call_args["systemInstruction"]["parts"][0]["text"]
        user_prompt = call_args["contents"][0]["parts"][0]["text"]

        assert "linux-mint-dev" not in sys_inst
        assert "developer" not in sys_inst
        assert "linux-mint-dev" not in user_prompt
        assert "developer" not in user_prompt
