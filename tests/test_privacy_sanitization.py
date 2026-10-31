"""
Unit tests for Privacy Sanitize Data Layer in ContextEngine and Gemini integration
"""

import json
import os
import pwd
import socket

import pytest
from brain.context_engine import ContextEngine
from engine.ai_assistant import GeminiAssistant
from brain.knowledge_base import KnowledgeBase
from brain.learning_governance import LearningGovernance
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


def test_external_answer_and_context_are_scrubbed_before_storage(tmp_path, monkeypatch):
    hostname = "private-ayfam-host"
    username = "private-ayfam-user"
    openai_secret = "sk-FAKE-KEY-ONLY-0123456789"
    google_secret = "AIzaSyFAKEGoogleKeyFake0000000000000"
    bearer_secret = "Bearer fake-bearer-secret-123456789"

    monkeypatch.setattr(socket, "gethostname", lambda: hostname)
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr(pwd, "getpwuid", lambda _uid: type("User", (), {"pw_name": username})())

    kb = KnowledgeBase(tmp_path / "privacy.db")
    governance = LearningGovernance(kb)
    answer = (
        f"Host {hostname}, user {username}, path /home/{username}/.ssh/id_rsa. "
        f"Keys: {openai_secret}, {google_secret}, {bearer_secret}."
    )
    context = {
        "nested": [f"Host {hostname}; path /home/{username}/Documents/notes.txt"],
        "credentials": f"OPENAI_API_KEY={openai_secret}",
    }
    interaction_id = governance.record_external_answer(
        provider="openai",
        model="gpt-test",
        prompt=f"Review host {hostname} for {username}",
        context=context,
        answer=answer,
        source=f"openai:{openai_secret}:{hostname}",
    )

    row = kb._connect().execute(
        "SELECT prompt, context, answer, source, evaluation FROM external_interactions WHERE id=?",
        (interaction_id,),
    ).fetchone()
    proposal = governance.list_proposals()[0]
    stored = "\n".join((
        row["prompt"], row["context"], row["answer"], row["source"],
        row["evaluation"], json.dumps(proposal["payload"], ensure_ascii=False),
        str(governance.last_report),
    ))
    for secret in (hostname, username, openai_secret, google_secret, bearer_secret, "/home/private-ayfam-user"):
        assert secret not in stored
    assert "[API_KEY]" in stored
    assert "[LOCAL_PATH]" in stored
