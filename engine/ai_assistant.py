"""Unified AI assistant providers for AI AYFAM.

API keys are read from the process environment or local Settings and are never
sent to the browser, logged, or included in prompts. Provider failures are
reported as typed errors so callers can safely fall back to the local engine.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from utils import http_client
from engine.gemini_rate_limit import DEFAULT_GEMINI_MODEL, compact_text, gemini_model_name, wait_for_slot
from brain.context_engine import ContextEngine


class AssistantError(RuntimeError):
    """Actionable provider or response error."""


class AssistantProvider(Protocol):
    name: str

    def ask(self, prompt: str, *, system_context: str = "") -> str:
        ...


@dataclass(frozen=True)
class AssistantConfig:
    provider: str = "auto"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    gemini_api_key: str = ""
    gemini_model: str = DEFAULT_GEMINI_MODEL
    timeout: float = 30.0


def _text(value: Any) -> str:
    return str(value or "").strip()


def resolve_secret(configured: str, *environment_names: str, environ: Mapping[str, str] | None = None) -> str:
    """Prefer environment secrets over values saved in the local config file."""
    env = os.environ if environ is None else environ
    for name in environment_names:
        value = _text(env.get(name))
        if value:
            return value
    return _text(configured)


def _error_message(response: Any) -> str:
    try:
        payload = response.json()
    except (AttributeError, TypeError, ValueError):
        payload = {}
    if isinstance(payload, Mapping):
        error = payload.get("error", payload)
        if isinstance(error, Mapping):
            return _text(error.get("message") or error.get("type") or error.get("code"))
    return _text(getattr(response, "text", ""))


def _redact_secret(value: Any, secret: str) -> str:
    message = _text(value)
    return message.replace(secret, "[redacted]") if secret else message


class OpenAIAssistant:
    name = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o-mini", timeout: float = 30.0):
        self.api_key = _text(api_key)
        self.model = _text(model) or "gpt-4o-mini"
        self.timeout = timeout
        if not self.api_key:
            raise AssistantError("OpenAI API key is missing")

    def ask(self, prompt: str, *, system_context: str = "") -> str:
        if not _text(prompt):
            raise AssistantError("Prompt is empty")
        messages = [
            {
                "role": "system",
                "content": (
                    "You are AI AYFAM, a senior cybersecurity assistant for Linux Mint and Ubuntu. "
                    "Give safe, concise, actionable advice. Never claim that a command was executed. "
                    "For every finding, explain the evidence, impact, confidence/limitations, and safest next step. "
                    "Distinguish observed facts from hypotheses and never call an open port or filename malicious without evidence. "
                    "When suggesting shell commands, explain that the user must review them first. "
                    "Answer in the user's language."
                    + (f"\nContext: {system_context}" if system_context else "")
                ),
            },
            {"role": "user", "content": prompt},
        ]
        response = http_client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json_data={"model": self.model, "messages": messages, "temperature": 0.2},
            timeout=self.timeout,
        )
        if getattr(response, "status_code", 0) != 200:
            detail = _error_message(response)
            raise AssistantError(f"OpenAI request failed ({response.status_code}): {detail or 'unknown error'}")
        try:
            payload = response.json()
            text = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise AssistantError("OpenAI returned an invalid response") from exc
        answer = _text(text)
        if not answer:
            raise AssistantError("OpenAI returned an empty response")
        return answer


class GeminiAssistant:
    name = "gemini"

    def __init__(self, api_key: str, model: str = DEFAULT_GEMINI_MODEL, timeout: float = 30.0):
        self.api_key = _text(api_key)
        self.model = gemini_model_name(model)
        self.timeout = timeout
        if not self.api_key:
            raise AssistantError("Gemini API key is missing")

    def ask(self, prompt: str, *, system_context: str = "") -> str:
        if not _text(prompt):
            raise AssistantError("Prompt is empty")

        # Privacy anonymization scrubbing before outbound API transmission
        prompt = ContextEngine.sanitize_privacy_data(prompt)
        system_context = ContextEngine.sanitize_privacy_data(system_context)

        prompt = compact_text(prompt, 3600)
        context = compact_text(system_context, 600)
        instruction = (
            "You are AI AYFAM, a senior cybersecurity assistant for Linux Mint and Ubuntu. "
            "Give safe, concise, actionable advice. Never claim that a command was executed. "
            "Explain evidence, impact, confidence/limitations, and safest next step. "
            "Distinguish observed facts from hypotheses and do not overstate scanner results. "
            "Answer in the user's language."
        )
        if context:
            instruction += f"\nContext: {context}"
        try:
            wait_for_slot(self.api_key)
            response = http_client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
                headers={"x-goog-api-key": self.api_key, "Content-Type": "application/json"},
                json_data={
                    "systemInstruction": {"parts": [{"text": instruction}]},
                    "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                    # 256 tokens is too small for Arabic answers and can stop
                    # Gemini in the middle of a sentence.
                    "generationConfig": {"temperature": 0.1, "maxOutputTokens": 2048},
                },
                timeout=self.timeout,
            )
        except Exception as exc:
            detail = _redact_secret(exc, self.api_key)
            raise AssistantError(
                f"Gemini connection failed: {detail or type(exc).__name__}"
            ) from exc
        if getattr(response, "status_code", 0) != 200:
            detail = _redact_secret(_error_message(response), self.api_key)
            raise AssistantError(f"Gemini request failed ({response.status_code}): {detail or 'unknown error'}")
        try:
            payload = response.json()
            parts = payload["candidates"][0]["content"]["parts"]
            answer = "\n".join(_text(part.get("text")) for part in parts if isinstance(part, Mapping))
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise AssistantError("Gemini returned an invalid response") from exc
        if not _text(answer):
            raise AssistantError("Gemini returned an empty response")
        return answer.strip()


def build_provider(config: AssistantConfig) -> AssistantProvider | None:
    """Build the requested provider; ``auto`` prefers OpenAI, then Gemini."""
    provider = _text(config.provider).lower() or "auto"
    openai_key = resolve_secret(config.openai_api_key, "OPENAI_API_KEY")
    gemini_key = resolve_secret(config.gemini_api_key, "GOOGLE_API_KEY", "GEMINI_API_KEY")
    if provider in ("openai", "auto") and openai_key:
        return OpenAIAssistant(openai_key, config.openai_model, config.timeout)
    if provider in ("gemini", "auto") and gemini_key:
        return GeminiAssistant(gemini_key, config.gemini_model, config.timeout)
    if provider not in ("auto", "local", ""):
        raise AssistantError(f"Provider '{provider}' is selected but its API key is not configured")
    return None
