"""Local API bridge for the Angular cockpit.

Run with: python3 api_server.py
The server binds to 127.0.0.1 by default. Provider keys remain in the process
environment or ~/.ayfam/config.json and are never returned to the client.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from config.settings import Settings
from engine.ai_assistant import AssistantConfig, AssistantError, build_provider


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "AI-AYFAM-API/1.0"

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "http://localhost:4200")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "http://localhost:4200")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api/health":
            self._send(200, {"ok": True, "service": "ai-ayfam-api"})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/assistant":
            self._send(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 32_768:
                raise ValueError("request_too_large")
            data = json.loads(self.rfile.read(length) or b"{}")
            prompt = str(data.get("prompt", "")).strip()
            if not prompt or len(prompt) > 8_000:
                self._send(400, {"error": "prompt_required_or_too_long"})
                return
            settings = Settings()
            provider = build_provider(AssistantConfig(
                provider=os.getenv("AI_PROVIDER", settings.get("ai_provider", "auto")),
                openai_api_key=settings.get("openai_api_key", ""),
                openai_model=os.getenv("OPENAI_MODEL", settings.get("openai_model", "gpt-4o-mini")),
                gemini_api_key=settings.get("gemini_api_key", ""),
                gemini_model=os.getenv("GEMINI_MODEL", settings.get("gemini_model", "gemini-2.5-flash")),
                timeout=25.0,
            ))
            if provider is None:
                self._send(200, {"provider": "local", "answer": ""})
                return
            answer = provider.ask(prompt, system_context=f"language={settings.get('language', 'ar')}")
            self._send(200, {"provider": provider.name, "answer": answer})
        except (AssistantError, ValueError, json.JSONDecodeError) as exc:
            self._send(400 if isinstance(exc, ValueError) else 502, {"error": str(exc)})
        except Exception as exc:  # keep internals out of the response
            self.log_error("API error: %s", exc)
            self._send(500, {"error": "internal_server_error"})

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep prompts, headers and response bodies out of logs.
        if self.path in ("/api/health", "/api/assistant"):
            super().log_message(fmt, *args)


def main() -> None:
    host = os.getenv("AYFAM_API_HOST", "127.0.0.1")
    port = int(os.getenv("AYFAM_API_PORT", "8787"))
    server = ThreadingHTTPServer((host, port), ApiHandler)
    print(f"AI AYFAM API listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
