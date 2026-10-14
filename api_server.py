"""Local API bridge for the Angular cockpit.

Run with: python3 api_server.py
Provider keys remain server-side and are never returned to the browser.
"""
from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from config.settings import Settings
from engine.ai_assistant import AssistantConfig, AssistantError, build_provider
from tools import network, system


def _finding(item: dict[str, Any], index: int, source: str) -> dict[str, Any]:
    """Normalize heterogeneous scanner output for the UI without inventing evidence."""
    severity = str(item.get("severity", "info")).lower()
    if severity not in {"critical", "high", "medium", "low", "info", "safe"}:
        severity = "info"
    title = str(item.get("title") or "نتيجة فحص بدون عنوان").strip()
    detail = str(item.get("detail") or "لم يوفر الفاحص تفاصيل إضافية.").strip()
    fix = str(item.get("fix") or "راجع الدليل وأعد الفحص بعد المعالجة.").strip()
    return {
        "id": f"scan-{source}-{index}",
        "severity": severity,
        "title": title,
        "titleEn": title,
        "detail": detail,
        "detailEn": detail,
        "fix": fix,
        "fixEn": fix,
        "category": str(item.get("category") or source),
        "tags": [source],
        "attackIds": [],
        "effort": "medium",
        "riskOfFix": "medium",
        "fixed": False,
        "discoveredAt": time.strftime("%H:%M:%S"),
        "confidence": item.get("confidence"),
        "evidence": item.get("evidence"),
        "source": source,
    }


def _run_check(source: str, fn: Callable[[], dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        result = fn() or {}
        return [_finding(item, i, source) for i, item in enumerate(result.get("findings", []), 1)]
    except Exception as exc:  # one broken optional check must not hide all results
        return [_finding({
            "severity": "info",
            "title": f"تعذر تشغيل فحص {source}",
            "detail": f"توقف هذا الفاحص بسبب خطأ داخلي آمن: {type(exc).__name__}.",
            "fix": "راجع صلاحيات التشغيل وسجل الخادم ثم أعد المحاولة.",
        }, 1, source)]


def run_scan(profile: str, target: str) -> dict[str, Any]:
    """Run only real local checks selected by the caller; no shell input is accepted here."""
    profile = profile if profile in {"full", "network", "system", "logs"} else "full"
    started = time.monotonic()
    findings: list[dict[str, Any]] = []
    checks: list[str] = []

    def add(name: str, fn: Callable[[], dict[str, Any]]) -> None:
        nonlocal findings
        checks.append(name)
        findings.extend(_run_check(name, fn))

    if profile in {"full", "network"}:
        add("firewall", network.check_firewall)
        add("ports", lambda: network.scan_ports(target, "1-1024"))
        add("network", lambda: {"findings": network.check_data_leaks().get("findings", [])})
    if profile in {"full", "system"}:
        add("ssh", system.check_ssh_config)
        add("suid", system.check_suid_files)
        add("system", lambda: {"findings": system.check_world_writable().get("findings", [])})
    if profile in {"full", "logs"}:
        add("logs", system.analyze_logs)

    if not findings:
        findings.append(_finding({
            "severity": "safe",
            "title": "لم يرصد الفحص مشكلة في النطاق المحدد",
            "detail": "اكتملت الفحوص الفعلية المتاحة ولم تنتج نتائج تحتاج معالجة.",
            "fix": "استمر في الفحص الدوري وراجع السجل عند تغيير إعدادات النظام.",
        }, 1, "scan"))

    counts = {level: sum(1 for f in findings if f["severity"] == level)
              for level in ("critical", "high", "medium", "low", "info", "safe")}
    return {
        "ok": True,
        "profile": profile,
        "target": target,
        "checks": checks,
        "findings": findings,
        "counts": counts,
        "elapsedMs": round((time.monotonic() - started) * 1000),
        "source": "local-scanners",
    }


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "AI-AYFAM-API/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(90.0)

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api/health":
            self._send(200, {"ok": True, "service": "ai-ayfam-api", "scanners": True})
        else:
            self._send(404, {"error": "not_found"})

    def _read_json(self, max_length: int = 32_768) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None or not raw_length.isdigit():
            raise ValueError("content_length_required")
        length = int(raw_length)
        if length <= 0 or length > max_length:
            raise ValueError("request_too_large")
        data = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(data, dict):
            raise ValueError("json_object_required")
        return data

    def do_POST(self) -> None:  # noqa: N802
        try:
            data = self._read_json()
            if self.path == "/api/scan":
                profile = str(data.get("profile", "full")).strip().lower()
                target = str(data.get("target", "127.0.0.1")).strip()
                if len(target) > 255:
                    raise ValueError("target_too_long")
                self._send(200, run_scan(profile, target))
                return
            if self.path != "/api/assistant":
                self._send(404, {"error": "not_found"})
                return
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
                timeout=45.0,
            ))
            if provider is None:
                self._send(200, {"provider": "local", "answer": ""})
                return
            answer = provider.ask(prompt, system_context=f"language={settings.get('language', 'ar')}")
            self._send(200, {"provider": provider.name, "answer": answer})
        except (AssistantError, ValueError, json.JSONDecodeError) as exc:
            self._send(400 if isinstance(exc, ValueError) else 502, {"error": str(exc)})
        except Exception as exc:
            self.log_error("API error: %s", exc)
            self._send(500, {"error": "internal_server_error"})

    def log_message(self, fmt: str, *args: Any) -> None:
        if self.path in ("/api/health", "/api/assistant", "/api/scan"):
            super().log_message(fmt, *args)


def main() -> None:
    host = os.getenv("AYFAM_API_HOST", "127.0.0.1")
    port = int(os.getenv("AYFAM_API_PORT", "8787"))

    class BoundedServer(ThreadingHTTPServer):
        daemon_threads = True
        request_queue_size = 32

    server = BoundedServer((host, port), ApiHandler)
    print(f"AI AYFAM API listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
