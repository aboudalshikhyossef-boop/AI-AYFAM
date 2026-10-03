"""Privacy-first Gemini threat intelligence engine.

Only the API key and a generic threat-intelligence prompt leave the machine.
Host inventory and indicators are matched locally after the response returns.
The Google Gen AI SDK is imported lazily so the rest of AI AYFAM works offline.
"""

from __future__ import annotations

import json
import os
import platform
import re
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping

THREAT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "generated_at": {"type": "string"},
        "window_hours": {"type": "integer"},
        "threats": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "description": {"type": "string"},
                    "products": {"type": "array", "items": {"type": "string"}},
                    "affected_versions": {"type": "array", "items": {"type": "string"}},
                    "iocs": {"type": "array", "items": {"type": "string"}},
                    "recommendations": {"type": "array", "items": {"type": "string"}},
                    "sources": {"type": "array", "items": {"type": "string"}},
                    "published_at": {"type": "string"},
                },
                "required": ["id", "title", "severity", "description", "products", "affected_versions", "iocs", "recommendations", "sources", "published_at"],
            },
        },
    },
    "required": ["generated_at", "window_hours", "threats"],
}

SYSTEM_PROMPT = """You are a cyber threat-intelligence research assistant.
Search authoritative public sources only: CISA, MITRE, NVD, CERT advisories,
CrowdStrike, Cisco Talos, Microsoft Security, Google Cloud security, and vendor
security advisories. Find significant vulnerabilities, exploited campaigns, and
malware indicators first published or materially updated in the last 48 hours.
Return only the requested JSON. Do not request, infer, or include host telemetry,
user identity, local file names, installed packages, IP addresses, or private data.
If there is no trustworthy item, return an empty threats array. Never invent CVEs,
versions, IOCs, dates, or URLs; every item must include source URLs.
"""


class GeminiCTIError(RuntimeError):
    """Actionable error raised for SDK, key, model, network, or response failures."""


@dataclass(frozen=True)
class ModelInfo:
    name: str
    display_name: str = ""
    description: str = ""
    input_token_limit: int = 0
    output_token_limit: int = 0

    @property
    def short_name(self) -> str:
        return self.name.rsplit("/", 1)[-1]


def _text(value: Any) -> str:
    return str(value or "").strip()


def _model_name(model: Any) -> str:
    return _text(getattr(model, "name", None) or (model.get("name") if isinstance(model, Mapping) else ""))


def _supports_generate(model: Any) -> bool:
    methods = getattr(model, "supported_actions", None) or getattr(model, "supported_generation_methods", None)
    if methods is None and isinstance(model, Mapping):
        methods = model.get("supportedGenerationMethods") or model.get("supported_actions")
    if not methods:
        return True
    return any("generate" in _text(item).lower() for item in methods)


def _is_text_research_model(short_name: str) -> bool:
    """Return whether a model name is suitable for text + Search grounding."""
    name = short_name.lower()
    # These families may support generation but are not interchangeable with
    # ordinary text models in the Gemini API (and often require another API).
    excluded = (
        "embedding", "image", "tts", "text-to-speech", "native-audio", "audio",
        "live", "realtime", "real-time", "speech", "transcribe", "music",
        "robotics", "aqa", "computer-use",
    )
    return not any(token in name for token in excluded)


def _score_model(model: ModelInfo) -> tuple[int, int, int, int, str]:
    name = model.short_name.lower()
    # Prefer stable flash models for speed/cost, then stable pro models.
    stable = int("preview" not in name and "experimental" not in name)
    flash = int("flash" in name)
    pro = int("pro" in name)
    # General text models are safer defaults than multimodal/specialized families.
    general_purpose = int("omni" not in name and "live" not in name)
    vision_only = int(any(x in name for x in ("embedding", "image", "tts", "robotics")))
    return (stable, general_purpose, flash * 3 + pro, int(model.output_token_limit > 0) - vision_only, name)


class GeminiThreatClient:
    def __init__(self, api_key: str, timeout: float = 45.0):
        self.api_key = api_key.strip()
        self.timeout = timeout
        self._client = None
        self._model: ModelInfo | None = None
        self._models: list[ModelInfo] = []
        if not self.api_key:
            raise GeminiCTIError("Gemini API key is missing")

    @classmethod
    def from_environment(cls) -> "GeminiThreatClient":
        key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""
        return cls(key)

    def _sdk(self):
        try:
            from google import genai
        except ImportError as exc:
            raise GeminiCTIError("google-genai is not installed; run: python3 -m pip install google-genai") from exc
        if self._client is None:
            try:
                self._client = genai.Client(api_key=self.api_key, http_options={"timeout": int(self.timeout * 1000)})
            except TypeError:
                self._client = genai.Client(api_key=self.api_key)
            except Exception as exc:
                raise GeminiCTIError(f"Could not initialize Gemini client: {exc}") from exc
        return genai

    def discover_models(self, force: bool = False) -> list[ModelInfo]:
        if self._models and not force:
            return list(self._models)
        self._sdk()
        try:
            raw_models = list(self._client.models.list())
        except Exception as exc:
            raise GeminiCTIError(f"Could not list models for this API key: {exc}") from exc
        models: list[ModelInfo] = []
        for raw in raw_models:
            name = _model_name(raw)
            if not name or not _supports_generate(raw):
                continue
            short = name.rsplit("/", 1)[-1].lower()
            if not _is_text_research_model(short):
                continue
            models.append(ModelInfo(
                name=name,
                display_name=_text(getattr(raw, "display_name", None)),
                description=_text(getattr(raw, "description", None)),
                input_token_limit=int(getattr(raw, "input_token_limit", 0) or 0),
                output_token_limit=int(getattr(raw, "output_token_limit", 0) or 0),
            ))
        if not models:
            raise GeminiCTIError("The Gemini key has no usable generate-content model")
        models.sort(key=_score_model, reverse=True)
        self._models = models
        self._model = models[0]
        return models

    @property
    def selected_model(self) -> ModelInfo:
        return self.discover_models()[0]

    @staticmethod
    def _is_quota_error(exc: Exception) -> bool:
        text = str(exc).upper()
        return "429" in text or "RESOURCE_EXHAUSTED" in text or "QUOTA" in text

    @staticmethod
    def _is_invalid_model_error(exc: Exception) -> bool:
        text = str(exc).lower()
        return (
            "model" in text
            and any(token in text for token in ("not found", "not supported", "invalid_argument", "invalid model"))
        )

    @staticmethod
    def _retry_hint(exc: Exception) -> str:
        match = re.search(r"retry(?:Delay| in)\D+(\d+)(?:\.\d+)?s", str(exc), re.I)
        return f" Retry after approximately {match.group(1)} seconds." if match else ""

    def _request_with_interactions(self, model: ModelInfo, query: str) -> str:
        """Use the current official API so Google Search does not trigger AFC warnings."""
        interactions = getattr(self._client, "interactions", None)
        if interactions is None or not hasattr(interactions, "create"):
            raise GeminiCTIError("This google-genai SDK is too old for the Interactions API; upgrade google-genai")
        interaction = interactions.create(
            model=model.name,
            input=query,
            tools=[{"type": "google_search"}],
            response_format={
                "type": "text",
                "mime_type": "application/json",
                "schema": THREAT_SCHEMA,
            },
        )
        return _text(getattr(interaction, "output_text", None))

    def fetch_threats(self, window_hours: int = 48) -> dict[str, Any]:
        query = f"""{SYSTEM_PROMPT}

Research window: the last {window_hours} hours from now (UTC).
Return this exact JSON shape:
{json.dumps(THREAT_SCHEMA, ensure_ascii=False)}
"""
        models = self.discover_models()
        quota_failures: list[tuple[ModelInfo, Exception]] = []
        invalid_models: list[tuple[ModelInfo, Exception]] = []
        for model in models:
            try:
                raw = self._request_with_interactions(model, query)
                if not raw:
                    raise GeminiCTIError(f"Gemini returned an empty response from {model.short_name}")
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise GeminiCTIError(f"Gemini returned invalid JSON: {exc}") from exc
                return validate_threat_feed(data, window_hours=window_hours)
            except Exception as exc:
                if self._is_quota_error(exc):
                    quota_failures.append((model, exc))
                    continue
                if self._is_invalid_model_error(exc):
                    # Google can list stale/preview aliases; skip them and try
                    # the next live model instead of aborting the whole scan.
                    invalid_models.append((model, exc))
                    continue
                if isinstance(exc, GeminiCTIError):
                    raise
                raise GeminiCTIError(f"Gemini threat research failed using {model.short_name}: {exc}") from exc
        if quota_failures:
            names = ", ".join(model.short_name for model, _ in quota_failures[:5])
            hint = self._retry_hint(quota_failures[0][1])
            raise GeminiCTIError(
                "Gemini API key was accepted, but all attempted models returned "
                f"RESOURCE_EXHAUSTED (free-tier quota is 0 for: {names}). "
                "Enable billing/use a project with available quota, or retry later."
                + hint
            )
        if invalid_models:
            names = ", ".join(model.short_name for model, _ in invalid_models[:5])
            raise GeminiCTIError(
                "Google listed model aliases that are not valid for this API request "
                f"({names}), and no remaining text research model completed the request. "
                "Refresh the SDK/model list or use a current Gemini text model."
            )
        raise GeminiCTIError("No usable Gemini model completed the threat research request")

    def close(self) -> None:
        if self._client is not None:
            close = getattr(self._client, "close", None)
            if callable(close):
                close()


def validate_threat_feed(data: Any, window_hours: int = 48) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise GeminiCTIError("Threat feed must be a JSON object")
    threats = data.get("threats", [])
    if not isinstance(threats, list):
        raise GeminiCTIError("Threat feed threats must be an array")
    clean: list[dict[str, Any]] = []
    for item in threats:
        if not isinstance(item, dict) or not _text(item.get("id")) or not _text(item.get("title")):
            continue
        severity = _text(item.get("severity")).lower()
        if severity not in {"critical", "high", "medium", "low", "info"}:
            severity = "info"
        clean.append({
            "id": _text(item.get("id")), "title": _text(item.get("title")), "severity": severity,
            "description": _text(item.get("description")),
            "products": _string_list(item.get("products")),
            "affected_versions": _string_list(item.get("affected_versions")),
            "iocs": _string_list(item.get("iocs")),
            "recommendations": _string_list(item.get("recommendations")),
            "sources": _string_list(item.get("sources")),
            "published_at": _text(item.get("published_at")),
        })
    return {"generated_at": _text(data.get("generated_at")) or datetime.now(timezone.utc).isoformat(), "window_hours": window_hours, "threats": clean}


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [_text(item) for item in value if _text(item)]
    return []


@dataclass
class LocalSnapshot:
    platform: str
    packages: set[str]
    executables: set[str]
    files: set[str]


class LocalThreatMatcher:
    """Offline-only host matcher. It receives no API client and never performs HTTP."""

    def collect_snapshot(self) -> LocalSnapshot:
        system = platform.system().lower()
        packages: set[str] = set()
        if system == "linux":
            for command in (("dpkg-query", "-W", "-f=${binary:Package}\\n"), ("rpm", "-qa")):
                try:
                    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0:
                        packages.update(line.strip().lower() for line in result.stdout.splitlines() if line.strip())
                        break
                except (OSError, subprocess.SubprocessError):
                    pass
        elif system == "windows":
            try:
                result = subprocess.run(["powershell", "-NoProfile", "-Command", "Get-Command * | Select-Object -Expand Name"], capture_output=True, text=True, timeout=20)
                packages.update(line.strip().lower() for line in result.stdout.splitlines() if line.strip())
            except (OSError, subprocess.SubprocessError):
                pass
        elif system == "darwin":
            try:
                result = subprocess.run(["brew", "list"], capture_output=True, text=True, timeout=15)
                packages.update(line.strip().lower() for line in result.stdout.splitlines() if line.strip())
            except (OSError, subprocess.SubprocessError):
                pass
        executables: set[str] = set()
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            if not directory:
                continue
            try:
                executables.update(item.name.lower() for item in Path(directory).iterdir() if item.is_file())
            except OSError:
                continue
        return LocalSnapshot(system, packages, executables, set())

    def match(self, feed: Mapping[str, Any], snapshot: LocalSnapshot | None = None) -> list[dict[str, Any]]:
        snapshot = snapshot or self.collect_snapshot()
        matched: list[dict[str, Any]] = []
        searchable = snapshot.packages | snapshot.executables | {p.lower() for p in snapshot.files}
        for threat in feed.get("threats", []):
            products = [_text(p).lower() for p in threat.get("products", []) if _text(p)]
            iocs = [_text(i).lower() for i in threat.get("iocs", []) if _text(i)]
            product_hits = sorted({p for p in products for value in searchable if p and (p in value or value in p)})
            ioc_hits = sorted({ioc for ioc in iocs if ioc in searchable})
            if product_hits or ioc_hits:
                result = dict(threat)
                result["local_match"] = {"products": product_hits, "iocs": ioc_hits, "platform": snapshot.platform}
                matched.append(result)
        return matched


class ThreatHistory:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or Path.home() / ".ayfam" / "gemini_cti.db").expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self):
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _init(self):
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS feeds (id INTEGER PRIMARY KEY, generated_at TEXT NOT NULL, model TEXT NOT NULL, feed_json TEXT NOT NULL, matched_json TEXT NOT NULL, created_at TEXT NOT NULL)")

    def save(self, feed: Mapping[str, Any], matched: list[dict[str, Any]], model: str) -> int:
        with self._connect() as db:
            cursor = db.execute("INSERT INTO feeds(generated_at, model, feed_json, matched_json, created_at) VALUES (?, ?, ?, ?, ?)", (feed.get("generated_at", ""), model, json.dumps(feed, ensure_ascii=False), json.dumps(matched, ensure_ascii=False), datetime.now(timezone.utc).isoformat()))
            return int(cursor.lastrowid)


def markdown_report(feed: Mapping[str, Any], matched: Iterable[Mapping[str, Any]], model: str) -> str:
    matches = list(matched)
    lines = ["# AI AYFAM — Gemini Threat Intelligence Report", "", f"- Generated: `{feed.get('generated_at', '')}`", f"- Window: `{feed.get('window_hours', 48)} hours`", f"- Model: `{model}`", f"- Local matches: **{len(matches)}**", "", "> Host data was matched locally and was not sent to Gemini.", ""]
    if not matches:
        lines.append("No locally matched threat was found in this feed.")
        return "\n".join(lines) + "\n"
    for threat in matches:
        lines.extend([f"## {threat['severity'].upper()} — {threat['id']}: {threat['title']}", "", threat.get("description", ""), "", f"**Local match:** `{json.dumps(threat.get('local_match', {}), ensure_ascii=False)}`", "", "### Recommendations"])
        lines.extend(f"- {item}" for item in threat.get("recommendations", []))
        lines.extend(["", "### Sources"])
        lines.extend(f"- {source}" for source in threat.get("sources", []))
        lines.append("")
    return "\n".join(lines)
