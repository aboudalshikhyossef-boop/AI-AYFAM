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

from utils import http_client as requests
from engine.gemini_rate_limit import DEFAULT_GEMINI_MODEL, compact_text, gemini_model_name, wait_for_slot
from engine.ai_assistant import AssistantError, validate_model_access
from brain.context_engine import ContextEngine

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

# Google Search grounding is available on the Gemini 2.5 Flash family in the
# Gemini API Free tier. Gemini 3.x inference can be free, but its Search
# grounding is not available on the Free tier. Keep CTI on a separate model so
# normal chat can continue using the configured Gemini 3.x model.
CTI_SEARCH_MODEL = "gemini-2.5-flash-lite"
FREE_TIER_SEARCH_MODELS = (DEFAULT_GEMINI_MODEL,)

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


def resolve_api_key(configured: str = "", environ: Mapping[str, str] | None = None) -> str:
    """Resolve the effective key; explicit environment values override saved config."""
    env = os.environ if environ is None else environ
    return _text(env.get("GOOGLE_API_KEY") or env.get("GEMINI_API_KEY") or configured)


def _is_model_scoped_quota(details: Any) -> bool:
    """Only permit fallback when Google identifies the 429 as model-scoped."""
    violations: list[Mapping[str, Any]] = []
    if not isinstance(details, list):
        return False
    for detail in details:
        if not isinstance(detail, Mapping):
            continue
        kind = _text(detail.get("@type")).lower()
        if "quotafailure" not in kind and not isinstance(detail.get("violations"), list):
            continue
        violations.extend(item for item in detail.get("violations", []) if isinstance(item, Mapping))
    if not violations:
        return False
    for violation in violations:
        dimensions = violation.get("quotaDimensions")
        quota_id = _text(violation.get("quotaId")).lower().replace("_", "").replace("-", "")
        if not (isinstance(dimensions, Mapping) and dimensions.get("model")) and "permodel" not in quota_id:
            return False
    return True


class GeminiHTTPError(GeminiCTIError):
    """HTTP error that preserves Google's machine-readable error and quota details."""

    def __init__(self, response: Any):
        self.status_code = int(response.status_code)
        try:
            payload = response.json()
        except (ValueError, TypeError, AttributeError):
            payload = {}
        error = payload.get("error", {}) if isinstance(payload, Mapping) else {}
        if not isinstance(error, Mapping):
            error = {}
        self.error_code = _text(error.get("status") or error.get("code"))
        self.message = _text(error.get("message")) or _text(getattr(response, "text", ""))
        self.details = error.get("details", [])
        self.model_scoped_quota = self.status_code == 429 and _is_model_scoped_quota(self.details)
        parts = [f"HTTP {self.status_code}"]
        if self.error_code:
            parts.append(self.error_code)
        if self.message:
            parts.append(self.message)
        if self.details:
            rendered = json.dumps(self.details, ensure_ascii=False, separators=(",", ":"))
            parts.append("details=" + rendered[:1400])
        super().__init__("; ".join(parts))


def _interaction_output_text(body: Any) -> str:
    """Extract text from current REST steps, generateContent candidates, with compatibility for older responses."""
    if not isinstance(body, Mapping):
        return ""
    candidates = body.get("candidates")
    if isinstance(candidates, list) and candidates:
        first = candidates[0]
        if isinstance(first, Mapping):
            content = first.get("content")
            if isinstance(content, Mapping):
                parts = content.get("parts")
                if isinstance(parts, list):
                    texts = [_text(p.get("text")) for p in parts if isinstance(p, Mapping) and _text(p.get("text"))]
                    if texts:
                        return "\n".join(texts)
    direct = _text(body.get("output_text"))
    if direct:
        return direct
    texts: list[str] = []
    steps = body.get("steps", [])
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, Mapping) or step.get("type") != "model_output":
                continue
            content = step.get("content", [])
            if not isinstance(content, list):
                continue
            for part in content:
                if isinstance(part, Mapping) and part.get("type") in (None, "text"):
                    text = _text(part.get("text"))
                    if text:
                        texts.append(text)
    if texts:
        return "\n".join(texts)
    outputs = body.get("outputs", [])
    if isinstance(outputs, list):
        for output in outputs:
            if not isinstance(output, Mapping) or output.get("type") not in (None, "text"):
                continue
            text = _text(output.get("text"))
            if text:
                texts.append(text)
    return "\n".join(texts)


def _model_name(model: Any) -> str:
    return _text(getattr(model, "name", None) or (model.get("name") if isinstance(model, Mapping) else ""))


def _model_field(model: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(model, Mapping) and name in model:
            return model[name]
        value = getattr(model, name, None)
        if value is not None:
            return value
    return default


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


def _google_search_tool_type(model: ModelInfo) -> str:
    """Use the legacy grounding tool for Gemini 2.x; current Gemini 3.x uses google_search."""
    name = model.short_name.lower()
    if name.startswith(("gemini-2.5-", "gemini-2.0-")):
        return "google_search_retrieval"
    return "google_search"


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
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"
        self._client = None
        self._model: ModelInfo | None = None
        self._models: list[ModelInfo] = []
        if not self.api_key:
            raise GeminiCTIError("Gemini API key is missing")

    def ask_assistant(self, prompt: str, system_context: str = "") -> str:
        """Make exactly one compact Gemini request; no SDK/model fallback burst."""
        prompt = ContextEngine.sanitize_privacy_data(prompt)
        system_context = ContextEngine.sanitize_privacy_data(system_context)

        sys_instruction = (
            "You are AI AYFAM, a senior cybersecurity expert for Linux Mint and Ubuntu. "
            "Answer briefly with evidence, impact, confidence limits, and one safe next step. "
            "Never claim a command was executed. Support Arabic and English."
        )
        context = compact_text(system_context, 600)
        if context:
            sys_instruction += f"\nContext: {context}"
        model = gemini_model_name(os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL))
        try:
            validate_model_access("gemini", self.api_key, model, timeout=self.timeout)
        except AssistantError as exc:
            raise GeminiCTIError(str(exc)) from exc
        payload = {"contents": [{"parts": [{"text": compact_text(prompt, 3600)}]}],
                   "systemInstruction": {"parts": [{"text": sys_instruction}]},
                   "generationConfig": {"temperature": 0.1, "maxOutputTokens": 2048}}
        wait_for_slot(self.api_key, timeout=self.timeout)
        try:
            response = requests.post(f"{self.base_url}/models/{model}:generateContent",
                headers={"x-goog-api-key": self.api_key, "Content-Type": "application/json"},
                json_data=payload, timeout=self.timeout)
            if response.status_code != 200:
                raise GeminiHTTPError(response)
            body = response.json()
            candidates = body.get("candidates", [])
            parts = candidates[0].get("content", {}).get("parts", []) if candidates else []
            answer = "\n".join(p.get("text", "") for p in parts if isinstance(p, dict) and p.get("text")).strip()
            if not answer:
                raise GeminiCTIError("Gemini returned an empty response")
            return answer
        except GeminiCTIError:
            raise
        except Exception as exc:
            raise GeminiCTIError(f"Could not generate assistant response: {exc}") from exc

    @classmethod
    def from_environment(cls) -> "GeminiThreatClient":
        return cls(resolve_api_key())

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
        try:
            response = requests.get(
                f"{self.base_url}/models",
                headers={"x-goog-api-key": self.api_key},
                params={"pageSize": 1000},
                timeout=(10, self.timeout),
            )
            if response.status_code >= 400:
                raise GeminiHTTPError(response)
            raw_models = response.json().get("models", [])
        except Exception as exc:
            if isinstance(exc, GeminiCTIError):
                raise
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
                display_name=_text(_model_field(raw, "display_name", "displayName", default="")),
                description=_text(_model_field(raw, "description", default="")),
                input_token_limit=int(_model_field(raw, "input_token_limit", "inputTokenLimit", default=0) or 0),
                output_token_limit=int(_model_field(raw, "output_token_limit", "outputTokenLimit", default=0) or 0),
            ))
        if not models:
            raise GeminiCTIError("The Gemini key has no usable generate-content model")
        models.sort(key=_score_model, reverse=True)
        by_name = {model.short_name.lower(): model for model in models}
        preferred = [by_name[name] for name in FREE_TIER_SEARCH_MODELS if name in by_name]
        remaining = [m for m in models if m not in preferred]
        usable_models = preferred + remaining
        if not usable_models:
            raise GeminiCTIError("No usable text model is available for this Gemini API key.")
        self._models = usable_models
        self._model = usable_models[0]
        return list(self._models)

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
        """Send one grounded generateContent request only."""
        payload = {
            "contents": [{"parts": [{"text": compact_text(query, 5200)}]}],
            "tools": [{_google_search_tool_type(model): {}}],
            "generationConfig": {"responseMimeType": "application/json",
                                 "responseSchema": THREAT_SCHEMA,
                                 "temperature": 0.1, "maxOutputTokens": 900},
        }
        wait_for_slot(self.api_key, timeout=self.timeout)
        response = requests.post(
            f"{self.base_url}/models/{model.short_name}:generateContent",
            headers={"x-goog-api-key": self.api_key, "Content-Type": "application/json"},
            json_data=payload, timeout=(10, self.timeout))
        if response.status_code >= 400:
            raise GeminiHTTPError(response)
        try:
            text = _interaction_output_text(response.json())
        except ValueError as exc:
            raise GeminiCTIError("Gemini returned a non-JSON HTTP response") from exc
        if not text:
            raise GeminiCTIError("Gemini returned an empty response")
        return text

    def fetch_threats(self, window_hours: int = 48) -> dict[str, Any]:
        query = f"""{SYSTEM_PROMPT}
Research window: the last {int(window_hours)} hours from now (UTC).
Return one compact JSON object with at most 5 significant items. Each item must have one short description,
one recommendation, and at most 2 authoritative source URLs. Return [] when evidence is insufficient."""
        # Keep the operational path to one API call: model discovery is an
        # explicit settings/diagnostic action, not part of threat collection.
        # Do not inherit the normal chat model here: Gemini 3.x Search
        # grounding is unavailable on the Free tier and returns HTTP 429.
        configured_model = os.getenv("AYFAM_GEMINI_CTI_MODEL", CTI_SEARCH_MODEL).strip() or CTI_SEARCH_MODEL
        try:
            available = {item.short_name for item in self.discover_models()}
            if configured_model not in available:
                suggestion = next(iter(sorted(available)), DEFAULT_GEMINI_MODEL)
                raise GeminiCTIError(
                    f"Selected Gemini CTI model '{configured_model}' is unavailable. "
                    f"Choose an available model explicitly; suggestion: {suggestion}. "
                    "النموذج المحدد غير متاح؛ اختر نموذجاً من القائمة يدوياً."
                )
            model = ModelInfo(f"models/{configured_model}")
            raw = self._request_with_interactions(model, query)
            return validate_threat_feed(json.loads(raw), window_hours=window_hours)
        except GeminiHTTPError as exc:
            raise GeminiCTIError(f"Gemini threat research failed using {model.short_name}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise GeminiCTIError(f"Gemini returned invalid JSON: {exc}") from exc
        except GeminiCTIError:
            raise
        except Exception as exc:
            raise GeminiCTIError(f"Gemini threat research failed using {model.short_name}: {exc}") from exc

    def close(self) -> None:
        if self._client is not None:
            close = getattr(self._client, "close", None)
            if callable(close):
                close()
            self._client = None


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
        sources = _string_list(item.get("sources"))
        if not any(src.lower().startswith(("http://", "https://")) for src in sources):
            continue
        clean.append({
            "id": _text(item.get("id")), "title": _text(item.get("title")), "severity": severity,
            "description": _text(item.get("description")),
            "products": _string_list(item.get("products")),
            "affected_versions": _string_list(item.get("affected_versions")),
            "iocs": _string_list(item.get("iocs")),
            "recommendations": _string_list(item.get("recommendations")),
            "sources": sources,
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
