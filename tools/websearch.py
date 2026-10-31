"""بحث الإنترنت الدقيق: Google (عبر CSE أو تأريض Gemini) + ويكيبيديا، مع تصفية الصلة.

القواعد:
  • عبارة البحث تُرسل كاملة بعد حذف كلمات الأمر («ابحث في الإنترنت عن …»).
  • النتائج غير المرتبطة بكلمات الاستعلام تُحذف بدل عرضها.
  • كل محرك يُبلّغ عن حالته (يعمل / غير مفعّل / فشل) ولا يُخفى فشله.
  • DuckDuckGo احتياط فقط إذا لم يتوفر Google أو فشل.
  • لا يُحفظ شيء تلقائياً: التعلّم من الإنترنت يُنتج ملفاً للمراجعة ثم يقرر المستخدم.
"""
from __future__ import annotations

import os
import re
import time
import urllib.parse
import html
from defusedxml import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from brain.language import clean_search_query, normalize, wants_source

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None

from utils import http_client

USER_AGENT = "AI-AYFAM/9.0 (https://github.com/aboudalshikhyossef-boop/AI-AYFAM; local security assistant)"
GEMINI_MODELS = ("gemini-3.8-flash",)
TIMEOUT = 9
DEFAULT_GOOGLE_CSE_CX = "f5fbcd40fda484bc7"

_STOPWORDS = {normalize(w) for w in (
    "في", "من", "على", "عن", "الى", "إلى", "هذا", "هذه", "ذلك", "تلك", "ما", "ماذا", "هو", "هي", "لي", "لك", "مع", "او", "أو",
    "كيف", "لماذا", "متى", "اين", "أين", "هل", "التي", "الذي", "يكون", "كان", "بين", "ثم", "كل", "حول", "بشكل", "جدا", "جداً",
    "the", "a", "an", "of", "for", "to", "in", "on", "is", "are", "and", "or", "what", "how", "why", "with", "about", "from",
)}


def _stem(word: str) -> str:
    word = normalize(word)
    for prefix in ("وال", "بال", "كال", "فال", "لل", "ال"):
        if word.startswith(prefix) and len(word) - len(prefix) >= 3:
            return word[len(prefix):]
    return word


def query_terms(query: str) -> list[str]:
    words = re.findall(r"[A-Za-z0-9_.+#-]+|[\u0600-\u06FF]+", query)
    terms = []
    for word in words:
        key = normalize(word)
        if key and key not in _STOPWORDS and len(key) > 1:
            terms.append(_stem(word))
    return terms or [normalize(query)]


@dataclass
class SearchHit:
    title: str
    url: str
    snippet: str
    engine: str
    relevance: float = 0.0
    lang: str = ""

    @property
    def engine_label(self) -> str:
        return {"google": "Google", "google-cse": "Google", "wikipedia-ar": "ويكيبيديا (عربي)",
                "wikipedia-en": "Wikipedia (EN)", "duckduckgo": "DuckDuckGo", "bing-rss": "Bing"}.get(self.engine, self.engine)


@dataclass
class SearchReport:
    query: str
    hits: list[SearchHit] = field(default_factory=list)
    answer: str = ""
    engines: dict[str, str] = field(default_factory=dict)
    online: bool = True
    elapsed: float = 0.0
    dropped: int = 0

    @property
    def ok(self) -> bool:
        return bool(self.hits or self.answer)


class SearchProviderError(RuntimeError):
    def __init__(self, provider: str, status: int | None = None, reason: str = "", message: str = ""):
        self.provider = provider
        self.status = status
        self.reason = reason
        self.message = message
        super().__init__(self._format())

    def _format(self) -> str:
        code = f"HTTP {self.status}" if self.status else "اتصال"
        parts = [p for p in (self.message, self.reason) if p]
        detail = " — ".join(parts) if parts else "خطأ غير موصوف"
        return f"{self.provider}: {code} — {detail}"

    def __str__(self) -> str:
        return self._format()


def _settings_map(settings) -> dict:
    """وحّد قراءة الإعدادات سواء وُجّه dict أو كائن Settings."""
    if settings is None:
        return {}
    if isinstance(settings, dict):
        return settings
    data = getattr(settings, "_data", None)
    if isinstance(data, dict):
        return data
    if hasattr(settings, "get"):
        keys = (
            "google_cse_key", "google_cse_cx", "gemini_api_key",
            "language", "nvd_api_key", "openai_api_key",
        )
        return {k: settings.get(k, "") for k in keys}
    return {}


def normalize_cse_key(key: str) -> str:
    """تنظيف مفتاح Google API من مسافات وعلامات اقتباس."""
    key = (key or "").strip().strip('"').strip("'")
    return key


def normalize_cse_cx(cx: str) -> str:
    """استخرج معرّف cx حتى لو لصق المستخدم رابط CSE كاملاً."""
    cx = (cx or "").strip().strip('"').strip("'")
    if not cx:
        return DEFAULT_GOOGLE_CSE_CX
    # رابط مثل https://cse.google.com/cse?cx=XXXX أو #gsc.tab=0&cx=XXXX
    m = re.search(r"(?:[?&#]|^)cx=([A-Za-z0-9_-]{8,128})", cx)
    if m:
        return m.group(1)
    # أحياناً يُلصق فقط المعرّف
    if re.fullmatch(r"[A-Za-z0-9_-]{8,128}", cx):
        return cx
    return cx


def _get_json(url: str, params: dict | None = None, headers: dict | None = None) -> dict:
    merged = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    merged.update(headers or {})
    response = http_client.get(url, headers=merged, params=params, timeout=TIMEOUT)
    if response.status_code != 200:
        detail = ""
        try:
            payload = response.json()
            error = payload.get("error", payload) if isinstance(payload, dict) else {}
            detail = error.get("message", "") if isinstance(error, dict) else ""
            if isinstance(error, dict) and error.get("errors"):
                reason = (error["errors"][0] or {}).get("reason", "")
                detail = f"{reason}: {detail}" if reason and reason not in detail else detail
        except Exception:
            detail = re.sub(r"\s+", " ", getattr(response, "text", ""))[:180]
        raise SearchProviderError(urllib.parse.urlparse(url).netloc or "HTTP", response.status_code, message=detail)
    return response.json()


def check_connectivity() -> bool:
    try:
        _get_json("https://en.wikipedia.org/w/api.php", {"action": "query", "meta": "siteinfo", "format": "json"})
        return True
    except Exception:
        return False


def wikipedia(query: str, lang: str = "ar", limit: int = 5, sentences: int = 3) -> list[SearchHit]:
    data = _get_json(f"https://{lang}.wikipedia.org/w/api.php", {
        "action": "query", "format": "json", "generator": "search", "gsrsearch": query, "gsrlimit": limit,
        "prop": "extracts|info", "exintro": 1, "explaintext": 1, "exsentences": sentences, "exlimit": limit,
        "inprop": "url", "redirects": 1,
    })
    pages = list((data.get("query") or {}).get("pages", {}).values())
    pages.sort(key=lambda page: page.get("index", 99))
    return [
        SearchHit(page.get("title", ""), page.get("fullurl") or f"https://{lang}.wikipedia.org/?curid={page.get('pageid')}",
                  re.sub(r"\s+", " ", page.get("extract", "")).strip(), f"wikipedia-{lang}", lang=lang)
        for page in pages if page.get("extract")
    ]


def google_cse(query: str, key: str, cx: str, lang: str, limit: int = 6) -> list[SearchHit]:
    key = normalize_cse_key(key)
    cx = normalize_cse_cx(cx)
    if not key:
        raise SearchProviderError(
            "Google CSE",
            reason="مفتاح API مفقود (GOOGLE_CSE_KEY) — ضع Google API Key في الإعدادات (ليس رابط المحرك). من Google Cloud → APIs → Custom Search API",
        )
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", cx):
        raise SearchProviderError(
            "Google CSE",
            reason=f"معرّف المحرك (cx) غير صالح: «{cx[:40]}». الصق المعرّف فقط أو رابط CSE الذي يحتوي cx=",
        )
    params = {"key": key, "cx": cx, "q": query, "num": max(1, min(int(limit), 10)), "hl": lang}
    if lang in ("ar", "en"):
        params["lr"] = f"lang_{lang}"
    try:
        data = _get_json("https://www.googleapis.com/customsearch/v1", params)
    except SearchProviderError as exc:
        exc.provider = "Google CSE"
        # رسائل أوضح لحالات شائعة
        msg = (exc.message or "").lower()
        if exc.status in (400, 403) and ("key" in msg or "invalid" in msg or "api" in msg):
            exc.reason = (exc.reason or "") + " — تحقق أن Custom Search API مفعّل للمفتاح وأن المفتاح ليس مفتاح OAuth"
        raise
    return [
        SearchHit(item.get("title", ""), item.get("link", ""), re.sub(r"\s+", " ", item.get("snippet", "")).strip(), "google-cse", lang=lang)
        for item in data.get("items", []) if item.get("link")
    ]


def google_grounded(query: str, api_key: str, lang: str) -> tuple[str, list[SearchHit]]:
    from engine.gemini_rate_limit import compact_text, wait_for_slot, gemini_model_name
    model = gemini_model_name(os.environ.get("GEMINI_MODEL", GEMINI_MODELS[0]))
    prompt = (f"ابحث في Google عن: {compact_text(query, 600)}. "
              f"أجب بـ{'العربية' if lang == 'ar' else 'English'} في 3 أسطر فقط، "
              "اذكر أهم حقيقة ومصدرين كحد أقصى، ولا تخترع معلومات.")
    body = {"contents": [{"parts": [{"text": prompt}]}], "tools": [{"googleSearch": {}}],
            "generationConfig": {"temperature": 0.1, "maxOutputTokens": 180}}
    wait_for_slot(api_key)
    try:
        response = http_client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            headers={"x-goog-api-key": api_key, "Content-Type": "application/json", "User-Agent": USER_AGENT},
            json_data=body, timeout=25)
        wait_for_slot(api_key)
        if response.status_code != 200:
            raise SearchProviderError("Google (Gemini)", response.status_code, reason=f"Model {model} error")
        data = response.json()
        candidates = data.get("candidates") or [{}]
        if not candidates:
            return "", []
        candidate = candidates[0]
        answer = "".join(part.get("text", "") for part in (candidate.get("content") or {}).get("parts", []) if isinstance(part, dict)).strip()
        meta = candidate.get("groundingMetadata") or {}
        chunks = meta.get("groundingChunks") or []
        snippets: dict[int, list[str]] = {}
        for support in meta.get("groundingSupports") or []:
            if isinstance(support, dict):
                text = (support.get("segment") or {}).get("text", "")
                for index in support.get("groundingChunkIndices") or []:
                    if isinstance(index, int):
                        snippets.setdefault(index, []).append(text)
        hits = []
        for index, chunk in enumerate(chunks):
            if isinstance(chunk, dict):
                web = chunk.get("web") or {}
                uri = web.get("uri") or ""
                if uri:
                    hits.append(SearchHit(web.get("title") or urllib.parse.urlparse(uri).netloc or "Google Result",
                                          uri, " ".join(snippets.get(index, [])[:2])[:320],
                                          "google", lang=lang))
        return answer, hits
    except Exception as exc:
        if isinstance(exc, SearchProviderError):
            raise
        raise SearchProviderError("Google (Gemini)", message=str(exc)) from exc


def execute_google_search(query: str, cse_key: str, cse_cx: str, gemini_key: str, lang: str, limit: int = 6) -> tuple[str, str, Any]:
    errors = []
    cse_key = normalize_cse_key(cse_key)
    cse_cx = normalize_cse_cx(cse_cx)
    if cse_key:
        try:
            hits = google_cse(query, cse_key, cse_cx, lang, limit)
            if hits:
                return "Google (CSE)", "hits", hits
            errors.append("Google (CSE): لم يُرجع نتائج")
        except Exception as exc:
            errors.append(str(exc))

    if gemini_key:
        try:
            answer, hits = google_grounded(query, gemini_key, lang)
            if answer or hits:
                return "Google (Gemini)", "grounded", (answer, hits)
            errors.append("Google (Gemini): لم يُرجع إجابة أو نتائج")
        except Exception as exc:
            errors.append(str(exc))

    if not cse_key and not gemini_key:
        raise SearchProviderError(
            "Google",
            reason="غير مفعّل: ضع Google CSE Key في الإعدادات (أو Gemini API Key). cx وحده لا يكفي — يلزم مفتاح API من Google Cloud",
        )

    reason_text = " — ".join(errors) if errors else "تعذّر الحصول على نتائج من Google"
    raise SearchProviderError("Google", reason=reason_text)


def duckduckgo(query: str, limit: int = 6) -> list[SearchHit]:
    from tools import web
    rows = web._ddg_html_search(query, limit)
    return [SearchHit(r.get("title", ""), r.get("url", ""), r.get("snippet", ""), "duckduckgo") for r in rows if r.get("url")]


def bing_rss(query: str, lang: str = "en", limit: int = 6) -> list[SearchHit]:
    response = http_client.get(
        "https://www.bing.com/search",
        headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/xml"},
        params={"q": query, "format": "rss", "setlang": lang},
        timeout=TIMEOUT,
    )
    if response.status_code != 200:
        raise SearchProviderError("Bing RSS", response.status_code)
    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as exc:
        raise SearchProviderError("Bing RSS", message=f"XML غير صالح: {exc}") from exc
    hits: list[SearchHit] = []
    for item in root.findall("./channel/item")[: max(1, min(int(limit), 10))]:
        title = html.unescape((item.findtext("title") or "").strip())
        url = (item.findtext("link") or "").strip()
        snippet = html.unescape(re.sub(r"<[^>]+>", " ", item.findtext("description") or ""))
        snippet = re.sub(r"\s+", " ", snippet).strip()
        if title and url:
            hits.append(SearchHit(title, url, snippet, "bing-rss", lang=lang))
    return hits


_DOMAIN_WORDS = tuple(normalize(w) for w in (
    "حاسوب", "حاسب", "حوسبة", "شبكة", "شبكات", "أمن", "امن", "حماية", "برمجيات", "نظام", "لينكس", "خادم", "بروتوكول",
    "computer", "network", "security", "software", "linux", "protocol", "firewall", "vulnerability", "server", "malware",
))


def _words(text: str) -> set[str]:
    return {_stem(w) for w in re.findall(r"[a-z0-9]+|[\u0600-\u06FF]+", normalize(text))}


def score_hit(hit: SearchHit, terms: list[str], latin_terms: list[str] | None = None) -> float:
    active = latin_terms if (hit.lang == "en" and latin_terms) else terms
    if not active:
        return 0.0
    title_words, body_words = _words(hit.title), _words(hit.snippet)
    score = 0.0
    for term in active:
        pieces = set(re.findall(r"[a-z0-9]+|[\u0600-\u06FF]+", term)) or {term}
        if pieces <= title_words:
            score += 1.0
        elif pieces <= (title_words | body_words):
            score += 0.6
    return round(score / len(active), 2)


def _domain_boost(hit: SearchHit) -> float:
    text = normalize(hit.title + " " + hit.snippet[:220])
    return 0.1 if any(word in text for word in _DOMAIN_WORDS) else 0.0


def _filter_and_rank(hits: list[SearchHit], terms: list[str], latin_terms: list[str] | None = None) -> tuple[list[SearchHit], int]:
    kept, dropped, seen = [], 0, set()
    for hit in hits:
        hit.relevance = score_hit(hit, terms, latin_terms)
        trusted = hit.engine in ("google", "google-cse")
        active = latin_terms if (hit.lang == "en" and latin_terms) else terms
        floor = 0.0 if trusted else (0.5 if len(active) >= 2 else 0.6)
        key = re.sub(r"[#?].*$", "", hit.url).rstrip("/").lower()
        if key in seen:
            continue
        if hit.relevance < floor:
            dropped += 1
            continue
        seen.add(key)
        kept.append(hit)
    kept.sort(key=lambda h: -(h.relevance + _domain_boost(h)))
    return kept, dropped


def _resolve_gemini_key(settings: dict | None) -> str:
    try:
        from engine.gemini_cti import resolve_api_key
        return resolve_api_key((settings or {}).get("gemini_api_key", "")) or ""
    except Exception:
        return (settings or {}).get("gemini_api_key", "") or os.environ.get("GEMINI_API_KEY", "")


def search(raw_query: str, settings=None, limit: int = 6, deep: bool = False) -> SearchReport:
    """بحث دقيق بعبارة المستخدم الكاملة. لا يرفع استثناءً: الحالة تُسجَّل لكل محرك."""
    started = time.time()
    settings = _settings_map(settings)
    requested = wants_source(raw_query)
    query = clean_search_query(raw_query)
    report = SearchReport(query=query)
    if len(normalize(query)) < 2:
        report.engines["البحث"] = "عبارة البحث فارغة"
        return report
    if not check_connectivity():
        report.online = False
        report.engines["الاتصال"] = "لا يوجد اتصال بالإنترنت"
        report.elapsed = time.time() - started
        return report

    lang = "ar" if re.search(r"[\u0600-\u06FF]", query) else "en"
    latin_terms_list = re.findall(r"[A-Za-z0-9_.+#-]{2,}", query)
    terms = query_terms(query)
    sentences = 7 if deep else 3

    cse_key = normalize_cse_key(settings.get("google_cse_key") or os.environ.get("GOOGLE_CSE_KEY", ""))
    cse_cx = normalize_cse_cx(settings.get("google_cse_cx") or os.environ.get("GOOGLE_CSE_CX", "") or DEFAULT_GOOGLE_CSE_CX)
    gemini_key = _resolve_gemini_key(settings)

    jobs: dict[str, callable] = {}
    want_google = not requested or "google" in requested
    want_wiki = not requested or bool({"wiki", "wikipedia"} & requested)

    collected: list[SearchHit] = []

    # Google first when requested or by default
    if want_google:
        try:
            engine_name, kind, payload = execute_google_search(query, cse_key, cse_cx, gemini_key, lang, limit)
            if kind == "hits":
                collected.extend(payload)
                report.engines[engine_name] = f"✓ {len(payload)} نتيجة"
            else:
                answer, hits = payload
                report.answer = answer
                collected.extend(hits)
                report.engines[engine_name] = f"✓ إجابة مؤسَّسة + {len(hits)} مصدر"
        except Exception as exc:
            report.engines["Google"] = str(exc)

    # Wikipedia
    if want_wiki:
        for wlang in (("ar", "en") if lang == "ar" else ("en", "ar")):
            try:
                wiki_hits = wikipedia(query, wlang, limit=min(limit, 4), sentences=sentences)
                collected.extend(wiki_hits)
                report.engines[f"ويكيبيديا ({wlang})"] = f"✓ {len(wiki_hits)} نتيجة"
            except Exception as exc:
                report.engines[f"ويكيبيديا ({wlang})"] = str(exc)

    # Fallbacks when Google failed or no hits
    if not collected and not report.answer:
        try:
            bing_hits = bing_rss(query, lang, limit)
            collected.extend(bing_hits)
            report.engines["Bing"] = f"✓ {len(bing_hits)} نتيجة"
        except Exception as exc:
            report.engines["Bing"] = str(exc)
        try:
            ddg_hits = duckduckgo(query, limit)
            collected.extend(ddg_hits)
            report.engines["DuckDuckGo"] = f"✓ {len(ddg_hits)} نتيجة"
        except Exception as exc:
            report.engines["DuckDuckGo"] = str(exc)

    latin_terms = [normalize(t) for t in latin_terms_list] if latin_terms_list else None
    report.hits, report.dropped = _filter_and_rank(collected, terms, latin_terms)
    report.elapsed = time.time() - started
    return report


def write_learning_file(topic: str, report: SearchReport, folder: str) -> Path:
    """اكتب ملفاً للمراجعة اليدوية قبل حفظه في المكتبة."""
    out = Path(folder) / "web-learning"
    out.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w\u0600-\u06FF-]+", "_", topic)[:80] or "topic"
    path = out / f"{safe}_{int(time.time())}.md"
    lines = [f"# {topic}", "", f"استعلام: {report.query}", f"الوقت: {report.elapsed:.1f}s", ""]
    if report.answer:
        lines += ["## ملخص", report.answer, ""]
    lines.append("## مصادر")
    for hit in report.hits:
        lines += [f"### {hit.title}", f"- المحرك: {hit.engine_label}", f"- الصلة: {hit.relevance}", f"- الرابط: {hit.url}", "", hit.snippet, ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
