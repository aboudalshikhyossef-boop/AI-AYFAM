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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from brain.language import clean_search_query, normalize, wants_source

try:  # requests اختيارية: نعود إلى عميل المكتبة القياسية
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None

from utils import http_client

USER_AGENT = "AI-AYFAM/9.0 (https://github.com/aboudalshikhyossef-boop/AI-AYFAM; local security assistant)"
GEMINI_MODELS = ("gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-flash-latest")
TIMEOUT = 9

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
    engine: str                    # google | wikipedia-ar | wikipedia-en | duckduckgo
    relevance: float = 0.0
    lang: str = ""

    @property
    def engine_label(self) -> str:
        return {"google": "Google", "google-cse": "Google", "wikipedia-ar": "ويكيبيديا (عربي)",
                "wikipedia-en": "Wikipedia (EN)", "duckduckgo": "DuckDuckGo"}.get(self.engine, self.engine)


@dataclass
class SearchReport:
    query: str
    hits: list[SearchHit] = field(default_factory=list)
    answer: str = ""                                   # ملخص مؤسَّس من Google إن وُجد
    engines: dict[str, str] = field(default_factory=dict)
    online: bool = True
    elapsed: float = 0.0
    dropped: int = 0                                   # نتائج حُذفت لعدم الصلة

    @property
    def ok(self) -> bool:
        return bool(self.hits or self.answer)


# ── أدوات HTTP ──────────────────────────────────────────────────────────────
def _get_json(url: str, params: dict | None = None, headers: dict | None = None) -> dict:
    merged = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    merged.update(headers or {})
    response = http_client.get(url, headers=merged, params=params, timeout=TIMEOUT)
    if response.status_code != 200:
        raise RuntimeError(f"HTTP {response.status_code}")
    return response.json()


def check_connectivity() -> bool:
    """اتصال حقيقي سريع (ويكيبيديا مستقرة وخفيفة)."""
    try:
        _get_json("https://en.wikipedia.org/w/api.php", {"action": "query", "meta": "siteinfo", "format": "json"})
        return True
    except Exception:
        return False


# ── ويكيبيديا ───────────────────────────────────────────────────────────────
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


# ── Google ──────────────────────────────────────────────────────────────────
def google_cse(query: str, key: str, cx: str, lang: str, limit: int = 6) -> list[SearchHit]:
    data = _get_json("https://www.googleapis.com/customsearch/v1", {
        "key": key, "cx": cx, "q": query, "num": min(limit, 10), "hl": lang, "lr": f"lang_{lang}" if lang in ("ar", "en") else None,
    })
    return [SearchHit(item.get("title", ""), item.get("link", ""), re.sub(r"\s+", " ", item.get("snippet", "")).strip(), "google-cse", lang=lang)
            for item in data.get("items", []) if item.get("link")]


def google_grounded(query: str, api_key: str, lang: str) -> tuple[str, list[SearchHit]]:
    """بحث Google الحقيقي عبر أداة التأريض في Gemini؛ يعيد ملخصاً مع روابط المصادر."""
    last_error = "لا نموذج متاح"
    prompt = (
        f"ابحث في Google عن: {query}\n"
        f"أجب بإيجاز ودقة بـ{'العربية' if lang == 'ar' else 'English'} في 4 إلى 6 أسطر اعتماداً على نتائج البحث فقط، "
        "دون اختلاق معلومات. إن لم تجد نتائج مطابقة قل ذلك صراحة."
    )
    body = {"contents": [{"parts": [{"text": prompt}]}], "tools": [{"googleSearch": {}}], "generationConfig": {"temperature": 0.1}}
    for model in GEMINI_MODELS:
        try:
            response = http_client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                headers={"x-goog-api-key": api_key, "Content-Type": "application/json", "User-Agent": USER_AGENT},
                json_data=body, timeout=25,
            )
            if response.status_code != 200:
                last_error = f"{model}: HTTP {response.status_code}"
                if response.status_code in (400, 401, 403):
                    break
                continue
            candidate = (response.json().get("candidates") or [{}])[0]
            answer = "".join(part.get("text", "") for part in (candidate.get("content") or {}).get("parts", [])).strip()
            meta = candidate.get("groundingMetadata") or {}
            chunks = meta.get("groundingChunks") or []
            snippets: dict[int, list[str]] = {}
            for support in meta.get("groundingSupports") or []:
                text = (support.get("segment") or {}).get("text", "")
                for index in support.get("groundingChunkIndices") or []:
                    snippets.setdefault(index, []).append(text)
            hits = []
            for index, chunk in enumerate(chunks):
                web = chunk.get("web") or {}
                if web.get("uri"):
                    hits.append(SearchHit(web.get("title") or urllib.parse.urlparse(web["uri"]).netloc, web["uri"],
                                          " ".join(snippets.get(index, [])[:2])[:320], "google", lang=lang))
            return answer, hits
        except Exception as exc:
            last_error = f"{model}: {exc}"
    raise RuntimeError(last_error)


def duckduckgo(query: str, limit: int = 6) -> list[SearchHit]:
    from tools import web  # الاحتياط القديم، يبقى كما هو

    rows = web._ddg_html_search(query, limit)
    return [SearchHit(r.get("title", ""), r.get("url", ""), r.get("snippet", ""), "duckduckgo") for r in rows if r.get("url")]


# ── الصلة والترتيب ──────────────────────────────────────────────────────────
_DOMAIN_WORDS = tuple(normalize(w) for w in (
    "حاسوب", "حاسب", "حوسبة", "شبكة", "شبكات", "أمن", "امن", "حماية", "برمجيات", "نظام", "لينكس", "خادم", "بروتوكول",
    "computer", "network", "security", "software", "linux", "protocol", "firewall", "vulnerability", "server", "malware",
))


def _words(text: str) -> set[str]:
    return {_stem(w) for w in re.findall(r"[a-z0-9]+|[\u0600-\u06FF]+", normalize(text))}


def score_hit(hit: SearchHit, terms: list[str], latin_terms: list[str] | None = None) -> float:
    """نسبة الكلمات المطلوبة الموجودة (العنوان وزنه أعلى). نتائج الإنجليزية تُقاس بالكلمات اللاتينية فقط."""
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
    # ترتيب مستقر: يحافظ على ترتيب المحرك الأصلي عند تساوي الصلة
    kept.sort(key=lambda h: -(h.relevance + _domain_boost(h)))
    return kept, dropped


def _resolve_gemini_key(settings: dict | None) -> str:
    try:
        from engine.gemini_cti import resolve_api_key

        return resolve_api_key((settings or {}).get("gemini_api_key", "")) or ""
    except Exception:
        return (settings or {}).get("gemini_api_key", "") or os.environ.get("GEMINI_API_KEY", "")


# ── الواجهة الرئيسية ────────────────────────────────────────────────────────
def search(raw_query: str, settings: dict | None = None, limit: int = 6, deep: bool = False) -> SearchReport:
    """بحث دقيق بعبارة المستخدم الكاملة. لا يرفع استثناءً: الحالة تُسجَّل لكل محرك."""
    started = time.time()
    settings = settings or {}
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
    latin_terms = " ".join(re.findall(r"[A-Za-z0-9_.+#-]{2,}", query))
    terms = query_terms(query)
    sentences = 7 if deep else 3

    cse_key = settings.get("google_cse_key") or os.environ.get("GOOGLE_CSE_KEY", "")
    cse_cx = settings.get("google_cse_cx") or os.environ.get("GOOGLE_CSE_CX", "")
    gemini_key = _resolve_gemini_key(settings)

    jobs: dict[str, callable] = {}
    want_google = not requested or "google" in requested
    want_wiki = not requested or "wikipedia" in requested
    if want_google:
        if cse_key and cse_cx:
            jobs["Google (CSE)"] = lambda: ("hits", google_cse(query, cse_key, cse_cx, lang, limit))
        elif gemini_key:
            jobs["Google (Gemini)"] = lambda: ("grounded", google_grounded(query, gemini_key, lang))
        else:
            report.engines["Google"] = "غير مفعّل: أضف مفتاح Gemini أو Google CSE من الإعدادات"
    if want_wiki:
        jobs[f"ويكيبيديا ({lang})"] = lambda: ("hits", wikipedia(query, lang, limit, sentences))
        if lang == "ar" and latin_terms and latin_terms.lower() != query.lower():
            jobs["Wikipedia (en)"] = lambda: ("hits", wikipedia(latin_terms, "en", 3, sentences))
        elif lang == "en":
            pass

    collected: list[SearchHit] = []
    with ThreadPoolExecutor(max_workers=max(1, len(jobs))) as pool:
        futures = {pool.submit(job): name for name, job in jobs.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                kind, payload = future.result()
                if kind == "grounded":
                    answer, hits = payload
                    report.answer = answer
                    collected.extend(hits)
                    report.engines[name] = f"يعمل — {len(hits)} مصدر"
                else:
                    collected.extend(payload)
                    report.engines[name] = f"يعمل — {len(payload)} نتيجة"
            except Exception as exc:
                report.engines[name] = f"فشل: {str(exc)[:90]}"

    google_ok = any(h.engine.startswith("google") for h in collected) or bool(report.answer)
    if not google_ok and want_google and not requested - {"google"}:
        try:
            ddg = duckduckgo(query, limit)
            collected.extend(ddg)
            report.engines["DuckDuckGo احتياط"] = f"يعمل — {len(ddg)} نتيجة" if ddg else "لا نتائج"
        except Exception as exc:
            report.engines["DuckDuckGo احتياط"] = f"فشل: {str(exc)[:60]}"

    latin_stems = [_stem(t) for t in latin_terms.split()] or None
    report.hits, report.dropped = _filter_and_rank(collected, terms, latin_stems)
    if want_wiki and len(report.hits) < 2:
        # ويكيبيديا تطابق العبارات الطويلة بصرامة؛ نوسّع تدريجياً ثم نعيد التقييم على العبارة الأصلية الكاملة.
        raw = [w for w in re.findall(r"[A-Za-z0-9_.+#-]+|[\u0600-\u06FF]+", query) if normalize(w) not in _STOPWORDS]
        variants = []
        for words in (raw[:-1], raw[:2], raw[:1]):
            text = " ".join(words)
            if text and text != query and text not in variants and len(raw) > 1:
                variants.append(text)
        extra = []
        for variant in variants:
            try:
                extra.extend(wikipedia(variant, lang, limit, sentences))
            except Exception:
                continue
            ranked, _ = _filter_and_rank(collected + extra, terms, latin_stems)
            if len(ranked) >= 3:
                break
        if extra:
            collected.extend(extra)
            report.hits, report.dropped = _filter_and_rank(collected, terms, latin_stems)
            for name in list(report.engines):
                if name.startswith("ويكيبيديا") and report.engines[name].startswith("يعمل"):
                    report.engines[name] += " (بعد توسيع البحث)"
    report.hits = report.hits[: limit + 2]
    report.elapsed = time.time() - started
    return report


# ── التعلّم من الإنترنت: ملف للمراجعة ───────────────────────────────────────
def slugify(text: str) -> str:
    value = re.sub(r"[^\w\u0600-\u06FF]+", "-", text, flags=re.UNICODE).strip("-")
    return value[:48] or "topic"


def build_learning_markdown(topic: str, report: SearchReport) -> str:
    lines = [f"# {topic}", "", f"> جُمعت من الإنترنت بتاريخ {time.strftime('%Y-%m-%d %H:%M')} — للمراجعة قبل الاعتماد.", ""]
    if report.answer:
        lines += ["## ملخص (Google)", "", report.answer, ""]
    for hit in report.hits:
        lines += [f"## {hit.title}", f"*المصدر: {hit.engine_label}* — {hit.url}", "", hit.snippet, ""]
    lines += ["## حالة المحركات", ""] + [f"- {name}: {status}" for name, status in report.engines.items()]
    return "\n".join(lines).strip() + "\n"


def write_learning_file(topic: str, report: SearchReport, directory: str | os.PathLike) -> Path:
    folder = Path(directory) / "learning"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{slugify(topic)}_{time.strftime('%Y%m%d_%H%M%S')}.md"
    path.write_text(build_learning_markdown(topic, report), encoding="utf-8")
    return path
