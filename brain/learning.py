"""تعلّم المعنى لا النص: قواعد كلمات قصيرة ومرادفات ونقاط جهل معرفية.

عندما يقول المستخدم «تعلّم أن كلمة جيد تعني جيد أو تمام، وعندما أقول تمام ردّ بجيد»
نخزّن قاعدة قصيرة (تمام ← جيد) وليس الجملة كاملة. لاحقاً عند قوله «تمام» يكتب
الوكيل «جيد» فقط. المعلومات الوصفية الطويلة تبقى حقائق عادية في قاعدة المعرفة.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher

from brain.language import collapse_repeats, normalize

_SCHEMA = """
CREATE TABLE IF NOT EXISTS phrase_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trigger_norm TEXT NOT NULL UNIQUE,
    trigger_raw TEXT NOT NULL,
    reply TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'reply',      -- reply | alias
    hits INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS knowledge_gaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query_norm TEXT NOT NULL UNIQUE,
    query TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    resolved INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT DEFAULT (datetime('now'))
);
"""

_PUNCT = re.compile(r"[\s\.\,\!\?\؟،؛:;\"'«»()\[\]{}…\-_]+")
_QUOTES = " \t\"'«»“”‘’`.,:;،؛!؟?"


def _clean_term(value: str) -> str:
    value = value.strip(_QUOTES)
    value = re.sub(r"^(?:كلمة|كلمه|عبارة|عباره|مصطلح|word|phrase|term)\s+", "", value, flags=re.IGNORECASE).strip(_QUOTES)
    value = re.sub(r"\s+(?:فقط|بس|لا غير|only)$", "", value, flags=re.IGNORECASE).strip(_QUOTES)
    return value


def _compare_key(text: str) -> str:
    return _PUNCT.sub(" ", collapse_repeats(normalize(text))).strip()


@dataclass
class TeachingResult:
    kind: str                       # reply | alias | forget
    pairs: list[tuple[str, str]]    # (trigger, reply_or_meaning)
    summary: str


# ── أنماط التعليم ────────────────────────────────────────────────────────────
_WHEN = r"(?:عندما|عندما|لما|لمّا|حين|حينما|اذا|إذا|كلما|when|if|whenever)"
_SAY = r"(?:اقول|أقول|قلت|اكتب|أكتب|ارسلت|أرسلت|يقول|قال|say|i say|i type|i write)"
_MUST = (
    r"(?:(?:يجب|لازم|عليك|فعليك|ينبغي|لا بد|must|should)(?:\s+(?:ان|أن|that))?(?:\s+(?:ترد|تقول|تجيب|تكتب|reply|respond|answer|say))?"
    r"|ترد|رد|تقول|قل|قول|اجب|أجب|تجيب|اكتب|reply|respond|answer|say)"
)
_BY = r"(?:\s+(?:ب|بـ|بكلمة|بعبارة|بقول|with|by|:))?"
_REPLY_RULE = re.compile(
    _WHEN + r"\s+" + _SAY + r"\s+(?P<trigger>.+?)\s+" + _MUST + _BY + r"\s+(?P<reply>.+?)\s*(?:فقط|بس|only)?\s*[.!؟?]*\s*$",
    re.IGNORECASE,
)
_REPLY_RULE_ANYWHERE = re.compile(
    _WHEN + r"\s+" + _SAY + r"\s+(?P<trigger>.+?)\s+" + _MUST + _BY + r"\s+(?P<reply>[^\s،,.؟?!]+(?:\s+[^\s،,.؟?!]+){0,3})",
    re.IGNORECASE,
)
_MEANS = r"(?:تعني|يعني|معناها|معناه|تساوي|مرادفة لـ?|مرادف لـ?|هي نفسها|هو نفسه|means|equals|is the same as)"
_MEANING = re.compile(
    r"^(?:(?:تعلم|تعلّم|اعلم|احفظ|تذكر|سجل|خذ بعلمك|learn|remember)\s*(?:ان|أن|that)?\s*)?"
    r"(?P<term>.+?)\s+" + _MEANS + r"\s+(?P<meaning>.+?)\s*[.!؟?]*\s*$",
    re.IGNORECASE,
)
_SPLIT_ALTS = re.compile(r"\s*(?:\bاو\b|\bأو\b|\bor\b|،|,|/|\||\s+و(?=\S)|\s+and\s+)\s*", re.IGNORECASE)
_FORGET = re.compile(
    r"^(?:انس[ىي]?|إنس[ىي]?|احذف|امسح|forget|delete)\s+(?:(?:كلمة|كلمه|قاعدة|قاعده|عبارة|عباره|رد)\s+)?(?P<trigger>.+?)\s*[.!؟?]*$",
    re.IGNORECASE,
)
# رسالة لا يجوز اعتبارها تعليماً للمعنى: أسئلة وأوامر تقنية
_NOT_TEACHING = re.compile(r"^(?:ما|ماذا|هل|كيف|لماذا|what|why|how|is|does)\b", re.IGNORECASE)


def parse_teaching(text: str) -> TeachingResult | None:
    """Return the learned meaning (short mapping) or None if this is not a meaning-teaching message."""
    raw = re.sub(r"\s+", " ", str(text or "")).strip()
    if not raw:
        return None

    forget = _FORGET.match(raw)
    if forget:
        trigger = _clean_term(forget.group("trigger"))
        if trigger and len(trigger.split()) <= 4:
            return TeachingResult("forget", [(trigger, "")], f"نسيت قاعدة «{trigger}»")

    pairs: list[tuple[str, str]] = []
    kind = "reply"

    # 1) «عندما أقول X يجب أن ترد Y» — قاعدة ردّ صريحة (قد تكون بعد جملة تعريف)
    match = _REPLY_RULE.search(raw) or _REPLY_RULE_ANYWHERE.search(raw)
    if match:
        trigger, reply = _clean_term(match.group("trigger")), _clean_term(match.group("reply"))
        if trigger and reply and len(trigger.split()) <= 5 and len(reply.split()) <= 6:
            pairs.append((trigger, reply))

    # 2) «كلمة X تعني Y أو Z» — إن ذُكرت X ضمن معانيها فهي الكلمة الأساس والبقية مرادفات تُجاب بها
    meaning_source = raw[: match.start()].strip(" ،,.") if match else raw
    mean = _MEANING.match(meaning_source) if meaning_source else None
    if mean and not _NOT_TEACHING.match(raw):
        term = _clean_term(mean.group("term"))
        alternatives = [_clean_term(p) for p in _SPLIT_ALTS.split(mean.group("meaning")) if _clean_term(p)]
        if term and alternatives and len(term.split()) <= 4 and all(len(a.split()) <= 5 for a in alternatives):
            term_key = _compare_key(term)
            if any(_compare_key(a) == term_key for a in alternatives):
                for alt in alternatives:
                    if _compare_key(alt) != term_key:
                        pairs.append((alt, term))
            elif not pairs:
                kind = "alias"
                pairs.append((term, alternatives[0]))

    # لا تكرار لنفس الزوج
    unique: list[tuple[str, str]] = []
    seen = set()
    for trigger, reply in pairs:
        key = (_compare_key(trigger), _compare_key(reply))
        if key[0] and key[0] != key[1] and key not in seen:
            seen.add(key)
            unique.append((trigger, reply))
    if not unique:
        return None
    arrow = "، ".join(f"«{a}» ← «{b}»" for a, b in unique)
    return TeachingResult(kind, unique, arrow)


class PhraseMemory:
    """Short learned mappings stored beside the knowledge base (same SQLite file)."""

    def __init__(self, kb):
        self.kb = kb
        self._conn().executescript(_SCHEMA)
        self._conn().commit()

    def _conn(self):
        return self.kb._connect()

    # ── قواعد الكلمات ──
    def learn(self, trigger: str, reply: str, kind: str = "reply") -> None:
        key = _compare_key(trigger)
        if not key or not reply.strip():
            return
        conn = self._conn()
        conn.execute(
            "INSERT INTO phrase_rules (trigger_norm, trigger_raw, reply, kind) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(trigger_norm) DO UPDATE SET trigger_raw=excluded.trigger_raw, reply=excluded.reply, kind=excluded.kind",
            (key, trigger.strip(), reply.strip(), kind),
        )
        conn.commit()

    def forget(self, trigger: str) -> bool:
        conn = self._conn()
        cur = conn.execute("DELETE FROM phrase_rules WHERE trigger_norm = ?", (_compare_key(trigger),))
        conn.commit()
        return cur.rowcount > 0

    def list_rules(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT trigger_raw, reply, kind, hits FROM phrase_rules ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]

    def match(self, message: str, kind: str | None = None) -> dict | None:
        """Exact (punctuation/repeat-insensitive) match; a single-typo fuzzy match for short triggers."""
        key = _compare_key(message)
        if not key or len(key.split()) > 6:
            return None
        rows = self._conn().execute(
            "SELECT id, trigger_norm, trigger_raw, reply, kind FROM phrase_rules"
            + (" WHERE kind = ?" if kind else ""), (kind,) if kind else ()).fetchall()
        best = None
        for row in rows:
            if row["trigger_norm"] == key:
                best = row
                break
            if len(key) >= 4 and SequenceMatcher(None, key, row["trigger_norm"]).ratio() >= 0.9:
                best = best or row
        if not best:
            return None
        self._conn().execute("UPDATE phrase_rules SET hits = hits + 1 WHERE id = ?", (best["id"],))
        self._conn().commit()
        return {"trigger": best["trigger_raw"], "reply": best["reply"], "kind": best["kind"]}

    def apply_aliases(self, text: str) -> tuple[str, list[tuple[str, str]]]:
        """Replace learned alias terms by their meaning inside a longer message (meaning-only learning)."""
        rows = self._conn().execute(
            "SELECT trigger_raw, trigger_norm, reply FROM phrase_rules WHERE kind = 'alias'").fetchall()
        applied: list[tuple[str, str]] = []
        result = text
        for row in sorted(rows, key=lambda r: -len(r["trigger_raw"])):
            pattern = re.compile(r"(?<![\w\u0600-\u06FF])" + re.escape(row["trigger_raw"]) + r"(?![\w\u0600-\u06FF])", re.IGNORECASE)
            if pattern.search(result):
                result = pattern.sub(row["reply"], result)
                applied.append((row["trigger_raw"], row["reply"]))
        return result, applied

    # ── فجوات المعرفة ──
    def record_gap(self, query: str) -> None:
        key = _compare_key(query)
        if len(key) < 3:
            return
        conn = self._conn()
        conn.execute(
            "INSERT INTO knowledge_gaps (query_norm, query) VALUES (?, ?) "
            "ON CONFLICT(query_norm) DO UPDATE SET count = count + 1, resolved = 0, last_seen = datetime('now')",
            (key, query.strip()[:200]),
        )
        conn.commit()

    def top_gaps(self, limit: int = 3) -> list[str]:
        rows = self._conn().execute(
            "SELECT query FROM knowledge_gaps WHERE resolved = 0 ORDER BY count DESC, last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [r["query"] for r in rows]

    def resolve_gap(self, query: str) -> None:
        conn = self._conn()
        conn.execute("UPDATE knowledge_gaps SET resolved = 1 WHERE query_norm = ?", (_compare_key(query),))
        conn.commit()
