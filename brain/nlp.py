"""
AI AYFAM — NLP Engine (بدون API خارجي)
يفهم العربية والإنجليزية — يستخرج النية والكيانات

ملاحظة صادقة: هذا محرّك قائم على قواعد + تشابه نصي (Jaccard) + الآن أيضاً
تسامح مع الأخطاء الإملائية البسيطة (fuzzy matching عبر difflib). إنه ليس
نموذج ذكاء اصطناعي/LLM حقيقياً — بل مطابقة أنماط محلية أذكى من مجرد
substring matching، تعمل بالكامل دون اتصال بالإنترنت أو أي خدمة خارجية.
"""

import re
from difflib import SequenceMatcher
from typing import Optional

# ─── Arabic normalization helpers ────────────────────────────────────────────
_AR_NORM = str.maketrans("أإآى", "اااي")  # normalize hamza variants + alef maksura

def _normalize(text: str) -> str:
    return text.lower().translate(_AR_NORM).strip()

# ─── Entity Extraction Patterns ──────────────────────────────────────────────
_IP_RE    = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_CVE_RE   = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
_URL_RE   = re.compile(r'https?://[^\s]+|(?:www\.)[^\s]+', re.IGNORECASE)
_PORT_RE  = re.compile(r'\b(?:port|منفذ|البورت)[\s:]+(\d{1,5})\b|\b(\d{2,5})/(?:tcp|udp)\b', re.IGNORECASE)
_MAC_RE   = re.compile(r'\b([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b')
_DOMAIN_RE = re.compile(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', re.IGNORECASE)
_FILEPATH_RE = re.compile(
    r'"([^"]+\.(?:pdf|txt|md|markdown))"'
    r"|'([^']+\.(?:pdf|txt|md|markdown))'"
    r'|((?:~|\.{0,2}/)[^\s"\']+\.(?:pdf|txt|md|markdown))',
    re.IGNORECASE
)
_PKG_TRIGGER_RE = re.compile(r'(?:حزمة|package|pkg|مكتبة|library|osv)', re.IGNORECASE)

# ─── Command Keywords for free-form input ────────────────────────────────────
_EXPLAIN_TRIGGERS = [
    "اشرح", "ما هو", "ما معنى", "ماذا يعني", "define", "what is",
    "explain", "tell me about", "أخبرني عن", "وصف", "describe",
    "ما هي", "كيف يعمل", "how does", "what does"
]

_ANALYZE_TRIGGERS = [
    "حلل", "analyze", "analyse", "فحص", "scan", "check", "افحص",
    "راجع", "review", "inspect", "تحقق"
]

_FIX_TRIGGERS = [
    "إصلاح", "أصلح", "fix", "repair", "علاج", "حل", "solve", "patch"
]

_SEARCH_TRIGGERS = [
    "ابحث", "بحث", "search", "find", "ابحث عن", "جد", "look for"
]

_TEACH_TRIGGERS = [
    "تعلم أن", "اعلم أن", "اعرف أن", "تذكر أن", "خذ بعلمك أن", "سجل أن",
    "remember that", "note that", "keep in mind that", "learn that",
]


def _fuzzy_ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _fuzzy_token_overlap(tokens_a: set, tokens_b: set):
    """تطابق تقريبي يتسامح مع الأخطاء الإملائية البسيطة (حرف زائد/ناقص/مبدَّل).
    يُستخدم فقط كطبقة احتياطية عندما لا يوجد تطابق تام — لا يُبطئ الحالة
    الشائعة (تطابق تام) ولا يُضعِف دقتها."""
    exact = tokens_a & tokens_b
    if exact:
        return exact, 0.0
    remaining_a = tokens_a - exact
    remaining_b = tokens_b - exact
    fuzzy_credit = 0.0
    used_b = set()
    for ta in remaining_a:
        if len(ta) < 3:
            continue  # كلمات قصيرة جداً غير موثوقة للمطابقة التقريبية
        best_tb, best_ratio = None, 0.0
        for tb in remaining_b - used_b:
            if len(tb) < 3 or abs(len(ta) - len(tb)) > 2:
                continue
            ratio = _fuzzy_ratio(ta, tb)
            if ratio > best_ratio:
                best_ratio, best_tb = ratio, tb
        if best_tb and best_ratio >= 0.82:
            fuzzy_credit += 0.7  # وزن أقل من التطابق التام حتى لا يتفوّق عليه
            used_b.add(best_tb)
    return exact, fuzzy_credit


def _fuzzy_contains(haystack_tokens: list, needle: str, threshold: float = 0.82) -> bool:
    """هل تحتوي الجملة على كلمة قريبة جداً من needle (تسامح مع خطأ إملائي واحد)؟"""
    if len(needle) < 3:
        return False
    for tok in haystack_tokens:
        if len(tok) < 3 or abs(len(tok) - len(needle)) > 2:
            continue
        if _fuzzy_ratio(tok, needle) >= threshold:
            return True
    return False


class ParsedCommand:
    """نتيجة تحليل الأمر الطبيعي"""
    def __init__(self):
        self.intent: Optional[str] = None
        self.score: float = 0.0
        self.entities: dict = {}
        self.raw_input: str = ""
        self.normalized: str = ""
        self.sub_action: Optional[str] = None
        self.explain_target: Optional[str] = None

    def __repr__(self):
        return f"<ParsedCommand intent={self.intent} score={self.score:.2f} entities={self.entities}>"


class NLPEngine:
    def __init__(self, knowledge_base=None):
        self.kb = knowledge_base
        self._intents = []
        self._load_intents()

    def _load_intents(self):
        if self.kb:
            self._intents = self.kb.get_intents()
        else:
            from brain.knowledge_base import SEED_INTENTS
            self._intents = SEED_INTENTS

    def reload_intents(self):
        self._load_intents()

    # ─── Main Parse ─────────────────────────────────────────────────────────
    def parse(self, user_input: str) -> ParsedCommand:
        cmd = ParsedCommand()
        cmd.raw_input = user_input
        cmd.normalized = _normalize(user_input)

        # Extract entities first
        cmd.entities = self._extract_entities(user_input)

        # Detect "teach" intent — صياغة صريحة جداً فتُعطى أولوية قصوى قبل أي
        # منطق آخر. نستخرج نص الحقيقة من النص الأصلي (وليس المُطبَّع) للحفاظ
        # على حالة الأحرف الأصلية؛ التطبيع لا يغيّر طول النص فيبقى الموضع متطابقاً.
        for trigger in _TEACH_TRIGGERS:
            trig_norm = _normalize(trigger)
            idx = cmd.normalized.find(trig_norm)
            if idx != -1:
                fact_start = idx + len(trig_norm)
                fact = user_input[fact_start:].strip(" :،,.\n")
                if fact:
                    cmd.intent = "teach"
                    cmd.score = 0.95
                    cmd.entities["fact"] = fact
                    return cmd

        # Detect explain intent early (تطابق تام أولاً)
        for trigger in _EXPLAIN_TRIGGERS:
            if trigger in cmd.normalized:
                cmd.intent = "explain"
                cmd.score = 0.9
                # What to explain?
                cmd.explain_target = cmd.normalized
                for t in _EXPLAIN_TRIGGERS:
                    cmd.explain_target = cmd.explain_target.replace(t, "").strip()
                return cmd

        # طبقة احتياطية: تسامح مع خطأ إملائي واحد في محفّزات الشرح المكوّنة
        # من كلمة واحدة (مثال: "اشرحلي" أو "اكسبلين" لن تُغطّى، لكن "اشرج"
        # بدل "اشرح" ستُفهم).
        input_tokens = re.findall(r"[\w\u0600-\u06FF]+", cmd.normalized, flags=re.UNICODE)
        for trigger in _EXPLAIN_TRIGGERS:
            if " " not in trigger and _fuzzy_contains(input_tokens, trigger):
                cmd.intent = "explain"
                cmd.score = 0.75
                cmd.explain_target = cmd.normalized
                return cmd

        # Score all intents
        best_intent, best_score = self._score_intents(cmd.normalized)

        # Check entity-based overrides
        if cmd.entities.get("cve") and best_score < 0.7:
            best_intent = "cve_search"
            best_score = 0.85
        elif cmd.entities.get("concept_a") and cmd.entities.get("concept_b") and best_score < 0.7:
            best_intent = "concept_link"
            best_score = 0.85
        elif cmd.entities.get("book_title") and best_score < 0.6:
            best_intent = "summarize_doc"
            best_score = 0.8
        elif cmd.entities.get("concept") and best_score < 0.6:
            best_intent = "concept_explore"
            best_score = 0.8
        elif cmd.entities.get("package") and best_score < 0.6:
            best_intent = "pkg_vuln_search"
            best_score = 0.8
        elif cmd.entities.get("ip") and best_score < 0.5:
            best_intent = "check_ip"
            best_score = 0.75
        elif cmd.entities.get("url") and best_score < 0.6:
            best_intent = "scan_website"
            best_score = 0.8

        cmd.intent = best_intent
        cmd.score = best_score

        # Sub-action hints
        if any(t in cmd.normalized for t in _FIX_TRIGGERS):
            cmd.sub_action = "fix"
        elif any(t in cmd.normalized for t in _SEARCH_TRIGGERS):
            cmd.sub_action = "search"

        # Track in KB
        if self.kb and best_intent and best_score > 0.3:
            self.kb.increment_intent(best_intent)

        return cmd

    # ─── Intent Scoring ──────────────────────────────────────────────────────
    def _score_intents(self, normalized: str):
        """Hybrid scorer: exact-phrase + Jaccard token overlap + usage-frequency boost.
        Unicode-aware tokenizer handles Arabic correctly (plain \\w in default re excludes some)."""
        best_intent = None
        best_score = 0.0

        # Unicode-friendly token regex — includes Arabic block U+0600-U+06FF
        token_re = re.compile(r"[\w\u0600-\u06FF]+", flags=re.UNICODE)
        tokens = set(token_re.findall(normalized))

        # Usage-frequency boost: intents the user picks often get a slight edge
        # (reads kb.intents.hit_count if available — falls back to no boost)
        hit_counts = {}
        if self.kb:
            try:
                rows = self.kb._connect().execute(
                    "SELECT name, hit_count FROM intents"
                ).fetchall()
                max_hits = max((r["hit_count"] for r in rows), default=0) or 1
                hit_counts = {r["name"]: r["hit_count"] / max_hits for r in rows}
            except Exception:
                pass

        for intent_name, patterns in self._intents:
            score = 0.0
            for pattern in patterns:
                pat_norm = _normalize(pattern)
                if pat_norm and pat_norm in normalized:
                    phrase_score = 0.5 + min(0.45, len(pat_norm) / 25.0)
                    score = max(score, phrase_score)
                else:
                    pat_tokens = set(token_re.findall(pat_norm))
                    if not pat_tokens:
                        continue
                    exact_hits, fuzzy_credit = _fuzzy_token_overlap(tokens, pat_tokens)
                    overlap = len(exact_hits) + fuzzy_credit
                    if overlap > 0:
                        # Jaccard-like: rewards both precision and recall
                        union = len(tokens | pat_tokens)
                        jaccard = overlap / union if union else 0
                        token_score = min(0.55, jaccard * 1.5)
                        score = max(score, token_score)
            # Usage-frequency boost — at most +0.05 so it never overrides a strong match
            score += hit_counts.get(intent_name, 0) * 0.05
            if score > best_score:
                best_score = score
                best_intent = intent_name

        return best_intent, best_score

    # ─── Entity Extraction ───────────────────────────────────────────────────
    def _extract_entities(self, text: str) -> dict:
        entities = {}

        ips = _IP_RE.findall(text)
        if ips:
            entities["ip"] = ips[0]
            entities["ips"] = ips

        cves = _CVE_RE.findall(text)
        if cves:
            entities["cve"] = cves[0].upper()
            entities["cves"] = [c.upper() for c in cves]

        urls = _URL_RE.findall(text)
        if urls:
            entities["url"] = urls[0]

        ports = []
        for m in _PORT_RE.finditer(text):
            p = m.group(1) or m.group(2)
            if p:
                ports.append(int(p))
        if ports:
            entities["port"] = ports[0]
            entities["ports"] = ports

        macs = _MAC_RE.findall(text)
        if macs:
            entities["mac"] = macs[0]

        for m in _FILEPATH_RE.finditer(text):
            path = m.group(1) or m.group(2) or m.group(3)
            if path:
                entities["filepath"] = path.strip()
                break

        # Keywords for search
        kw_match = re.search(r'(?:عن|about|for|بخصوص|حول)\s+(.+?)(?:\s|$)', text, re.IGNORECASE)
        if kw_match:
            entities["keyword"] = kw_match.group(1).strip()

        # Package name (for OSV.dev dependency-vulnerability search) — الأسماء
        # الحقيقية للحزم لاتينية دائماً (PyPI/npm/...)، لذا نلتقط آخر كلمة
        # لاتينية متبقية بعد استبعاد كلمات الزناد/الحشو الشائعة، بدل افتراض
        # ترتيب ثابت مثل "package <name>" الذي لا يغطي "package vulnerabilities
        # django" أو "check django package vulnerabilities".
        if _PKG_TRIGGER_RE.search(text):
            _pkg_stop = {
                "package", "packages", "pkg", "vulnerability", "vulnerabilities",
                "vulnerable", "osv", "library", "libraries", "check", "search",
                "for", "in", "of", "the", "dependency", "dependencies", "audit",
            }
            latin_tokens = re.findall(r"[a-zA-Z0-9_.+-]{2,}", text)
            candidates = [t for t in latin_tokens if t.lower() not in _pkg_stop]
            if candidates:
                entities["package"] = candidates[-1]

        # ربط مفهومين (اربط بين X و Y) — لا بد من التقاطهما معاً قبل أي
        # تقسيم آخر للنص، لأن كل طرف قد يحتوي مسافات (عبارة لا كلمة واحدة)
        link_match = re.search(
            r'(?:اربط بين|الرابط بين|العلاقة بين|link between|relation(?:ship)? between|connection between)'
            r'\s+(.+?)\s+(?:و|and|with)\s+(.+?)(?:[\?\.]|$)',
            text, re.IGNORECASE
        )
        if link_match:
            entities["concept_a"] = link_match.group(1).strip()
            entities["concept_b"] = link_match.group(2).strip()

        # استكشاف مفهوم واحد (اشرح مفهوم X / ما هو مفهوم X)
        concept_match = re.search(
            r'(?:اشرح مفهوم|ما هو مفهوم|مفهوم|explain concept|concept of|what is the concept of)\s+(.+?)(?:[\?\.]|$)',
            text, re.IGNORECASE
        )
        if concept_match and "concept_a" not in entities:
            entities["concept"] = concept_match.group(1).strip()

        # تلخيص كتاب محدد (لخص كتاب X / summarize book X) — يتطلب ذكر
        # "كتاب/book" صراحةً لتفادي التقاط أي "لخص" عام لا علاقة له بمكتبة
        book_match = re.search(
            r'(?:لخص كتاب|لخص الكتاب|ملخص كتاب|summarize book|summarize the book)\s+(.+?)(?:[\?\.]|$)',
            text, re.IGNORECASE
        )
        if book_match:
            entities["book_title"] = book_match.group(1).strip()

        # GitHub repo pattern
        repo_match = re.search(r'([a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+)', text)
        if repo_match:
            entities["repo"] = repo_match.group(1)

        return entities

    # ─── Explanation ─────────────────────────────────────────────────────────
    def explain(self, target: str) -> str:
        if not self.kb:
            return f"لا تتوفر قاعدة معرفة لشرح: {target}"

        sections = []

        # 0) هل هذا سؤال عن أداة معروفة (nmap, ping, curl...)؟ إن كان كذلك،
        #    أعطِ أولوية قصوى للمعرفة المُهيكَلة (structured) المستخرجة من
        #    كتبك عن هذه الأداة تحديداً — أدق بكثير من بحث نصي عام.
        from brain.tech_extractor import KNOWN_TOOLS, detect_tool_in_text
        tool_hit = detect_tool_in_text(target)
        if tool_hit:
            tool_knowledge = self.kb.get_tool_knowledge(tool_hit, limit=6)
            base_desc = KNOWN_TOOLS.get(tool_hit, "")
            lines = [f"🔧 الأداة: {tool_hit}" + (f" — {base_desc} (من قاموسي الأساسي)" if base_desc else "")]
            commands = [r for r in tool_knowledge if r.get("command_text")]
            contexts = [r for r in tool_knowledge if not r.get("command_text")]
            if commands:
                lines.append(f"\n📖 أوامر فعلية من كتبك لهذه الأداة تحديداً:")
                for r in commands[:5]:
                    loc = f" ({r['page_hint']})" if r.get("page_hint") else ""
                    lines.append(f"  $ {r['command_text']}\n    — من: «{r['doc_title']}»{loc}")
            elif contexts:
                r = contexts[0]
                loc = f" ({r['page_hint']})" if r.get("page_hint") else ""
                lines.append(f"\n📖 من كتابك «{r['doc_title']}»{loc}:\n  {r['context_snippet']}")
            else:
                lines.append(
                    "\nلم أجد بعد أي شرح لهذه الأداة في كتبك — علّمني كتاباً "
                    "يذكرها (بقول 'تعلم من ملف <المسار>') لأتعلم استخداماتها الفعلية."
                )
            sections.append("\n".join(lines))

        # 1) قاعدة المعرفة المدمجة + ما علّمك إياه المستخدم سابقاً (نفس الجدول،
        #    لكن نميّز المصدر عند العرض حتى يعرف المستخدم من أين أتت الإجابة).
        results = self.kb.search_knowledge(target, limit=3)
        if results:
            lines = [f"🔍 وجدت في معرفتي عن '{target}':\n"]
            for r in results:
                if r.get("source") == "user":
                    origin = "💬 مما علّمتني إياه سابقاً"
                elif r.get("source") == "self_learned":
                    origin = "🧠 تعلّمتها ذاتياً من تكرار سابق"
                else:
                    origin = f"📚 [{r['category'].upper()}]"
                lines.append(f"  {origin} — {r['key']}\n  {r['content']}\n")
            sections.append("\n".join(lines))

        # 2) المكتبة الشخصية (كتب/ملفات علّمتها للأداة عبر 'تعلم من ملف')
        #    — نتخطّى هذا إن كان القسم (0) أعلاه قد استخرج أوامر فعلية
        #    بالفعل لنفس الأداة، تفادياً لعرض نفس المقطع مرتين بلا فائدة.
        skip_generic_library = bool(tool_hit and commands)
        lib_results = [] if skip_generic_library else self.kb.search_library(target, limit=3)
        if lib_results:
            lines = [f"📖 وجدت في الكتب/الملفات التي علّمتني إياها:\n"]
            for r in lib_results:
                loc = f" ({r['page_hint']})" if r.get("page_hint") else ""
                excerpt = r["content"][:400].strip()
                if len(r["content"]) > 400:
                    excerpt += "…"
                lines.append(f"  📄 من: «{r['title']}»{loc}\n  {excerpt}\n")
            sections.append("\n".join(lines))
        elif not skip_generic_library:
            # لا نتائج من البحث الحرفي (FTS5) — هذا بالضبط ما تفشل فيه
            # المطابقة الحرفية مع الأسئلة المفاهيمية (صياغة مختلفة قليلاً
            # عن النص الأصلي). نجرّب الترتيب الإحصائي (TF-IDF) عبر كل
            # المكتبة دفعة واحدة كخط دفاع ثانٍ قبل الاستسلام تماماً.
            try:
                from brain import relevance_engine
                if relevance_engine.is_index_built():
                    ranked = relevance_engine.search(target, self.kb, top_k=3)
                    ranked = [r for r in ranked if "error" not in r]
                    if ranked:
                        lines = [f"📖 وجدت مقاطع ذات صلة إحصائية (ترتيب أدق من المطابقة الحرفية):\n"]
                        for r in ranked:
                            loc = f" ({r['page_hint']})" if r.get("page_hint") else ""
                            excerpt = r["content"][:400].strip()
                            if len(r["content"]) > 400:
                                excerpt += "…"
                            lines.append(f"  📄 من: «{r['title']}»{loc} (صلة: {r['relevance']})\n  {excerpt}\n")
                        sections.append("\n".join(lines))
            except Exception:
                pass

        if sections:
            return "\n".join(sections)

        # 3) احتياطي: منفذ شبكي معروف
        port_m = re.search(r'\b(\d{2,5})\b', target)
        if port_m:
            info = self.kb.lookup("port", port_m.group(1))
            if info:
                return f"📡 المنفذ {port_m.group(1)}: {info}"

        # 4) احتياطي: نوع هجوم معروف
        for attack in ["brute_force","sql","xss","mitm","ddos","ransomware","phishing","rootkit"]:
            if attack.replace("_"," ") in target or attack in target:
                info = self.kb.lookup("attack", attack)
                if info:
                    return f"⚠️  {info}"

        return (
            f"لم أجد شرحاً محدداً لـ '{target}' — لا في معرفتي المدمجة ولا في "
            f"الكتب/الملفات التي علّمتني إياها حتى الآن.\n"
            f"يمكنك: البحث عن هذا في الإنترنت، أو تعليمي منه مباشرة "
            f"بقول 'تعلم أن {target} هو...'، أو تحميل مرجع عنه بقول "
            f"'تعلم من ملف <المسار>'."
        )

    # ─── Intent → Arabic Description ─────────────────────────────────────────
    def describe_intent(self, intent: str, lang: str = "ar") -> str:
        descriptions = {
            "scan_network":  ("فحص الشبكة والاتصالات النشطة", "Scanning network & active connections"),
            "scan_ports":    ("فحص المنافذ المفتوحة", "Scanning open ports"),
            "check_firewall":("فحص جدار الحماية", "Checking firewall status"),
            "check_ip":      ("فحص سمعة عنوان IP", "Checking IP reputation"),
            "wifi":          ("إدارة شبكات WiFi", "Managing WiFi networks"),
            "usb_control":   ("مركز تحكم أجهزة USB", "USB device control center"),
            "scan_system":   ("فحص النظام الشامل", "Full system security scan"),
            "scan_logs":     ("تحليل سجلات النظام", "Analyzing system logs"),
            "scan_website":  ("فحص أمان الموقع الإلكتروني", "Website security test"),
            "cve_search":    ("البحث في قاعدة بيانات CVE", "Searching CVE database"),
            "pkg_vuln_search": ("بحث ثغرات حزمة برمجية (OSV.dev)", "Package vulnerability search (OSV.dev)"),
            "scan_trend":    ("عرض تطوّر الوضع الأمني عبر الفحوصات السابقة", "Showing security trend across past scans"),
            "rebuild_index": ("إعادة بناء فهرس الذكاء المحلي (TF-IDF + خريطة مفاهيم)", "Rebuilding the local intelligence index (TF-IDF + concept graph)"),
            "concept_explore": ("استكشاف مفهوم عبر كل كتبك", "Exploring a concept across your books"),
            "concept_link":  ("ربط مفهومين عبر كتبك", "Linking two concepts across your books"),
            "summarize_doc": ("تلخيص كتاب مُستوعَب (استخلاص جمل حقيقية، لا توليد)", "Summarizing an ingested book (extractive, not generated)"),
            "github":        ("مركز GitHub والأدوات", "GitHub center & tools"),
            "web_search":    ("البحث في الإنترنت", "Web search"),
            "autofix":       ("تطبيق إصلاح أمني تلقائي", "Applying security auto-fix"),
            "full_scan":     ("الفحص الشامل الكامل", "Full comprehensive scan"),
            "update_intel":  ("تحديث معلومات التهديدات", "Updating threat intelligence"),
            "agent_status":  ("حالة الوكيل ومعلوماته", "Agent status & info"),
            "agent_update":  ("تحديث قاعدة معرفة الوكيل", "Updating agent knowledge base"),
            "explain":       ("شرح مصطلح أو مفهوم أمني", "Explaining a security concept"),
            "help":          ("قائمة المساعدة والأوامر", "Help & command list"),
            "config":        ("الإعدادات", "Settings"),
            "learn_file":    ("تعلّم من ملف وفهرسته في المكتبة الشخصية", "Learning from a file into personal library"),
            "teach":         ("حفظ حقيقة جديدة تعلّمتها منك", "Saving a new fact you taught me"),
            "show_learned":  ("عرض كل ما تعلمته حتى الآن", "Showing everything learned so far"),
            "ping_host":     ("اختبار اتصال (ping) بهدف", "Pinging a target"),
            "exit":          ("الخروج", "Exit"),
        }
        desc = descriptions.get(intent, (intent, intent))
        return desc[0] if lang == "ar" else desc[1]
