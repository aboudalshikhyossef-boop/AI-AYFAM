"""قراءة المدخلات: تطبيع عربي، تصحيح إملائي محافظ، تنظيف عبارات البحث، وتصحيح المفاهيم.

كل شيء هنا محلي ومحدّد القواعد (بدون نموذج لغوي). الهدف: فهم ما يقصده المستخدم
حتى لو أخطأ في الهمزة أو التاء المربوطة أو كرّر حرفاً، دون تعديل الأوامر والمسارات
والعناوين التقنية التي يجب أن تبقى كما كُتبت.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher, get_close_matches

_DIACRITICS = re.compile(r"[\u064B-\u065F\u0670\u06D6-\u06ED\u0640]")
_ARABIC_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")
_LETTER_MAP = str.maketrans({"أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا", "ى": "ي", "ة": "ه", "ؤ": "و", "ئ": "ي", "گ": "ك", "ڤ": "ف", "پ": "ب"})
_TOKEN = re.compile(r"[A-Za-z0-9_]+|[\u0621-\u063A\u0641-\u064A\u0671\u06A9\u06AF\u06CC]+")
_WEAK = str.maketrans({"أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا", "ى": "ي"})
_PROTECTED = re.compile(
    r"https?://\S+|www\.\S+|(?:~|\.{0,2})/[\w./\-~]+|\b(?:\d{1,3}\.){3}\d{1,3}\b|CVE-\d{4}-\d{4,7}|"
    r"`[^`]*`|\"[^\"]*\"|'[^']*'|\b[\w.-]+\.(?:pdf|txt|md|py|sh|conf|log)\b",
    re.IGNORECASE,
)
_ARABIC_PREFIXES = ("وال", "فال", "بال", "كال", "لل", "ال", "و", "ف", "ب", "ل", "ك")


def normalize(text: str) -> str:
    """Canonical comparison form: no diacritics, unified alef/yaa/taa-marbuta, ascii digits."""
    value = _DIACRITICS.sub("", str(text or "")).translate(_ARABIC_DIGITS).translate(_LETTER_MAP).lower()
    return re.sub(r"\s+", " ", value).strip()


def collapse_repeats(word: str) -> str:
    """جيددددد -> جيد ; سلاااام -> سلام (three or more identical letters)."""
    return re.sub(r"(.)\1{2,}", r"\1", word)


def detect_language(text: str) -> str:
    arabic = len(re.findall(r"[\u0600-\u06FF]", text))
    latin = len(re.findall(r"[A-Za-z]", text))
    if arabic and arabic >= latin:
        return "ar"
    return "en" if latin else "ar"


# ── المفردات المعروفة للتصحيح (الشكل الصحيح الظاهر للمستخدم) ───────────────
VOCABULARY = [
    "فحص", "افحص", "الفحص", "شامل", "الشبكة", "شبكة", "المنافذ", "منفذ", "منافذ", "جدار", "الحماية", "النظام",
    "السجلات", "سجلات", "تحليل", "حلل", "تقرير", "التقرير", "التقارير", "ثغرات", "ثغرة", "الثغرات", "بحث", "ابحث",
    "الإنترنت", "الانترنت", "إنترنت", "تعلم", "تعلّم", "اشرح", "اشرحلي", "ماذا", "كيف", "لماذا", "أجهزة", "الأجهزة",
    "المتصلة", "فلاشة", "كلمة", "المرور", "كلمات", "تشفير", "اختراق", "المخترق", "فيروس", "فيروسات", "برمجيات",
    "خبيثة", "الخبيثة", "مشبوه", "مشبوهة", "اتصالات", "الاتصالات", "عمليات", "العمليات", "المستخدم", "المستخدمين",
    "الحماية", "تحديث", "التحديثات", "إصلاح", "أصلح", "المكتبة", "الملف", "ملف", "كتاب", "الكتب", "الذاكرة",
    "الخدمات", "خدمة", "الموقع", "موقع", "سمعة", "جيد", "تمام", "شكراً", "مرحباً", "سلام", "مرحبا", "تبحث", "يبحث", "نبحث", "تفحص", "يفحص", "نفحص", "تشرح", "يشرح", "مساعدة", "الإعدادات",
    "scan", "network", "ports", "firewall", "system", "logs", "report", "search", "learn", "explain", "vulnerability",
    "vulnerabilities", "password", "malware", "internet", "update", "website", "device", "devices", "wifi",
]
_VOCAB_BY_NORM: dict[str, str] = {}
for _word in VOCABULARY:
    _VOCAB_BY_NORM.setdefault(normalize(_word), _word)
_VOCAB_KEYS = list(_VOCAB_BY_NORM)
# Short ambiguous words that must never be "corrected" into something else.
_NEVER_FIX = {normalize(w) for w in ("جدا", "جداً", "من", "عن", "في", "على", "هذا", "هذه", "ما", "هل", "لا", "نعم", "الى", "إلى", "مع", "او", "أو", "ثم", "كل", "اذا", "إذا", "ان", "أن", "التي", "الذي")}


def _is_inflection(a: str, b: str) -> bool:
    """«تماما» vs «تمام»: one is the other plus letters, a different word form, not a typo."""
    return a != b and (a.startswith(b) or b.startswith(a) or a.endswith(b) or b.endswith(a))


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (adjacent transposition counts as 1)."""
    if a == b:
        return 0
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[-1][-1]


def _near(word: str, minimum: int = 5) -> str | None:
    """Single-slip typo only (one edit, same first letter); ambiguous or longer words are left alone."""
    if len(word) < minimum:
        return None
    limit = 2 if len(word) >= 10 else 1
    found = [key for key in _VOCAB_KEYS
             if abs(len(key) - len(word)) <= limit and key[0] == word[0]
             and 0 < edit_distance(word, key) <= limit and not _is_inflection(word, key)]
    return found[0] if len(found) == 1 else None


def _lookup_word(token: str) -> str | None:
    """Return the properly-spelled vocabulary word when `token` is a misspelling of it."""
    norm = collapse_repeats(normalize(token))
    if norm in _NEVER_FIX or len(norm) < 3:
        return None
    if norm in _VOCAB_BY_NORM:
        return _VOCAB_BY_NORM[norm]
    undoubled = re.sub(r"(.)\1", r"\1", norm)   # «فححص» -> «فحص»
    if undoubled in _VOCAB_BY_NORM and undoubled != norm:
        return _VOCAB_BY_NORM[undoubled]
    for prefix in _ARABIC_PREFIXES:
        if norm.startswith(prefix) and len(norm) - len(prefix) >= 3:
            rest = norm[len(prefix):]
            if rest in _VOCAB_BY_NORM:
                return prefix_restore(token, prefix, _VOCAB_BY_NORM[rest])
            near = _near(rest)
            if near:
                return prefix_restore(token, prefix, _VOCAB_BY_NORM[near])
    near = _near(norm)
    return _VOCAB_BY_NORM[near] if near else None


def prefix_restore(original: str, prefix: str, fixed: str) -> str:
    plain = normalize(original)
    surface = original[: len(prefix)] if plain.startswith(prefix) and len(original) >= len(prefix) else prefix
    return surface + fixed


@dataclass
class Correction:
    original: str
    fixed: str


@dataclass
class InputAnalysis:
    raw: str
    text: str                        # النص بعد التصحيح (يُمرَّر للمحلّل)
    language: str = "ar"
    corrections: list[Correction] = field(default_factory=list)
    kind: str = "statement"          # question | command | greeting | statement
    word_count: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.corrections)


_GREETINGS = {normalize(w) for w in ("مرحبا", "مرحباً", "اهلا", "أهلاً", "السلام عليكم", "هلا", "hello", "hi", "hey", "صباح الخير", "مساء الخير")}
_QUESTION_WORDS = tuple(normalize(w) for w in ("ما", "ماذا", "لماذا", "كيف", "متى", "اين", "أين", "هل", "من", "كم", "what", "why", "how", "when", "where", "who", "is", "are", "can", "does"))
_COMMAND_WORDS = tuple(normalize(w) for w in ("افحص", "فحص", "حلل", "ابحث", "اشرح", "تعلم", "اعرض", "شغل", "أصلح", "اصلح", "scan", "check", "search", "show", "run", "fix", "learn", "explain"))


def classify_kind(text: str) -> str:
    norm = normalize(text)
    if norm in _GREETINGS:
        return "greeting"
    first = norm.split(" ", 1)[0] if norm else ""
    if "؟" in text or "?" in text or first in _QUESTION_WORDS:
        return "question"
    if first in _COMMAND_WORDS:
        return "command"
    return "statement"


def correct_text(text: str) -> tuple[str, list[Correction]]:
    """تصحيح إملائي محافظ للكلمات المعروفة فقط؛ لا يلمس الروابط والمسارات والعناوين والاقتباسات."""
    protected: list[tuple[int, int]] = [m.span() for m in _PROTECTED.finditer(text)]

    def is_protected(pos: int) -> bool:
        return any(a <= pos < b for a, b in protected)

    corrections: list[Correction] = []
    pieces: list[str] = []
    cursor = 0
    for match in _TOKEN.finditer(text):
        token = match.group(0)
        if is_protected(match.start()) or token.isdigit() or (token.isascii() and len(token) < 4):
            continue
        fixed = _lookup_word(token)
        # Hamza/alef-maksura variants are accepted spellings, not errors.
        if fixed and fixed.translate(_WEAK) != token.translate(_WEAK):
            pieces.append(text[cursor:match.start()])
            pieces.append(fixed)
            cursor = match.end()
            corrections.append(Correction(token, fixed))
    pieces.append(text[cursor:])
    return "".join(pieces), corrections


def analyze(raw: str) -> InputAnalysis:
    cleaned = re.sub(r"\s+", " ", str(raw or "")).strip()
    fixed, corrections = correct_text(cleaned)
    return InputAnalysis(
        raw=raw, text=fixed, language=detect_language(fixed), corrections=corrections,
        kind=classify_kind(fixed), word_count=len(_TOKEN.findall(fixed)),
    )


# ── استخراج عبارة البحث الدقيقة ─────────────────────────────────────────────
_SEARCH_PREFIXES = [
    r"(?:من فضلك\s+|لو سمحت\s+|الرجاء\s+|رجاء\s+|please\s+)?",
    r"(?:(?:ممكن|هل يمكنك|بامكانك|تقدر|اريدك ان|أريدك أن|اريد ان|أريد أن|اريد|أريد|بدي|لازم)\s+)?",
]
_SEARCH_VERBS = (
    r"(?:[تاني]?بحث|إبحث|[تاني]?دور|[تاني]?فتش|[تاني]?جد|اوجد|أوجد|هات لي|هات|جيب لي|جيب|search for|search|look up|look for|find|google search|google|"
    r"قوقل|جوجل|غوغل|ويكيبيديا|ويكيديا|wikipedia)"
)
_WHERE = (
    r"(?:\s+(?:لي|لى))?(?:\s+(?:في|على|عبر|ب[ـ\-]?|من|بواسطة|باستخدام|using|on|in|via|with|from))?"
    r"(?:\s+(?:محرك\s+|موقع\s+|خدمة\s+)?)?"
    r"(?:\s+(?:الانترنت|الإنترنت|الانترنيت|النت|الويب|الشبكة العنكبوتية|جوجل|قوقل|غوغل|google|ويكيبيديا|ويكيديا|wikipedia|the internet|internet|the web|web|online))*"
)
_ABOUT = r"(?:\s+(?:عن|حول|بخصوص|about|for|on|regarding))?"
_SEARCH_RE = re.compile(
    r"^\s*" + "".join(_SEARCH_PREFIXES) + _SEARCH_VERBS + _WHERE + _ABOUT + r"\s+(?P<q>.+?)\s*[?؟.!]*\s*$",
    re.IGNORECASE,
)
_TRAILING_SOURCE = re.compile(
    r"\s+(?:في|على|عبر|من|باستخدام|بواسطة|b|using|on|in|via|with|from)\s*(?:محرك\s+|موقع\s+)?"
    r"(?:الانترنت|الإنترنت|النت|الويب|جوجل|قوقل|غوغل|google|ويكيبيديا|ويكيديا|wikipedia|internet|web)\s*$",
    re.IGNORECASE,
)


def clean_search_query(text: str) -> str:
    """'ابحث لي في الانترنت عن ثغرات SSH الجديدة' -> 'ثغرات SSH الجديدة' (العبارة كاملة لا كلمة واحدة)."""
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    match = _SEARCH_RE.match(value)
    if match:
        value = match.group("q")
    # Clean secondary leftover leading search verbs/prepositions or engine phrases if matched
    value = re.sub(r"^(?:search\s+for|search\s+on|search|find|look\s+up|ابحث\s+عن|ابحث)\s+", "", value, flags=re.IGNORECASE).strip()
    value = re.sub(r"^(?:ب[ـ\-]?|عبر\s+|في\s+|باستخدام\s+)?(?:محرك\s+|موقع\s+)?(?:جوجل|قوقل|غوغل|google|ويكيبيديا|wikipedia)\s+(?:عن\s+|حول\s+|for\s+)?", "", value, flags=re.IGNORECASE).strip()
    value = _TRAILING_SOURCE.sub("", value).strip(" \t\"'«»؟?.!،,")
    return value


_SOURCE_RE = re.compile(
    r"(?:^|\s)(?:"
    r"(?:في|على|عبر|من|بواسطة|باستخدام|ب|using|on|in|via|with|from|using\s+the|on\s+the)\s*(?:محرك\s+|موقع\s+|خدمة\s+)?"
    r"|(?<=ابحث\s)|(?<=إبحث\s)|(?<=بحث\s)|(?<=دور\s)|(?<=فتش\s)|(?<=search\s)|(?<=look\ up\ )"
    r"|(?<=google\ )"
    r")(?P<src>جوجل|قوقل|غوغل|google|ويكيبيديا|ويكيديا|ويكي|wikipedia)(?=\s|$|[.,،؟?!])"
    r"|(?:^|\s)(?P<src_direct>google|قوقل|جوجل|غوغل)\s+(?:search|بحث|ابحث|دور)",
    re.IGNORECASE,
)


def wants_source(text: str) -> set[str]:
    """Which engines did the user explicitly ask for? (google / wikipedia)  — only when named as the place to search."""
    wanted = set()
    norm = normalize_for_trigger(text)
    for match in _SOURCE_RE.finditer(norm):
        src = (match.group("src") or match.group("src_direct") or "").lower()
        if src in ("جوجل", "قوقل", "غوغل", "google"):
            wanted.add("google")
        elif src in ("ويكيبيديا", "ويكيديا", "ويكي", "wikipedia"):
            wanted.add("wikipedia")
    return wanted


# ── تعلّم من الإنترنت ───────────────────────────────────────────────────────
_LEARN_ONLINE_RE = re.compile(
    r"^\s*(?:من فضلك\s+)?(?:(?:اريدك|أريدك|اريد|أريد|لازم|يجب)(?:\s+(?:ان|أن))?\s+)?"
    r"(?:ت?تعلم|ت?تعلّم|اتعلم|تعلمي|تثقف|ثقف نفسك|درس نفسك|حدث معلوماتك|حدّث معلوماتك|learn)\s*"
    r"(?:(?:بنفسك|ذاتيا|ذاتياً|تلقائيا|تلقائياً)\s*)?"
    r"(?:من|عبر|في|على|using|from|on|via)?\s*"
    r"(?:الانترنت|الإنترنت|الانترنيت|النت|الويب|الشبكة العنكبوتية|the internet|internet|the web|web|online)\s*"
    r"(?:(?:عن|حول|بخصوص|about|on)\s+(?P<topic>.+?))?\s*[?؟.!]*\s*$",
    re.IGNORECASE,
)
_LEARN_ONLINE_ALT = re.compile(
    r"^\s*(?:ابحث|بحث|دور)\s+(?:في\s+)?(?:الانترنت|الإنترنت|النت)\s+(?:وتعلم|و\s*تعلم|وتعلّم)\s*(?:عن\s+(?P<topic>.+?))?\s*[?؟.!]*\s*$",
    re.IGNORECASE,
)


def parse_learn_online(text: str) -> tuple[bool, str]:
    """Return (is_learn_online, topic). topic may be '' => infer what is missing automatically."""
    value = collapse_spaces(text)
    for rx in (_LEARN_ONLINE_RE, _LEARN_ONLINE_ALT):
        match = rx.match(normalize_for_trigger(value))
        if match:
            topic = (match.group("topic") or "").strip(" \"'«»؟?.!،,")
            return True, topic
    return False, ""


def collapse_spaces(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def normalize_for_trigger(text: str) -> str:
    """Light normalisation (keeps original letters of the topic) used before trigger regexes."""
    return _DIACRITICS.sub("", text).translate(_ARABIC_DIGITS)


# ── تصحيح المفاهيم الخاطئة الشائعة (أمن المعلومات) ─────────────────────────
@dataclass(frozen=True)
class Misconception:
    key: str
    pattern: re.Pattern
    claim: str
    correction: str


def _mc(key: str, pattern: str, claim: str, correction: str) -> Misconception:
    return Misconception(key, re.compile(pattern, re.IGNORECASE), claim, correction)


MISCONCEPTIONS = [
    _mc("vpn_anon", r"(vpn|في بي ان|فى بى ان).{0,25}(يخفي|تخفي|مجهول|اخفاء|إخفاء|تجعلني).{0,20}(تماما|تمامًا|كليا|كلياً|100|بالكامل|مجهول)",
        "الـ VPN يجعلني مجهولاً تماماً", "الـ VPN يشفّر الاتصال ويخفي عنوانك عن المواقع، لكنه لا يجعلك مجهولاً: مزوّد الـ VPN يرى حركتك، وبصمة المتصفح وحسابات تسجيل الدخول تكشفك."),
    _mc("linux_virus", r"(لينكس|لينوكس|linux).{0,25}(لا يصاب|لا تصاب|لايصاب|ما يصاب|محصن|مستحيل|بدون فيروس|خالي من الفيروس|آمن تماما|امن تماما)",
        "لينكس لا يصاب بالبرمجيات الخبيثة", "لينكس أقل استهدافاً لكنه ليس محصناً: توجد برمجيات فدية وبوتات وثغرات في الخدمات والتطبيقات، وأخطر نقطة غالباً هي المستخدم وكلمات المرور."),
    _mc("hundred_percent", r"(حماية|امان|أمان|أمن|امن|secure|security).{0,20}(100\s*%|مية بالمية|مئة بالمئة|مطلقة|كاملة 100|لا يمكن اختراق)",
        "هناك حماية 100%", "لا يوجد أمان مطلق؛ الهدف تقليل المخاطر بطبقات: تحديثات، صلاحيات أقل، جدار حماية، نسخ احتياطي، ومراقبة."),
    _mc("open_port_hacked", r"(منفذ|port).{0,20}(مفتوح|open).{0,25}(يعني|معناه|مخترق|اختراق|hacked)",
        "المنفذ المفتوح يعني أنني مخترق", "المنفذ المفتوح يعني أن خدمة تستمع للاتصالات فقط. الخطر يتعلق بنوع الخدمة وإصدارها ومن يستطيع الوصول إليها، وليس بالفتح وحده."),
    _mc("incognito", r"(incognito|تصفح خفي|وضع التخفي|التصفح الخاص).{0,30}(يخفي|مجهول|لا يراني|آمن|امن|يحميني)",
        "التصفح الخفي يخفيني عن الإنترنت", "التصفح الخفي لا يحفظ السجل محلياً فقط؛ مزوّد الإنترنت والمواقع وجهة العمل ما زالوا يرون نشاطك."),
    _mc("antivirus_enough", r"(مضاد فيروسات|antivirus|انتي فايروس|أنتي فيروس).{0,25}(يكفي|كافي|يغنيني|وحده|enough)",
        "مضاد الفيروسات وحده يكفي", "مضاد الفيروسات طبقة واحدة. تحتاج أيضاً تحديثات النظام، جدار حماية، كلمات مرور قوية ومصادقة ثنائية، ونسخاً احتياطية."),
    _mc("https_safe", r"(https|القفل الاخضر|القفل الأخضر|قفل المتصفح).{0,25}(يعني|معناه).{0,15}(آمن|امن|موثوق|safe)",
        "HTTPS يعني أن الموقع آمن وموثوق", "HTTPS يعني أن الاتصال مشفّر فقط. مواقع التصيّد قد تستخدم HTTPS أيضاً، فتحقق من اسم النطاق نفسه."),
    _mc("hide_wifi", r"(اخفاء|إخفاء|اخفي|أخفي|hide).{0,15}(ssid|اسم الشبكة|اسم الواي فاي|wifi).{0,25}(يحمي|حماية|آمن|امن|يمنع)",
        "إخفاء اسم الواي فاي يحميه", "إخفاء الـ SSID لا يوفّر حماية حقيقية لأنه يُكشف بسهولة. الحماية الفعلية هي WPA2/WPA3 وكلمة مرور قوية."),
]


def find_misconceptions(text: str) -> list[Misconception]:
    cleaned = collapse_spaces(_DIACRITICS.sub("", text))
    return [m for m in MISCONCEPTIONS if m.pattern.search(cleaned)]
