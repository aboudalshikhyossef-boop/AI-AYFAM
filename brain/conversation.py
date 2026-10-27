"""محرك المحادثة: قراءة المدخل ← تصحيح ← تعلّم المعنى ← تصحيح مفاهيم ← تحديد النية.

يعمل قبل موجّه الأوامر (NLP) ويقرر ماذا يجب أن يحدث، مع «أثر تفكير» قصير يمكن عرضه
للمستخدم. لا ينفّذ فحوصات ولا شبكة بنفسه: يعيد قراراً (Turn) تنفّذه الواجهة أو الوكيل.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from brain import language
from brain.learning import PhraseMemory, parse_teaching

ROUTE_THRESHOLD = 0.35     # دون هذا لا نشغّل فحصاً أبداً
CLARIFY_THRESHOLD = 0.2    # بين الحدّين نسأل «هل تقصد؟»

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_SMALLTALK = {
    "greeting": "أهلاً بك. اكتب أمراً مثل «افحص الشبكة» أو اسأل عن أي مفهوم أمني لخدمتك فوراً.",
    "thanks": "على الرحب والسعة، أنا هنا دائماً لخدمتك وتطبيق توجيهاتك بصرامة وسرعة.",
}
_THANKS = {language.normalize(w) for w in ("شكرا", "شكراً", "شكرا لك", "شكراً لك", "thanks", "thank you", "مشكور")}
_SUGGESTIONS = [("فحص الشبكة", "افحص الشبكة"), ("فحص النظام", "افحص النظام"), ("تحليل السجلات", "حلل السجلات"), ("جدار الحماية", "افحص جدار الحماية")]

INTENT_LABELS = {
    "scan_network": "فحص الشبكة", "scan_ports": "فحص المنافذ", "check_firewall": "فحص جدار الحماية", "check_ip": "فحص سمعة IP",
    "wifi": "حالة Wi-Fi", "usb_control": "أجهزة USB", "scan_system": "فحص النظام", "scan_logs": "تحليل السجلات",
    "scan_website": "فحص موقع", "cve_search": "بحث CVE", "pkg_vuln_search": "ثغرات حزمة", "full_scan": "الفحص الشامل",
    "web_search": "بحث في الإنترنت", "explain": "شرح مفهوم", "show_learned": "ما تعلمته", "teach": "تعليم معلومة",
    "update_intel": "تحديث التهديدات", "scan_trend": "تطور الوضع", "learn_file": "التعلم من ملف", "help": "المساعدة",
}


@dataclass
class Turn:
    raw: str
    analysis: language.InputAnalysis
    action: str = "route"            # reply | route | web_search | learn_online | clarify | ai
    style: str = "brief_action"      # brief_action | detailed_explanation | step_by_step_guidance | misconception_correction | compound_route
    reply: str = ""
    cmd: object | None = None
    query: str = ""
    steps: list[str] = field(default_factory=list)
    suggestions: list[tuple[str, str]] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.analysis.text


class ConversationEngine:
    def __init__(self, kb, nlp, memory: PhraseMemory | None = None):
        self.kb = kb
        self.nlp = nlp
        self.memory = memory or PhraseMemory(kb)

    # ── أثر التفكير ──
    @staticmethod
    def _reading_steps(analysis: language.InputAnalysis) -> list[str]:
        kinds = {"question": "سؤال", "command": "أمر", "greeting": "تحية", "statement": "جملة"}
        steps = [f"قرأت {kinds[analysis.kind]} بالـ{'عربية' if analysis.language == 'ar' else 'إنجليزية'} ({analysis.word_count} كلمات)"]
        for item in analysis.corrections[:3]:
            steps.append(f"صحّحت «{item.original}» إلى «{item.fixed}»")
        return steps

    def process(self, raw: str) -> Turn:
        analysis = language.analyze(raw)
        turn = Turn(raw=raw, analysis=analysis, steps=self._reading_steps(analysis))
        text = analysis.text

        # 1) تعليم معنى (لا نص): «عندما أقول تمام ردّ بجيد» / «كلمة X تعني Y» / «انسَ X»
        teaching = parse_teaching(raw)
        if teaching:
            turn.action = "reply"
            turn.style = "brief_action"
            if teaching.kind == "forget":
                removed = self.memory.forget(teaching.pairs[0][0])
                turn.reply = f"نسيت «{teaching.pairs[0][0]}»." if removed else f"لا توجد قاعدة باسم «{teaching.pairs[0][0]}»."
                turn.steps.append("حذفت القاعدة" if removed else "لم أجد قاعدة مطابقة")
            else:
                for trigger, reply in teaching.pairs:
                    self.memory.learn(trigger, reply, teaching.kind)
                turn.reply = f"فهمت المعنى فقط ولم أحفظ النص: {teaching.summary}. عندما تكتب «{teaching.pairs[0][0]}» سأجيب بـ«{teaching.pairs[0][1]}» فقط."
                turn.steps.append("استخرجت المعنى المختصر بدل حفظ الجملة")
            return turn

        # 2) كلمة تعلمتها: الردّ المختصر فقط
        rule = self.memory.match(raw) or (self.memory.match(text) if text != raw else None)
        if rule:
            turn.action = "reply"
            turn.style = "brief_action"
            turn.reply = rule["reply"]
            turn.steps.append(f"طابقت كلمة تعلمتها «{rule['trigger']}»")
            return turn

        # 3) مرادفات تعلمتها داخل جملة أطول: تُستبدل بمعناها قبل الفهم
        replaced, applied = self.memory.apply_aliases(text)
        if applied:
            text = replaced
            turn.analysis.text = text
            for term, meaning in applied[:2]:
                turn.steps.append(f"فهمت «{term}» بمعنى «{meaning}»")

        # 4) تصحيح مفهوم خاطئ شائع
        wrong = language.find_misconceptions(raw) or language.find_misconceptions(text)
        if wrong:
            first = wrong[0]
            turn.action = "reply"
            turn.style = "misconception_correction"
            turn.reply = f"تصحيح مفهوم: قد يكون الاعتقاد بأن «{first.claim}» غير دقيق.\n{first.correction}"
            turn.steps.append("رصدت مفهوماً شائعاً غير دقيق وصحّحته")
            return turn

        # 5) تعلّم من الإنترنت (الموضوع قد يكون فارغاً: أستنتج ما ينقصني)
        is_learn, topic = language.parse_learn_online(text)
        if is_learn:
            turn.action = "learn_online"
            turn.query = topic
            turn.steps.append("النية: التعلم من الإنترنت" + (f" عن «{topic}»" if topic else " فيما ينقصني"))
            return turn

        cmd = self.nlp.parse(text)
        turn.cmd = cmd
        intent, score = cmd.intent, cmd.score

        # 6) بحث ويب صريح: عبارة كاملة، ما لم يكن معرّف CVE أو أمراً أقوى
        search_match = language._SEARCH_RE.match(text)
        explicit_source = bool(language.wants_source(text))
        if search_match and not _CVE_RE.search(text) and intent not in ("pkg_vuln_search", "github", "learn_file", "scan_ports"):
            query = language.clean_search_query(text)
            if query:
                turn.action = "web_search"
                turn.query = text
                turn.steps.append(f"النية: بحث دقيق عن «{query}»" + (" في المصدر الذي حددته" if explicit_source else ""))
                return turn

        # 7) ثقة النية
        if intent and score >= ROUTE_THRESHOLD:
            turn.action = "route"
            if intent in ("explain", "concept_explore", "concept_link", "summarize_doc"):
                turn.style = "detailed_explanation"
            elif intent in ("autofix", "config"):
                turn.style = "step_by_step_guidance"
            else:
                turn.style = "brief_action"
            turn.steps.append(f"النية: {INTENT_LABELS.get(intent, intent)} (ثقة {int(score * 100)}%)")
            return turn
        if intent and score >= CLARIFY_THRESHOLD and analysis.kind != "question":
            turn.action = "clarify"
            turn.style = "brief_action"
            label = INTENT_LABELS.get(intent, intent)
            turn.reply = f"لم أتأكد من قصدك. هل تريد: {label}؟"
            turn.suggestions = [(label, text if score >= 0.3 else language.collapse_spaces(label)), ("لا، سؤال آخر", "")]
            turn.steps.append(f"ثقة منخفضة ({int(score * 100)}%) فاخترت أن أسألك")
            return turn

        # 8) محادثة عادية
        norm = language.normalize(text)
        if analysis.kind == "greeting":
            turn.action, turn.reply, turn.style = "reply", _SMALLTALK["greeting"], "brief_action"
            return turn
        if norm in _THANKS:
            turn.action, turn.reply, turn.style = "reply", _SMALLTALK["thanks"], "brief_action"
            return turn
        if analysis.kind != "question" and analysis.word_count <= 2 and not _CVE_RE.search(text):
            turn.action = "clarify"
            turn.style = "brief_action"
            turn.reply = "لم أفهم المطلوب تماماً. جرّب أحد هذه الخيارات أو اكتب سؤالك كاملاً."
            turn.suggestions = list(_SUGGESTIONS)
            turn.steps.append("المدخل قصير وغير واضح، لن أشغّل أي فحص دون تأكيد")
            return turn
        turn.action = "ai"
        turn.style = "detailed_explanation" if analysis.kind == "question" or analysis.word_count > 4 else "brief_action"
        turn.query = text
        turn.steps.append("سؤال مفتوح: أستعين بالمعرفة المحلية ثم بالذكاء المتاح")
        return turn

    def direct_reply(self, raw: str) -> str | None:
        """للطرفية: ردّ فوري إن كانت الرسالة تعليماً أو كلمة متعلَّمة، وإلا None."""
        turn = self.process(raw)
        return turn.reply if turn.action == "reply" else None
