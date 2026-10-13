"""اختبارات: تصحيح اللغة، التعلم بالمعنى، محرك المحادثة، البحث الدقيق، ملف التعلم، كتالوج المنافذ."""
import os
import socket
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from brain import language
from brain.conversation import ConversationEngine, ROUTE_THRESHOLD
from brain.knowledge_base import KnowledgeBase
from brain.learning import PhraseMemory, parse_teaching
from brain.nlp import NLPEngine
from tools import network, port_catalog, websearch

TEACH = "تعلم كلمة جيد تعني جيد او تمام فقط عندما اقول تمام يجب ب جيد"


@pytest.fixture()
def engine(tmp_path):
    kb = KnowledgeBase(db_path=str(tmp_path / "k.db"))
    return ConversationEngine(kb, NLPEngine(knowledge_base=kb), PhraseMemory(kb))


# ── اللغة ──
@pytest.mark.parametrize("word", ["الحديثة", "تماما", "جدا", "السجلات", "الفيروسات", "المتصفح", "البرمجيات", "VPN"])
def test_no_false_corrections(word):
    assert language.analyze(f"اعرض {word}").corrections == []


@pytest.mark.parametrize("typo,fixed", [("افحص المنافز", "افحص المنافذ"), ("فحص النضام", "فحص النظام"), ("افحص الشبكه", "افحص الشبكة"), ("فححص الشبكة", "فحص الشبكة")])
def test_typos_are_fixed(typo, fixed):
    assert language.analyze(typo).text == fixed


def test_search_query_keeps_full_phrase():
    assert language.clean_search_query("ابحث لي في الانترنت عن جدار الحماية في لينكس") == "جدار الحماية في لينكس"


def test_source_only_when_named():
    assert "wikipedia" in language.wants_source("ابحث في ويكيبيديا عن لينكس")
    assert not language.wants_source("ابحث عن جوجل كروم")


def test_learn_online_topic_optional():
    assert language.parse_learn_online("تعلم من الانترنت") == (True, "")
    assert language.parse_learn_online("تعلم من الانترنت عن ufw") == (True, "ufw")


# ── التعلم بالمعنى ──
def test_parse_teaching_user_sentence():
    teaching = parse_teaching(TEACH)
    assert teaching and ("تمام", "جيد") in teaching.pairs


def test_learned_word_answers_with_meaning_only(engine):
    first = engine.process(TEACH)
    assert first.action == "reply" and "جيد" in first.reply and TEACH not in first.reply
    for variant in ("تمام", "تمام!", "تمااام"):
        turn = engine.process(variant)
        assert (turn.action, turn.reply) == ("reply", "جيد")


def test_forget_rule(engine):
    engine.process(TEACH)
    assert engine.process("انسى كلمة تمام").action == "reply"
    assert engine.process("تمام").reply != "جيد"


# ── محرك المحادثة ──
def test_low_confidence_never_runs_a_scan(engine):
    for text in ("تمام", "شبكتي بطيئة", "ok"):
        turn = engine.process(text)
        assert turn.action != "route", text


def test_scan_is_routed_after_correction(engine):
    turn = engine.process("افحص الشبكه")
    assert turn.action == "route" and turn.cmd.intent == "scan_network" and turn.cmd.score >= ROUTE_THRESHOLD


def test_explicit_search_uses_whole_phrase(engine):
    turn = engine.process("ابحث لي في الانترنت عن جدار الحماية")
    assert turn.action == "web_search"


def test_learn_online_action(engine):
    assert engine.process("تعلم من الانترنت").action == "learn_online"


def test_misconception_is_corrected(engine):
    turn = engine.process("VPN يخفيني تماما")
    assert turn.action == "reply" and "تصحيح" in turn.reply


def test_open_question_goes_to_assistant(engine):
    assert engine.process("كيف احمي جهازي من الفيروسات؟").action == "ai"


# ── البحث (HTTP مُحاكى) ──
def _fake_wiki(query, lang="ar", limit=5, sentences=3):
    return [
        websearch.SearchHit("جدار الحماية", "https://ar.wikipedia.org/wiki/x", "جدار الحماية نظام يراقب حركة الشبكة", "wikipedia-ar"),
        websearch.SearchHit("مطبخ إيطالي", "https://ar.wikipedia.org/wiki/y", "وصفات المعكرونة والبيتزا", "wikipedia-ar"),
    ]


def test_search_filters_irrelevant_and_reports_engines(monkeypatch):
    monkeypatch.setattr(websearch, "check_connectivity", lambda: True)
    monkeypatch.setattr(websearch, "wikipedia", _fake_wiki)
    monkeypatch.setattr(websearch, "duckduckgo", lambda q, n=6: [])
    report = websearch.search("ابحث لي في الانترنت عن جدار الحماية", {})
    assert report.query == "جدار الحماية"
    titles = [h.title for h in report.hits]
    assert "جدار الحماية" in titles and "مطبخ إيطالي" not in titles
    assert any("Google" in name for name in report.engines) and report.dropped >= 1


def test_search_offline(monkeypatch):
    monkeypatch.setattr(websearch, "check_connectivity", lambda: False)
    report = websearch.search("لينكس", {})
    assert report.online is False and not report.hits


def test_named_source_only(monkeypatch):
    called = []
    monkeypatch.setattr(websearch, "check_connectivity", lambda: True)
    monkeypatch.setattr(websearch, "wikipedia", lambda *a, **k: called.append("wiki") or _fake_wiki(*a))
    report = websearch.search("ابحث في ويكيبيديا عن جدار الحماية", {})
    assert called and not any(name.startswith("Google") or name.startswith("DuckDuckGo") for name in report.engines)


def test_learning_file_roundtrip(tmp_path):
    report = websearch.SearchReport(query="ufw", hits=_fake_wiki("ufw")[:1])
    path = websearch.write_learning_file("ufw", report, tmp_path)
    text = Path(path).read_text(encoding="utf-8")
    assert path.exists() and "جدار الحماية" in text and "https://ar.wikipedia.org" in text


# ── كتالوج المنافذ وفاحص المنافذ ──
def test_port_catalog_known_and_unknown():
    telnet = port_catalog.describe(23)
    assert telnet["risk"] == "critical" and "ufw" in telnet["fix"]
    unknown = port_catalog.describe(48123)
    assert unknown["known"] is False and "48123" in unknown["fix"]


def test_port_scan_produces_findings_for_every_open_port(monkeypatch):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    port = server.getsockname()[1]
    stop = threading.Event()

    def serve():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.sendall(b"SSH-2.0-TestServer\r\n")
                conn.close()
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        from utils import safe_exec
        real_run = safe_exec.run
        monkeypatch.setattr(safe_exec, "run", lambda args, *a, **k: real_run(["false"]) if args[0] == "nmap" else real_run(args, *a, **k))
        result = network.scan_ports("127.0.0.1", f"{port}-{port}")
    finally:
        stop.set()
        server.close()
    assert result["tool_used"] == "python-socket"
    assert [p["port"] for p in result["open_ports"]] == [f"{port}/tcp"]
    assert result["open_ports"][0]["banner"].startswith("SSH-2.0")
    assert any(str(port) in f["title"] for f in result["findings"])


# ── الواجهة (offscreen) ──
def test_gui_chat_flow_and_summary():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication
    from ui.gui_app import UnifiedCockpitWindow, summarize_findings, sort_findings, finding_html

    findings = [{"severity": "low", "title": "ب"}, {"severity": "critical", "title": "أ", "fix": "sudo ufw enable"}]
    assert sort_findings(findings)[0]["title"] == "أ"
    summary = summarize_findings(findings, "فحص")
    assert "1 حرجة" in summary and "sudo ufw enable" in summary and "الخطوة التالية" in summary
    assert "لم يرصد" in summarize_findings([], "فحص")
    assert "كيف أصلحها" in finding_html(findings[1])

    app = QApplication.instance() or QApplication([])
    window = UnifiedCockpitWindow()
    window.show()
    window.agent.phrases.forget("تمام")
    for text in (TEACH, "تمام"):
        window.chat_input.setText(text)
        window.send_chat_message()
    assert window.worker is None or not window.worker.isRunning()   # لا فحص تشغّل بسبب «تمام»
    texts = [b._text for b in window.chat_display.bubbles if getattr(b, "role", "") == "assistant"]
    assert texts[-1] == "جيد"
    window.agent.phrases.forget("تمام")
    assert window.hover_controller.flow.borders          # إطارات متحركة مسجلة للجداول والحقول
    window.close()
