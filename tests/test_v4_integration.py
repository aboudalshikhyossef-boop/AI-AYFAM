import sys, os, tempfile, io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from contextlib import redirect_stdout

TMP_HOME = tempfile.mkdtemp(prefix="ayfam_home_v4_")
os.environ["HOME"] = TMP_HOME

from config.settings import Settings
from ui.terminal import TerminalUI
from brain.knowledge_base import KnowledgeBase
from core.agent import AYFAMAgent
from brain import relevance_engine

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

# فهرس الذكاء مؤقت ومعزول عن أي بيانات حقيقية على هذا الجهاز
tmp_intel = tempfile.mkdtemp(prefix="ayfam_intel_v4_")
import pathlib
relevance_engine.INTEL_DIR = pathlib.Path(tmp_intel)
relevance_engine.VECTORIZER_PATH = relevance_engine.INTEL_DIR / "tfidf_vectorizer.pkl"
relevance_engine.MATRIX_PATH = relevance_engine.INTEL_DIR / "tfidf_matrix.npz"
relevance_engine.CHUNK_IDS_PATH = relevance_engine.INTEL_DIR / "chunk_ids.json"
relevance_engine.META_PATH = relevance_engine.INTEL_DIR / "meta.json"

settings = Settings()
ui = TerminalUI(no_color=True)
ui.ask = lambda prompt, default=None: (default if default is not None else "")
ui.confirm = lambda prompt, default=False: False
agent = AYFAMAgent(settings=settings, ui=ui, verbose=False)
agent.kb = KnowledgeBase(db_path=os.path.join(TMP_HOME, "test_brain.db"))

def run_silently(fn, *a, **kw):
    buf = io.StringIO()
    err = None
    try:
        with redirect_stdout(buf):
            fn(*a, **kw)
    except Exception as e:
        err = e
    return buf.getvalue(), err

# ── إنشاء "كتابين" اصطناعيين واقعيين كملفات نصية فعلية (كبيرة بما يكفي
#    لتنتج عدة مقاطع فعلية عبر خط أنابيب التقطيع الحقيقي في library.py،
#    وليس مقطعاً واحداً فقط كما يحدث مع نص قصير جداً) ───────────────────
# ── إنشاء "كتابين" اصطناعيين واقعيين كملفات نصية فعلية بتنويع حقيقي في
#    الجمل (كتب حقيقية لا تكرر نفس الجملة حرفياً مئات المرات — التكرار
#    الحرفي المصطنع يجعل max_df يستبعد المصطلح كأنه "كلمة شائعة جداً"،
#    وهذا سلوك صحيح للمحرك لكنه غير واقعي لمحتوى كتاب فعلي) ──────────────
_NMAP_SENTENCES = [
    "Nmap is the standard tool for network reconnaissance and port scanning.",
    "A typical scan uses nmap -sV -p- target.com to enumerate open ports and service versions.",
    "Stealth scanning with nmap -sS avoids completing the TCP handshake to reduce detection.",
    "Port scanning is often the first reconnaissance step before any further penetration testing.",
    "Firewall evasion techniques in nmap include fragmenting packets and using decoy source addresses.",
    "Understanding open ports and running services helps build an accurate map of the target network.",
    "Experienced testers combine nmap results with manual verification before exploitation.",
    "UDP scanning is slower and less reliable than TCP scanning but reveals different services.",
    "Nmap scripting engine (NSE) can automate vulnerability detection during a scan.",
    "Rate limiting a scan avoids triggering intrusion detection systems on the target network.",
    "Service version detection helps identify outdated software that may be vulnerable.",
    "OS fingerprinting during a scan can reveal the target's operating system and kernel version.",
    "A ping sweep across a subnet quickly identifies which hosts are alive before deeper scanning.",
    "Output formats like XML and grepable text make scan results easy to parse programmatically.",
    "Combining nmap with other reconnaissance tools builds a fuller picture of the attack surface.",
]
_PRIVESC_SENTENCES = [
    "Privilege escalation on Linux often exploits misconfigured SUID binaries.",
    "Finding SUID binaries is a routine reconnaissance step during privilege escalation.",
    "This step is conceptually similar to port scanning in network reconnaissance workflows.",
    "A world-writable file combined with a SUID binary can create a privilege escalation chain.",
    "Kernel exploits are another common vector for privilege escalation on outdated systems.",
    "After privilege escalation, an attacker typically establishes persistence mechanisms.",
    "Auditing SUID binaries regularly is one of the most effective defenses against this attack class.",
    "Misconfigured sudo rules can allow a low-privileged user to run commands as root.",
    "Writable cron jobs owned by root are a classic privilege escalation vector on Linux systems.",
    "Capabilities assigned to binaries can sometimes be abused similarly to SUID permissions.",
    "Container breakout techniques often rely on the same privilege escalation principles.",
    "Password reuse across accounts can turn a minor compromise into full root access.",
    "Enumeration scripts automate the search for common Linux privilege escalation vectors.",
    "Kernel version disclosure during reconnaissance helps identify applicable local exploits.",
    "Defense in depth reduces the impact of any single privilege escalation vulnerability.",
]

BOOK1 = "Network Reconnaissance Fundamentals\n\n" + " ".join(_NMAP_SENTENCES * 6)
BOOK2 = "Linux Privilege Escalation Techniques\n\n" + " ".join(_PRIVESC_SENTENCES * 6)

book1_path = os.path.join(TMP_HOME, "network_recon.txt")
book2_path = os.path.join(TMP_HOME, "privesc.txt")
with open(book1_path, "w") as f:
    f.write(BOOK1)
with open(book2_path, "w") as f:
    f.write(BOOK2)

print("\n[1] _learn_from_file ingests both synthetic books")
out1, err1 = run_silently(agent._learn_from_file, book1_path)
check("book 1 ingested without exception", err1 is None)
out2, err2 = run_silently(agent._learn_from_file, book2_path)
check("book 2 ingested without exception", err2 is None)
docs = agent.kb.list_library_documents()
check("2 documents now in library", len(docs) == 2)

print("\n[2] _rebuild_index builds TF-IDF + concept graph + summaries end-to-end")
out3, err3 = run_silently(agent._rebuild_index)
check("no exception raised", err3 is None)
if err3:
    print("     EXCEPTION:", repr(err3))
check("mentions success", "✅" in out3)
check("intelligence index actually built on disk", relevance_engine.is_index_built())

print("\n[3] _concept_explore finds cross-book relevant passages")
out4, err4 = run_silently(agent._concept_explore, "port scanning reconnaissance")
check("no exception raised", err4 is None)
if err4:
    print("     EXCEPTION:", repr(err4))
check("finds at least one relevant book", "network_recon" in out4.lower() or "privesc" in out4.lower())

print("\n[4] _concept_link checks the SUID<->recon cross-book link")
out5, err5 = run_silently(agent._concept_link, "suid", "port scanning")
check("no exception raised", err5 is None)
if err5:
    print("     EXCEPTION:", repr(err5))

print("\n[5] _summarize_doc produces a real extractive summary")
out6, err6 = run_silently(agent._summarize_doc, "network_recon")
check("no exception raised", err6 is None)
if err6:
    print("     EXCEPTION:", repr(err6))
check("summary output non-trivial length", len(out6) > 50)
doc1_id = [d["id"] for d in agent.kb.list_library_documents() if "network_recon" in d["title"]][0]
saved_summary = agent.kb.get_document_summary(doc1_id)
check("summary actually persisted to DB", bool(saved_summary))

print("\n[6] _explain falls back to TF-IDF ranking for a conceptual (non-exact) phrase")
out7, err7 = run_silently(agent._explain, "escalation chain via writable files")
check("no exception raised", err7 is None)
if err7:
    print("     EXCEPTION:", repr(err7))

print("\n[7] _show_learned reports the built index status")
out8, err8 = run_silently(agent._show_learned)
check("no exception raised", err8 is None)
check("reports index is built", "🧠" in out8)

print("\n[8] web.web_search reranking doesn't crash with real rank_texts call")
from tools import web
from unittest.mock import patch
with patch("tools.web._ddg_instant_answer", return_value=[]), \
     patch("tools.web._ddg_html_search", return_value=[
         {"title": "Unrelated pizza recipe", "url": "http://a", "snippet": "delicious dough", "source": "DDG", "type": "search"},
         {"title": "Nmap port scanning guide", "url": "http://b", "snippet": "scan open ports with nmap", "source": "DDG", "type": "search"},
     ]), \
     patch("tools.web._wikipedia_search", return_value=[]):
    ranked = web.web_search("nmap port scanning", max_results=5)
check("reranked so the relevant nmap result comes first", ranked[0]["url"] == "http://b")

print("\n[9] Intent routing dispatches all four new intents without KeyError")
class FakeCmd:
    def __init__(self, intent, entities=None):
        self.intent = intent; self.score = 1.0
        self.entities = entities or {}; self.explain_target = None

for intent, ents in [
    ("rebuild_index", {}),
    ("concept_explore", {"concept": "port scanning"}),
    ("concept_link", {"concept_a": "suid", "concept_b": "port scanning"}),
    ("summarize_doc", {"book_title": "network_recon"}),
]:
    out, err = run_silently(agent._route_nlp, FakeCmd(intent, ents), intent)
    check(f"{intent} routes without exception", err is None)
    if err:
        print("     EXCEPTION:", repr(err))

print(f"\n{'='*50}\nTOTAL: {passed} passed, {failed} failed\n{'='*50}")

import shutil
shutil.rmtree(tmp_intel, ignore_errors=True)
