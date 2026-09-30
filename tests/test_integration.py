import sys, os, tempfile, io
from contextlib import redirect_stdout

TMP_HOME = tempfile.mkdtemp(prefix="ayfam_home_")
os.environ["HOME"] = TMP_HOME
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import Settings
from ui.terminal import TerminalUI
from brain.knowledge_base import KnowledgeBase
from core.agent import AYFAMAgent

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

settings = Settings()
ui = TerminalUI(no_color=True)
# لا نريد أي input() تفاعلي يعلّق الاختبار — نُرجع قيماً افتراضية آمنة دائماً
ui.ask = lambda prompt, default=None: (default if default is not None else "")
ui.confirm = lambda prompt, default=False: False

agent = AYFAMAgent(settings=settings, ui=ui, verbose=False)
# قاعدة معرفة مؤقتة منعزلة عن أي بيانات حقيقية
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

print("\n[1] _scan_system runs end-to-end (real local checks + blocked-network CVE enrichment)")
out1, err1 = run_silently(agent._scan_system)
check("no exception raised", err1 is None)
if err1:
    print("     EXCEPTION:", repr(err1))
check("first run: no trend narrative yet (no prior scan)", "📈" not in out1)

print("\n[2] second _scan_system run produces a trend comparison")
out2, err2 = run_silently(agent._scan_system)
check("no exception raised", err2 is None)
check("trend narrative present on 2nd run", "📈" in out2)
history = agent.kb.get_scan_history("system", limit=5)
check("2 scans recorded in history", len(history) == 2)

print("\n[3] _scan_network runs end-to-end")
out3, err3 = run_silently(agent._scan_network)
check("no exception raised", err3 is None)
if err3:
    print("     EXCEPTION:", repr(err3))

print("\n[4] _scan_logs runs end-to-end")
out4, err4 = run_silently(agent._scan_logs)
check("no exception raised", err4 is None)
if err4:
    print("     EXCEPTION:", repr(err4))

print("\n[5] _full_scan runs end-to-end (exercises every new integration point at once)")
out5, err5 = run_silently(agent._full_scan)
check("no exception raised", err5 is None)
if err5:
    print("     EXCEPTION:", repr(err5))

print("\n[6] _cve_search gracefully degrades when NVD is unreachable (sandboxed network)")
out6, err6 = run_silently(agent._cve_search, "openssh")
check("no exception raised", err6 is None)
if err6:
    print("     EXCEPTION:", repr(err6))

print("\n[7] _web_search gracefully degrades when all sources are unreachable")
out7, err7 = run_silently(agent._web_search, "nmap")
check("no exception raised", err7 is None)
if err7:
    print("     EXCEPTION:", repr(err7))

print("\n[8] _check_ip gracefully degrades (no key configured, network blocked)")
out8, err8 = run_silently(agent._check_ip, "8.8.8.8")
check("no exception raised", err8 is None)
if err8:
    print("     EXCEPTION:", repr(err8))

print("\n[9] _pkg_vuln_search (OSV.dev) gracefully degrades when network is blocked")
ui.ask = lambda prompt, default=None: "requests" if "حزمة" in prompt or "Package" in prompt else (default or "PyPI")
out9, err9 = run_silently(agent._pkg_vuln_search, "requests")
check("no exception raised", err9 is None)
if err9:
    print("     EXCEPTION:", repr(err9))

print("\n[10] _show_trend renders after several scans exist")
out10, err10 = run_silently(agent._show_trend)
check("no exception raised", err10 is None)
check("shows a table for system scans", "system" in out10.lower() or "🖥️" in out10)
if err10:
    print("     EXCEPTION:", repr(err10))

print("\n[11] _update_intel gracefully reports no connectivity (sandboxed network)")
out11, err11 = run_silently(agent._update_intel)
check("no exception raised", err11 is None)
if err11:
    print("     EXCEPTION:", repr(err11))

print("\n[12] _config_menu new options (5/6) work without crashing")
ui.ask = lambda prompt, default=None: "5" if (default == "0") else "TESTKEY123456"
out12a, err12a = run_silently(agent._config_menu)
check("option 5 (abuseipdb_key) no exception", err12a is None)
check("abuseipdb_key actually saved", agent.settings.get("abuseipdb_key") == "TESTKEY123456")

ui.ask = lambda prompt, default=None: "6" if (default == "0") else "NVDKEY7890"
out12b, err12b = run_silently(agent._config_menu)
check("option 6 (nvd_api_key) no exception", err12b is None)
check("nvd_api_key actually saved", agent.settings.get("nvd_api_key") == "NVDKEY7890")

print("\n[13] intent routing dispatches to new handlers without KeyError")
class FakeCmd:
    def __init__(self, intent, entities=None):
        self.intent = intent; self.score = 1.0
        self.entities = entities or {}; self.explain_target = None

ui.ask = lambda prompt, default=None: (default if default is not None else "")
out13, err13 = run_silently(agent._route_nlp, FakeCmd("pkg_vuln_search", {"package": "flask"}), "ثغرات حزمة flask")
check("pkg_vuln_search intent routes without exception", err13 is None)
if err13:
    print("     EXCEPTION:", repr(err13))

out14, err14 = run_silently(agent._route_nlp, FakeCmd("scan_trend"), "تطور الوضع")
check("scan_trend intent routes without exception", err14 is None)
if err14:
    print("     EXCEPTION:", repr(err14))

print(f"\n{'='*50}\nTOTAL: {passed} passed, {failed} failed\n{'='*50}")
sys.exit(1 if failed else 0)
