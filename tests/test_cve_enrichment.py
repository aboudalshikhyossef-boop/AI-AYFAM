import sys, os, tempfile, io
from contextlib import redirect_stdout
from unittest.mock import patch

TMP_HOME = tempfile.mkdtemp(prefix="ayfam_home2_")
os.environ["HOME"] = TMP_HOME
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import Settings
from ui.terminal import TerminalUI
from brain.knowledge_base import KnowledgeBase
from core.agent import AYFAMAgent
from tools import system as system_tool

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

settings = Settings()
ui = TerminalUI(no_color=True)
ui.ask = lambda prompt, default=None: (default if default is not None else "")
ui.confirm = lambda prompt, default=False: False
agent = AYFAMAgent(settings=settings, ui=ui, verbose=False)
agent.kb = KnowledgeBase(db_path=os.path.join(TMP_HOME, "test_brain.db"))

FAKE_KEV = [{"cve_id": "CVE-2024-9999", "vendor": "OpenBSD", "product": "openssh",
             "description": "OpenSSH RCE", "date_added": "2024-01-01", "severity": "CRITICAL"}]

with patch("tools.system.list_upgradable_security_packages",
           return_value={"packages": [{"package": "openssh-server", "raw_line": "..."}]}), \
     patch("core.agent.web.get_cisa_known_exploited", return_value=FAKE_KEV):
    buf = io.StringIO()
    with redirect_stdout(buf):
        agent._scan_system()
    out = buf.getvalue()

check("CVE-enriched finding title appears in output", "CISA KEV" in out or "CISA" in out)
check("finding mentions the matched package name", "openssh-server" in out)

last = agent.kb.get_last_scan("system")
findings = last["result"]["findings"] if last else []
enriched = [f for f in findings if f.get("cve_enriched")]
check("at least one finding marked cve_enriched=True in saved scan", len(enriched) >= 1)
check("enriched finding is critical severity (KEV match)", any(f["severity"] == "critical" for f in enriched))

print(f"\n{'='*50}\nTOTAL: {passed} passed, {failed} failed\n{'='*50}")
