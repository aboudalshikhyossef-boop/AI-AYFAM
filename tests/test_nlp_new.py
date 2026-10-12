import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from brain.knowledge_base import SEED_INTENTS
from brain.nlp import NLPEngine

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

nlp = NLPEngine(knowledge_base=None)  # falls back to SEED_INTENTS directly

def parse(text):
    return nlp.parse(text)

print("\n[1] New: pkg_vuln_search entity + intent routing")
c = parse("ثغرات حزمة requests")
check("intent=pkg_vuln_search", c.intent == "pkg_vuln_search")
check("package entity extracted", c.entities.get("package") == "requests")

c2 = parse("package vulnerabilities django")
check("english phrasing also routes to pkg_vuln_search", c2.intent == "pkg_vuln_search")
check("package entity extracted (en)", c2.entities.get("package") == "django")

print("\n[2] New: scan_trend intent routing")
c3 = parse("قارن بالفحص السابق")
check("intent=scan_trend (ar)", c3.intent == "scan_trend")
c4 = parse("show me the security trend")
check("intent=scan_trend (en)", c4.intent == "scan_trend")

print("\n[3] Regression: existing intents still route correctly")
r1 = parse("افحص الشبكة")
check("scan_network still works", r1.intent == "scan_network")
r2 = parse("CVE-2024-12345")
check("cve entity still overrides to cve_search", r2.intent == "cve_search" and r2.entities.get("cve") == "CVE-2024-12345")
r3 = parse("ما هو nmap")
check("explain intent still works", r3.intent == "explain")
r4 = parse("فحص سمعة IP 8.8.8.8")
check("check_ip still works with ip entity", r4.intent == "check_ip" and r4.entities.get("ip") == "8.8.8.8")
r5 = parse("خروج")
check("exit still works", r5.intent == "exit")

print("\n[4] describe_intent has entries for new intents (both languages)")
from brain.nlp import NLPEngine as _E
desc_ar = nlp.describe_intent("pkg_vuln_search", "ar")
desc_en = nlp.describe_intent("pkg_vuln_search", "en")
check("pkg_vuln_search ar description exists and != raw key", desc_ar != "pkg_vuln_search")
check("pkg_vuln_search en description exists and != raw key", desc_en != "pkg_vuln_search")
desc_ar2 = nlp.describe_intent("scan_trend", "ar")
check("scan_trend ar description exists", desc_ar2 != "scan_trend")

print(f"\n{'='*50}\nTOTAL: {passed} passed, {failed} failed\n{'='*50}")
