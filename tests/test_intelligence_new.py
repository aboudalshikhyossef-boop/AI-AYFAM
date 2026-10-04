import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.intelligence import SecurityIntelligence

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

intel = SecurityIntelligence(language="ar")

# ── compound risk: SSH root login + password auth ──────────────────────
print("\n[1] detect_compound_risks — SSH root+password")
findings = [
    {"severity": "high", "title": "SSH يسمح بدخول root مباشر!", "detail": "", "fix": ""},
    {"severity": "medium", "title": "SSH يقبل كلمات المرور — استخدم SSH keys", "detail": "", "fix": ""},
]
compound = intel.detect_compound_risks(findings)
check("exactly 1 compound finding produced", len(compound) == 1)
check("severity escalated to critical", compound[0]["severity"] == "critical")
check("marked as compound", compound[0].get("compound") is True)
check("mentions both source titles", "SSH يسمح بدخول root" in compound[0]["detail"] and "SSH يقبل كلمات المرور" in compound[0]["detail"])

print("\n[2] detect_compound_risks — no match when only one condition present")
partial = intel.detect_compound_risks([{"severity": "high", "title": "SSH يسمح بدخول root مباشر!", "detail": "", "fix": ""}])
check("no compound finding for a single condition", len(partial) == 0)

print("\n[3] detect_compound_risks — firewall disabled + dangerous port")
fw_case = intel.detect_compound_risks([
    {"severity": "high", "title": "جدار الحماية UFW معطَّل / UFW Firewall is disabled", "detail": "", "fix": ""},
    {"severity": "high", "title": "منفذ خطير مفتوح: Telnet (23)", "detail": "", "fix": ""},
])
check("firewall+port rule fires", len(fw_case) == 1 and fw_case[0]["severity"] == "critical")

print("\n[4] detect_compound_risks — multiple rules can fire simultaneously")
multi = intel.detect_compound_risks([
    {"severity": "high", "title": "SSH يسمح بدخول root مباشر!", "detail": "", "fix": ""},
    {"severity": "medium", "title": "SSH يقبل كلمات المرور — استخدم SSH keys", "detail": "", "fix": ""},
    {"severity": "high", "title": "جدار الحماية UFW معطَّل / UFW Firewall is disabled", "detail": "", "fix": ""},
    {"severity": "high", "title": "منفذ خطير مفتوح: Telnet (23)", "detail": "", "fix": ""},
])
check("2 independent rules both fire", len(multi) == 2)

print("\n[5] English language output")
intel_en = SecurityIntelligence(language="en")
compound_en = intel_en.detect_compound_risks(findings)
check("english title used", "Compound risk" in compound_en[0]["title"])

# ── compare_scans / trend ────────────────────────────────────────────────
print("\n[6] compare_scans — first-ever scan (no previous)")
first = intel.compare_scans(None, {"risk": {"score": 50, "level": "medium"}, "findings": []})
check("returns None for first scan", first is None)

print("\n[7] compare_scans — improved (fewer findings, lower score)")
prev = {
    "scanned_at": "2026-07-01 10:00:00",
    "result": {
        "risk": {"score": 150, "level": "high"},
        "findings": [
            {"severity": "high", "title": "منفذ خطير مفتوح: Telnet (23)"},
            {"severity": "medium", "title": "تحديثات معلّقة: 5 حزمة"},
        ],
    },
}
cur = {
    "risk": {"score": 40, "level": "low"},
    "findings": [
        {"severity": "medium", "title": "تحديثات معلّقة: 5 حزمة"},
    ],
}
cmp1 = intel.compare_scans(prev, cur)
check("trend is improved", cmp1["trend"] == "improved")
check("1 resolved finding detected", len(cmp1["resolved"]) == 1 and "Telnet" in cmp1["resolved"][0]["title"])
check("0 new findings", len(cmp1["new_findings"]) == 0)
check("score_delta negative", cmp1["score_delta"] == 40 - 150)
narrative = intel.generate_trend_narrative(cmp1)
check("narrative mentions improvement status", "[تحسّن]" in narrative or "Improved" in narrative)
check("narrative mentions resolved count", "تم حلّ 1 مشكلة" in narrative)

print("\n[8] compare_scans — worsened (new critical finding appeared)")
cur2 = {
    "risk": {"score": 250, "level": "critical"},
    "findings": [
        {"severity": "medium", "title": "تحديثات معلّقة: 5 حزمة"},
        {"severity": "critical", "title": "دخول root ناجح عبر SSH!"},
    ],
}
cmp2 = intel.compare_scans(prev, cur2)
check("trend is worsened", cmp2["trend"] == "worsened")
check("1 new finding detected", len(cmp2["new_findings"]) == 1)
narrative2 = intel.generate_trend_narrative(cmp2)
check("narrative mentions warning status", "[تدهور]" in narrative2 or "Worsened" in narrative2)
check("narrative mentions new-issue count", "ظهرت 1 مشكلة جديدة" in narrative2)

print("\n[9] compare_scans — stable (identical findings/score)")
cmp3 = intel.compare_scans(prev, {"risk": {"score": 150, "level": "high"}, "findings": prev["result"]["findings"]})
check("trend is stable", cmp3["trend"] == "stable")
check("no resolved/new", len(cmp3["resolved"]) == 0 and len(cmp3["new_findings"]) == 0)

print(f"\n{'='*50}\nTOTAL: {passed} passed, {failed} failed\n{'='*50}")
sys.exit(1 if failed else 0)
