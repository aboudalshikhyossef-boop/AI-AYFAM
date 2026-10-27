"""
Unit tests for brain/narrator.py

These tests verify deterministic narration logic including empty findings,
informational-only findings, multi-severity prioritization, explicit fix approval warnings,
no claims of unexecuted fixes, and bilingual intent narration.
"""

from brain.narrator import narrate_findings, narrate_intent


def test_narrate_findings_empty():
    """1. حالة عدم وجود findings."""
    res_ar = narrate_findings([], "فحص النظام", lang="ar")
    assert "انتهيت من فحص النظام" in res_ar
    assert "لم أسجّل أي ملاحظة" in res_ar

    res_en = narrate_findings([], "System Scan", lang="en")
    assert "Finished System Scan" in res_en
    assert "Nothing to report at all" in res_en


def test_narrate_findings_informational_only():
    """2. حالة وجود findings معلوماتية فقط."""
    findings = [
        {"title": "Info Note 1", "severity": "info"},
        {"title": "Info Note 2", "severity": "INFO"},
    ]

    res_ar = narrate_findings(findings, "فحص الشبكة", lang="ar")
    assert "كل ما ظهر كان معلوماتياً فقط" in res_ar
    assert "لا توجد مشاكل أمنية حقيقية" in res_ar

    res_en = narrate_findings(findings, "Network Scan", lang="en")
    assert "Everything was informational only" in res_en
    assert "no real security issues" in res_en


def test_narrate_findings_all_severities():
    """3. حالة تحتوي critical وhigh وmedium وlow."""
    findings = [
        {"title": "Crit Bug", "severity": "critical"},
        {"title": "High Bug", "severity": "high"},
        {"title": "Med Bug", "severity": "medium"},
        {"title": "Low Bug", "severity": "low"},
        {"title": "Info Bug", "severity": "info"},
    ]

    res_ar = narrate_findings(findings, "فحص شامل", lang="ar")
    assert "4 ملاحظة تستحق انتباهك" in res_ar
    assert "1 خطيرة جداً" in res_ar
    assert "1 خطيرة" in res_ar
    assert "1 متوسطة" in res_ar
    assert "1 منخفضة" in res_ar
    assert "الأهم أولاً: Crit Bug" in res_ar

    res_en = narrate_findings(findings, "Full Scan", lang="en")
    assert "found 4 issue(s) worth your attention" in res_en
    assert "1 critical" in res_en
    assert "1 high" in res_en
    assert "1 medium" in res_en
    assert "1 low" in res_en
    assert "Most important first: Crit Bug" in res_en


def test_narrate_intent_arabic():
    """4. اختبار narrate_intent باللغة العربية."""
    intent_ar = narrate_intent("فحص المنافذ المفتوحة", lang="ar")
    assert intent_ar == "سأقوم الآن بـ: فحص المنافذ المفتوحة"


def test_narrate_intent_english():
    """5. اختبار narrate_intent باللغة الإنجليزية."""
    intent_en = narrate_intent("scanning open ports", lang="en")
    assert intent_en == "I'm about to: scanning open ports"


def test_critical_high_priority():
    """6. التأكد من أولوية critical/high بغض النظر عن الترتيب في القائمة."""
    findings = [
        {"title": "Low Priority First", "severity": "low"},
        {"title": "Medium Priority Second", "severity": "medium"},
        {"title": "High Threat Found", "severity": "high"},
        {"title": "Critical Threat Found", "severity": "critical"},
    ]

    res_ar = narrate_findings(findings, "فحص الثغرات", lang="ar")
    assert "الأهم أولاً: High Threat Found" in res_ar or "الأهم أولاً: Critical Threat Found" in res_ar
    # Ensure it picked the first critical/high finding (High Threat Found in this list) instead of Low Priority First
    assert "Low Priority First" not in res_ar.split("الأهم أولاً:")[1]

    res_en = narrate_findings(findings, "Vulnerability Scan", lang="en")
    assert "Low Priority First" not in res_en.split("Most important first:")[1]


def test_explicit_approval_required_for_fixes():
    """7. التأكد من أن النظام يطلب موافقة صريحة قبل تطبيق أي إصلاح."""
    urgent_findings = [{"title": "Critical Kernel Flaw", "severity": "critical"}]

    res_ar = narrate_findings(urgent_findings, "فحص النواة", lang="ar")
    assert "لن أطبّق أي إصلاح دون موافقتك صراحةً" in res_ar

    res_en = narrate_findings(urgent_findings, "Kernel Scan", lang="en")
    assert "I won't apply anything without your explicit approval" in res_en


def test_narration_does_not_claim_fix_executed():
    """8. التأكد من أن السرد لا يدّعي تنفيذ إصلاح لم يُنفذ."""
    findings = [
        {"title": "Misconfigured SSH", "severity": "high"},
        {"title": "Unpatched Package", "severity": "medium"},
    ]

    res_ar = narrate_findings(findings, "فحص الإعدادات", lang="ar")
    res_en = narrate_findings(findings, "Config Scan", lang="en")

    # Narration should inform and propose, never claim that a fix was already executed or applied
    claims_ar = ["تم إغلاق", "تم حظر", "تم إصلاح", "تم التطبيق", "قمت بصلح", "تم التعديل"]
    claims_en = ["fixed", "remediated", "applied fix", "resolved automatically", "patched"]

    for claim in claims_ar:
        assert claim not in res_ar, f"Narration should not claim completed fix execution: '{claim}'"

    for claim in claims_en:
        assert claim.lower() not in res_en.lower(), f"Narration should not claim completed fix execution: '{claim}'"
