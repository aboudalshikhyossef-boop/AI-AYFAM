"""
AI AYFAM — Narrator
يحوّل نتائج الفحص الخام (findings) إلى فقرة تمهيدية بلغة طبيعية تشرح
للمستخدم ماذا وجدت الأداة وما الأهم أولاً — قبل عرض الجداول والإحصائيات
التفصيلية. هذا ليس توليداً بذكاء اصطناعي، بل صياغة محلية مبنية على قواعد
واضحة، متّسقة، وقابلة للتنبؤ (وهذا مقصود — لا نريد "إبداعاً" في تقرير أمني).
"""


def _t(lang, ar, en):
    return ar if lang == "ar" else en


def narrate_findings(findings: list, scan_title: str, lang: str = "ar") -> str:
    """فقرة من 2-3 جمل: ماذا فعلت، ماذا وجدت، وما الأهم — قبل التفاصيل."""
    if not findings:
        return _t(lang,
            f"انتهيت من {scan_title}. لم أسجّل أي ملاحظة على الإطلاق.",
            f"Finished {scan_title}. Nothing to report at all.")

    counts = {}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1

    issues = [f for f in findings if (f.get("severity") or "").lower() in ("critical", "high", "medium", "low")]
    if not issues:
        return _t(lang,
            f"انتهيت من {scan_title}. كل ما ظهر كان معلوماتياً فقط — لا توجد مشاكل أمنية حقيقية.",
            f"Finished {scan_title}. Everything was informational only — no real security issues.")

    crit, high = counts.get("critical", 0), counts.get("high", 0)
    med, low = counts.get("medium", 0), counts.get("low", 0)
    top = next((f for f in issues if (f.get("severity") or "").lower() in ("critical", "high")), issues[0])
    urgent = crit > 0 or high > 0

    if lang == "ar":
        bits = []
        if crit: bits.append(f"{crit} خطيرة جداً")
        if high: bits.append(f"{high} خطيرة")
        if med:  bits.append(f"{med} متوسطة")
        if low:  bits.append(f"{low} منخفضة")
        breakdown = "، ".join(bits)
        lead = f"انتهيت من {scan_title} ووجدت {len(issues)} ملاحظة تستحق انتباهك ({breakdown})."
        focus = f" الأهم أولاً: {top.get('title','')}."
        closing = (" التفاصيل والحلول المقترحة أدناه — لن أطبّق أي إصلاح دون موافقتك صراحةً."
                   if urgent else " لا شيء عاجل، لكنها تستحق المراجعة عند الفرصة.")
        return lead + focus + closing

    bits = []
    if crit: bits.append(f"{crit} critical")
    if high: bits.append(f"{high} high")
    if med:  bits.append(f"{med} medium")
    if low:  bits.append(f"{low} low")
    breakdown = ", ".join(bits)
    lead = f"Finished {scan_title} and found {len(issues)} issue(s) worth your attention ({breakdown})."
    focus = f" Most important first: {top.get('title','')}."
    closing = (" Full details and suggested fixes are below — I won't apply anything without your explicit approval."
               if urgent else " Nothing urgent, but worth a look when you have time.")
    return lead + focus + closing


def narrate_intent(intent_desc: str, lang: str = "ar") -> str:
    """جملة قصيرة تُقال *قبل* بدء أي عملية — 'سأقوم بـ...' — شفافية استباقية."""
    return _t(lang, f"سأقوم الآن بـ: {intent_desc}", f"I'm about to: {intent_desc}")
