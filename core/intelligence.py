"""
AI AYFAM - Intelligence Engine
محرك التحليل الذكي — يحلل نتائج الفحص ويصنّف المخاطر
"""

from datetime import datetime
from typing import List, Dict, Any


SEVERITY_SCORE = {"critical": 100, "high": 70, "medium": 40, "low": 10, "info": 2}

RISK_THRESHOLDS = {
    "critical": 200,
    "high": 100,
    "medium": 40,
    "low": 10,
}

ARABIC_SEVERITY = {
    "critical": "خطير جداً",
    "high": "خطير",
    "medium": "متوسط",
    "low": "منخفض",
    "info": "معلومات",
    "CRITICAL": "خطير جداً",
    "HIGH": "خطير",
    "MEDIUM": "متوسط",
    "LOW": "منخفض",
}

# ─────────────────────────────────────────────────────────────────────────
#  Compound Risk Correlation — ربط ذكي بين نتائج منفصلة قد تكون كل واحدة
#  منها متوسطة الخطورة بمفردها، لكن اجتماعها يعني خطراً أعلى بكثير من مجموع
#  الاثنين. هذا رُكن على العناوين الفعلية التي تُنتجها tools/system.py و
#  tools/network.py اليوم (عربية دائماً بغضّ النظر عن لغة الواجهة).
# ─────────────────────────────────────────────────────────────────────────

_RULE_ID_TAGS = {
    "ssh_root_login":      ["SSH-ROOT-001"],
    "ssh_password_auth":   ["SSH-PASS-001"],
    "firewall_disabled":   ["FIREWALL-001"],
    "dangerous_port_open": ["NET-PORT-001"],
    "brute_force":         ["LOG-SSH-BRUTE"],
    "successful_root_ssh": ["SSH-ROOT-001"],
    "rogue_uid0_user":     ["SYS-USER-ROOT0"],
    "malicious_cron":      ["NET-SUSP-PROC"],
    "dangerous_suid":      ["SYS-SUID-001"],
    "world_writable":      ["SYS-WRITE-001"],
}

CORRELATION_RULES = [
    {
        "requires": ("ssh_root_login", "ssh_password_auth"),
        "severity": "critical",
        "title_ar": "🔗 خطر مركّب: دخول root عبر SSH بكلمة مرور — قابل للاختراق بالقوة الغاشمة مباشرة",
        "title_en": "🔗 Compound risk: SSH root login + password auth — directly brute-forceable",
        "detail_ar": "كل شرط وحده خطر، لكن اجتماعهما يعني أن أي مهاجم يحتاج فقط تخمين كلمة مرور واحدة للوصول الكامل كـ root.",
        "detail_en": "Each condition alone is risky, but together an attacker only needs to guess one password for full root access.",
        "fix": "PermitRootLogin no\nPasswordAuthentication no\n# في /etc/ssh/sshd_config ثم: sudo systemctl restart sshd",
    },
    {
        "requires": ("firewall_disabled", "dangerous_port_open"),
        "severity": "critical",
        "title_ar": "🔗 خطر مركّب: جدار حماية معطَّل + منفذ خطير مكشوف — الخدمة مكشوفة فعلياً للشبكة",
        "title_en": "🔗 Compound risk: firewall disabled + dangerous port exposed — service is actually reachable",
        "detail_ar": "بدون جدار حماية، أي منفذ خطير مفتوح يُصبح قابلاً للوصول مباشرة من أي مكان على الشبكة، لا محلياً فقط.",
        "detail_en": "Without a firewall, a dangerous open port becomes directly reachable from anywhere on the network, not just locally.",
        "fix": "sudo ufw enable\nsudo ufw default deny incoming",
    },
    {
        "requires": ("brute_force", "ssh_password_auth"),
        "severity": "critical",
        "title_ar": "🔗 خطر مركّب: هجوم قوة غاشمة نشط ضد SSH يسمح بكلمات المرور",
        "title_en": "🔗 Compound risk: active brute-force attack against password-auth SSH",
        "detail_ar": "الهجوم مستمر فعلياً الآن، والباب لا يزال مفتوحاً (كلمات المرور مسموحة) — أولوية فورية قصوى.",
        "detail_en": "The attack is actively ongoing right now, and the door is still open (passwords allowed) — top immediate priority.",
        "fix": "sudo apt install fail2ban && sudo systemctl enable --now fail2ban\nPasswordAuthentication no",
    },
    {
        "requires": ("brute_force", "successful_root_ssh"),
        "severity": "critical",
        "title_ar": "🔗 خطر مركّب: دخول root ناجح تزامَن مع هجوم قوة غاشمة — مؤشر اختراق محتمل",
        "title_en": "🔗 Compound risk: successful root login coincided with a brute-force attack — possible breach indicator",
        "detail_ar": "هذا لا يعني اختراقاً مؤكداً، لكنه نمط يستحق تحقيقاً فورياً: راجع من دخل ومتى.",
        "detail_en": "This doesn't confirm a breach, but the pattern warrants immediate investigation: check who logged in and when.",
        "fix": "راجع: last -a | head -20\nراجع /var/log/auth.log لنفس الفترة\nغيّر كلمات مرور كل حسابات root/sudo فوراً",
    },
    {
        "requires": ("rogue_uid0_user", "malicious_cron"),
        "severity": "critical",
        "title_ar": "🔗 خطر مركّب: حساب بصلاحية root غير معروف + مهمة cron خبيثة — نمط باب خلفي (backdoor)",
        "title_en": "🔗 Compound risk: unknown UID=0 account + malicious cron job — classic backdoor pattern",
        "detail_ar": "هذا التزامن تحديداً هو النمط الكلاسيكي لآلية استمرارية (persistence) بعد اختراق — يستحق تحقيقاً فورياً.",
        "detail_en": "This specific combination is the classic post-compromise persistence pattern — warrants immediate investigation.",
        "fix": "لا تُصلح تلقائياً — وثّق أولاً (لقطات، نسخ من /etc/passwd وcrontab)، اعزل الجهاز عن الشبكة، ثم استشر مختص استجابة حوادث.",
    },
    {
        "requires": ("dangerous_suid", "world_writable"),
        "severity": "high",
        "title_ar": "🔗 خطر مركّب: ملف SUID في مكان حسّاس + ملف نظام قابل للكتابة من الجميع — سلسلة تصعيد صلاحيات محتملة",
        "title_en": "🔗 Compound risk: sensitive SUID binary + world-writable system file — possible privilege-escalation chain",
        "detail_ar": "إن كان أحدهما يقع ضمن مسار الآخر أو يُستخدَم به، فهذا نمط تصعيد صلاحيات كلاسيكي.",
        "detail_en": "If one sits within or is used by the other, this is a classic privilege-escalation pattern.",
        "fix": "راجع يدوياً: هل الملف القابل للكتابة من الجميع يقع ضمن مسار البرنامج SUID أو يُستدعى منه؟",
    },
]


def _tag_findings(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """يُرجع dict: وسم -> قائمة النتائج المطابقة له بحسب rule_id أو tags فقط (بدون أي مطابقة نصية للعنوان)."""
    tagged: Dict[str, List[Dict]] = {}
    for f in findings:
        r_id = f.get("rule_id", "")
        f_tags = f.get("tags") or []
        for tag, rule_ids in _RULE_ID_TAGS.items():
            if r_id in rule_ids or any(t in f_tags for t in rule_ids):
                tagged.setdefault(tag, []).append(f)
    return tagged


class SecurityIntelligence:
    def __init__(self, language: str = "ar"):
        self.language = language
        self.findings_cache = []

    def score_finding(self, finding: Dict) -> int:
        sev = finding.get("severity", "info").lower()
        return SEVERITY_SCORE.get(sev, 0)

    def aggregate_findings(self, *finding_lists) -> List[Dict]:
        all_findings = []
        for lst in finding_lists:
            if isinstance(lst, list):
                all_findings.extend(lst)
            elif isinstance(lst, dict) and "findings" in lst:
                all_findings.extend(lst["findings"])
        all_findings.sort(key=lambda f: SEVERITY_SCORE.get(f.get("severity", "info").lower(), 0), reverse=True)
        self.findings_cache = all_findings
        return all_findings

    def compute_risk_score(self, findings: List[Dict]) -> Dict:
        total = sum(self.score_finding(f) for f in findings)
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1

        if total >= RISK_THRESHOLDS["critical"] or counts["critical"] >= 2:
            level = "critical"
            label_ar = "[حرج] خطر شديد"
            label_en = "[CRITICAL] CRITICAL RISK"
        elif total >= RISK_THRESHOLDS["high"] or counts["critical"] >= 1 or counts["high"] >= 3:
            level = "high"
            label_ar = "[مرتفع] خطر عالي"
            label_en = "[HIGH] HIGH RISK"
        elif total >= RISK_THRESHOLDS["medium"] or counts["high"] >= 1:
            level = "medium"
            label_ar = "[متوسط] خطر متوسط"
            label_en = "[MEDIUM] MEDIUM RISK"
        elif total >= RISK_THRESHOLDS["low"] or counts["medium"] >= 1:
            level = "low"
            label_ar = "[منخفض] خطر منخفض"
            label_en = "[LOW] LOW RISK"
        else:
            level = "safe"
            label_ar = "[آمن] آمن"
            label_en = "[SAFE] SAFE"

        return {
            "score": total,
            "level": level,
            "label_ar": label_ar,
            "label_en": label_en,
            "counts": counts,
            "total_findings": len(findings),
        }

    def generate_summary(self, risk: Dict, findings: List[Dict], scan_type: str = "general") -> str:
        from brain.narrator import narrate_findings
        lang = self.language
        counts = risk["counts"]
        score = risk["score"]
        level = risk["level"]
        narration = narrate_findings(findings, scan_type, lang)

        if lang == "ar":
            summary = f"""
[التحليل]: {narration}

[ملخص الفحص الأمني — AI AYFAM]
{'='*50}
نوع الفحص  : {scan_type}
وقت الفحص  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
مستوى الخطر : {risk['label_ar']}
نقاط الخطر : {score}

إحصائيات النتائج:
  [حرج] خطير جداً : {counts['critical']}
  [مرتفع] خطير   : {counts['high']}
  [متوسط] متوسط  : {counts['medium']}
  [منخفض] منخفض  : {counts['low']}
  [معلومات] معلومات: {counts['info']}
  ─────────────────
  المجموع       : {risk['total_findings']}
"""
            if level == "safe":
                summary += "\n[آمن] النظام في حالة جيدة. لم يتم رصد مشاكل أمنية كبيرة.\n"
            elif level in ("critical", "high"):
                summary += "\n[تحذير] تم رصد مشاكل أمنية خطيرة تستوجب التدخل الفوري!\n"
            else:
                summary += "\n[ملاحظة] يُنصح بمعالجة النتائج المُكتشفة لتعزيز أمان النظام.\n"
        else:
            summary = f"""
[Analysis]: {narration}

[Security Scan Summary — AI AYFAM]
{'='*50}
Scan Type  : {scan_type}
Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Risk Level : {risk['label_en']}
Risk Score : {score}

Findings Summary:
  [CRITICAL] Critical : {counts['critical']}
  [HIGH]     High     : {counts['high']}
  [MEDIUM]   Medium   : {counts['medium']}
  [LOW]      Low      : {counts['low']}
  [INFO]     Info     : {counts['info']}
  ─────────────────
  Total               : {risk['total_findings']}
"""
            if level == "safe":
                summary += "\n[SAFE] System appears to be in good security posture.\n"
            elif level in ("critical", "high"):
                summary += "\n[WARNING] Critical security issues detected! Immediate action required!\n"
            else:
                summary += "\n[NOTE] Review and address findings to improve system security.\n"

        return summary

    def prioritize_fixes(self, findings: List[Dict]) -> List[Dict]:
        with_fix = [f for f in findings if f.get("fix")]
        without_fix = [f for f in findings if not f.get("fix")]
        with_fix.sort(key=lambda f: SEVERITY_SCORE.get(f.get("severity", "info").lower(), 0), reverse=True)
        return with_fix + without_fix

    def translate_finding(self, finding: Dict) -> Dict:
        if self.language == "ar":
            sev = finding.get("severity", "info").lower()
            finding = {**finding, "severity_label": ARABIC_SEVERITY.get(sev, sev)}
        return finding

    def explain_finding(self, finding: Dict) -> str:
        lang = self.language
        sev = finding.get("severity", "info").lower()
        sev_ar = ARABIC_SEVERITY.get(sev, sev)
        title = finding.get("title", "")
        detail = finding.get("detail", "")
        fix = finding.get("fix", "")

        if lang == "ar":
            text = f"⚠️  [{sev_ar}] {title}\n"
            if detail:
                text += f"   التفاصيل: {detail}\n"
            if fix:
                text += f"   الحل المقترح:\n"
                for step in fix.split("\n"):
                    if step.strip():
                        text += f"     → {step}\n"
        else:
            text = f"⚠️  [{sev.upper()}] {title}\n"
            if detail:
                text += f"   Details: {detail}\n"
            if fix:
                text += f"   Suggested Fix:\n"
                for step in fix.split("\n"):
                    if step.strip():
                        text += f"     → {step}\n"
        return text

    def analyze_usb_risk(self, devices: list) -> Dict:
        findings = []
        for dev in devices:
            for flag in dev.get("flags", []):
                sev = "critical" if "BadUSB" in flag or "Rubber" in flag else "medium"
                findings.append({
                    "severity": sev,
                    "title": f"جهاز USB: {dev.get('product', dev.get('description', 'Unknown'))} — {flag}",
                    "detail": f"Vendor ID: {dev.get('vendor_id')} | Product ID: {dev.get('product_id')} | Bus: {dev.get('bus')}:{dev.get('device')}",
                    "fix": "\n".join(dev.get("recommendations", ["راجع الجهاز وافصله إن كنت لا تعرفه"])),
                })
        return {"findings": findings}

    def correlate_findings(self, findings: List[Dict]) -> List[Dict]:
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("title", "")[:50], f.get("severity", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def detect_compound_risks(self, findings: List[Dict]) -> List[Dict]:
        """
        يبحث عن تركيبات معروفة الخطورة بين نتائج منفصلة (مثال: SSH يسمح
        بدخول root + SSH يقبل كلمات مرور = خطر مركّب أعلى بكثير من مجموع
        الاثنين منفردَين). كل نتيجة مركّبة تحمل "compound": True وتوضّح
        بالضبط أي نتائج أصلية اجتمعت لتوليدها — شفافية كاملة، وليست
        صندوقاً أسود. لا تُزال أي نتيجة أصلية؛ هذه إضافات فوق القائمة.
        """
        tagged = _tag_findings(findings)
        compound = []
        for rule in CORRELATION_RULES:
            if all(tag in tagged for tag in rule["requires"]):
                source_titles = [tagged[tag][0].get("title", "") for tag in rule["requires"]]
                sep = "\n\nمبني على: " if self.language == "ar" else "\n\nBased on: "
                detail = (rule["detail_ar"] if self.language == "ar" else rule["detail_en"]) + sep + " + ".join(source_titles)
                compound.append({
                    "severity": rule["severity"],
                    "title": rule["title_ar"] if self.language == "ar" else rule["title_en"],
                    "detail": detail,
                    "fix": rule["fix"],
                    "compound": True,
                })
        return compound

    def compare_scans(self, previous: Dict, current: Dict) -> Dict:
        """
        يقارن نتيجة فحص سابق (بالشكل الذي تعيده kb.get_last_scan) بنتيجة
        الفحص الحالي: نتائج جديدة، نتائج تم حلّها، تغيّر نقاط الخطر،
        واتجاه عام (تحسّن/تدهور/استقرار). previous=None يعني أول فحص من
        هذا النوع على الإطلاق — لا مقارنة ممكنة، فنعيد None بدل تخمين.
        """
        if not previous:
            return None

        prev_result = previous.get("result", previous)
        prev_findings = prev_result.get("findings", []) or []
        prev_risk = prev_result.get("risk", {}) or {}

        cur_findings = current.get("findings", []) or []
        cur_risk = current.get("risk", {}) or {}

        def _key(f):
            fp = f.get("fingerprint") or f.get("id")
            if fp:
                return fp
            return (f.get("rule_id", ""), f.get("title", "")[:60], f.get("severity", ""))

        prev_map = {_key(f): f for f in prev_findings}
        cur_map = {_key(f): f for f in cur_findings}

        resolved = [f for k, f in prev_map.items() if k not in cur_map]
        new_findings = [f for k, f in cur_map.items() if k not in prev_map]
        unchanged_count = len([k for k in cur_map if k in prev_map])

        score_delta = cur_risk.get("score", 0) - prev_risk.get("score", 0)
        trend = "improved" if score_delta < 0 else ("worsened" if score_delta > 0 else "stable")

        return {
            "previous_scanned_at": previous.get("scanned_at", ""),
            "resolved": resolved,
            "new_findings": new_findings,
            "unchanged_count": unchanged_count,
            "prev_score": prev_risk.get("score", 0),
            "cur_score": cur_risk.get("score", 0),
            "score_delta": score_delta,
            "prev_level": prev_risk.get("level", "?"),
            "cur_level": cur_risk.get("level", "?"),
            "trend": trend,
        }

    def generate_trend_narrative(self, comparison: Dict, lang: str = None) -> str:
        """يحوّل ناتج compare_scans() لنص قابل للعرض المباشر في الواجهة."""
        if not comparison:
            return ""
        lang = lang or self.language
        resolved_n = len(comparison["resolved"])
        new_n = len(comparison["new_findings"])
        delta = comparison["score_delta"]
        when = (comparison.get("previous_scanned_at") or "")[:16]

        if lang == "ar":
            lines = [f"[مقارنة] مقارنة بالفحص السابق ({when}):"]
            if comparison["trend"] == "improved":
                lines.append(f"  [تحسّن] انخفضت نقاط الخطر {abs(delta)} نقطة ({comparison['prev_level']} ← {comparison['cur_level']})")
            elif comparison["trend"] == "worsened":
                lines.append(f"  [تدهور] ارتفعت نقاط الخطر {delta} نقطة ({comparison['prev_level']} ← {comparison['cur_level']})")
            else:
                lines.append(f"  [مستقر] نفس نقاط الخطر ({comparison['cur_level']})")
            if resolved_n:
                lines.append(f"  [تم الحل] تم حلّ {resolved_n} مشكلة كانت موجودة سابقاً:")
                lines.extend(f"     • {f.get('title','')[:70]}" for f in comparison["resolved"][:3])
            if new_n:
                lines.append(f"  [جديد] ظهرت {new_n} مشكلة جديدة منذ آخر فحص:")
                lines.extend(f"     • {f.get('title','')[:70]}" for f in comparison["new_findings"][:3])
            if not resolved_n and not new_n:
                lines.append("  (لا فرق في النتائج منذ آخر فحص)")
        else:
            lines = [f"[Trend] Compared to previous scan ({when}):"]
            if comparison["trend"] == "improved":
                lines.append(f"  [Improved] risk score dropped {abs(delta)} pts ({comparison['prev_level']} → {comparison['cur_level']})")
            elif comparison["trend"] == "worsened":
                lines.append(f"  [Worsened] risk score rose {delta} pts ({comparison['prev_level']} → {comparison['cur_level']})")
            else:
                lines.append(f"  [Stable] same risk score ({comparison['cur_level']})")
            if resolved_n:
                lines.append(f"  [Resolved] {resolved_n} issue(s) resolved since last scan:")
                lines.extend(f"     • {f.get('title','')[:70]}" for f in comparison["resolved"][:3])
            if new_n:
                lines.append(f"  [New] {new_n} new issue(s) since last scan:")
                lines.extend(f"     • {f.get('title','')[:70]}" for f in comparison["new_findings"][:3])
            if not resolved_n and not new_n:
                lines.append("  (No difference in findings since last scan)")

        return "\n".join(lines)

    def get_remediation_plan(self, findings: List[Dict]) -> str:
        lang = self.language
        critical = [f for f in findings if f.get("severity", "").lower() == "critical"]
        high = [f for f in findings if f.get("severity", "").lower() == "high"]
        medium = [f for f in findings if f.get("severity", "").lower() == "medium"]

        if lang == "ar":
            plan = "خطة المعالجة الأمنية — AI AYFAM\n" + "="*50 + "\n"
            if critical:
                plan += "\n[حرج] الأولوية القصوى (فوري):\n"
                for i, f in enumerate(critical[:5], 1):
                    plan += f"  {i}. {f.get('title', '')}\n"
                    if f.get("fix"):
                        plan += f"     الحل: {f['fix'].split(chr(10))[0]}\n"
            if high:
                plan += "\n[مرتفع] الأولوية العالية (خلال 24 ساعة):\n"
                for i, f in enumerate(high[:5], 1):
                    plan += f"  {i}. {f.get('title', '')}\n"
            if medium:
                plan += "\n[متوسط] الأولوية المتوسطة (خلال أسبوع):\n"
                for i, f in enumerate(medium[:5], 1):
                    plan += f"  {i}. {f.get('title', '')}\n"
            if not any([critical, high, medium]):
                plan += "\n[آمن] لا توجد مشاكل أمنية عاجلة.\n"
        else:
            plan = "Security Remediation Plan — AI AYFAM\n" + "="*50 + "\n"
            if critical:
                plan += "\n[CRITICAL] IMMEDIATE:\n"
                for i, f in enumerate(critical[:5], 1):
                    plan += f"  {i}. {f.get('title', '')}\n"
                    if f.get("fix"):
                        plan += f"     Fix: {f['fix'].split(chr(10))[0]}\n"
            if high:
                plan += "\n[HIGH] HIGH PRIORITY (24 hours):\n"
                for i, f in enumerate(high[:5], 1):
                    plan += f"  {i}. {f.get('title', '')}\n"
            if medium:
                plan += "\n[MEDIUM] MEDIUM PRIORITY (1 week):\n"
                for i, f in enumerate(medium[:5], 1):
                    plan += f"  {i}. {f.get('title', '')}\n"
            if not any([critical, high, medium]):
                plan += "\n[SAFE] No urgent security issues found.\n"
        return plan
