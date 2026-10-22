"""
AI AYFAM v8 — Attack Chain Correlation Engine
محرك الارتباط الذكي — يربط النتائج من فاحصات مختلفة في سلاسل هجوم
واقعية قابلة للتفسير، ويولّد توصيات إصلاح ذكية مرتبة بالأثر.

الفرق بين هذا المحرك و detect_compound_risks القديم:
  - detect_compound_risks يكشف أنماط ثنائية بسيطة (X + Y = خطر)
  - هذا المحرك يبني سلاسل هجوم كاملة متعددة الخطوات قابلة للتفسير:
    "سرقة اعتماد → تصعيد صلاحية → استمرارية → انتشار أفقي"

كل قاعدة تُنتج Finding بصيغة attack_chain تحتوي:
  - evidence: النتائج الأصلية التي ربطها المحرك
  - detail: شرح السلسلة بالكامل
  - fix: أول إصلاح مؤثّر (chokepoint) لا أمر عشوائي
  - attack_ids: تقنيات MITRE ATT&CK المرتبطة
"""

from __future__ import annotations

import re
from typing import List, Dict, Any, Optional
from engine.finding import Finding
from engine.attack import AttackEngine

# ─── Helper: find findings by tag/category ────────────────────────────────────

def _find_by_tag(findings: List[Finding], tag: str) -> List[Finding]:
    """ابحث عن كل النتائج التي تحمل وسماً معيناً."""
    return [f for f in findings if tag in (f.get("tags") or [])]


def _find_by_category(findings: List[Finding], cat: str) -> List[Finding]:
    """ابحث عن كل النتائج من فئة معينة."""
    return [f for f in findings if (f.get("category") or "").startswith(cat)]


def _find_by_severity(findings: List[Finding], min_sev: str = "medium") -> List[Finding]:
    """ابحث عن كل النتائج بدرجة خطورة معينة أو أعلى."""
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "safe": 0}
    threshold = order.get(min_sev, 2)
    return [f for f in findings if order.get((f.get("severity") or "info").lower(), 0) >= threshold]


def _extract_ips(text: str) -> List[str]:
    return list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text or "")))


def _extract_paths(text: str) -> List[str]:
    return list(set(re.findall(r'(/[\w\.-]+(?:/[\w\.-]+)+)', text or "")))


# ─── Attack Chain Rules ───────────────────────────────────────────────────────
# كل قاعدة تأخذ findings وتُعيد قائمة من Finding (attack_chain) أو [].
# القواعد مكتوبة لتكون مستقلة عن الترتيب — تعمل على أي مجموعة نتائج.

def _rule_ssh_compromise_path(findings: List[Finding]) -> List[Finding]:
    """
    سلسلة هجوم SSH الكاملة:
    1) SSH يسمح بكلمة المرور أو root (SSH-001 / SSH-002)
    2) هجوم brute force مسجّل في السجلات (LOG-SSH-BRUTE)
    3) → مسار اختراق مباشر عبر SSH
    """
    chains = []

    ssh_weak = [
        f for f in findings
        if f.get("rule_id") in ("SSH-001", "SSH-002") or "ssh" in (f.get("tags") or [])
    ]

    brute = [
        f for f in findings
        if f.get("rule_id") == "LOG-SSH-BRUTE" or "brute_force" in (f.get("tags") or [])
    ]

    if ssh_weak and brute:
        ssh_finding = ssh_weak[0]
        brute_finding = brute[0]
        ssh_ips = _extract_ips(brute_finding.get("detail", "") + " " + brute_finding.get("title", ""))

        evidence = {
            "ssh_finding_id": ssh_finding.get("id"),
            "brute_finding_id": brute_finding.get("id"),
            "attacker_ips": ssh_ips[:3],
            "ssh_title": ssh_finding.get("title"),
            "brute_title": brute_finding.get("title"),
        }

        chains.append(Finding(
            severity="critical",
            title="🔗 سلسلة اختراق SSH: إعدادات ضعيفة + هجوم قوة غاشمة نشط",
            detail=(
                f"المهاجم يستغل ضعفاً في إعدادات SSH ({ssh_finding.get('title', '')}) "
                f"مع هجوم brute force مسجّل ({brute_finding.get('title', '')}). "
                f"هذا مسار اختراق مباشر: المهاجم يحاول كلمات مرور شائعة بينما "
                f"النظام يقبلها. "
                + (f"عناوين IP المهاجمة: {', '.join(ssh_ips[:3])}. " if ssh_ips else "")
                + "الحل الفوري: تعطيل مصادقة كلمة المرور في SSH ومنع root من الدخول."
            ),
            fix="PermitRootLogin no\nPasswordAuthentication no\n# ثم: sudo systemctl restart sshd",
            category="attack_chain",
            tags=["attack_chain", "ssh", "brute_force", "credential_access"],
            attack_ids=["T1110.001", "T1078", "T1021.004"],
            evidence=evidence,
            effort="low",
            risk_of_fix="low",
            confidence=0.9,
        ))

    return chains


def _rule_exposed_service_path(findings: List[Finding]) -> List[Finding]:
    """
    خدمة حساسة مكشوفة (NET-PORT-001) + جدار حماية معطّل (FIREWALL-001) = سطح هجوم مباشر.
    """
    chains = []

    exposed = [
        f for f in findings
        if f.get("rule_id") == "NET-PORT-001"
        or "open_port" in (f.get("tags") or [])
        or "listening" in (f.get("tags") or [])
    ]

    fw_weak = [
        f for f in findings
        if f.get("rule_id") == "FIREWALL-001"
        or "firewall" in (f.get("tags") or [])
    ]

    if exposed and fw_weak:
        exposed_f = exposed[0]
        fw_f = fw_weak[0]

        chains.append(Finding(
            severity="critical",
            title="🔗 سطح هجوم مكشوف: خدمة حساسة + جدار حماية معطّل",
            detail=(
                f"الخدمة ({exposed_f.get('title', '')}) مكشوفة على الإنترنت "
                f"بينما جدار الحماية معطّل أو ضعيف ({fw_f.get('title', '')}). "
                f"هذا يعني أن المهاجم يمكنه الوصول المباشر للخدمة دون أي عائق. "
                f"أي ثغرة في هذه الخدمة تصبح قابلة للاستغلال الفوري من خارج الشبكة."
            ),
            fix=f"sudo ufw enable\n# ثم قيّد المنفذ: sudo ufw deny <port>",
            category="attack_chain",
            tags=["attack_chain", "exposed_service", "firewall", "initial_access"],
            attack_ids=["T1190", "T1021"],
            evidence={
                "exposed_finding_id": exposed_f.get("id"),
                "firewall_finding_id": fw_f.get("id"),
                "exposed_title": exposed_f.get("title"),
                "firewall_title": fw_f.get("title"),
            },
            effort="low",
            risk_of_fix="low",
            confidence=0.85,
        ))

    return chains


def _rule_credential_to_privilege_path(findings: List[Finding]) -> List[Finding]:
    """
    أسرار مكشوفة + مشكلة SUID/تصعيد صلاحيات = مسار تصعيد صلاحية كامل.
    سرقة اعتماد → استخدام SUID → root.
    نستخدم وسوم suid/suid_anomaly فقط، لا permissions العامة.
    """
    chains = []

    # أسرار أو مفاتيح مكشوفة
    secrets = [f for f in findings if "secrets" in (f.get("tags") or []) or "credential_leak" in (f.get("tags") or [])]

    # مشكلة SUID فقط (ليست permissions العامة)
    suid = [f for f in findings if "suid" in (f.get("tags") or []) or "suid_anomaly" in (f.get("tags") or [])]

    privilege_issues = suid

    if secrets and privilege_issues:
        secret_f = secrets[0]
        priv_f = privilege_issues[0]

        chains.append(Finding(
            severity="critical",
            title="🔗 مسار تصعيد الصلاحيات: اعتمادات مسربة + ثغرة صلاحيات",
            detail=(
                f"تم اكتشاف أسرار/اعتمادات مكشوفة ({secret_f.get('title', '')}) "
                f"بالإضافة إلى مشكلة في الصلاحيات ({priv_f.get('title', '')}). "
                f"هذا مسار هجوم كامل: المهاجم يسرق الاعتماد من الملف المكشوف، "
                f"ثم يستخدم ثغرة SUID/الصلاحيات لتصعيد صلاحياته إلى root. "
                f"كل خطوة منفردة قد تبدأ متوسطة الخطورة، لكن معاً تشكّل خطراً حرجاً."
            ),
            fix=(
                f"# 1) أزل السر من الكود: انقله إلى متغيرات بيئة\n"
                f"# 2) أزل صلاحية SUID: sudo chmod u-s <path>\n"
                f"# 3) راجع صلاحيات الملف: sudo chmod 640 <secret_file>"
            ),
            category="attack_chain",
            tags=["attack_chain", "credential_access", "privilege_escalation"],
            attack_ids=["T1552.001", "T1548.001", "T1078"],
            evidence={
                "secret_finding_id": secret_f.get("id"),
                "privilege_finding_id": priv_f.get("id"),
                "secret_title": secret_f.get("title"),
                "privilege_title": priv_f.get("title"),
            },
            effort="medium",
            risk_of_fix="low",
            confidence=0.8,
        ))

    return chains


def _rule_persistence_path(findings: List[Finding]) -> List[Finding]:
    """
    مهام مجدولة مشبوهة + ملفات تشغيل شيل + عملية من ملف محذوف
    = استمرارية محتملة (Persistence).
    """
    chains = []

    cron = [f for f in findings if "cron" in (f.get("tags") or []) and (f.get("severity") or "") in ("high", "critical")]
    shell_backdoor = [f for f in findings if "shell_backdoor" in (f.get("tags") or [])]
    deleted_exe = [f for f in findings if "deleted_binary" in (f.get("tags") or [])]

    persistence_indicators = len(cron) + len(shell_backdoor) + len(deleted_exe)

    if persistence_indicators >= 2:
        # اجمع الأدلة
        evidence_items = []
        titles = []
        if cron:
            evidence_items.append({"type": "cron", "id": cron[0].get("id"), "title": cron[0].get("title")})
            titles.append(f"مهام مجدولة مشبوهة ({cron[0].get('title', '')[:60]})")
        if shell_backdoor:
            evidence_items.append({"type": "shell_backdoor", "id": shell_backdoor[0].get("id"), "title": shell_backdoor[0].get("title")})
            titles.append(f"باب خلفي في شيل ({shell_backdoor[0].get('title', '')[:60]})")
        if deleted_exe:
            evidence_items.append({"type": "deleted_exe", "id": deleted_exe[0].get("id"), "title": deleted_exe[0].get("title")})
            titles.append(f"عملية من ملف محذوف ({deleted_exe[0].get('title', '')[:60]})")

        chains.append(Finding(
            severity="critical",
            title="🔗 استمرارية محتملة: مؤشرات تثبيت متعددة مكتشفة",
            detail=(
                f"تم رصد {persistence_indicators} مؤشرات استمرارية متقاطعة:\n"
                + "\n".join(f"  • {t}" for t in titles) +
                "\nوجود أكثر من مؤشر استمرارية معاً يشير بقوة إلى أن المهاجم "
                "ثبّت آليات متعددة للحفاظ على الوصول للنظام حتى بعد إعادة التشغيل "
                "أو محاولة الإزالة. يجب فحص النظام بالكامل وعزله عن الشبكة."
            ),
            fix=(
                "# 1) افحص وأزل المهام المشبوهة: sudo crontab -e\n"
                "# 2) راجع ملفات الشيل: cat /etc/profile /etc/bash.bashrc\n"
                "# 3) ابحث عن العمليات المخفية: ps aux | grep deleted\n"
                "# 4) فكّر في إعادة تثبيت النظام إن كان الاختراق مؤكداً"
            ),
            category="attack_chain",
            tags=["attack_chain", "persistence", "defense_evasion"],
            attack_ids=["T1053.003", "T1546.004", "T1070.004"],
            evidence={"indicators": evidence_items, "count": persistence_indicators},
            effort="high",
            risk_of_fix="medium",
            confidence=0.85,
        ))

    return chains


def _rule_exploitability_amplifier(findings: List[Finding]) -> List[Finding]:
    """
    ASLR معطّل + خدمة مكشوفة أو تحديثات أمنية معلّقة = قابلية استغلال عالية.
    """
    chains = []

    aslr_off = [
        f for f in findings
        if "aslr" in (f.get("tags") or [])
    ]

    exposed = [
        f for f in findings
        if f.get("rule_id") == "NET-PORT-001"
        or "open_port" in (f.get("tags") or [])
        or "listening" in (f.get("tags") or [])
    ]
    updates = [
        f for f in findings
        if f.get("rule_id") == "SYS-UPDATE-001"
        or "updates" in (f.get("tags") or [])
    ]

    if aslr_off and (exposed or updates):
        aslr_f = aslr_off[0]
        amplifiers = []
        if exposed:
            amplifiers.append(f"خدمة مكشوفة ({exposed[0].get('title', '')[:50]})")
        if updates:
            amplifiers.append(f"تحديثات أمنية معلّقة ({updates[0].get('title', '')[:50]})")

        chains.append(Finding(
            severity="high",
            title="🔗 مضخّم قابلية الاستغلال: ASLR معطّل + نقاط ضعف أخرى",
            detail=(
                f"تعطيل ASLR ({aslr_f.get('title', '')}) يضاعف من قابلية استغلال "
                f"أي ثغرة في النظام. مع وجود: {'; '.join(amplifiers)}. "
                f"بدون ASLR، يمكن للمهاجم استخدام هجمات تجاوز سعة المخزن المؤقت "
                f"بثبات أكبر بكثير. إعادة تفعيل ASLR إجراء منخفض المخاطر وعالي الأثر."
            ),
            fix="sudo sysctl -w kernel.randomize_va_space=2\n# للثبات: أضف 'kernel.randomize_va_space = 2' في /etc/sysctl.d/99-ayfam.conf",
            category="attack_chain",
            tags=["attack_chain", "memory_protection", "exploit_mitigation"],
            attack_ids=["T1068"],
            evidence={
                "aslr_finding_id": aslr_f.get("id"),
                "amplifiers": amplifiers,
            },
            effort="low",
            risk_of_fix="low",
            confidence=0.9,
        ))

    return chains


def _rule_data_exfiltration_path(findings: List[Finding]) -> List[Finding]:
    """
    اتصال خارجي مريب + أسرار مكشوفة = مسار تسريب بيانات محتمل.
    """
    chains = []

    reverse_shell = [f for f in findings if "reverse_shell" in (f.get("tags") or [])]
    suspicious_outbound = [f for f in findings if "c2" in (f.get("tags") or [])]
    secrets = [f for f in findings if "secrets" in (f.get("tags") or [])]

    c2_indicators = reverse_shell + suspicious_outbound

    if c2_indicators and secrets:
        c2_f = c2_indicators[0]
        secret_f = secrets[0]

        chains.append(Finding(
            severity="critical",
            title="🔗 مسار تسريب بيانات: اتصال خارجي مريب + اعتمادات مكشوفة",
            detail=(
                f"تم رصد اتصال خارجي مريب ({c2_f.get('title', '')}) "
                f"بالإضافة إلى اعتمادات/أسرار مكشوفة ({secret_f.get('title', '')}). "
                f"هذا يشير إلى أن المهاجم قد يكون قد سرق الاعتمادات ويرسلها "
                f"إلى خادم خارجي. يجب عزل الجهاز عن الشبكة فوراً وتدوير "
                f"كل المفاتيح/كلمات المرور المكشوفة."
            ),
            fix=(
                "# 1) افصل الجهاز عن الشبكة فوراً\n"
                "# 2) حدّد العملية: sudo ss -tunap | grep ESTAB\n"
                "# 3) أوقف العملية: sudo kill -9 <pid>\n"
                "# 4) دوّر كل المفاتيح/كلمات المرور المكشوفة"
            ),
            category="attack_chain",
            tags=["attack_chain", "exfiltration", "c2", "credential_access"],
            attack_ids=["T1071", "T1552.001", "T1041"],
            evidence={
                "c2_finding_id": c2_f.get("id"),
                "secret_finding_id": secret_f.get("id"),
            },
            effort="high",
            risk_of_fix="high",
            confidence=0.75,
        ))

    return chains


# ─── Smart Remediation Prioritization ────────────────────────────────────────

class SmartRemediationAdvisor:
    """
    يأخذ قائمة findings ويولّد توصيات إصلاح ذكية مرتبة بالأثر،
    مع شرح واضح لكل توصية: لماذا، ما الأثر، وما التكلفة.
    """

    @staticmethod
    def prioritize(findings: List[Finding], top_n: int = 5) -> List[Dict[str, Any]]:
        """
        يُرجع قائمة توصيات مرتبة بالأثر (الأعلى أولاً)، كل واحدة تحتوي:
        - priority: حرج/عالي/متوسط
        - title: عنوان الإصلاح
        - reason: لماذا هذا الإصلاح الآن
        - impact: عدد النتائج التي يحلها + تقنيات ATT&CK المكسورة
        - effort: جهد التنفيذ (منخفض/متوسط/عالي)
        - fix_cmd: أمر الإصلاح الفعلي
        - risk_of_fix: مخاطرة التطبيق
        """
        if not findings:
            return []

        # استخدم تحليل نقاط الاختناق من AttackEngine
        attack_engine = AttackEngine()
        for f in findings:
            attack_engine.enrich_finding(f)
        chokepoints = attack_engine.chokepoint_analysis(findings)

        # احسب درجة الأثر لكل chokepoint
        recommendations = []
        for cp in chokepoints[:top_n * 2]:  # خذ ضعف العدد ثم رشّح
            # الأثر = عدد التقنيات المكسورة × عدد النتائج المحلولة
            impact_score = cp["broken_techniques_count"] * 2 + cp["findings_resolved"]

            # حدد الأولوية
            if impact_score >= 8 or any(
                t in (cp.get("mitigated_techniques") or [])
                for t in ("T1548.001", "T1078", "T1110.001", "T1552.001")
            ):
                priority = "حرج"
            elif impact_score >= 4:
                priority = "عالي"
            else:
                priority = "متوسط"

            recommendations.append({
                "priority": priority,
                "title": cp["resolved_titles"][0] if cp["resolved_titles"] else "إصلاح أمني",
                "reason": (
                    f"هذا الإصلاح يكسر {cp['broken_techniques_count']} تقنيات هجوم "
                    f"MITRE ATT&CK ويحل {cp['findings_resolved']} نتيجة أمنية. "
                    f"التقنيات المتأثرة: {', '.join(cp['mitigated_techniques'][:3])}"
                ),
                "impact_score": impact_score,
                "techniques_broken": cp["broken_techniques_count"],
                "findings_resolved": cp["findings_resolved"],
                "effort": cp.get("effort", "medium"),
                "fix_cmd": cp["fix_cmd"],
                "full_fix": cp["full_fix"],
                "risk_of_fix": "low",  # most security fixes are low risk
            })

        # رتّب بالأثر ثم بالأولوية
        priority_order = {"حرج": 3, "عالي": 2, "متوسط": 1}
        recommendations.sort(
            key=lambda r: (priority_order.get(r["priority"], 0), r["impact_score"]),
            reverse=True
        )

        return recommendations[:top_n]

    @staticmethod
    def format_recommendations(findings: List[Finding], top_n: int = 5) -> str:
        """يُرجع التوصيات منسّقة كنص قابل للعرض."""
        recs = SmartRemediationAdvisor.prioritize(findings, top_n)
        if not recs:
            return "لا توجد توصيات إصلاح متاحة — شغّل فحصاً أولاً."

        lines = ["🧠 توصيات إصلاح ذكية — مرتبة بالأثر:", "=" * 55]
        for i, rec in enumerate(recs, 1):
            lines.append(
                f"\n{i}. [{rec['priority']}] {rec['title']}\n"
                f"   السبب: {rec['reason']}\n"
                f"   الجهد: {rec['effort']} | مخاطرة التطبيق: {rec['risk_of_fix']}\n"
                f"   الأمر: {rec['fix_cmd']}"
            )
        lines.append("\n" + "=" * 55)
        lines.append("💡 ابدأ بالتوصيات الحرجة أولاً — أكبر أثر بأقل جهد.")
        return "\n".join(lines)


# ─── Main Correlation Engine ─────────────────────────────────────────────────

class CorrelationEngine:
    """
    المحرك الرئيسي لربط النتائج في سلاسل هجوم ذكية قابلة للتفسير.
    """

    # قواعد الارتباط — مرتبة بالأولوية (الأعلى أولاً)
    RULES = [
        ("ssh_compromise", _rule_ssh_compromise_path),
        ("exposed_service", _rule_exposed_service_path),
        ("credential_to_privilege", _rule_credential_to_privilege_path),
        ("persistence", _rule_persistence_path),
        ("data_exfiltration", _rule_data_exfiltration_path),
        ("exploitability_amplifier", _rule_exploitability_amplifier),
    ]

    def analyze(self, findings: List[Finding]) -> List[Finding]:
        """
        يحلل النتائج ويُنتج سلاسل هجوم جديدة قابلة للتفسير.
        النتائج الأصلية تُعاد كما هي، والسلاسل تُضاف عليها.
        """
        chains = []
        seen_titles = set()

        for rule_name, rule_fn in self.RULES:
            try:
                rule_chains = rule_fn(findings)
                for chain in rule_chains:
                    # تجنّب التكرار
                    if chain.get("title") not in seen_titles:
                        chains.append(chain)
                        seen_titles.add(chain.get("title"))
            except Exception:
                # القواعد مستقلة — فشل واحدة لا يوقف الباقي
                continue

        return chains

    def analyze_and_extend(self, findings: List[Finding]) -> List[Finding]:
        """
        يحلل النتائج ويُضيف سلاسل الهجوم المكتشفة إلى القائمة الأصلية.
        """
        chains = self.analyze(findings)
        return findings + chains
