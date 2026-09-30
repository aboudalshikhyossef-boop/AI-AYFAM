"""
AI AYFAM v5 — MITRE ATT&CK Matrix & Chokepoint Reasoning
ربط النتائج بتكتيكات وتقنيات MITRE ATT&CK، وإجراء تحليل نقاط الاختناق
(Chokepoint Analysis) لتحديد أولويات الإصلاح رياضيّاً (Greedy Set Cover).
"""

from typing import List, Dict, Any, Set
from engine.finding import Finding

# مصفوفة تكتيكات لينكس المدعومة
TACTICS_MAP = {
    "initial-access": "الوصول الأولي / Initial Access",
    "execution": "التنفيذ / Execution",
    "persistence": "الاستمرارية / Persistence",
    "privilege-escalation": "تصعيد الصلاحيات / Privilege Escalation",
    "defense-evasion": "تجاوز الدفاعات / Defense Evasion",
    "credential-access": "سرقة الاعتمادات / Credential Access",
    "discovery": "الاستكشاف / Discovery",
    "lateral-movement": "التحرك الأفقي / Lateral Movement",
    "collection": "جمع البيانات / Collection",
    "impact": "التأثير والتخريب / Impact",
}

class AttackEngine:
    def __init__(self, mitre_dataset: Dict[str, Any] = None):
        self.dataset = mitre_dataset or {}

    def enrich_finding(self, finding: Finding):
        """تعيين تقنيات ATT&CK بناءً على وسوم وفئة النتيجة."""
        tags = set(finding.get("tags", []))
        category = finding.get("category", "")
        attack_ids = set(finding.get("attack_ids", []))

        if "suid" in tags or category == "privilege_escalation":
            attack_ids.add("T1548.001") # Setuid/Setgid
        if "ssh" in tags or "ssh_root_login" in tags:
            attack_ids.add("T1021.004") # SSH
            attack_ids.add("T1078")     # Valid Accounts
        if "cron" in tags:
            attack_ids.add("T1053.003") # Cron
        if "brute_force" in tags:
            attack_ids.add("T1110.001") # Password Guessing
        if "firewall" in tags or "firewall_disabled" in tags:
            attack_ids.add("T1686")     # Impair Defenses: Disable or Modify Firewall
        if "secrets" in tags:
            attack_ids.add("T1552.001") # Credentials in Files
        if "persistence" in tags:
            attack_ids.add("T1547.006") # Kernel Modules / Daemons

        finding["attack_ids"] = sorted(list(attack_ids))

    def chokepoint_analysis(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        تحليل نقاط الاختناق: حساب أي أمر/إجراء إصلاحي يُبطل أكبر عدد من
        تقنيات الهجوم ونتائج الخطورة العالية بأقل مجهود (Greedy Set Cover).
        """
        fix_to_techniques: Dict[str, Set[str]] = {}
        fix_to_findings: Dict[str, List[Finding]] = {}
        fix_details: Dict[str, str] = {}

        for f in findings:
            fix = f.get("fix", "").strip()
            if not fix or fix.startswith("#"):
                continue
            # توحيد السطر الأول من الإصلاح كمفتاح
            primary_cmd = fix.split("\n")[0].strip()
            if primary_cmd not in fix_to_techniques:
                fix_to_techniques[primary_cmd] = set()
                fix_to_findings[primary_cmd] = []
                fix_details[primary_cmd] = fix

            for tid in f.get("attack_ids", []):
                fix_to_techniques[primary_cmd].add(tid)
            fix_to_findings[primary_cmd].append(f)

        ranked = []
        for cmd, techs in fix_to_techniques.items():
            f_list = fix_to_findings[cmd]
            impact_score = sum(f.get("score", 10) for f in f_list)
            ranked.append({
                "fix_cmd": cmd,
                "full_fix": fix_details[cmd],
                "broken_techniques_count": len(techs),
                "mitigated_techniques": sorted(list(techs)),
                "impact_score": impact_score,
                "findings_resolved": len(f_list),
                "resolved_titles": [f.get("title") for f in f_list[:3]],
            })

        # الترتيب حسب كسر أكبر عدد من التقنيات ثم مجموع نقاط الأثر
        ranked.sort(key=lambda x: (x["broken_techniques_count"], x["impact_score"]), reverse=True)
        return ranked
