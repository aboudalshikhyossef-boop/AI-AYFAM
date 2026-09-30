"""
AI AYFAM v6 — Auto-Reactor & Rule Synthesizer
محرك الاستجابة التلقائية وتوليد القواعد — يحلل الهجمات المرصودة ويولد قواعد حماية
فورية لـ UFW و iptables و auditd لتصليب النظام ديناميكياً.
"""

from typing import List, Dict, Any
from engine.finding import Finding

class AutoReactor:
    @staticmethod
    def synthesize_rules(findings: List[Finding]) -> List[Dict[str, str]]:
        """توليد قواعد حماية جاهزة للتطبيق التلقائي بناءً على التهديدات المرصودة."""
        rules = []

        for f in findings:
            tags = f.get("tags", [])
            title = f.get("title", "")
            detail = f.get("detail", "")

            # 1. هجمات القوة الغاشمة والتخمين -> قواعد حظر فورية
            if "brute_force" in tags or "brute_force_success" in tags or "password_spraying" in tags:
                import re
                ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", title + " " + detail)
                for ip in set(ips):
                    if not ip.startswith(("127.", "0.0")):
                        rules.append({
                            "type": "FIREWALL_BLOCK",
                            "desc": f"حظر IP المهاجم {ip} في جدار الحماية",
                            "cmd": f"sudo ufw insert 1 deny from {ip}",
                        })

            # 2. خدمات غير محمية مكشوفة -> قواعد تقييد
            if "exposed_port" in tags or "exposed_service" in tags:
                import re
                ports = re.findall(r"منفذ\s+(\d+)", title)
                for port in ports:
                    rules.append({
                        "type": "PORT_RESTRICTION",
                        "desc": f"إغلاق المنفذ المكشوف {port} عن الخارج",
                        "cmd": f"sudo ufw deny {port}/tcp",
                    })

            # 3. ملفات امتيازات خطيرة -> إزالة SUID
            if "suid" in tags or "suid_anomaly" in tags:
                import re
                paths = re.findall(r"(/[\w\.-]+(?:/[\w\.-]+)+)", title + " " + detail)
                for p in paths:
                    if os.path.exists(p):
                        rules.append({
                            "type": "PRIVILEGE_STRIP",
                            "desc": f"إزالة صلاحية SUID من الملف {p}",
                            "cmd": f"sudo chmod u-s {p}",
                        })

        return rules
