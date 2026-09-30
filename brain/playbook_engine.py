"""
AI AYFAM v6 — Security Playbook & Knowledge Synthesizer
محرك تفكيك المراجع واستخراج خطط العمل (Security Playbooks):
- تحويل مقاطع الكتب إلى مسارات عمل مهيكلة (استطلاع -> فحص -> كسر صلاحيات -> تحصين)
- تفكيك الأوامر التقنية وتوضيح وظائف الخيارات (Flags)
- الاستشهاد برقم الصفحة واسم الكتاب بدقة 100% بدون أي هلوسة
"""

import re
from typing import List, Dict, Any, Optional

class PlaybookEngine:
    def __init__(self, kb=None):
        self.kb = kb

    def generate_playbook(self, topic: str, limit: int = 6) -> Dict[str, Any]:
        """
        توليد خطة عمل متكاملة لموضوع أو أداة معينة بالاعتماد على الكتب المفهرسة
        في قاعدة المعرفة.
        """
        topic_clean = topic.strip().lower()
        commands_extracted = []
        contexts_extracted = []

        if self.kb:
            # 1. جلب الأوامر الموثقة في جدول الأدوات
            tool_know = self.kb.get_tool_knowledge(topic_clean, limit=limit)
            for item in tool_know:
                if item.get("command_text"):
                    commands_extracted.append({
                        "cmd": item["command_text"],
                        "book": item.get("doc_title", "Unknown"),
                        "page": item.get("page_hint", "غير محدد"),
                    })
                elif item.get("context_snippet"):
                    contexts_extracted.append({
                        "text": item["context_snippet"][:250],
                        "book": item.get("doc_title", "Unknown"),
                        "page": item.get("page_hint", "غير محدد"),
                    })

            # 2. إذا كانت الأوامر قليلة، ابحث في نصوص المكتبة FTS5
            if len(commands_extracted) < 3:
                lib_results = self.kb.search_library(topic_clean, limit=limit)
                for r in lib_results:
                    txt = r.get("content", "")
                    # التقاط أسطر الأوامر
                    for line in txt.splitlines():
                        line_str = line.strip()
                        if line_str.startswith(("$", "#", ">")):
                            clean_cmd = re.sub(r"^[\$#>]\s*", "", line_str)
                            if topic_clean in clean_cmd.lower() and clean_cmd not in [c["cmd"] for c in commands_extracted]:
                                commands_extracted.append({
                                    "cmd": clean_cmd,
                                    "book": r.get("title", "Unknown"),
                                    "page": r.get("page_hint", "غير محدد"),
                                })

        # تنظيم الخطة مرحلياً
        recon_steps = []
        exploit_steps = []
        defense_steps = []

        for c in commands_extracted:
            cmd_l = c["cmd"].lower()
            if any(k in cmd_l for k in ["-s", "-p", "scan", "list", "enum", "find", "recon", "dig", "whois"]):
                recon_steps.append(c)
            elif any(k in cmd_l for k in ["chmod", "chown", "ufw", "iptables", "deny", "secure", "protect"]):
                defense_steps.append(c)
            else:
                exploit_steps.append(c)

        return {
            "topic": topic,
            "total_commands": len(commands_extracted),
            "stages": {
                "1. الاستكشاف والمسح (Reconnaissance)": recon_steps,
                "2. التحقق والتنفيذ (Execution / Testing)": exploit_steps,
                "3. التحصين والدفاع (Hardening & Remediation)": defense_steps,
            },
            "theoretical_context": contexts_extracted[:2],
        }
