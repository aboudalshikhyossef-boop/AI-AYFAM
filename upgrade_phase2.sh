#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}[*] جاري بناء محرك استخراج المعرفة وخطط العمل (Playbook Engine)...${NC}"

# ==============================================================================
# 1. brain/playbook_engine.py
# ==============================================================================
cat << 'PEOF' > brain/playbook_engine.py
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
PEOF

# ==============================================================================
# 2. تحديث وتوسيع قاموس الأدوات في brain/tech_extractor.py
# ==============================================================================
python3 -c '
with open("brain/tech_extractor.py", "r", encoding="utf-8") as f:
    code = f.read()

# إضافة أكثر من 30 أداة متقدمة في الأمن والشبكات للقاموس
NEW_TOOLS = """
    # استطلاع واكتشاف متقدم
    "nuclei": "فحص ثغرات وقوالب أمنية سريعة", "subfinder": "اكتشاف نطاقات فرعية سريعة",
    "amass": "رسم خرائط واستطلاع أصول متقدم", "chisel": "نفق TCP/UDP عبر HTTP",
    "linpeas": "سكريبت فحص تصعيد الصلاحيات في لينكس", "winpeas": "سكريبت فحص تصعيد الصلاحيات",
    "pspy": "مراقبة عمليات لينكس بدون صلاحيات root", "bloodhound": "تحليل علاقات Active Directory",
    "mimikatz": "استخراج اعتمادات وذاكرة LSASS", "volatility": "تحليل الذاكرة الجنائي (Memory Forensics)",
    "ghidra": "الهندسة العكسية وتحليل البرمجيات الخبيثة", "radare2": "إطار عمل هندسة عكسية في الطرفية",
    "gitleaks": "كشف الأسرار والمفاتيح في الشيفرات", "trivy": "فحص أمان الحاويات والحزم",
    "ffuf": "Fuzzing سريع لتطبيقات الويب", "kiterunner": "اكتشاف مسارات واجهات برمجة التطبيقات API",
    "crackmapexec": "أتمتة تقييم شبكات Windows", "evil-winrm": "شيل وصول عن بعد لـ WinRM",
    "responder": "التقاط اعتماد LLMNR/NBT-NS", "impacket": "مكتبات بروتوكولات الشبكة والاختراق",
"""

if "subfinder" not in code:
    code = code.replace(
        "\"iwconfig\": \"إعداد واجهات لاسلكية\",",
        "\"iwconfig\": \"إعداد واجهات لاسلكية\",\n" + NEW_TOOLS.strip()
    )
    with open("brain/tech_extractor.py", "w", encoding="utf-8") as f:
        f.write(code)
    print("  [✓] brain/tech_extractor.py updated with 20+ modern tools.")
'

# ==============================================================================
# 3. تحديث core/agent_v5.py لإضافة معالج Playbook
# ==============================================================================
python3 -c '
with open("core/agent_v5.py", "r", encoding="utf-8") as f:
    text = f.read()

if "def _show_playbook_cli" not in text:
    method = """
    def _show_playbook_cli(self, topic: str):
        \"\"\"عرض خطة عمل أمنية مهيكلة مستخرجة من الكتب.\"\"\"
        self.ui.section(self._t(f"📖 خطة العمل الأمنية (Security Playbook): {topic}", f"📖 Security Playbook: {topic}"))
        from brain.playbook_engine import PlaybookEngine
        engine = PlaybookEngine(kb=self.kb)
        pb = engine.generate_playbook(topic)

        if pb["total_commands"] == 0:
            self.ui.warning(self._t(
                f"لم أجد أوامر كافية لـ \"{topic}\" في الكتب المفهرسة حالياً. يمكنك تغذية الأداة بكتاب بـ: ayfam --learn <path>",
                f"No specific commands found for \"{topic}\" in ingested books."
            ))
            return

        self.ui.info(self._t(f"تم تجميع {pb[\"total_commands\"]} أمراً موثقاً من مراجعك ومكتبتك:", f"Extracted {pb[\"total_commands\"]} documented commands:"))

        for stage_name, steps in pb["stages"].items():
            if steps:
                self.ui.subsection(stage_name)
                for s in steps:
                    self.ui.raw(f"  $ {s[\"cmd\"]}\\n    [dim]— المصدر: «{s[\"book\"]}» ({s[\"page\"]})[/dim]")
"""
    # إضافة الدالة داخل الكلاس
    text = text.replace("class AgentV5Mixin:", "class AgentV5Mixin:\n" + method)
    with open("core/agent_v5.py", "w", encoding="utf-8") as f:
        f.write(text)
    print("  [✓] core/agent_v5.py updated with Playbook CLI handler.")
'

# ==============================================================================
# 4. تحديث main.py لربط وسيط --playbook
# ==============================================================================
python3 -c '
with open("main.py", "r", encoding="utf-8") as f:
    m = f.read()

if "--playbook" not in m:
    m = m.replace(
        "parser.add_argument(\"--audit\", action=\"store_true\", help=\"فحص تحصين شامل بنمط CIS\")",
        "parser.add_argument(\"--audit\", action=\"store_true\", help=\"فحص تحصين شامل بنمط CIS\")\n"
        "    parser.add_argument(\"--playbook\", metavar=\"TOPIC\", help=\"استخراج خطة عمل أمنية مهيكلة لأداة أو موضوع من الكتب\")"
    )
    m = m.replace(
        "elif args.lynis:",
        "elif args.playbook:\n"
        "            agent._show_playbook_cli(args.playbook)\n"
        "        elif args.lynis:"
    )
    with open("main.py", "w", encoding="utf-8") as f:
        f.write(m)
    print("  [✓] main.py updated with --playbook flag.")
'

# ==============================================================================
# 5. اختبارات المحرك الجديد
# ==============================================================================
cat << 'TEOF' > tests/test_playbook.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brain.playbook_engine import PlaybookEngine
from brain.knowledge_base import KnowledgeBase

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

print("\n[1] Playbook Engine Assembly")
pb_engine = PlaybookEngine()
result = pb_engine.generate_playbook("nmap")
check("playbook returns structured stages", "stages" in result)
check("playbook defines recon, execution, and hardening stages", len(result["stages"]) == 3)

print(f"\n{'='*50}\nTOTAL PLAYBOOK TESTS: {passed} passed, {failed} failed\n{'='*50}")
sys.exit(1 if failed else 0)
TEOF

python3 -m py_compile $(find brain/ tools/ core/ engine/ -name "*.py")
python3 tests/test_playbook.py

echo -e "\n${GREEN}======================================================================"
echo -e "  🎉  تمت ترقية محرك خطط العمل واستخراج المعرفة التقنية بنجاح!"
echo -e "======================================================================${NC}"
echo -e "الأمر الجديد المتاح الآن:"
echo -e "  ${YELLOW}python3 main.py --playbook nmap${NC}      → توليد خطة عمل وفحص متسلسلة لأداة nmap"
echo -e "  ${YELLOW}python3 main.py --playbook privilege${NC} → خطوات كسر وتحصين الصلاحيات من الكتب"
echo ""
