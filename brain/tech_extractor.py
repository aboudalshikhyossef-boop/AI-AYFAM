"""
AI AYFAM — Technical Content Extractor
يحلل نص أي مقطع من كتاب/ملف تقني ويستخرج منه معرفة مُهيكَلة (structured):
- أسماء أدوات معروفة (nmap, ping, curl, ss...) من قاموس مُنسَّق يدوياً.
- أوامر Shell فعلية مذكورة في النص (وليس فقط اسم الأداة عابراً).
- السياق المحيط بكل ذِكر، مع الحفاظ على مصدره (رقم الصفحة/المقطع).

هذا استخراج قائم على قواعد وأنماط (regex) + قاموس ثابت — وليس فهماً لغوياً
حقيقياً. الهدف: تحويل "نص خام مفهرَس بحثاً عاماً" إلى "معرفة مربوطة بالأداة
والأمر تحديداً"، لأن هذا هو الفرق الذي يجعل الإجابة دقيقة عند سؤال محدد
("اشرح nmap") بدل مقطع عشوائي قد يذكر الكلمة عرضاً.
"""

import re

# قاموس أدوات معروفة في الشبكات/الأمن السيبراني/إدارة لينكس — ثابت ومُنسَّق
# يدوياً (لا يحتاج اتصالاً خارجياً، ولا يحوي أي معلومة حساسة، هذه أسماء
# أدوات عامة معروفة). التصنيف يُستخدم لاحقاً لتجميع/عرض المعرفة بشكل منطقي.
KNOWN_TOOLS = {
    # استطلاع وشبكات
    "nmap": "فحص منافذ وشبكات", "masscan": "فحص منافذ سريع على نطاق واسع",
    "zmap": "فحص شبكي على مستوى الإنترنت", "ping": "اختبار اتصال بمضيف",
    "traceroute": "تتبع مسار الشبكة", "mtr": "تتبع مسار وقياس جودة الشبكة",
    "curl": "إرسال طلبات HTTP/HTTPS", "wget": "تحميل ملفات عبر HTTP",
    "ss": "عرض اتصالات الشبكة النشطة", "netstat": "عرض اتصالات ومنافذ الشبكة (قديم)",
    "dig": "استعلام DNS", "nslookup": "استعلام DNS", "host": "استعلام DNS مبسّط",
    "whois": "معلومات تسجيل نطاق/IP", "tcpdump": "التقاط حزم الشبكة",
    "wireshark": "تحليل حزم الشبكة (رسومية)", "tshark": "تحليل حزم الشبكة (سطر أوامر)",
    # فحص الويب والثغرات
    "nikto": "فحص ثغرات خوادم الويب", "sqlmap": "اكتشاف واستغلال حقن SQL",
    "wpscan": "فحص ثغرات WordPress", "gobuster": "اكتشاف مسارات/نطاقات فرعية",
    "dirb": "اكتشاف مسارات مخفية على خادم ويب", "ffuf": "Fuzzing سريع لطلبات الويب",
    "wfuzz": "Fuzzing لتطبيقات الويب", "burpsuite": "اختبار اختراق تطبيقات الويب",
    # استغلال وكلمات مرور
    "metasploit": "إطار عمل استغلال ثغرات", "msfconsole": "واجهة Metasploit",
    "hydra": "تخمين كلمات مرور (Brute force)", "medusa": "تخمين كلمات مرور",
    "john": "كسر كلمات المرور (John the Ripper)", "hashcat": "كسر تجزئات بتسريع GPU",
    # OSINT
    "theharvester": "جمع استخبارات مفتوحة المصدر (OSINT)", "recon-ng": "إطار استطلاع OSINT",
    "shodan": "محرك بحث عن أجهزة متصلة بالإنترنت", "maltego": "تحليل علاقات OSINT بصرياً",
    # شبكات لاسلكية
    "aircrack-ng": "اختبار أمان شبكات WiFi", "airmon-ng": "تفعيل وضع المراقبة اللاسلكي",
    "wifite": "أتمتة اختبار اختراق WiFi",
    # SMB / Windows
    "enum4linux": "استطلاع أنظمة Windows/Samba", "smbclient": "الاتصال بمشاركات SMB",
    "crackmapexec": "استطلاع واستغلال شبكات Windows", "responder": "التقاط اعتماد عبر LLMNR/NBT-NS",
    # اتصال شبكي عام
    "nc": "أداة شبكية متعددة الاستخدامات (Netcat)", "ncat": "نسخة محدَّثة من Netcat",
    "socat": "توجيه بيانات بين قنوات الشبكة", "ssh": "اتصال آمن عن بعد",
    "scp": "نسخ ملفات عبر SSH", "rsync": "مزامنة ونسخ ملفات",
    "ftp": "نقل ملفات (غير مُشفَّر)", "telnet": "اتصال عن بعد (غير آمن، قديم)",
    # جدار الحماية والأمان
    "iptables": "قواعد جدار الحماية (منخفض المستوى)", "ufw": "جدار حماية مبسَّط للينكس",
    "firewalld": "إدارة جدار حماية ديناميكي", "fail2ban": "حظر تلقائي لمحاولات الاختراق",
    # إدارة النظام
    "systemctl": "إدارة خدمات systemd", "journalctl": "قراءة سجلات systemd",
    "ps": "عرض العمليات الجارية", "top": "مراقبة العمليات والموارد لحظياً",
    "htop": "مراقبة تفاعلية للعمليات والموارد", "kill": "إنهاء عملية",
    "chmod": "تغيير صلاحيات ملف", "chown": "تغيير مالك ملف",
    "useradd": "إضافة مستخدم", "usermod": "تعديل مستخدم", "passwd": "تغيير كلمة مرور",
    "sudo": "تنفيذ أمر بصلاحيات أعلى", "crontab": "جدولة مهام دورية",
    "grep": "البحث داخل النصوص", "awk": "معالجة نصوص وأعمدة", "sed": "تحرير نصوص",
    "find": "البحث عن ملفات", "tar": "أرشفة وضغط ملفات", "git": "إدارة إصدارات الكود",
    "docker": "إدارة حاويات", "ip": "إدارة الشبكة (حديث)", "ifconfig": "إدارة واجهات الشبكة (قديم)",
    "iwconfig": "إعداد واجهات لاسلكية",
# استطلاع واكتشاف متقدم
    "nuclei": "فحص ثغرات وقوالب أمنية سريعة", "subfinder": "اكتشاف نطاقات فرعية سريعة",
    "amass": "رسم خرائط واستطلاع أصول متقدم", "chisel": "نفق TCP/UDP عبر HTTP",
    "linpeas": "سكريبت فحص تصعيد الصلاحيات في لينكس", "winpeas": "سكريبت فحص تصعيد الصلاحيات",
    "pspy": "مراقبة عمليات لينكس بدون صلاحيات root", "bloodhound": "تحليل علاقات Active Directory",
    "mimikatz": "استخراج اعتمادات وذاكرة LSASS", "volatility": "تحليل الذاكرة الجنائي (Memory Forensics)",
    "ghidra": "الهندسة العكسية وتحليل البرمجيات الخبيثة", "radare2": "إطار عمل هندسة عكسية في الطرفية",
    "gitleaks": "كشف الأسرار والمفاتيح في الشيفرات", "trivy": "فحص أمان الحاويات والحزم",
    "kiterunner": "اكتشاف مسارات واجهات برمجة التطبيقات API", "evil-winrm": "شيل وصول عن بعد لـ WinRM",
    "impacket": "مكتبات بروتوكولات الشبكة والاختراق",
}

# الأدوات المربوطة فعلياً بوظيفة آمنة ومُتحقَّق منها داخل هذه الأداة —
# فقط هذه الفئة يمكن اقتراح تنفيذها مباشرة (عبر core/agent.py)، والباقي
# يُعرض كمرجع نصي فقط أبداً لا يُنفَّذ تلقائياً.
EXECUTABLE_BRIDGE = {"nmap": "scan_ports", "ping": "ping_host"}

_TOOL_PATTERN = re.compile(
    r'(?<![-\w])(' + '|'.join(re.escape(t) for t in sorted(KNOWN_TOOLS, key=len, reverse=True)) + r')(?![\w-])',
    re.IGNORECASE
)
_PROMPT_LINE_RE = re.compile(r'^[ \t]*[\$#>][ \t]*([^\n]{2,150})$', re.MULTILINE)
_FLAG_RE = re.compile(r'(?:^|\s)(-{1,2}[A-Za-z][\w-]*)')
_TARGETLIKE_RE = re.compile(
    r'\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|(?:[a-z0-9-]+\.)+[a-z]{2,})\b', re.IGNORECASE
)
MAX_RESULTS_PER_CHUNK = 12


def _line_at(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    if end == -1:
        end = len(text)
    return text[start:end].strip()


def _surrounding(text: str, start: int, end: int, radius: int = 90) -> str:
    s = max(0, start - radius)
    e = min(len(text), end + radius)
    return text[s:e].strip()


def _normalize_cmd_line(line: str) -> str:
    """يزيل رمز موجّه الأوامر ($ # >) من بداية السطر حتى يتطابق نفس الأمر
    سواء اكتُشف عبر نمط الموجّه الصريح أو عبر ذِكر الأداة المباشر."""
    return re.sub(r'^[\$#>]\s*', '', line.strip()).strip()


def extract_from_chunk(text: str) -> list:
    """يُرجع قائمة سجلات {tool, category, command, context} من مقطع نص
    واحد. command تكون None إن لم يُعثر على تركيب أمر مقنع، فيبقى context
    فقط (ذِكر عام للأداة في سياقه)."""
    if not text or not text.strip():
        return []

    commands_found = []  # (tool, normalized_command_line)

    for m in _PROMPT_LINE_RE.finditer(text):
        line = _normalize_cmd_line(m.group(1))
        tool_m = _TOOL_PATTERN.search(line)
        if tool_m:
            commands_found.append((tool_m.group(1).lower(), line))

    for m in _TOOL_PATTERN.finditer(text):
        tool = m.group(1).lower()
        raw_line = _line_at(text, m.start())
        line = _normalize_cmd_line(raw_line)
        if any(t == tool and c == line for t, c in commands_found):
            continue
        # يُحصَر فحص العلم/الهدف داخل *نفس السطر* فقط — وليس نافذة قد
        # تمتد لسطر مجاور، وهو ما كان يلتقط جملاً نثرية عادية خطأً على
        # أنها أوامر لمجرد وجود IP أو علم قريب في السطر التالي.
        if _FLAG_RE.search(raw_line) or _TARGETLIKE_RE.search(raw_line):
            commands_found.append((tool, line))

    results, seen_cmds, mentioned = [], set(), set()
    for tool, cmd in commands_found:
        key = (tool, cmd)
        if key in seen_cmds:
            continue
        seen_cmds.add(key)
        mentioned.add(tool)
        results.append({"tool": tool, "category": KNOWN_TOOLS.get(tool, ""), "command": cmd, "context": cmd})
        if len(results) >= MAX_RESULTS_PER_CHUNK:
            return results

    for m in _TOOL_PATTERN.finditer(text):
        tool = m.group(1).lower()
        if tool in mentioned:
            continue
        mentioned.add(tool)
        results.append({
            "tool": tool, "category": KNOWN_TOOLS.get(tool, ""), "command": None,
            "context": _surrounding(text, m.start(), m.end()),
        })
        if len(results) >= MAX_RESULTS_PER_CHUNK:
            break
    return results


def detect_tool_in_text(text: str):
    """هل يذكر هذا النص (سؤال المستخدم مثلاً) اسم أداة معروفة؟ يُرجع اسمها
    أو None. يُستخدم لتوجيه الشرح مباشرة للمعرفة المُهيكَلة عن الأداة."""
    if not text:
        return None
    m = _TOOL_PATTERN.search(text.lower())
    return m.group(1).lower() if m else None
