"""
AI AYFAM — Knowledge Base Engine
قاعدة المعرفة المحلية — SQLite (تنمو حتى 1GB+)
تحتوي على: CVEs، أنماط هجوم، شرح أوامر، تاريخ محادثات، سجل تحسينات
"""

import sqlite3
import re
import json
import os
import hashlib
import threading
from datetime import datetime
from pathlib import Path
import pathlib

DB_PATH = Path.home() / ".ayfam" / "brain.db"
# NOTE: parent dir creation moved into KnowledgeBase.__init__ to avoid import-time crash

# ─── SEED DATA ─────────────────────────────────────────────────────────────

SEED_INTENTS = [
    # Network
    ("scan_network",  ["فحص الشبكة","scan network","شبكة","network","اتصالات","connections","scan net","كشف الشبكة","فحص الأجهزة على الشبكة"]),
    ("scan_ports",    ["فحص المنافذ","scan ports","منافذ","ports","port scan","nmap","فحص البورتات","منافذ مفتوحة"]),
    ("check_firewall",["جدار الحماية","firewall","ufw","iptables","check fw","حماية","حالة جدار الحماية","تأمين الجدار الناري"]),
    ("check_ip",      ["سمعة IP","ip reputation","check ip","فحص ip","blacklist","نبلاك","فحص ip مشبوه"]),
    ("wifi",          ["واي فاي","wifi","wireless","شبكات لاسلكية","wlan","حماية الواي فاي","فحص wifi"]),
    # USB
    ("usb_control",   ["usb","يو اس بي","فلاشة","flash","هاتف","phone","أجهزة","devices","bluetooth","بلوتوث","wifi adapter","التحكم بأجهزة usb"]),
    # System
    ("scan_system",   ["فحص النظام","scan system","نظام","system","suid","cron","processes","عمليات","مستخدمون","users","فحص الأمان المحلي","تدقيق النظام"]),
    ("scan_logs",     ["سجلات","logs","log analysis","تحليل سجلات","brute force","auth","تحليل سجلات النظام","سجلات الأحداث"]),
    # Web/CVE
    ("scan_website",  ["فحص موقع","scan website","website","موقع","url","http","https","ssl","headers","اختبار أمان موقع"]),
    ("cve_search",    ["cve","ثغرة","ثغرات","vulnerability","exploit","سيفي","cisa","nvd","بحث عن ثغرة cve"]),
    ("pkg_vuln_search", ["ثغرات حزمة","ثغرة حزمة","ثغرات مكتبة","package vulnerabilities",
                          "package vulnerability","osv","pypi vulnerabilities","npm audit",
                          "dependency vulnerabilities","vulnerable package","فحص مكتبات النظام"]),
    # GitHub
    ("github",        ["github","جيتهاب","مستودع","repo","repository","token","push report","أدوات"]),
    # Search
    ("web_search",    ["بحث","search","ابحث","google","دك دك","duckduckgo","إنترنت","internet","ابحث في الويب"]),
    # Fix
    ("autofix",       ["إصلاح","fix","repair","علاج","حل مشكلة","تطبيق إصلاح","تصليح الثغرة","تطبيق العلاج التلقائي"]),
    ("full_scan",     ["فحص شامل","full scan","شامل","كامل","everything","كل شيء","فحص كامل للنظام والشبكة"]),
    # Update
    ("update_intel",  ["تحديث","update","تهديدات","threats","intel","kev","cisa update","تحديث قاعدة التهديدات"]),
    # Agent self
    ("agent_status",  ["كيف حالك","how are you","ما وضعك","status","حالة الوكيل","agent status","معلوماتك","وضع الأداء"]),
    ("agent_update",  ["تحديث قاعدة البيانات","update knowledge","تعلّم","learn","improve","تطور","self improve","حدّث نفسك","تحديث الذكاء المحلي"]),
    ("explain",       ["اشرح","explain","ما هو","what is","ما معنى","define","تعريف","وصف","describe","وضح لي"]),
    ("help",          ["مساعدة","help","وش أفعل","ماذا تفعل","قائمة","menu","list","أوامر","commands","كيف استخدمك"]),
    ("config",        ["إعدادات","settings","config","configuration","ضبط","تغيير الخيارات"]),
    ("exit",          ["خروج","exit","quit","bye","وداعاً","إنهاء"]),
    # Learning / personal library
    ("learn_file",    ["تعلم من ملف","تعلم من كتاب","اقرأ هذا الملف","اقرأ هذا الكتاب","علمك من ملف",
                        "استوعب ملف","ضيف كتاب","أضف كتاب","learn from file","learn from book",
                        "read this file","read this book","ingest file","teach yourself from"]),
    ("teach",         ["تعلم أن","اعلم أن","اعرف أن","تذكر أن","خذ بعلمك أن","سجل أن",
                        "remember that","note that","keep in mind that","learn that"]),
    ("show_learned",  ["ماذا تعلمت","ماذا تعلمتِ","اعرض ما تعلمت","ما الذي تعلمته","معرفتك المكتسبة",
                        "what have you learned","show what you learned","show learned knowledge","مكتبتك"]),
    ("ping_host",     ["اختبر الاتصال","بينج","اعمل بينج","تحقق من اتصال","هل يستجيب","ping"]),
    ("scan_trend",    ["تطور الوضع الأمني","تحسن الوضع","تدهور الوضع","قارن بالفحص السابق",
                        "مقارنة الفحوصات","تاريخ الفحوصات","security trend","compare last scan",
                        "scan history","scan trend"]),
    ("rebuild_index", ["إعادة بناء فهرس الذكاء","ابن فهرس الذكاء","حدّث فهرس الذكاء",
                        "بناء فهرس الذكاء","rebuild intelligence index","build intelligence index",
                        "rebuild index","reindex library"]),
    ("concept_explore", ["اشرح مفهوم","ما هو مفهوم","استكشف مفهوم","explain concept",
                          "what is the concept of","concept of","explore concept"]),
    ("concept_link",  ["اربط بين","الرابط بين","العلاقة بين","link between",
                        "relation between","relationship between","connection between"]),
    ("summarize_doc", ["لخص كتاب","لخص الكتاب","ملخص كتاب","summarize book",
                        "summarize the book","book summary"]),
]

_SEARCH_STOPWORDS = {
    "ما", "ماذا", "كيف", "هل", "لماذا", "متى", "اين", "أين", "هو", "هي", "من", "عن",
    "الى", "إلى", "في", "على", "the", "what", "how", "why", "when", "where", "is", "are",
    "a", "an", "of", "to", "in", "on", "and", "or", "explain", "اشرح", "لي", "please",
}


def _meaningful_search_terms(text: str) -> list[str]:
    terms = re.findall(r"[\w\u0600-\u06FF]+", text or "", flags=re.UNICODE)
    return [term.lower() for term in terms if len(term) >= 2 and term.lower() not in _SEARCH_STOPWORDS]


def _relevance_filter(rows: list[dict], query: str, *, limit: int) -> list[dict]:
    """Keep only results sharing meaningful query terms, ranked by overlap."""
    query_terms = set(_meaningful_search_terms(query))
    if not query_terms:
        return []
    ranked = []
    for row in rows:
        haystack = " ".join(str(value or "") for value in row.values()).lower()
        overlap = query_terms.intersection(_meaningful_search_terms(haystack))
        if not overlap:
            continue
        item = dict(row)
        item["query_overlap"] = round(len(overlap) / len(query_terms), 3)
        ranked.append(item)
    ranked.sort(key=lambda item: item["query_overlap"], reverse=True)
    for item in ranked:
        item.pop("query_overlap", None)
    return ranked[:limit]

SEED_KNOWLEDGE = [
    # Ports
    ("port", "22",   "SSH — Secure Shell. يُستخدم للوصول الآمن عن بُعد. إذا كان مفتوحاً للعالم → خطر عالٍ."),
    ("port", "80",   "HTTP — بروتوكول نقل النص التشعبي. حركة مرور الويب غير المشفرة."),
    ("port", "443",  "HTTPS — نسخة مشفرة من HTTP. آمن في الغالب."),
    ("port", "21",   "FTP — بروتوكول نقل الملفات. قديم وغير آمن — يُنصح بإغلاقه."),
    ("port", "23",   "Telnet — بروتوكول قديم جداً ويرسل البيانات بدون تشفير → CRITICAL."),
    ("port", "3389", "RDP — سطح المكتب البعيد لـ Windows. هدف رئيسي للمخترقين."),
    ("port", "4444", "Metasploit افتراضي / منفذ شائع لـ reverse shells → خطر شديد."),
    ("port", "6666", "منفذ مشبوه — يُستخدم كثيراً في تطبيقات خبيثة."),
    ("port", "8080", "HTTP بديل — خوادم ويب للتطوير. قد يكون مفتوحاً بدون قصد."),
    ("port", "3306", "MySQL — قاعدة بيانات. يجب ألا يكون مفتوحاً للخارج."),
    ("port", "5432", "PostgreSQL — قاعدة بيانات. نفس تحذير MySQL."),
    ("port", "27017","MongoDB — قاعدة بيانات. تسببت في تسريبات ضخمة عند تركها مفتوحة."),
    ("port", "53",   "DNS — تحويل الأسماء إلى عناوين IP. يستهدف في هجمات DNS Amplification."),
    ("port", "123",  "NTP — مزامنة الوقت. يستهدف في هجمات NTP Amplification."),
    ("port", "139",  "NetBIOS — مشاركة الملفات والطابعات في شبكات ويندوز القديمة."),
    ("port", "445",  "SMB — مشاركة الملفات في شبكات ويندوز. استُهدف بثغرات EternalBlue وWannaCry."),

    # Attack types
    ("attack", "brute_force",   "هجوم القوة الغاشمة: تجربة كلمات مرور بشكل آلي حتى الوصول. الحل: fail2ban + كلمة مرور قوية."),
    ("attack", "sql_injection",  "حقن SQL: إدخال كود SQL في نماذج الويب للوصول للبيانات. خطير جداً."),
    ("attack", "xss",            "Cross-Site Scripting: حقن JavaScript خبيث في صفحات الويب."),
    ("attack", "mitm",           "Man-in-the-Middle: اعتراض الاتصالات بين طرفين. يحدث في الشبكات العامة."),
    ("attack", "ddos",           "هجوم حجب الخدمة الموزع: إغراق الخادم بطلبات. يسقط المواقع."),
    ("attack", "ransomware",     "برنامج الفدية: يشفّر الملفات ويطلب فدية. النسخ الاحتياطي هو الحل."),
    ("attack", "phishing",       "التصيد الاحتيالي: رسائل مزيفة تنتحل هوية جهات موثوقة."),
    ("attack", "rootkit",        "Rootkit: برنامج خبيث يختبئ في عمق النظام ويمنح المخترق تحكماً كاملاً."),
    ("attack", "keylogger",      "Keylogger: يسجل كل ما تكتبه. خطير جداً على كلمات المرور."),
    ("attack", "zero_day",       "Zero-Day: ثغرة أمنية غير معروفة لمطور البرنامج ولا يوجد لها علاج فور اكتشافها."),
    ("attack", "privilege_escalation", "تصعيد الصلاحيات: رفع مستوى صلاحيات المستخدم العادي إلى جذر النظام (root)."),
    ("attack", "supply_chain",   "هجوم سلسلة التوريد: استهداف الموردين أو المكتبات البرمجية للوصول للهدف النهائي."),

    # Linux & Mint administration & hardening
    ("linux_admin", "linux_mint", "نظام Linux Mint هو توزيعة مبنية على Ubuntu/Debian، توفر بيئة سطح مكتب استثنائية وسلسة للمستخدمين مع مستويات أمان عالية."),
    ("linux_admin", "ufw", "Uncomplicated Firewall: أداة إدارة جدار الحماية المبسطة في نظام لينكس مينت وأوبونتو."),
    ("linux_admin", "polkit", "PolicyKit: إطار عمل لإدارة الصلاحيات في أنظمة لينكس يتيح للتطبيقات غير المرتفعة تشغيل العمليات الممتازة عبر المساعد المخصص بصورة آمنة."),
    ("linux_admin", "sysctl_hardening", "تشديد النواة عبر sysctl: تعديل إعدادات /etc/sysctl.conf لمنع هجمات IP Spoofing وASLR bypass وSYN flood."),
    ("linux_admin", "apparmor", "AppArmor: نظام تحكم بالوصول الإجباري (MAC) يحد من الصلاحيات والوصول للملفات لكل تطبيق."),
    ("linux_admin", "auditd", "Auditd: نظام التفتيش والمراقبة لـ Linux Kernel الذي يسجل الأحداث الأمنية والتغييرات الحساسة."),

    # Linux commands
    ("cmd", "ss -tulpn",         "يعرض جميع المنافذ المفتوحة والعمليات المرتبطة بها. أسرع من netstat."),
    ("cmd", "netstat -tulpn",    "قائمة المنافذ المفتوحة. مشابه لـ ss لكن أقدم."),
    ("cmd", "lsusb",             "يعرض جميع أجهزة USB المتصلة بالنظام."),
    ("cmd", "lsusb -v",          "تفاصيل كاملة عن أجهزة USB — Vendor ID، Product ID، Class."),
    ("cmd", "ufw status",        "حالة جدار الحماية UFW — هل مُفعَّل وما القواعد."),
    ("cmd", "ps aux",            "قائمة جميع العمليات الجارية مع المستخدم والذاكرة والـ CPU."),
    ("cmd", "find / -perm -4000","يبحث عن ملفات SUID — خطرة إذا وُجدت في أماكن غير متوقعة."),
    ("cmd", "last",              "سجل تسجيل الدخول الأخير للمستخدمين."),
    ("cmd", "who",               "المستخدمون المسجلون الدخول حالياً."),
    ("cmd", "dmesg",             "رسائل نواة Linux — مفيدة لتشخيص مشاكل الأجهزة."),
    ("cmd", "journalctl -xe",    "عرض سجلات النظام التفصيلية والأخطاء مع آخر الأحداث."),
    ("cmd", "sysctl -a",         "عرض جميع إعدادات النواة الجارية."),

    # CVE severity
    ("cve_severity", "critical", "CVSS 9.0-10.0: ثغرة خطيرة جداً — تستدعي إجراءً فورياً خلال 24 ساعة."),
    ("cve_severity", "high",     "CVSS 7.0-8.9: خطيرة — يجب معالجتها خلال أسبوع."),
    ("cve_severity", "medium",   "CVSS 4.0-6.9: متوسطة — يجب معالجتها خلال شهر."),
    ("cve_severity", "low",      "CVSS 0.1-3.9: منخفضة — معالجة عند الفرصة."),

    # Tools
    ("tool", "nmap",      "أداة فحص الشبكات الأقوى. تكشف المنافذ والخدمات وأنظمة التشغيل."),
    ("tool", "wireshark", "محلل حزم الشبكة. يُظهر كل حزمة بيانات تمر عبر الشبكة."),
    ("tool", "metasploit","إطار عمل اختبار الاختراق الأكثر شهرة. يحتوي على آلاف الـ exploits."),
    ("tool", "burpsuite",  "أداة فحص أمان تطبيقات الويب. تعترض وتعدّل الطلبات."),
    ("tool", "fail2ban",   "يحظر IPs تلقائياً بعد محاولات دخول فاشلة. ضروري لأي خادم."),
    ("tool", "suricata",   "IDS/IPS — يكتشف الهجمات في الوقت الفعلي."),
    ("tool", "hashcat",    "كسر كلمات المرور المشفرة (hash). يستخدم GPU."),
    ("tool", "john",       "John the Ripper — كسر كلمات المرور. الأقدم والأكثر استخداماً."),
    ("tool", "aircrack",   "فحص واختراق شبكات WiFi. يكشف كلمات مرور WEP/WPA."),
    ("tool", "hydra",      "تجربة كلمات مرور على خدمات متعددة (SSH, FTP, HTTP)."),
    ("tool", "yara",       "أداة مطابقة الأنماط وتصنيف البرمجيات الخبيثة بناءً على قواعد نصية وثنائية."),
]

SEED_ERRORS = [
    ("ModuleNotFoundError: No module named 'rich'",
     "مكتبة rich غير مثبتة",
     "pip3 install rich requests"),
    ("ModuleNotFoundError: No module named 'requests'",
     "مكتبة requests غير مثبتة",
     "pip3 install requests"),
    ("Permission denied",
     "لا توجد صلاحيات كافية",
     "شغّل الأمر بـ sudo أو أضف المستخدم لمجموعة sudo"),
    ("Connection refused",
     "رُفض الاتصال — الخدمة لا تعمل أو المنفذ مغلق",
     "تحقق أن الخدمة تعمل: systemctl status <service>"),
    ("lsusb: command not found",
     "أداة lsusb غير مثبتة",
     "sudo apt-get install usbutils"),
    ("adb: command not found",
     "أداة ADB غير مثبتة",
     "sudo apt-get install adb"),
    ("nmap: command not found",
     "أداة nmap غير مثبتة",
     "sudo apt-get install nmap"),
    ("ufw: command not found",
     "جدار الحماية UFW غير مثبت",
     "sudo apt-get install ufw && sudo ufw enable"),
]


# ─── Database Class ──────────────────────────────────────────────────────────

class KnowledgeBase:
    def __init__(self, db_path=None):
        self.db_path = str(db_path or DB_PATH)
        # Ensure parent directory exists at instantiation time (not import time)
        try:
            pathlib.Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            # Fall back to /tmp if home dir is not writable
            import tempfile, os as _os
            fallback = _os.path.join(tempfile.gettempdir(), "ayfam-brain.db")
            print(f"[KB] Cannot use {self.db_path} ({e}); falling back to {fallback}")
            self.db_path = fallback
        self._local = threading.local()
        self._init_db()
        self._seed_if_empty()
        self._migrate_new_intents()

    def _connect(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            self._local.conn = conn
        return conn

    def _init_db(self):
        conn = self._connect()
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS intents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            patterns TEXT NOT NULL,
            hit_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS knowledge (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            key TEXT NOT NULL,
            content TEXT NOT NULL,
            confidence REAL DEFAULT 1.0,
            source TEXT DEFAULT 'seed',
            updated_at TEXT DEFAULT (datetime('now')),
            UNIQUE(category, key)
        );
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role TEXT NOT NULL,
            message TEXT NOT NULL,
            intent TEXT,
            entities TEXT,
            timestamp TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS error_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,
            explanation TEXT NOT NULL,
            fix_cmd TEXT NOT NULL,
            hit_count INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS self_improvements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            data TEXT,
            approved INTEGER DEFAULT 0,
            applied INTEGER DEFAULT 0,
            proposed_at TEXT DEFAULT (datetime('now')),
            applied_at TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            target TEXT,
            result TEXT NOT NULL,
            risk_level TEXT,
            findings_count INTEGER DEFAULT 0,
            scanned_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS updates_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            items_added INTEGER DEFAULT 0,
            description TEXT,
            logged_at TEXT DEFAULT (datetime('now'))
        );

        -- ─── المكتبة الشخصية: كتب/ملفات يُعلِّمها المستخدم للأداة ─────────────
        CREATE TABLE IF NOT EXISTS library_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            source_path TEXT,
            file_type TEXT,
            total_chars INTEGER DEFAULT 0,
            chunk_count INTEGER DEFAULT 0,
            added_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS library_chunks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_id INTEGER NOT NULL REFERENCES library_documents(id) ON DELETE CASCADE,
            chunk_index INTEGER NOT NULL,
            page_hint TEXT,
            content TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_library_chunks_doc ON library_chunks(doc_id);

        -- ─── محرك الذكاء المحلي (TF-IDF + خريطة مفاهيم) — v4 ──────────────
        -- ملخص استخلاصي (جمل فعلية من النص، عبر TextRank) لكل مستند —
        -- يُبنى عند 'إعادة بناء فهرس الذكاء'، وليس عند كل استيعاب فردي.
        CREATE TABLE IF NOT EXISTS document_summaries (
            doc_id INTEGER PRIMARY KEY REFERENCES library_documents(id) ON DELETE CASCADE,
            summary_text TEXT NOT NULL,
            built_at TEXT DEFAULT (datetime('now'))
        );

        -- أهم المصطلحات (كلمة أو عبارة حتى 3 كلمات) لكل مستند بحسب TF-IDF
        -- عبر كامل المكتبة — هذا "فهرس المفاهيم" الذي يُبحث فيه عند سؤال
        -- عن مفهوم عام وليس اسم أداة محدد من القاموس الثابت.
        CREATE TABLE IF NOT EXISTS concept_index (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            term TEXT NOT NULL,
            doc_id INTEGER NOT NULL REFERENCES library_documents(id) ON DELETE CASCADE,
            weight REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_concept_index_term ON concept_index(term);
        CREATE INDEX IF NOT EXISTS idx_concept_index_doc ON concept_index(doc_id);

        -- خريطة المفاهيم: مصطلحان يتكرر ظهورهما معاً كأهم مصطلحات لنفس
        -- الكتاب — كلما زاد عدد الكتب المشترِكة زاد الوزن. term_a<term_b
        -- دائماً (ترتيب أبجدي) لتفادي ازدواج نفس الرابط بترتيب معكوس.
        CREATE TABLE IF NOT EXISTS concept_graph (
            term_a TEXT NOT NULL,
            term_b TEXT NOT NULL,
            weight REAL NOT NULL DEFAULT 1,
            PRIMARY KEY (term_a, term_b)
        );
        CREATE INDEX IF NOT EXISTS idx_concept_graph_a ON concept_graph(term_a);
        CREATE INDEX IF NOT EXISTS idx_concept_graph_b ON concept_graph(term_b);

        -- معرفة مُهيكَلة (structured) عن أدوات/أوامر مستخرجة من الكتب —
        -- هذا ما يفرّق بين "بحث نصي عام" و"ربط دقيق بالأداة تحديداً"
        CREATE TABLE IF NOT EXISTS library_tool_mentions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_id INTEGER NOT NULL REFERENCES library_documents(id) ON DELETE CASCADE,
            chunk_id INTEGER NOT NULL REFERENCES library_chunks(id) ON DELETE CASCADE,
            tool_name TEXT NOT NULL,
            category TEXT,
            command_text TEXT,
            context_snippet TEXT,
            page_hint TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_tool_mentions_name ON library_tool_mentions(tool_name);
        CREATE INDEX IF NOT EXISTS idx_tool_mentions_doc ON library_tool_mentions(doc_id);

        -- فهرس بحث نصي كامل (FTS5) على مقاطع المكتبة — نفس نمط knowledge_fts
        CREATE VIRTUAL TABLE IF NOT EXISTS library_fts USING fts5(
            content, page_hint UNINDEXED,
            content='library_chunks', content_rowid='id',
            tokenize='unicode61 remove_diacritics 2'
        );
        CREATE TRIGGER IF NOT EXISTS library_chunks_ai AFTER INSERT ON library_chunks BEGIN
            INSERT INTO library_fts(rowid, content, page_hint)
            VALUES (new.id, new.content, new.page_hint);
        END;
        CREATE TRIGGER IF NOT EXISTS library_chunks_ad AFTER DELETE ON library_chunks BEGIN
            INSERT INTO library_fts(library_fts, rowid, content, page_hint)
            VALUES('delete', old.id, old.content, old.page_hint);
        END;

        CREATE INDEX IF NOT EXISTS idx_knowledge_cat ON knowledge(category);
        CREATE INDEX IF NOT EXISTS idx_conv_time ON conversations(timestamp);

        -- FTS5 full-text search index over knowledge (much better than LIKE %q%)
        CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
            key, content, category UNINDEXED,
            content='knowledge', content_rowid='id',
            tokenize='unicode61 remove_diacritics 2'
        );
        CREATE TRIGGER IF NOT EXISTS knowledge_ai AFTER INSERT ON knowledge BEGIN
            INSERT INTO knowledge_fts(rowid, key, content, category)
            VALUES (new.id, new.key, new.content, new.category);
        END;
        CREATE TRIGGER IF NOT EXISTS knowledge_ad AFTER DELETE ON knowledge BEGIN
            INSERT INTO knowledge_fts(knowledge_fts, rowid, key, content, category)
            VALUES('delete', old.id, old.key, old.content, old.category);
        END;
        CREATE TRIGGER IF NOT EXISTS knowledge_au AFTER UPDATE ON knowledge BEGIN
            INSERT INTO knowledge_fts(knowledge_fts, rowid, key, content, category)
            VALUES('delete', old.id, old.key, old.content, old.category);
            INSERT INTO knowledge_fts(rowid, key, content, category)
            VALUES (new.id, new.key, new.content, new.category);
        END;
        """)
        # Backfill FTS index for rows seeded before the virtual table existed
        try:
            conn.execute("INSERT INTO knowledge_fts(knowledge_fts) VALUES('rebuild')")
        except sqlite3.OperationalError:
            pass
        conn.commit()

    def _seed_if_empty(self):
        conn = self._connect()
        count = conn.execute("SELECT COUNT(*) FROM intents").fetchone()[0]
        if count > 0:
            return
        for name, patterns in SEED_INTENTS:
            conn.execute(
                "INSERT OR IGNORE INTO intents (name, patterns) VALUES (?, ?)",
                (name, json.dumps(patterns, ensure_ascii=False))
            )
        for cat, key, content in SEED_KNOWLEDGE:
            conn.execute(
                "INSERT OR IGNORE INTO knowledge (category, key, content) VALUES (?, ?, ?)",
                (cat, key, content)
            )
        for pattern, explanation, fix_cmd in SEED_ERRORS:
            conn.execute(
                "INSERT INTO error_patterns (pattern, explanation, fix_cmd) VALUES (?, ?, ?)",
                (pattern, explanation, fix_cmd)
            )
        conn.commit()

    def _migrate_new_intents(self):
        """يضمن وصول أي نية جديدة أُضيفت في تحديث لاحق لقواعد البيانات
        القديمة الموجودة مسبقاً (وليس فقط القواعد الجديدة تماماً)."""
        conn = self._connect()
        existing = {r["name"] for r in conn.execute("SELECT DISTINCT name FROM intents").fetchall()}
        added = 0
        for name, patterns in SEED_INTENTS:
            if name not in existing:
                conn.execute(
                    "INSERT INTO intents (name, patterns) VALUES (?, ?)",
                    (name, json.dumps(patterns, ensure_ascii=False))
                )
                added += 1
        if added:
            conn.commit()

    # ─── Intents ─────────────────────────────────────────────────────────
    def get_intents(self):
        rows = self._connect().execute("SELECT name, patterns FROM intents").fetchall()
        return [(r["name"], json.loads(r["patterns"])) for r in rows]

    def increment_intent(self, intent_name):
        self._connect().execute(
            "UPDATE intents SET hit_count = hit_count + 1 WHERE name = ?",
            (intent_name,)
        )
        self._connect().commit()

    # ─── Knowledge Lookup ─────────────────────────────────────────────────
    def lookup(self, category: str, key: str) -> str:
        row = self._connect().execute(
            "SELECT content FROM knowledge WHERE category = ? AND key = ?",
            (category, key)
        ).fetchone()
        return row["content"] if row else None

    def search_knowledge(self, query: str, limit: int = 5) -> list:
        """Semantic-ish full-text search using SQLite FTS5 with relevance ranking.
        Falls back to LIKE if FTS5 is unavailable or the query has no usable tokens."""
        if not query or not query.strip():
            return []
        conn = self._connect()
        # Sanitize query for FTS5: keep alnum + Arabic letters, then OR-join tokens with prefix match
        tokens = re.findall(r"[\w\u0600-\u06FF]+", query, flags=re.UNICODE)
        tokens = [t for t in tokens if len(t) >= 2]
        try:
            if tokens:
                fts_query = " OR ".join(f"{t}*" for t in tokens)
                rows = conn.execute(
                    "SELECT k.category, k.key, k.content, k.source "
                    "FROM knowledge k JOIN knowledge_fts f ON k.id = f.rowid "
                    "WHERE knowledge_fts MATCH ? ORDER BY rank LIMIT ?",
                    (fts_query, max(limit * 4, 12))
                ).fetchall()
                if rows:
                    candidates = [{"category": r["category"], "key": r["key"], "content": r["content"],
                                  "source": r["source"]} for r in rows]
                    filtered = _relevance_filter(candidates, query, limit=limit)
                    if filtered:
                        return filtered
                # else: FTS returned nothing for these tokens — fall through to LIKE
        except sqlite3.OperationalError:
            pass  # FTS5 not compiled in — fall through
        # Fallback: LIKE search
        rows = conn.execute(
            "SELECT category, key, content, source FROM knowledge WHERE content LIKE ? OR key LIKE ? LIMIT ?",
            (f"%{query}%", f"%{query}%", max(limit * 4, 12))
        ).fetchall()
        candidates = [{"category": r["category"], "key": r["key"], "content": r["content"],
                      "source": r["source"]} for r in rows]
        return _relevance_filter(candidates, query, limit=limit)

    def add_knowledge(self, category: str, key: str, content: str, source: str = "learned"):
        conn = self._connect()
        conn.execute(
            "INSERT OR REPLACE INTO knowledge (category, key, content, source, updated_at) VALUES (?, ?, ?, ?, datetime('now'))",
            (category, key, content, source)
        )
        conn.commit()

    # ─── Conversations ────────────────────────────────────────────────────
    def save_message(self, role: str, message: str, intent: str = None, entities: dict = None):
        self._connect().execute(
            "INSERT INTO conversations (role, message, intent, entities) VALUES (?, ?, ?, ?)",
            (role, message, intent, json.dumps(entities or {}, ensure_ascii=False))
        )
        self._connect().commit()

    def get_history(self, limit: int = 20) -> list:
        rows = self._connect().execute(
            "SELECT role, message, intent, timestamp FROM conversations ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [{"role": r["role"], "message": r["message"],
                 "intent": r["intent"], "time": r["timestamp"]} for r in reversed(rows)]

    def clear_history(self):
        self._connect().execute("DELETE FROM conversations")
        self._connect().commit()

    # ─── Error Patterns ───────────────────────────────────────────────────
    def match_error(self, error_text: str) -> dict:
        rows = self._connect().execute("SELECT * FROM error_patterns").fetchall()
        for row in rows:
            if row["pattern"].lower() in error_text.lower():
                self._connect().execute(
                    "UPDATE error_patterns SET hit_count = hit_count + 1 WHERE id = ?",
                    (row["id"],)
                )
                self._connect().commit()
                return {"pattern": row["pattern"], "explanation": row["explanation"], "fix": row["fix_cmd"]}
        return None

    def add_error_pattern(self, pattern: str, explanation: str, fix_cmd: str):
        self._connect().execute(
            "INSERT OR IGNORE INTO error_patterns (pattern, explanation, fix_cmd) VALUES (?, ?, ?)",
            (pattern, explanation, fix_cmd)
        )
        self._connect().commit()

    # ─── Self Improvements ────────────────────────────────────────────────
    def propose_improvement(self, category: str, description: str, data: dict = None):
        self._connect().execute(
            "INSERT INTO self_improvements (category, description, data) VALUES (?, ?, ?)",
            (category, description, json.dumps(data or {}, ensure_ascii=False))
        )
        self._connect().commit()

    def get_pending_improvements(self) -> list:
        rows = self._connect().execute(
            "SELECT id, category, description, data, proposed_at FROM self_improvements WHERE approved = 0"
        ).fetchall()
        return [{"id": r["id"], "category": r["category"],
                 "description": r["description"], "data": json.loads(r["data"]),
                 "proposed_at": r["proposed_at"]} for r in rows]

    def approve_improvement(self, improvement_id: int):
        self._connect().execute(
            "UPDATE self_improvements SET approved = 1 WHERE id = ?",
            (improvement_id,)
        )
        self._connect().commit()

    def apply_improvement(self, improvement_id: int):
        row = self._connect().execute(
            "SELECT * FROM self_improvements WHERE id = ?",
            (improvement_id,)
        ).fetchone()
        if not row:
            return False
        data = json.loads(row["data"])
        applied = False
        try:
            if row["category"] == "knowledge":
                # Accept either nested category or use the row category itself
                cat = data.get("category", "general")
                key = data.get("key") or row["description"][:60]
                content = data.get("content") or row["description"]
                self.add_knowledge(cat, key, content, source="self_learned")
                applied = True
            elif row["category"] == "error_pattern":
                self.add_error_pattern(
                    data.get("pattern", row["description"][:80]),
                    data.get("explanation", ""),
                    data.get("fix", "")
                )
                applied = True
            elif row["category"] == "intent":
                # Allow learning new intent patterns
                if data.get("name") and data.get("patterns"):
                    self._connect().execute(
                        "INSERT INTO intents (name, patterns) VALUES (?, ?)",
                        (data["name"], json.dumps(data["patterns"], ensure_ascii=False))
                    )
                    applied = True
        except Exception as e:
            print(f"[KB] apply_improvement failed for id={improvement_id}: {e}")
            return False
        if not applied:
            # Don't mark as applied if we didn't actually do anything
            return False
        self._connect().execute(
            "UPDATE self_improvements SET applied = 1, applied_at = datetime('now') WHERE id = ?",
            (improvement_id,)
        )
        self._connect().commit()
        return True

    # ─── Scan Cache ───────────────────────────────────────────────────────
    def save_scan(self, scan_type: str, result: dict, target: str = None):
        self._connect().execute(
            "INSERT INTO scan_cache (scan_type, target, result, risk_level, findings_count) VALUES (?, ?, ?, ?, ?)",
            (scan_type, target or "",
             json.dumps(result, ensure_ascii=False, default=str),
             result.get("risk", {}).get("level", "unknown"),
             len(result.get("findings", [])))
        )
        self._connect().commit()

    def get_last_scan(self, scan_type: str) -> dict:
        row = self._connect().execute(
            "SELECT result, scanned_at FROM scan_cache WHERE scan_type = ? ORDER BY id DESC LIMIT 1",
            (scan_type,)
        ).fetchone()
        if row:
            return {"result": json.loads(row["result"]), "scanned_at": row["scanned_at"]}
        return None

    def get_scan_history(self, scan_type: str, limit: int = 10) -> list:
        """يعيد آخر N فحص من نوع معيّن (الأحدث أولاً)، بما يكفي لبناء رسم بياني
        بسيط لتطوّر مستوى الخطر وعدد النتائج بمرور الوقت. جدول scan_cache كان
        يُخزِّن هذا أصلاً مع كل فحص (عبر save_scan) لكن لم توجد طريقة لاستعادته
        كتسلسل زمني — فقط get_last_scan لآخر فحص واحد."""
        rows = self._connect().execute(
            "SELECT scan_type, target, risk_level, findings_count, scanned_at "
            "FROM scan_cache WHERE scan_type = ? ORDER BY id DESC LIMIT ?",
            (scan_type, limit)
        ).fetchall()
        return [{
            "scan_type": r["scan_type"], "target": r["target"],
            "risk_level": r["risk_level"], "findings_count": r["findings_count"],
            "scanned_at": r["scanned_at"],
        } for r in rows]

    # ─── Stats ────────────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        conn = self._connect()
        kb_count    = conn.execute("SELECT COUNT(*) FROM knowledge").fetchone()[0]
        conv_count  = conn.execute("SELECT COUNT(*) FROM conversations").fetchone()[0]
        scan_count  = conn.execute("SELECT COUNT(*) FROM scan_cache").fetchone()[0]
        error_count = conn.execute("SELECT COUNT(*) FROM error_patterns").fetchone()[0]
        pending_imp = conn.execute("SELECT COUNT(*) FROM self_improvements WHERE approved=0").fetchone()[0]
        db_size_mb  = os.path.getsize(self.db_path) / (1024 * 1024) if os.path.exists(self.db_path) else 0
        return {
            "knowledge_entries": kb_count,
            "conversations": conv_count,
            "scans_cached": scan_count,
            "error_patterns": error_count,
            "pending_improvements": pending_imp,
            "db_size_mb": round(db_size_mb, 2),
            "db_capacity": "1024 MB",
        }

    # ─── Log Update ───────────────────────────────────────────────────────
    def log_update(self, source: str, items: int, description: str = ""):
        self._connect().execute(
            "INSERT INTO updates_log (source, items_added, description) VALUES (?, ?, ?)",
            (source, items, description)
        )
        self._connect().commit()

    # ─────────────────────────────────────────────────────────────────────
    #  المكتبة الشخصية — كتب/ملفات يُعلِّمها المستخدم للأداة
    # ─────────────────────────────────────────────────────────────────────
    def add_library_document(self, title: str, source_path: str, file_type: str) -> int:
        conn = self._connect()
        cur = conn.execute(
            "INSERT INTO library_documents (title, source_path, file_type) VALUES (?, ?, ?)",
            (title, source_path, file_type)
        )
        conn.commit()
        return cur.lastrowid

    def add_library_chunk(self, doc_id: int, chunk_index: int, content: str, page_hint: str = None) -> int:
        cur = self._connect().execute(
            "INSERT INTO library_chunks (doc_id, chunk_index, content, page_hint) VALUES (?, ?, ?, ?)",
            (doc_id, chunk_index, content, page_hint)
        )
        return cur.lastrowid

    def finalize_library_document(self, doc_id: int, total_chars: int, chunk_count: int):
        conn = self._connect()
        conn.execute(
            "UPDATE library_documents SET total_chars = ?, chunk_count = ? WHERE id = ?",
            (total_chars, chunk_count, doc_id)
        )
        conn.commit()

    def list_library_documents(self) -> list:
        rows = self._connect().execute(
            "SELECT id, title, source_path, file_type, total_chars, chunk_count, added_at "
            "FROM library_documents ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_library_document(self, doc_id: int) -> bool:
        conn = self._connect()
        row = conn.execute("SELECT id FROM library_documents WHERE id = ?", (doc_id,)).fetchone()
        if not row:
            return False
        conn.execute("DELETE FROM library_documents WHERE id = ?", (doc_id,))  # cascades to chunks
        conn.commit()
        return True

    def search_library(self, query: str, limit: int = 5) -> list:
        """بحث نصي كامل (FTS5 + BM25 ranking) داخل كل المستندات المُستوعَبة."""
        if not query or not query.strip():
            return []
        conn = self._connect()
        tokens = re.findall(r"[\w\u0600-\u06FF]+", query, flags=re.UNICODE)
        tokens = [t for t in tokens if len(t) >= 2]
        if not tokens:
            return []
        try:
            fts_query = " OR ".join(f"{t}*" for t in tokens)
            rows = conn.execute(
                "SELECT c.content, c.chunk_index, c.page_hint, d.title, d.id as doc_id "
                "FROM library_chunks c "
                "JOIN library_fts f ON c.id = f.rowid "
                "JOIN library_documents d ON d.id = c.doc_id "
                "WHERE library_fts MATCH ? ORDER BY rank LIMIT ?",
                (fts_query, max(limit * 4, 12))
            ).fetchall()
            candidates = [{"content": r["content"], "chunk_index": r["chunk_index"],
                           "page_hint": r["page_hint"], "title": r["title"], "doc_id": r["doc_id"]} for r in rows]
            return _relevance_filter(candidates, query, limit=limit)
        except sqlite3.OperationalError:
            return []

    # ─────────────────────────────────────────────────────────────────────
    #  ما يُعلِّمه المستخدم مباشرة عبر المحادثة (يُخزَّن كمعرفة من مصدر 'user')
    # ─────────────────────────────────────────────────────────────────────
    def teach_fact(self, fact_text: str) -> str:
        """يخزّن حقيقة يُمليها المستخدم بنفسه. المفتاح مُشتق من هاش المحتوى
        حتى لا تتكرر نفس الحقيقة مرتين، ويُحدَّث المحتوى إن أُعيد تعليمها."""
        key = hashlib.sha1(fact_text.strip().encode("utf-8")).hexdigest()[:16]
        self.add_knowledge("user_taught", key, fact_text.strip(), source="user")
        return key

    def get_taught_facts(self, limit: int = 100) -> list:
        rows = self._connect().execute(
            "SELECT key, content, updated_at FROM knowledge WHERE category='user_taught' "
            "ORDER BY updated_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [{"key": r["key"], "content": r["content"], "updated_at": r["updated_at"]} for r in rows]

    def get_learning_summary(self) -> dict:
        """ملخص شفاف لكل ما 'تعلمته' الأداة من كل المصادر — للعرض المباشر
        للمستخدم عند سؤاله 'ماذا تعلمت؟'."""
        conn = self._connect()
        taught = conn.execute("SELECT COUNT(*) FROM knowledge WHERE category='user_taught'").fetchone()[0]
        self_learned = conn.execute("SELECT COUNT(*) FROM knowledge WHERE source='self_learned'").fetchone()[0]
        error_patterns = conn.execute("SELECT COUNT(*) FROM error_patterns").fetchone()[0]
        applied_improvements = conn.execute("SELECT COUNT(*) FROM self_improvements WHERE applied=1").fetchone()[0]
        docs = conn.execute("SELECT COUNT(*), COALESCE(SUM(chunk_count),0) FROM library_documents").fetchone()
        return {
            "facts_taught_by_user": taught,
            "self_learned_knowledge": self_learned,
            "learned_error_fixes": error_patterns,
            "applied_self_improvements": applied_improvements,
            "library_documents": docs[0],
            "library_chunks": docs[1],
        }

    def search_everything(self, query: str, limit: int = 5) -> dict:
        """بحث موحّد: يجمع بين قاعدة المعرفة المدمجة والمكتبة الشخصية، ويُبقي
        على مصدر كل نتيجة واضحاً — تُستخدم في explain() وفي مرجعية الأخطاء."""
        return {
            "knowledge": self.search_knowledge(query, limit=limit),
            "library": self.search_library(query, limit=limit),
        }

    # ─────────────────────────────────────────────────────────────────────
    #  معرفة مُهيكَلة عن أدوات/أوامر مستخرجة من الكتب (tech_extractor)
    # ─────────────────────────────────────────────────────────────────────
    def add_tool_mention(self, doc_id: int, chunk_id: int, tool_name: str, category: str,
                          command_text: str, context_snippet: str, page_hint: str = None):
        self._connect().execute(
            "INSERT INTO library_tool_mentions "
            "(doc_id, chunk_id, tool_name, category, command_text, context_snippet, page_hint) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (doc_id, chunk_id, tool_name, category, command_text, context_snippet, page_hint)
        )

    def get_tool_knowledge(self, tool_name: str, limit: int = 8) -> list:
        """كل ما استُخرج عن أداة معيّنة من كل الكتب — الأوامر أولاً، ثم
        السياقات العامة، مرتّبة بحيث تظهر الأوامر الفعلية أولاً."""
        rows = self._connect().execute(
            "SELECT m.tool_name, m.category, m.command_text, m.context_snippet, m.page_hint, "
            "       d.title as doc_title, d.id as doc_id "
            "FROM library_tool_mentions m JOIN library_documents d ON d.id = m.doc_id "
            "WHERE m.tool_name = ? "
            "ORDER BY (m.command_text IS NULL), m.id LIMIT ?",
            (tool_name.lower(), limit)
        ).fetchall()
        return [dict(r) for r in rows]

    def list_known_tools_in_library(self) -> list:
        """كل الأدوات المكتشفة في مكتبتك + عدد مرات ورودها + عدد أوامر
        فعلية مستخرجة لكل واحدة — يُستخدم في 'ماذا تعلمت'."""
        rows = self._connect().execute(
            "SELECT tool_name, category, COUNT(*) as mentions, "
            "       SUM(CASE WHEN command_text IS NOT NULL THEN 1 ELSE 0 END) as commands "
            "FROM library_tool_mentions GROUP BY tool_name ORDER BY mentions DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_doc_tool_stats(self, doc_id: int) -> list:
        """إحصائية الأدوات المكتشفة لمستند واحد تحديداً — لعرضها في ملخص
        الاستيعاب مباشرة بعد تعلّم كتاب جديد."""
        rows = self._connect().execute(
            "SELECT tool_name, category, COUNT(*) as mentions, "
            "       SUM(CASE WHEN command_text IS NOT NULL THEN 1 ELSE 0 END) as commands "
            "FROM library_tool_mentions WHERE doc_id = ? GROUP BY tool_name ORDER BY mentions DESC",
            (doc_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def commit(self):
        """تثبيت صريح للمعاملات المفتوحة — تُستخدَم بعد إدخالات مجمَّعة
        كثيرة (بناء خريطة المفاهيم) بدل تثبيت كل سطر على حدة لأسباب أداء."""
        self._connect().commit()

    # ─────────────────────────────────────────────────────────────────────
    #  محرك الذكاء المحلي (TF-IDF + خريطة مفاهيم + ملخصات) — v4
    # ─────────────────────────────────────────────────────────────────────

    def get_all_library_chunks(self) -> list:
        """كل مقاطع كل الكتب — تُستخدَم مرة واحدة عند بناء فهرس TF-IDF."""
        rows = self._connect().execute("SELECT id, content FROM library_chunks ORDER BY id").fetchall()
        return [{"id": r["id"], "content": r["content"]} for r in rows]

    def get_library_chunk_ids(self) -> list[int]:
        rows = self._connect().execute("SELECT id FROM library_chunks ORDER BY id").fetchall()
        return [int(row[0]) for row in rows]

    def get_library_chunk_by_id(self, chunk_id: int) -> dict:
        row = self._connect().execute(
            "SELECT c.id, c.content, c.chunk_index, c.page_hint, d.title, d.id as doc_id "
            "FROM library_chunks c JOIN library_documents d ON d.id = c.doc_id WHERE c.id = ?",
            (chunk_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_chunk_ids_for_doc(self, doc_id: int) -> list:
        rows = self._connect().execute(
            "SELECT id FROM library_chunks WHERE doc_id = ? ORDER BY chunk_index", (doc_id,)
        ).fetchall()
        return [r["id"] for r in rows]

    def get_doc_full_text(self, doc_id: int, max_chars: int = 200000) -> str:
        """نص المستند كاملاً (حتى حد أقصى) — يُستخدَم لبناء ملخص استخلاصي
        على مستوى الكتاب كله، وليس مقطعاً واحداً بمعزل عن بقيته."""
        rows = self._connect().execute(
            "SELECT content FROM library_chunks WHERE doc_id = ? ORDER BY chunk_index", (doc_id,)
        ).fetchall()
        text = "\n".join(r["content"] for r in rows)
        return text[:max_chars]

    def clear_concept_data(self):
        conn = self._connect()
        conn.execute("DELETE FROM concept_index")
        conn.execute("DELETE FROM concept_graph")

    def add_concept_index_entry(self, term: str, doc_id: int, weight: float):
        self._connect().execute(
            "INSERT INTO concept_index (term, doc_id, weight) VALUES (?, ?, ?)",
            (term, doc_id, weight)
        )

    def add_concept_edge(self, term_a: str, term_b: str, weight_increment: float = 1.0):
        a, b = sorted((term_a, term_b))
        if a == b:
            return
        self._connect().execute(
            "INSERT INTO concept_graph (term_a, term_b, weight) VALUES (?, ?, ?) "
            "ON CONFLICT(term_a, term_b) DO UPDATE SET weight = weight + excluded.weight",
            (a, b, weight_increment)
        )

    def get_concept_matches(self, term: str, limit: int = 10) -> list:
        """أي الكتب تناقش هذا المفهوم، مرتّبة بحسب مدى مركزيته في كل كتاب.
        مطابقة جزئية (LIKE) لأن المفاهيم قد تكون عبارات لا كلمة واحدة."""
        rows = self._connect().execute(
            "SELECT ci.term, ci.weight, d.id as doc_id, d.title "
            "FROM concept_index ci JOIN library_documents d ON d.id = ci.doc_id "
            "WHERE ci.term LIKE ? ORDER BY ci.weight DESC LIMIT ?",
            (f"%{term.lower()}%", limit)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_concept_neighbors(self, term: str, limit: int = 10) -> list:
        """المفاهيم الأكثر ارتباطاً بمفهوم معيّن عبر كل المكتبة (خريطة
        المفاهيم) — تكرار الظهور معاً كأهم مصطلحات لنفس الكتب."""
        rows = self._connect().execute(
            "SELECT term_b as neighbor, weight FROM concept_graph WHERE term_a = ? "
            "UNION ALL "
            "SELECT term_a as neighbor, weight FROM concept_graph WHERE term_b = ? "
            "ORDER BY weight DESC LIMIT ?",
            (term.lower(), term.lower(), limit)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_direct_concept_link(self, term_a: str, term_b: str) -> dict:
        a, b = sorted((term_a.lower(), term_b.lower()))
        row = self._connect().execute(
            "SELECT weight FROM concept_graph WHERE term_a = ? AND term_b = ?", (a, b)
        ).fetchone()
        return {"linked": bool(row), "weight": row["weight"] if row else 0}

    def save_document_summary(self, doc_id: int, summary_text: str):
        self._connect().execute(
            "INSERT INTO document_summaries (doc_id, summary_text, built_at) VALUES (?, ?, datetime('now')) "
            "ON CONFLICT(doc_id) DO UPDATE SET summary_text = excluded.summary_text, built_at = excluded.built_at",
            (doc_id, summary_text)
        )

    def get_document_summary(self, doc_id: int) -> str:
        row = self._connect().execute(
            "SELECT summary_text FROM document_summaries WHERE doc_id = ?", (doc_id,)
        ).fetchone()
        return row["summary_text"] if row else None

    def find_document_by_title(self, title_query: str) -> dict:
        row = self._connect().execute(
            "SELECT id, title FROM library_documents WHERE title LIKE ? ORDER BY id DESC LIMIT 1",
            (f"%{title_query}%",)
        ).fetchone()
        return dict(row) if row else None
