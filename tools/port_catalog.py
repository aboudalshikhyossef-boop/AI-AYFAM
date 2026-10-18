"""كتالوج المنافذ: اسم الخدمة، مستوى الخطر، لماذا يهم، وكيف يُغلق أو يُؤمَّن."""
from __future__ import annotations

import socket

# port: (service, risk, why, fix)  — {port} يُستبدل برقم المنفذ
_CLOSE = "sudo ufw deny {port}/tcp   # أو أوقف الخدمة: sudo systemctl disable --now <service>"
_LAN_ONLY = "اربط الخدمة بالعنوان 127.0.0.1 في إعداداتها، أو: sudo ufw allow from 192.168.0.0/16 to any port {port}"

PORTS: dict[int, tuple[str, str, str, str]] = {
    20: ("FTP (بيانات)", "high", "FTP ينقل البيانات وكلمات المرور دون تشفير.", "استخدم SFTP بدلاً منه، وأغلق FTP: " + _CLOSE),
    21: ("FTP", "high", "FTP يرسل اسم المستخدم وكلمة المرور كنص صريح، ويسهل التقاطهما.", "استبدله بـ SFTP، وأغلق المنفذ: " + _CLOSE),
    22: ("SSH", "medium", "يتيح التحكم عن بعد؛ مستهدف دائماً بالتخمين الآلي لكلمات المرور.", "عطّل الدخول بكلمة مرور (PasswordAuthentication no) واستخدم المفاتيح، أو قيّده: sudo ufw limit 22/tcp"),
    23: ("Telnet", "critical", "Telnet بلا تشفير إطلاقاً ومتروك منذ عقود؛ وجوده مؤشر خطر.", "أوقفه فوراً واستخدم SSH: sudo systemctl disable --now telnet.socket && " + _CLOSE),
    25: ("SMTP", "medium", "خادم بريد مفتوح قد يُستغل لإرسال رسائل مزعجة.", "إن لم تكن خادم بريد أغلقه: " + _CLOSE),
    53: ("DNS", "medium", "خادم DNS مفتوح قد يُستغل في هجمات التضخيم.", "قيّده بالشبكة المحلية: " + _LAN_ONLY),
    67: ("DHCP", "low", "خدمة توزيع عناوين؛ طبيعية على الراوتر لا على الحاسوب.", "أوقفها إن لم تكن تشغّل DHCP عمداً."),
    69: ("TFTP", "high", "TFTP بلا مصادقة ويمكن قراءة الملفات عبره.", "أوقفه: " + _CLOSE),
    80: ("HTTP", "medium", "خادم ويب غير مشفّر؛ قد يعرض واجهات إدارة أو ملفات.", "فعّل HTTPS وحوّل إليه، أو أغلقه إن لم تحتجه: " + _CLOSE),
    110: ("POP3", "medium", "بريد وارد دون تشفير.", "استخدم POP3S على 995 وأغلق هذا المنفذ."),
    111: ("rpcbind", "high", "rpcbind يكشف خدمات RPC ويُستغل في الاستطلاع والهجمات.", "sudo systemctl disable --now rpcbind.socket rpcbind && " + _CLOSE),
    123: ("NTP", "low", "مزامنة الوقت؛ المفتوح للجميع قد يُستغل في التضخيم.", "قيّده بالمحلي إن لم تكن خادم وقت."),
    135: ("MS-RPC", "high", "منفذ Windows RPC؛ غير متوقع على لينكس.", "تحقق من العملية: sudo ss -ltnp 'sport = :135' ثم أغلقه."),
    137: ("NetBIOS", "medium", "يكشف أسماء الأجهزة ومعلومات الشبكة.", "sudo systemctl disable --now nmbd && " + _CLOSE),
    139: ("NetBIOS/SMB", "high", "مشاركة ملفات قديمة عرضة للتجسس والاستغلال.", "أوقف Samba إن لم تحتجها: sudo systemctl disable --now smbd nmbd"),
    143: ("IMAP", "medium", "بريد وارد دون تشفير.", "استخدم IMAPS على 993 وأغلق هذا المنفذ."),
    161: ("SNMP", "high", "SNMP بسلسلة المجتمع الافتراضية يسرّب معلومات الجهاز.", "عطّل SNMP أو استخدم الإصدار 3 وقيّده: sudo systemctl disable --now snmpd"),
    389: ("LDAP", "medium", "دليل مستخدمين غير مشفّر.", "استخدم LDAPS على 636 وقيّد الوصول."),
    443: ("HTTPS", "low", "ويب مشفّر؛ طبيعي لخادم ويب، تأكد من تحديث الشهادة والبرمجيات.", "حدّث الخادم والشهادة، وأغلقه إن لم تكن تستضيف موقعاً."),
    445: ("SMB", "high", "SMB هدف دائم لبرمجيات الفدية والديدان (مثل EternalBlue).", "أوقف Samba إن لم تحتجها: sudo systemctl disable --now smbd; وإلا قيّدها بالشبكة المحلية: " + _LAN_ONLY),
    465: ("SMTPS", "low", "بريد صادر مشفّر.", "أغلقه إن لم تكن خادم بريد."),
    512: ("rexec", "critical", "خدمة r-commands قديمة بلا تشفير.", "أوقفها فوراً: " + _CLOSE),
    513: ("rlogin", "critical", "دخول عن بعد بلا تشفير.", "أوقفها فوراً: " + _CLOSE),
    514: ("rsh/syslog", "high", "rsh بلا تشفير؛ أو syslog مفتوح للشبكة.", "أوقفه أو قيّده: " + _CLOSE),
    587: ("SMTP (إرسال)", "low", "إرسال بريد مصادَق.", "أغلقه إن لم تكن خادم بريد."),
    631: ("CUPS", "low", "خدمة الطباعة؛ لا يجب أن تُعرض خارج الجهاز.", "اجعلها محلية: sudo cupsctl --no-share-printers --no-remote-any"),
    873: ("rsync", "high", "rsync مفتوح قد يكشف ملفات دون مصادقة.", "قيّده أو أوقفه: " + _CLOSE),
    993: ("IMAPS", "low", "بريد وارد مشفّر.", "أغلقه إن لم تكن خادم بريد."),
    995: ("POP3S", "low", "بريد وارد مشفّر.", "أغلقه إن لم تكن خادم بريد."),
    1080: ("SOCKS proxy", "high", "وكيل SOCKS مفتوح يستغله المهاجمون لإخفاء هويتهم.", "أوقفه أو قيّده بالمحلي: " + _CLOSE),
    1433: ("MS SQL", "high", "قاعدة بيانات معروضة للشبكة.", _LAN_ONLY),
    1723: ("PPTP VPN", "high", "بروتوكول VPN قديم وضعيف التشفير.", "استبدله بـ WireGuard أو OpenVPN."),
    1883: ("MQTT", "medium", "وسيط رسائل IoT غالباً بلا مصادقة.", "فعّل المصادقة وTLS أو اجعله محلياً."),
    2049: ("NFS", "high", "مشاركة ملفات NFS قد تُركب من أجهزة أخرى.", "قيّد /etc/exports بعناوين محددة أو أوقفه."),
    2323: ("Telnet بديل", "critical", "منفذ Telnet بديل يظهر مع البرمجيات الخبيثة وأجهزة IoT المخترقة.", "تحقق من العملية: sudo ss -ltnp 'sport = :2323' ثم أوقفها."),
    3128: ("Squid proxy", "medium", "وكيل ويب قد يكون مفتوحاً للجميع.", "قيّده بالشبكة المحلية: " + _LAN_ONLY),
    3306: ("MySQL/MariaDB", "high", "قاعدة بيانات يجب ألا تُعرض للشبكة.", "اضبط bind-address = 127.0.0.1 في إعدادات MySQL ثم أعد تشغيلها."),
    3389: ("RDP", "high", "سطح المكتب البعيد؛ هدف رئيسي لهجمات القوة الغاشمة والفدية.", "أوقف xrdp إن لم تحتجه: sudo systemctl disable --now xrdp; أو ضعه خلف VPN."),
    4444: ("Metasploit/Backdoor", "critical", "منفذ شائع لأبواب خلفية وجلسات reverse shell.", "افحص العملية فوراً: sudo ss -ltnp 'sport = :4444' ثم أوقفها وافحص الجهاز."),
    4445: ("Backdoor", "critical", "منفذ مرتبط بأبواب خلفية.", "افحص العملية فوراً: sudo ss -ltnp 'sport = :4445'"),
    5000: ("Flask/UPnP", "low", "غالباً خادم تطوير؛ يجب ألا يُعرض للشبكة.", "اربطه بـ 127.0.0.1 أو أوقفه."),
    5060: ("SIP", "medium", "اتصالات VoIP عرضة للتجسس والاحتيال.", "أغلقه إن لم تستخدم VoIP."),
    5353: ("mDNS/Avahi", "low", "اكتشاف الخدمات المحلي؛ يكشف اسم الجهاز.", "sudo systemctl disable --now avahi-daemon.socket avahi-daemon"),
    5432: ("PostgreSQL", "high", "قاعدة بيانات يجب ألا تُعرض للشبكة.", "اضبط listen_addresses = 'localhost' في postgresql.conf."),
    5555: ("ADB", "critical", "Android Debug Bridge مفتوح يعطي تحكماً كاملاً بالجهاز.", "أوقفه: adb kill-server، وأغلق المنفذ."),
    5900: ("VNC", "high", "سطح مكتب بعيد غالباً بكلمة مرور ضعيفة وبلا تشفير.", "أوقف VNC أو مرره عبر نفق SSH."),
    5901: ("VNC :1", "high", "جلسة VNC ثانية معرضة للشبكة.", "أوقف VNC أو مرره عبر نفق SSH."),
    6379: ("Redis", "high", "Redis بلا مصادقة افتراضياً ويسمح بتنفيذ أوامر والكتابة على القرص.", "اضبط bind 127.0.0.1 وفعّل requirepass في redis.conf."),
    6666: ("IRC/Backdoor", "high", "منفذ يستخدمه IRC وبعض برمجيات التحكم.", "تحقق من العملية: sudo ss -ltnp 'sport = :6666'"),
    6667: ("IRC", "high", "IRC يُستخدم في شبكات الbotnet.", "أوقفه إن لم تكن خادم IRC عمداً."),
    8000: ("HTTP بديل", "low", "خادم ويب تطوير.", "اربطه بـ 127.0.0.1 إن كان للتطوير."),
    8080: ("HTTP بديل/وكيل", "medium", "واجهة ويب أو وكيل غالباً بلا حماية كافية.", "قيّده أو فعّل المصادقة وHTTPS."),
    8443: ("HTTPS بديل", "low", "واجهة ويب مشفّرة بديلة.", "تأكد من تحديثها وقيّدها."),
    8888: ("Jupyter/HTTP بديل", "high", "Jupyter المكشوف يتيح تنفيذ شيفرة برمجية على الجهاز.", "فعّل الرمز السري وربطه بالمحلي: jupyter notebook --ip=127.0.0.1"),
    9001: ("Tor/ORPort", "medium", "قد يكون عقدة Tor أو أداة تحكم.", "تأكد أنك شغّلته عمداً."),
    9090: ("لوحة إدارة", "medium", "واجهات مثل Prometheus/Cockpit؛ تكشف معلومات النظام.", "قيّدها بالمحلي أو خلف مصادقة."),
    9200: ("Elasticsearch", "high", "Elasticsearch المفتوح تسرّبت منه بيانات ضخمة كثيرة.", "اضبط network.host: 127.0.0.1 وفعّل الأمان."),
    9300: ("Elasticsearch (عقد)", "high", "اتصال العقد الداخلي لا يجب أن يُعرض.", "قيّده بالشبكة الداخلية."),
    11211: ("Memcached", "high", "Memcached المفتوح يُستغل في هجمات تضخيم ضخمة.", "اربطه بـ 127.0.0.1: -l 127.0.0.1 في memcached.conf."),
    12345: ("NetBus/Backdoor", "critical", "منفذ معروف لأبواب خلفية قديمة.", "افحص العملية فوراً: sudo ss -ltnp 'sport = :12345'"),
    27017: ("MongoDB", "high", "MongoDB المفتوح بلا مصادقة سُرقت منه بيانات كثيرة.", "اضبط bindIp: 127.0.0.1 وفعّل authorization في mongod.conf."),
    31337: ("Back Orifice", "critical", "منفذ كلاسيكي لباب خلفي (elite).", "افحص العملية فوراً: sudo ss -ltnp 'sport = :31337'"),
    51820: ("WireGuard", "low", "VPN حديث وآمن؛ طبيعي إن كنت تشغّله.", "لا إجراء إن كان عمداً."),
}

RISK_ORDER = ["critical", "high", "medium", "low", "info"]


def describe(port: int, service_hint: str = "") -> dict:
    """معلومات المنفذ؛ للمنافذ غير المعروفة نقترح خطوات تحديد العملية."""
    if port in PORTS:
        service, risk, why, fix = PORTS[port]
        return {"service": service, "risk": risk, "why": why, "fix": fix.replace("{port}", str(port)), "known": True}
    name = service_hint if service_hint and service_hint != "?" else ""
    if not name:
        try:
            name = socket.getservbyport(port, "tcp")
        except OSError:
            name = ""
    return {
        "service": name or "غير معروف",
        "risk": "medium",
        "why": ("منفذ غير معياري مفتوح؛ لا أعرف خدمته" if not name else f"خدمة {name} مفتوحة")
               + "، وكل خدمة مكشوفة تزيد سطح الهجوم.",
        "fix": f"اعرف العملية: sudo ss -ltnp 'sport = :{port}'؛ ثم أوقفها إن لم تحتجها أو احجب المنفذ: sudo ufw deny {port}/tcp",
        "known": False,
    }


def lower_risk(risk: str) -> str:
    index = RISK_ORDER.index(risk) if risk in RISK_ORDER else 2
    return RISK_ORDER[min(index + 1, len(RISK_ORDER) - 1)]
