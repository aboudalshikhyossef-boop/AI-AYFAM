"""
AI AYFAM v4 — Terminal UI
=========================
واجهة طرفية موحّدة التصميم: لون هوية واحد (Accent) للهيكل العام (عناوين،
حدود، مؤشرات)، وألوان دلالية منفصلة تماماً محجوزة فقط للخطورة/الحالة
الفعلية — لا تُستخدَم للزخرفة أبداً. شكل صندوق واحد ثابت لكل اللوحات،
وشكل واحد لكل الجداول، بدل عدة أطرزة متنافرة كانت تتبادل الظهور حسب
مكان الاستدعاء. لا حسابات محاذاة يدوية بعرض ثابت (مصدر أعطال محاذاة
حقيقي مع نص عربي RTL أو أسماء مضيف متغيّرة الطول) — كل التخطيط عبر
Table.grid/Panel من rich نفسها، فتحسب العرض تلقائياً وبشكل صحيح.
"""

import os
import sys
import re
import time
import random
import threading
from datetime import datetime
from collections import deque

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.markdown import Markdown
    from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn, TimeElapsedColumn
    from rich.prompt import Prompt, Confirm
    from rich.tree import Tree
    from rich.rule import Rule
    from rich import box
    RICH = True
except ImportError:
    RICH = False


# ─────────────────────────────────────────────────────────────────────────
#  Design System — هوية بصرية واحدة موحّدة لكل الأداة
# ─────────────────────────────────────────────────────────────────────────
ACCENT      = "bright_cyan"   # الهوية البصرية: عناوين، حدود، مؤشرات — بلا معنى دلالي
ACCENT_SOFT = "cyan"
TEXT        = "grey93"        # نص أساسي
TEXT_DIM    = "grey58"        # نص ثانوي/تفاصيل/طوابع زمنية
RULE_COLOR  = "grey35"        # خطوط وحدود هادئة غير دلالية

SUCCESS = "bold green"
DANGER  = "bold red"
WARN    = "bold yellow"

PANEL_BOX = box.ROUNDED if RICH else None
TABLE_BOX = box.SIMPLE_HEAVY if RICH else None
PANEL_PAD = (1, 2)

# خطورة → (لون، أيقونة). الألوان هنا مقصودة لتكون متمايزة بصرياً بوضوح
# عن بعضها (لم يعد الحرج والخطير يتشاركان درجتي أحمر شبه متطابقتين).
_SEV = {
    "critical": ("bold red",         "🔴", "CRITICAL"),
    "high":     ("bold dark_orange", "🟠", "HIGH"),
    "medium":   ("bold yellow",      "🟡", "MEDIUM"),
    "low":      ("bold cyan",        "🔵", "LOW"),
    "info":     ("grey58",           "⚪", "INFO"),
    "safe":     ("bold green",       "🟢", "SAFE"),
}

_THREAT_COLOR = {
    "CRITICAL": "bold red", "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow", "LOW": "bold green", "UNKNOWN": "grey58",
}

_MX = "ﾊﾐﾋｰｳｼﾅﾓﾆｻﾜﾂｵﾘｱﾎﾃﾏｹﾒｴｶｷﾑﾕﾗｾﾈｽﾀﾇﾍ01010110"


class TerminalUI:
    def __init__(self, no_color=False):
        self.no_color = no_color
        if RICH and not no_color:
            self.console = Console(highlight=False)
        else:
            self.console = None
        self._event_log: deque = deque(maxlen=200)
        self._lock = threading.Lock()

    # ─── Low-level print ────────────────────────────────────────────────────
    def _p(self, msg, end="\n"):
        if self.console:
            self.console.print(msg, end=end)
        else:
            print(re.sub(r'\[/?[^\]]*\]', '', str(msg)), end=end)

    # ─── Event Log ──────────────────────────────────────────────────────────
    def _log_event(self, level: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self._event_log.append((ts, level.upper(), msg))

    def get_events(self, n=12) -> list:
        with self._lock:
            return list(self._event_log)[-n:]

    # ─── Splash — شريط تحميل قصير واحترافي (بدل مطر الأحرف القديم) ────────
    def matrix_splash(self, seconds: float = 1.2):
        if not self.console:
            return
        try:
            steps = [
                "⚙  تهيئة الوحدات الأمنية",
                "🧠 تحميل محرك الذكاء المحلي",
                "📡 الاتصال بقاعدة المعرفة",
            ]
            per_step = max(0.12, seconds / len(steps))
            with Progress(
                TextColumn("{task.description}"),
                BarColumn(bar_width=26, style=RULE_COLOR, complete_style=ACCENT, finished_style=SUCCESS),
                TextColumn(f"[{TEXT_DIM}]" + "{task.percentage:>3.0f}%[/" + TEXT_DIM + "]"),
                console=self.console, transient=True,
            ) as progress:
                task = progress.add_task(f"[{ACCENT}]{steps[0]}[/{ACCENT}]", total=100)
                for i, label in enumerate(steps):
                    progress.update(task, description=f"[{ACCENT}]{label}[/{ACCENT}]")
                    start = time.time()
                    while time.time() - start < per_step:
                        frac = (i + (time.time() - start) / per_step) / len(steps)
                        progress.update(task, completed=min(99, frac * 100))
                        time.sleep(0.03)
                progress.update(task, completed=100)
        except Exception:
            pass

    # ─── Banner — لوحة الهوية والحالة الرئيسية ─────────────────────────────
    def banner(self, context=None):
        if self.console:
            self.console.clear()
        ts = datetime.now().strftime("%H:%M:%S")
        host, uptime, threat = "LOCALHOST", "", "LOW"

        if context:
            sys_ctx = getattr(context, "system", {}) or {}
            host = sys_ctx.get("hostname", "LOCALHOST")
            uptime = (sys_ctx.get("uptime", "") or "").replace("up ", "")
            threat = context.threat_level() if hasattr(context, "threat_level") else "LOW"
        t_color = _THREAT_COLOR.get(threat, "bold green")

        if not self.console:
            print(f"\n  AI AYFAM — {host} — THREAT: {threat}\n")
            return

        status = Table.grid(padding=(0, 3), expand=True)
        status.add_column(justify="left")
        status.add_column(justify="left")
        status.add_column(justify="left")
        status.add_column(justify="right")
        status.add_row(
            f"[{TEXT_DIM}]المضيف[/{TEXT_DIM}] [{ACCENT}]{host}[/{ACCENT}]",
            f"[{TEXT_DIM}]الوقت[/{TEXT_DIM}] [{TEXT}]{ts}[/{TEXT}]",
            f"[{TEXT_DIM}]التشغيل[/{TEXT_DIM}] [{TEXT}]{uptime or '—'}[/{TEXT}]",
            f"[{TEXT_DIM}]التهديد[/{TEXT_DIM}] [{t_color}]{threat}[/{t_color}]",
        )

        shortcuts = [
            ("1", "الشبكة"), ("2", "النظام"), ("3", "USB"), ("4", "التهديدات"),
            ("5", "السجلات"), ("6", "CVE"), ("7", "الأدوات"), ("8", "الوكيل"),
        ]
        menu = Table.grid(padding=(0, 3), expand=True)
        for _ in range(4):
            menu.add_column(justify="left")
        for i in range(0, len(shortcuts), 4):
            row = shortcuts[i:i + 4]
            cells = [f"[{TEXT_DIM}][[/{TEXT_DIM}][bold {ACCENT}]{k}[/bold {ACCENT}][{TEXT_DIM}]][/{TEXT_DIM}] {label}"
                     for k, label in row]
            while len(cells) < 4:
                cells.append("")
            menu.add_row(*cells)

        body = Table.grid(padding=(0, 0))
        body.add_column()
        body.add_row(status)
        body.add_row(Text(""))
        body.add_row(menu)

        title = f" [bold white on {ACCENT_SOFT}] AI AYFAM [/bold white on {ACCENT_SOFT}] [{TEXT_DIM}]Security Operations Console[/{TEXT_DIM}] "
        self.console.print(Panel(
            body, title=title, title_align="right" if _is_rtl_default() else "left",
            subtitle=f"[{TEXT_DIM}]اكتب أمراً أو رقماً من القائمة[/{TEXT_DIM}]",
            border_style=ACCENT, box=PANEL_BOX, padding=PANEL_PAD,
        ))

    # ─── Dashboard — لوحة حالة عامة (شبكة/نظام/أمن/أجهزة) ──────────────────
    def dashboard(self, context=None, kb_stats=None):
        if not context or not self.console:
            return

        sys_ctx = context.system
        net_ctx = context.network
        sec_ctx = context.security
        dev_ctx = context.devices
        user = context.user
        threat = context.threat_level()
        t_color = _THREAT_COLOR.get(threat, "bold green")

        def _kv_table():
            t = Table(box=None, show_header=False, padding=(0, 1))
            t.add_column(style=TEXT_DIM)
            t.add_column(style=TEXT)
            return t

        sys_tbl = _kv_table()
        sys_tbl.add_row("النظام", sys_ctx.get("os", "?")[:28])
        sys_tbl.add_row("Kernel", sys_ctx.get("kernel", "?"))
        sys_tbl.add_row("CPU", f"{sys_ctx.get('cpu_cores','?')} نواة | حمل {sys_ctx.get('load','?').strip()}")
        mem = sys_ctx.get("memory", {})
        sys_tbl.add_row("الذاكرة", f"{mem.get('used','?')} / {mem.get('total','?')}")
        sys_tbl.add_row("القرص /", sys_ctx.get("disk_root", "?"))
        sys_tbl.add_row("المستخدم", f"{user.get('username','?')} [{user.get('role','?')}]")

        sec_tbl = _kv_table()
        sec_tbl.add_row("التهديد", f"[{t_color}]{threat}[/{t_color}]")
        sec_tbl.add_row("جدار الحماية",
                        f"[{SUCCESS}]نشط ✓[/{SUCCESS}]" if net_ctx.get("firewall_active") else f"[{DANGER}]معطَّل ✗[/{DANGER}]")
        sec_tbl.add_row("منافذ مفتوحة", str(sec_ctx.get("open_ports_count", "?")))
        failed = sec_ctx.get("failed_login_attempts", 0)
        sec_tbl.add_row("محاولات فاشلة", f"[{DANGER if failed>5 else TEXT}]{failed}[/{DANGER if failed>5 else TEXT}]")
        sec_tbl.add_row("خدمات نشطة", str(sec_ctx.get("running_services", "?")))
        pending = sec_ctx.get("pending_updates", 0)
        sec_tbl.add_row("تحديثات معلّقة", f"[{WARN if pending>0 else TEXT}]{pending}[/{WARN if pending>0 else TEXT}]")

        net_tbl = _kv_table()
        for iface, addr in list(net_ctx.get("interfaces", {}).items())[:4]:
            net_tbl.add_row(iface, addr)
        net_tbl.add_row("البوابة", net_ctx.get("gateway", "?"))
        net_tbl.add_row("IP العام", net_ctx.get("public_ip", "?"))
        dns = net_ctx.get("dns", [])
        if dns:
            net_tbl.add_row("DNS", ", ".join(dns[:2]))

        dev_tbl = _kv_table()
        dev_tbl.add_row("أجهزة USB", str(dev_ctx.get("usb_count", 0)))
        dev_tbl.add_row("Bluetooth", f"[{SUCCESS}]مفعَّل[/{SUCCESS}]" if dev_ctx.get("bluetooth") else f"[{TEXT_DIM}]معطَّل[/{TEXT_DIM}]")
        wifi = dev_ctx.get("wifi_adapters", [])
        dev_tbl.add_row("واجهات WiFi", ", ".join(wifi) if wifi else "لا يوجد")
        phones = dev_ctx.get("android_phones", [])
        dev_tbl.add_row("أجهزة أندرويد", str(len(phones)) + (" 📱" if phones else ""))
        if kb_stats:
            dev_tbl.add_row("سجلات المعرفة", f"{kb_stats.get('knowledge_entries',0)}")
            dev_tbl.add_row("حجم القاعدة", f"{kb_stats.get('db_size_mb',0)}MB")

        # يُوازن عدد أسطر كل زوج جدولين متجاورين — بدون هذا، فروقات
        # العدد الطبيعية (مثال: عدد واجهات الشبكة يتغيّر) كانت تكسر محاذاة
        # الحد السفلي بين اللوحتين المتجاورتين بشكل واضح وغير احترافي.
        def _equalize(tbl_a, tbl_b):
            na, nb = len(tbl_a.rows), len(tbl_b.rows)
            for _ in range(nb - na):
                tbl_a.add_row("", "")
            for _ in range(na - nb):
                tbl_b.add_row("", "")

        _equalize(sys_tbl, sec_tbl)
        _equalize(net_tbl, dev_tbl)

        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_row(
            Panel(sys_tbl, title=f"[bold {ACCENT}]النظام[/bold {ACCENT}]", border_style=RULE_COLOR, box=PANEL_BOX),
            Panel(sec_tbl, title=f"[bold {ACCENT}]الأمان[/bold {ACCENT}]", border_style=RULE_COLOR, box=PANEL_BOX),
        )
        grid.add_row(
            Panel(net_tbl, title=f"[bold {ACCENT}]الشبكة[/bold {ACCENT}]", border_style=RULE_COLOR, box=PANEL_BOX),
            Panel(dev_tbl, title=f"[bold {ACCENT}]الأجهزة[/bold {ACCENT}]", border_style=RULE_COLOR, box=PANEL_BOX),
        )
        self.console.print(grid)

    # ─── Event Stream ───────────────────────────────────────────────────────
    def show_event_stream(self, n: int = 15):
        events = self.get_events(n)
        if not events:
            return
        if not self.console:
            print("\n  EVENT STREAM:")
            for ts, lvl, msg in events:
                print(f"  [{ts}] {lvl}: {msg}")
            return

        lvl_color = {"INFO": TEXT_DIM, "WARN": "bold yellow", "CRIT": "bold red",
                     "OK": "bold green", "ERR": "bold red"}
        rows = []
        for ts, lvl, msg in events:
            c = lvl_color.get(lvl, TEXT)
            rows.append(f"[{TEXT_DIM}]{ts}[/{TEXT_DIM}]  [{c}]{lvl:<4}[/{c}]  [{TEXT}]{msg[:90]}[/{TEXT}]")
        self.console.print(Panel(
            "\n".join(rows), title=f"[bold {ACCENT}]سجل الأحداث[/bold {ACCENT}]",
            border_style=RULE_COLOR, box=PANEL_BOX, padding=(0, 1),
        ))

    # ─── Chat ────────────────────────────────────────────────────────────────
    def _chat_width(self) -> int:
        """عرض ثابت ومعقول لصناديق المحادثة — يمنع تفاوت شكل الصندوق حسب
        أطول سطر (سبب رئيسي للشعور بالفوضى سابقاً)."""
        if not self.console:
            return 80
        return max(50, min(self.console.width - 6, 96))

    @staticmethod
    def _to_markdown_friendly(msg: str) -> str:
        """يحوّل تنسيقات نصية شائعة (• نقطة) إلى Markdown قياسي، ويضمن أن
        كل سطر يبقى سطراً منفصلاً مرئياً بدل أن يُدمَج في فقرة واحدة وفق
        معيار CommonMark — سلوك كان يُفسِد نصوصاً كثيرة هنا."""
        lines = msg.split("\n")
        converted = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("• "):
                indent = line[:len(line) - len(line.lstrip())]
                converted.append(f"{indent}- {stripped[2:]}")
            else:
                converted.append(line)
        result = []
        for line in converted:
            s = line.lstrip()
            if s == "" or s.startswith(("#", "-", "*", ">", "```", "|")):
                result.append(line)
            else:
                result.append(line + "  ")
        return "\n".join(result)

    def chat_you(self, msg: str):
        self._log_event("INFO", f"[USER] {msg}")
        if not self.console:
            print(f"\n  YOU > {msg}")
            return
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.print(f"\n[{TEXT_DIM}][{ts}][/{TEXT_DIM}] [bold {TEXT}]أنت ❯[/bold {TEXT}] [{TEXT}]{msg}[/{TEXT}]")

    def chat_agent(self, msg: str, intent: str = None):
        self._log_event("OK", f"[AGENT] {intent or ''} {msg[:60]}")
        if not self.console:
            print(f"\n  AYFAM > {msg}")
            return

        ts = datetime.now().strftime("%H:%M:%S")
        badge = f"  [{TEXT_DIM}]·[/{TEXT_DIM}]  [bold {ACCENT}]{intent.upper()}[/bold {ACCENT}]" if intent else ""
        self.console.print(f"\n[{TEXT_DIM}][{ts}][/{TEXT_DIM}] [bold {ACCENT}]🛡  AYFAM[/bold {ACCENT}]{badge}")
        body_src = self._to_markdown_friendly(msg.strip())
        try:
            body = Markdown(body_src, style=TEXT)
        except Exception:
            body = f"[{TEXT}]{body_src}[/{TEXT}]"
        self.console.print(Panel(body, border_style=ACCENT, padding=PANEL_PAD, width=self._chat_width(), box=PANEL_BOX))

    def chat_thinking(self, msg: str = "أحلل طلبك..."):
        if self.console:
            self.console.print(f"[{TEXT_DIM}]⏳ {msg}[/{TEXT_DIM}]", end="\r")

    # ─── Sections ────────────────────────────────────────────────────────────
    def section(self, title: str, color: str = ACCENT):
        if self.console:
            self.console.print()
            self.console.rule(f"[bold {color}] {title} [/bold {color}]", style=RULE_COLOR, characters="─")
        else:
            print(f"\n{'─'*70}\n  {title}\n{'─'*70}")

    def subsection(self, title: str):
        if self.console:
            self.console.print(f"\n[{TEXT_DIM}]▸[/{TEXT_DIM}] [bold {TEXT}]{title}[/bold {TEXT}]")
        else:
            print(f"\n  ▸ {title}")

    # ─── Message Types ───────────────────────────────────────────────────────
    def info(self, msg: str):
        self._log_event("INFO", msg)
        self._p(f"[{TEXT_DIM}]│[/{TEXT_DIM}] [{TEXT}]{msg}[/{TEXT}]")

    def success(self, msg: str):
        self._log_event("OK", msg)
        self._p(f"[{TEXT_DIM}]│[/{TEXT_DIM}] [{SUCCESS}]✓ {msg}[/{SUCCESS}]")

    def warning(self, msg: str):
        self._log_event("WARN", msg)
        self._p(f"[{TEXT_DIM}]│[/{TEXT_DIM}] [{WARN}]! {msg}[/{WARN}]")

    def error(self, msg: str):
        self._log_event("ERR", msg)
        self._p(f"[{TEXT_DIM}]│[/{TEXT_DIM}] [{DANGER}]✗ {msg}[/{DANGER}]")

    def critical(self, msg: str):
        self._log_event("CRIT", msg)
        if self.console:
            self.console.print(Panel(f"[bold white]⚠  {msg}[/bold white]", border_style="red",
                                       box=PANEL_BOX, padding=(0, 1), expand=False))
        else:
            print(f"\n  [!!!] {msg}")

    # ─── Findings ────────────────────────────────────────────────────────────
    def print_finding(self, severity: str, title: str, detail: str = "", fix: str = ""):
        sev = (severity or "").lower()
        color, icon, label = _SEV.get(sev, (TEXT, "•", sev.upper() or "—"))
        self._log_event("CRIT" if sev == "critical" else "WARN" if sev in ("high", "medium") else "INFO",
                         f"[{label}] {title[:80]}")
        if not self.console:
            print(f"\n  {icon} [{label}] {title}")
            if detail: print(f"     {detail}")
            if fix:    print(f"     Fix: {fix}")
            return

        body = f"[bold {TEXT}]{title}[/bold {TEXT}]"
        if detail:
            body += f"\n[{TEXT_DIM}]{detail.strip()[:300]}[/{TEXT_DIM}]"
        if fix:
            body += f"\n\n[{SUCCESS}]🔧 الحل:[/{SUCCESS}]\n[italic {TEXT_DIM}]{fix.strip()[:300]}[/italic {TEXT_DIM}]"
        self.console.print(Panel(
            body, title=f"[{color}]{icon} {label}[/{color}]",
            border_style=color, padding=(0, 2), width=self._chat_width(), box=PANEL_BOX,
        ))

    # ─── Tables ──────────────────────────────────────────────────────────────
    def print_table(self, headers: list, rows: list, title: str = None):
        if not rows:
            self.info("لا توجد بيانات / No data")
            return
        if not self.console:
            if title: print(f"\n  {title}")
            print("  " + " | ".join(str(h) for h in headers))
            print("  " + "─"*70)
            for row in rows:
                print("  " + " | ".join(str(c) for c in row))
            return

        tbl = Table(
            title=f"[bold {ACCENT}]{title}[/bold {ACCENT}]" if title else None,
            box=TABLE_BOX, header_style=f"bold {ACCENT}",
            border_style=RULE_COLOR, show_lines=False, padding=(0, 1),
        )
        for h in headers:
            tbl.add_column(str(h), overflow="fold")
        for row in rows:
            styled = []
            for cell in row:
                cs = str(cell)
                cl = cs.lower()
                if any(w in cl for w in ["critical", "🔴", "خطير جداً", "crit"]):
                    styled.append(f"[bold red]{cs}[/bold red]")
                elif any(w in cl for w in ["high", "🟠", "suspicious", "مشبوه"]):
                    styled.append(f"[bold dark_orange]{cs}[/bold dark_orange]")
                elif any(w in cl for w in ["safe", "آمن", "trusted", "🟢", "ok ✓", "low"]):
                    styled.append(f"[{SUCCESS}]{cs}[/{SUCCESS}]")
                elif any(w in cl for w in ["medium", "🟡", "warning"]):
                    styled.append(f"[{WARN}]{cs}[/{WARN}]")
                elif any(w in cl for w in ["open", "مفتوح", "active", "نشط"]):
                    styled.append(f"[{ACCENT}]{cs}[/{ACCENT}]")
                else:
                    styled.append(f"[{TEXT}]{cs}[/{TEXT}]")
            tbl.add_row(*styled)
        self.console.print(tbl)

    # ─── Tree ────────────────────────────────────────────────────────────────
    def print_tree(self, data: dict, title: str = ""):
        if self.console and isinstance(data, dict):
            tree = Tree(f"[bold {ACCENT}]{title}[/bold {ACCENT}]")
            self._build_tree(tree, data)
            self.console.print(tree)
        else:
            if title: print(f"\n  {title}")
            self._dump(data)

    def _build_tree(self, node, data, depth=0):
        if depth > 4: return
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, (dict, list)):
                    b = node.add(f"[{TEXT}]{k}[/{TEXT}]")
                    self._build_tree(b, v, depth+1)
                else:
                    node.add(f"[{TEXT_DIM}]{k}:[/{TEXT_DIM}] [{TEXT}]{v}[/{TEXT}]")
        elif isinstance(data, list):
            for item in data[:10]:
                if isinstance(item, (dict, list)):
                    b = node.add(f"[{TEXT_DIM}]·[/{TEXT_DIM}]")
                    self._build_tree(b, item, depth+1)
                else:
                    node.add(f"[{TEXT}]{item}[/{TEXT}]")

    def _dump(self, data, indent=0):
        sp = " " * indent
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, (dict, list)):
                    print(f"{sp}{k}:"); self._dump(v, indent+2)
                else:
                    print(f"{sp}{k}: {v}")
        elif isinstance(data, list):
            for item in data: self._dump(item, indent)

    # ─── Spinner ─────────────────────────────────────────────────────────────
    def spinner(self, msg: str):
        if self.console:
            return Progress(
                SpinnerColumn(spinner_name="dots", style=ACCENT),
                TextColumn(f"[{TEXT}]{msg}...[/{TEXT}]"),
                TimeElapsedColumn(),
                console=self.console, transient=True,
            )
        class _F:
            def __enter__(self): print(f"  ⏳ {msg}..."); return self
            def __exit__(self, *a): pass
            def add_task(self, *a, **kw): return 0
        return _F()

    # ─── Inputs ──────────────────────────────────────────────────────────────
    def ask(self, prompt: str, default: str = None) -> str:
        if self.console:
            try:
                return Prompt.ask(
                    f"\n[{TEXT_DIM}]╰──[/{TEXT_DIM}][bold {ACCENT}]❯[/bold {ACCENT}] [{TEXT}]{prompt}[/{TEXT}]",
                    default=default or "", console=self.console,
                )
            except Exception:
                val = input(f"\n  ❯ {prompt}: ")
                return val or (default or "")
        return input(f"\n  ❯ {prompt}: ") or (default or "")

    def confirm(self, prompt: str, default: bool = False) -> bool:
        if self.console:
            try:
                return Confirm.ask(
                    f"\n[{TEXT_DIM}]╰──[/{TEXT_DIM}][bold {WARN}]?[/bold {WARN}] [{TEXT}]{prompt}[/{TEXT}]",
                    default=default, console=self.console,
                )
            except Exception:
                ans = input(f"\n  ? {prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
                return ans in ("y", "yes", "نعم", "ن", "1") if ans else default
        ans = input(f"\n  ? {prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        return ans in ("y", "yes", "نعم", "ن", "1") if ans else default

    def chat_input(self) -> str:
        if self.console:
            try:
                return Prompt.ask(f"\n[bold {ACCENT}]❯[/bold {ACCENT}]", console=self.console)
            except Exception:
                return input("\n  ❯ ").strip()
        return input("\n  TYPE: ").strip()

    # ─── Raw output ──────────────────────────────────────────────────────────
    def raw(self, text: str, style: str = RULE_COLOR):
        if not text: return
        if self.console:
            self.console.print(Panel(f"[{TEXT}]{text}[/{TEXT}]", border_style=style,
                                       padding=PANEL_PAD, width=self._chat_width(), box=PANEL_BOX))
        else:
            print(text)

    # ─── Status Bar ──────────────────────────────────────────────────────────
    def status_bar(self, items: dict):
        if not self.console:
            print("  " + "  |  ".join(f"{k}: {v}" for k, v in items.items()))
            return
        row = Table.grid(padding=(0, 2), expand=True)
        for _ in items:
            row.add_column(justify="left")
        cells = []
        for k, v in items.items():
            vs = str(v).lower()
            if any(w in vs for w in ["active", "نشط", "متصل", "connected", "ready", "مُهيَّأ", "ok"]):
                col = SUCCESS
            elif any(w in vs for w in ["disabled", "off", "معطَّل", "غير متصل", "not set"]):
                col = DANGER
            else:
                col = WARN
            cells.append(f"[{TEXT_DIM}]{k}[/{TEXT_DIM}] [{col}]{v}[/{col}]")
        row.add_row(*cells)
        self.console.print(Panel(row, border_style=RULE_COLOR, box=PANEL_BOX, padding=(0, 1)))

    # ─── Self-Heal display ───────────────────────────────────────────────────
    def show_improvement(self, imp: dict):
        if self.console:
            self.console.print(Panel(
                f"[{TEXT_DIM}]الفئة:[/{TEXT_DIM}] [{ACCENT}]{imp['category']}[/{ACCENT}]\n"
                f"[{TEXT_DIM}]الوصف:[/{TEXT_DIM}] [{TEXT}]{imp['description']}[/{TEXT}]\n"
                f"[{TEXT_DIM}]اقتُرح في: {imp.get('proposed_at','')}[/{TEXT_DIM}]",
                title=f"[bold {WARN}]اقتراح تحسين[/bold {WARN}]",
                border_style=WARN, box=PANEL_BOX, padding=(0, 2), expand=False,
            ))
        else:
            print(f"\n  [+] اقتراح: {imp['description']}")


def _is_rtl_default() -> bool:
    """يُستخدَم فقط لاختيار محاذاة عنوان اللوحة الرئيسية بشكل يناسب
    الواجهة العربية افتراضياً — تفصيل تجميلي بسيط، وليس دعم bidi كاملاً."""
    return True
