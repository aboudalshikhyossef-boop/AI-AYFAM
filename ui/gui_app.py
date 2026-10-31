"""واجهة AI AYFAM الرسومية — مركز تحكم موحّد للفحوصات والتقارير (v2 — redesigned)."""

from __future__ import annotations

import html
import os
import sys
import ipaddress
import json
import math
import time
from pathlib import Path
from typing import Callable, Any

from PyQt6.QtCore import Qt, QTimer, QThread, QPropertyAnimation, pyqtSignal, QUrl, QSize, QRect, QEasingCurve, QRectF
from PyQt6.QtGui import QColor, QDesktopServices, QFont, QIcon, QAction, QShortcut, QKeySequence, QPainter, QPixmap, QPen, QLinearGradient, QRadialGradient
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QGraphicsOpacityEffect, QGridLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QSplitter, QStackedWidget, QTabWidget,
    QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget, QScrollArea, QSizePolicy,
    QInputDialog, QCheckBox,
)

from config.settings import Settings
from config.model_defaults import OPENAI_DEFAULT_MODEL
from config.version import APP_VERSION_LABEL
from core.agent import AYFAMAgent
from brain import library, relevance_engine
from engine.live_recon import LiveReconEngine
from engine.risk import RiskEngine
from tools.usb import analyze_mounted_filesystem, list_usb_devices, scan_mounted_drives
from tools.usb_control import (
    authorize_device,
    deauthorize_device,
    deep_scan_flash_privileged,
    eject_storage_device,
    fix_flash_issues,
)
from tools.websearch import DEFAULT_GOOGLE_CSE_CX
from engine.gemini_rate_limit import DEFAULT_GEMINI_MODEL
from ui.terminal import TerminalUI
from ui.icons import ICON_COLORS, framed_icon, glyph_icon
from ui.widgets import AccentLine, ChatView, SecurityGauge, StaticNavigationMenu, TelemetryChart
from ui.performance import EVENT_POLL_INTERVAL_MS, TELEMETRY_REFRESH_MS
from ui.intro_splash import AyfamIntroSplash, SystemOverviewDialog
from ui.views.findings import FindingsView
from ui.views.timeline import TimelineView
from ui.views.sentinel import SentinelView
from ui.views.attack_graph import AttackChainGraphView
from ui.theme import (
    QSS, get_qss, ACCENT, ACCENT_SECONDARY, ACCENT_SOFT, ACCENT_HUES, BG_BASE, BG_SURFACE, BG_ELEVATED, BG_HOVER,
    BORDER, BORDER_FOCUS, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO, SEV_SAFE,
    STATUS_OK, STATUS_ERROR, STATUS_IDLE,
    FONT_FAMILY, FONT_SIZE_BASE, FONT_SIZE_SMALL, FONT_SIZE_TITLE, FONT_SIZE_HERO, FONT_SIZE_METRIC,
    SP_XS, SP_SM, SP_MD, SP_LG, SP_XL, SP_2XL,
    CARD_ACCENTS, PAGE_ACCENTS, alpha, severity_color, severity_bg,
)
from utils import safe_exec
from utils.preflight import check_requirements, root_error, is_root


ROOT_DIR = Path(__file__).resolve().parents[1]

# Navigation items: (key, icon, label_ar)
NAV_ITEMS = [
    ("dashboard", "غرفة العمليات"),
    ("scans",     "الفحوصات الأمنية"),
    ("findings",  "النتائج الموحدة"),
    ("timeline",  "الخط الزمني"),
    ("sentinel",  "الحارس اللحظي"),
    ("attack_graph", "سلاسل الهجوم"),
    ("usb",       "الأجهزة المتصلة"),
    ("tools",     "ترسانة الأدوات"),
    ("chat",      "المحادثة الأمنية"),
    ("library",   "المكتبة المحلية"),
    ("playbooks", "خطط العمل"),
    ("reports",   "التقارير"),
    ("settings",  "إعدادات النظام"),
]


class GuiTerminalUI(TerminalUI):
    """Provide safe defaults for CLI prompts when agent methods run in the GUI."""

    def ask(self, prompt: str, default: str = None) -> str:
        return default or ""

    def confirm(self, prompt: str, default: bool = False) -> bool:
        return default

    def print_table(self, headers: list, rows: list, title: str = None) -> None:
        super().print_table(headers, rows, title)
        if title:
            self._log_event("INFO", title)
        for row in rows:
            self._log_event("INFO", " | ".join(str(value) for value in row))

    def print_tree(self, data: dict, title: str = "") -> None:
        super().print_tree(data, title)
        self._log_event("INFO", f"{title}: {data}" if title else str(data))

    def raw(self, text: str, style: str = "") -> None:
        super().raw(text, style)
        self._log_event("INFO", str(text))


class WorkerThread(QThread):
    task_result = pyqtSignal(object)

    def __init__(self, task_fn: Callable[..., Any], *args: Any):
        super().__init__()
        self.task_fn, self.args = task_fn, args

    def run(self) -> None:
        try:
            self.task_result.emit(self.task_fn(*self.args))
        except Exception as exc:
            self.task_result.emit(exc)


class LiveTelemetryWorker(QThread):
    """Collect potentially slow ss/ps data outside the Qt GUI thread."""

    result_ready = pyqtSignal(object)

    def run(self) -> None:
        try:
            self.result_ready.emit({
                "connections": LiveReconEngine.get_live_connections(),
                "processes": LiveReconEngine.get_top_processes(20),
            })
        except Exception as exc:
            self.result_ready.emit(exc)


def _sev_brush(severity: str) -> QColor:
    return QColor(severity_color(severity))



SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_AR = {"critical": "حرجة", "high": "عالية", "medium": "متوسطة", "low": "منخفضة", "info": "معلومة"}
SEV_WHY = {
    "critical": "قد يسمح باختراق مباشر أو فقدان بيانات. عالجه فوراً قبل أي شيء آخر.",
    "high": "ثغرة يمكن استغلالها بسهولة نسبية. يُنصح بإصلاحها اليوم.",
    "medium": "يضعف الحماية أو يتيح معلومات للمهاجم. خطط لإصلاحه قريباً.",
    "low": "أثره محدود لكنه يقلل من إحكام الإعداد. أصلحه عند الفرصة.",
    "info": "معلومة للإحاطة ولا تتطلب إجراءً عاجلاً.",
}
CONN_STATE_COLORS = {
    "LISTEN": SEV_SAFE, "ESTAB": ACCENT, "ESTABLISHED": ACCENT, "TIME_WAIT": SEV_HIGH, "TIME-WAIT": SEV_HIGH,
    "CLOSE_WAIT": SEV_HIGH, "SYN_SENT": SEV_MEDIUM, "SYN-SENT": SEV_MEDIUM, "UNCONN": SEV_INFO,
}


def _sev_key(finding: dict) -> str:
    key = str(finding.get("severity", "info")).lower()
    return key if key in SEV_ORDER else "info"


def score_state_color(score: float) -> str:
    """Map the posture score to the same semantic colors used by the dashboard."""
    if score >= 85:
        return SEV_SAFE
    if score >= 70:
        return SEV_MEDIUM
    if score >= 50:
        return SEV_HIGH
    return SEV_CRITICAL


def sort_findings(findings: list) -> list:
    return sorted(findings, key=lambda f: (SEV_ORDER.index(_sev_key(f)), -(f.get("confidence") or 0)))


def summarize_findings(findings: list, title: str) -> str:
    """ملخص عربي موجز بعد كل فحص: العدد حسب الخطورة، الأهم، والخطوة التالية."""
    if not findings:
        return (f"ملخص {title}: لم يرصد الفحص مشاكل أمنية. أعد الفحص بعد أي تغيير كبير في النظام أو الشبكة، "
                "وأبقِ التحديثات مفعّلة.")
    ordered = sort_findings(findings)
    counts = {key: sum(1 for f in findings if _sev_key(f) == key) for key in SEV_ORDER}
    parts = "، ".join(f"{counts[k]} {SEV_AR[k]}" for k in SEV_ORDER if counts[k])
    lines = [f"ملخص {title}: {len(findings)} نتيجة ({parts})."]
    lines.append("الأهم:")
    for i, f in enumerate(ordered[:3], 1):
        fix_lines = [ln.strip() for ln in str(f.get("fix") or "").splitlines() if ln.strip()]
        lines.append(f"{i}. [{SEV_AR[_sev_key(f)]}] {str(f.get('title', 'بلا عنوان'))[:110]}")
        if fix_lines:
            lines.append(f"    الإصلاح: {fix_lines[0][:110]}")
    urgent = counts["critical"] + counts["high"]
    lines.append("الخطوة التالية: " + (
        "ابدأ بالنتائج الحرجة والعالية في تبويب الفحوصات؛ حدد النتيجة لترى سببها وطريقة إصلاحها، ثم أعد الفحص للتأكد."
        if urgent else "راجع النتائج في تبويب الفحوصات وأصلح ما يناسبك، لا توجد مشاكل عاجلة."))
    return "\n".join(lines)


def finding_html(finding: dict) -> str:
    """تفاصيل منظمة: ما المشكلة / لماذا تهم / كيف أصلحها / الدليل."""
    esc = lambda v: html.escape(str(v)).replace("\n", "<br>")
    key = _sev_key(finding)
    color = severity_color(key)
    confidence = finding.get("confidence")
    conf = f"{float(confidence):.0%}" if isinstance(confidence, (int, float)) else "غير محددة"

    def section(heading: str, body: str, tint: str = ACCENT) -> str:
        return (f"<p style='margin:10px 0 2px 0'><span style='color:{tint};font-weight:700'>{heading}</span><br>"
                f"<span style='color:{TEXT_PRIMARY}'>{body}</span></p>")

    out = [f"<p style='margin:0'><span style='font-size:15px;font-weight:800;color:{TEXT_PRIMARY}'>{esc(finding.get('title', 'بلا عنوان'))}</span><br>"
           f"<span style='color:{color};font-weight:700'>الخطورة: {SEV_AR[key]}</span>"
           f"<span style='color:{TEXT_MUTED}'>  |  الثقة: {conf}  |  الفئة: {esc(finding.get('category', 'غير مصنفة'))}</span></p>"]
    out.append(section("ما المشكلة", esc(finding.get("detail") or "لم يوفر الفاحص تفاصيل إضافية.")))
    out.append(section("لماذا يهم", esc(finding.get("why") or finding.get("impact") or SEV_WHY[key]), color))
    out.append(section("كيف أصلحها", esc(finding.get("fix") or "لا توجد توصية آلية مسجلة؛ راجع التفاصيل أعلاه."), SEV_SAFE))
    evidence = finding.get("evidence") or {}
    if evidence:
        out.append(section("الدليل المسجل", "<pre style='margin:0'>" + html.escape(json.dumps(evidence, ensure_ascii=False, indent=2, default=str)) + "</pre>", TEXT_SECONDARY))
    extras = []
    if finding.get("tags"):
        extras.append("الوسوم: " + ", ".join(str(t) for t in finding["tags"]))
    if finding.get("attack_ids"):
        extras.append("ATT&CK: " + ", ".join(str(t) for t in finding["attack_ids"]))
    if extras:
        out.append(f"<p style='color:{TEXT_MUTED};margin:10px 0 0 0'>{esc(' | '.join(extras))}</p>")
    return "".join(out)


def prepare_table(table: QTableWidget, row_height: int = 38) -> None:
    """Common readable-table setup: tall rows, no grid, elide, row selection."""
    table.setAlternatingRowColors(True)
    table.setShowGrid(False)
    table.setWordWrap(False)
    table.setTextElideMode(Qt.TextElideMode.ElideRight)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(row_height)
    table.horizontalHeader().setMinimumSectionSize(64)
    table.horizontalHeader().setHighlightSections(False)


def _storage_size_text(value, size_bytes=None) -> str:
    """عرض حجم lsblk سواء أعاده كنص مقروء أو كعدد بايتات."""
    raw = str(value or "").strip()
    try:
        number = int(size_bytes if size_bytes not in (None, "") else raw)
    except (TypeError, ValueError):
        return raw if raw and raw not in {"0", "0B", "0 bytes"} else "غير معروف"
    if number <= 0:
        return raw if raw and raw not in {"0", "0B", "0 bytes"} else "غير معروف"
    units = ("B", "KB", "MB", "GB", "TB")
    amount = float(number)
    unit = 0
    while amount >= 1024 and unit < len(units) - 1:
        amount /= 1024
        unit += 1
    return f"{amount:.1f} {units[unit]}"


def table_cell(text, color: str | None = None, center: bool = False, bold: bool = False, tip: str | None = None, mono: bool = False) -> QTableWidgetItem:
    item = QTableWidgetItem(str(text))
    if color:
        item.setForeground(QColor(color))
    font = item.font()
    if bold:
        font.setBold(True)
    if mono:
        font.setFamily("monospace")
    item.setFont(font)
    if center:
        item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    else:
        item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
    item.setToolTip(tip if tip is not None else str(text))
    return item


class UnifiedCockpitWindow(QMainWindow):

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("cockpitWindow")
        self.setWindowTitle("AI AYFAM — Security Operations Center")
        self.resize(1400, 880)
        self.setMinimumSize(1000, 680)
        self.setStyleSheet(QSS)
        icon_path = ROOT_DIR / "resources" / "icon.svg"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self.settings = Settings()
        if not bool(self.settings.get("dark_mode", True)):
            self.setStyleSheet(get_qss("#6d8f8c", "#7d83a6"))
        self.agent = AYFAMAgent(settings=self.settings, ui=GuiTerminalUI(no_color=True))
        self.worker: WorkerThread | None = None
        self._closing_after_workers = False
        self.active_task_title = ""
        self.active_result_handler: Callable[[Any], None] | None = None
        self.visible_events: list[tuple[str, str, str]] = []
        self.current_findings: list[dict] = []
        self.all_findings: list[dict] = []
        self.chat_history: list[tuple[str, str]] = []
        self.task_buttons: list[QPushButton] = []
        self.usb_inventory_loaded = False
        self._selected_usb_device: dict = {}
        self._selected_usb_partition_data: dict = {}
        self._usb_selection_source = "none"
        self._event_store = None
        self._training_mode_active = False
        self._telemetry_history = {
            "الجاهزية الأمنية (%)": [],
            "النشاط التشغيلي (%)": [],
        }
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.setObjectName("telemetryRefreshTimer")
        self.timer.timeout.connect(self.update_live_telemetry)
        self.timer.start(TELEMETRY_REFRESH_MS)
        self.event_timer = QTimer(self)
        self.event_timer.setObjectName("eventPollTimer")
        self.event_timer.timeout.connect(self.update_agent_events)
        self.event_timer.start(EVENT_POLL_INTERVAL_MS)
        for table in self.findChildren(QTableWidget):      # كل الجداول بنفس معيار القراءة
            if table.verticalHeader().defaultSectionSize() < 44:
                prepare_table(table, 44)
        # Low-resource mode intentionally skips hover overlays, glow effects, and sound hooks.
        self.chat_display.hover_controller = None
        if hasattr(self, "setting_dark_mode"):
            self.setting_dark_mode.toggled.connect(self._toggle_dark_mode)
        self._busy_cursor_owned = False
        self.telemetry_worker: LiveTelemetryWorker | None = None
        self._last_telemetry_error = ""
        self._install_accessibility_shortcuts()

        self.update_live_telemetry()
        self._sync_control_labels()

    def open_command_palette(self) -> None:
        """شريط أوامر عائم زجاجي للوصول السريع للأدوات والوظائف."""
        items = [
            ("بدء فحص شامل", lambda: self.run_background_task(self.agent._full_scan, "الفحص الشامل")),
            ("الانتقال لـ غرفة العمليات", lambda: self.switch_page("dashboard")),
            ("الانتقال لـ الفحوصات الأمنية", lambda: self.switch_page("scans")),
            ("الانتقال لـ ترسانة الأدوات", lambda: self.switch_page("tools")),
            ("الانتقال لـ الأجهزة المتصلة USB", lambda: self.switch_page("usb")),
            ("الانتقال لـ المحادثة الذكية", lambda: self.switch_page("chat")),
            ("الانتقال لـ إعدادات النظام", lambda: self.switch_page("settings")),
            ("تحديث الرادار والبيانات", self.update_live_telemetry),
        ]
        labels = [item[0] for item in items]
        selected, ok = QInputDialog.getItem(self, "شريط الأوامر السريعة (Ctrl+K)", "اختر أمراً لتنفيذه مباشرة:", labels, 0, False)
        if ok and selected:
            for label, action in items:
                if label == selected:
                    action()
                    break

    def _install_accessibility_shortcuts(self) -> None:
        """Keyboard access to common actions without changing mouse workflows."""
        cmd_palette = QShortcut(QKeySequence("Ctrl+K"), self)
        cmd_palette.activated.connect(self.open_command_palette)
        refresh = QShortcut(QKeySequence("Ctrl+R"), self)
        refresh.setObjectName("refreshTelemetryShortcut")
        refresh.setWhatsThis("تحديث بيانات الاتصالات والعمليات")
        refresh.activated.connect(self.update_live_telemetry)
        full_scan = QShortcut(QKeySequence("Ctrl+Shift+F"), self)
        full_scan.setObjectName("fullScanShortcut")
        full_scan.setWhatsThis("بدء فحص أمني شامل")
        full_scan.activated.connect(lambda: self.run_background_task(self.agent._full_scan, "الفحص الشامل"))
        chat_focus = QShortcut(QKeySequence("Ctrl+L"), self)
        chat_focus.setObjectName("chatFocusShortcut")
        chat_focus.setWhatsThis("الانتقال إلى حقل المحادثة")
        chat_focus.activated.connect(lambda: self.chat_input.setFocus())

    def _tick_aurora(self) -> None:
        # Kept for backwards compatibility — AmbientSurface animates itself
        pass

    # ═══════════════════════════════════════════════════════════════════════════
    #  LAYOUT: Sidebar + Header + Stacked Content
    # ═══════════════════════════════════════════════════════════════════════════
    def init_ui(self) -> None:
        central = QWidget(objectName="appRoot")
        central.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Sidebar ──
        sidebar = QFrame(objectName="sidebar")
        sidebar.setFixedWidth(216)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(SP_MD, SP_LG, SP_MD, SP_MD)
        sidebar_layout.setSpacing(SP_XS)

        # Logo / Brand
        brand_row = QHBoxLayout()
        brand_row.setSpacing(SP_SM)
        brand_mark = QLabel()
        brand_mark.setPixmap(QIcon(str(ROOT_DIR / "resources" / "icon.svg")).pixmap(28, 28))
        brand_mark.setObjectName("brandMark")
        brand_row.addWidget(brand_mark, 0, Qt.AlignmentFlag.AlignLeft)
        brand = QLabel("AI AYFAM")
        brand.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: {FONT_SIZE_TITLE}px; font-weight: 900; padding: 4px 0;")
        brand_row.addWidget(brand)
        brand_row.addStretch()
        sidebar_layout.addLayout(brand_row)

        sub = QLabel("مركز العمليات الأمنية")
        sub.setObjectName("eyebrow")
        sub.setStyleSheet(f"color: {ACCENT}; font-size: 10px; font-weight: 700; padding: 0 6px 20px 6px;")
        sidebar_layout.addWidget(sub)

        labels = dict(NAV_ITEMS)
        wheel_items = [
            (key, labels[key], glyph_icon(key, ICON_COLORS.get(key, ACCENT), 88),
             PAGE_ACCENTS.get(key, ACCENT))
            for key, _label in NAV_ITEMS
        ]
        self.nav_wheel = StaticNavigationMenu(wheel_items, sidebar)
        self.nav_wheel.page_selected.connect(self.switch_page)
        sidebar_layout.addWidget(self.nav_wheel, 1)

        assistant_btn = QPushButton("  افتح المساعد الذكي")
        assistant_btn.setObjectName("assistantNavButton")
        assistant_btn.setProperty("glowColor", ICON_COLORS["chat"])
        assistant_btn.setIcon(glyph_icon("chat", "#34d399", 20))
        assistant_btn.setIconSize(QSize(20, 20))
        assistant_btn.clicked.connect(lambda: self.switch_page("chat"))
        sidebar_layout.addWidget(assistant_btn)

        # Status indicator at bottom of sidebar
        self.sidebar_status = QLabel("[ جاهز ]")
        self.sidebar_status.setStyleSheet(f"color: {STATUS_OK}; font-size: {FONT_SIZE_SMALL}px; padding: 8px 6px;")
        sidebar_layout.addWidget(self.sidebar_status)

        root.addWidget(sidebar)

        # ── Main content area ──
        main_area = QWidget()
        self.aurora_bg = main_area  # compatibility alias; the surface is now static
        self.main_area = main_area
        main_area.setObjectName("mainArea")
        main_layout = QVBoxLayout(main_area)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Header bar ──
        header = QFrame(objectName="headerBar")
        header.setFixedHeight(116)
        header_layout = QGridLayout(header)
        header_layout.setContentsMargins(SP_XL, SP_SM, SP_XL, SP_SM)
        header_layout.setHorizontalSpacing(SP_MD)
        header_layout.setColumnMinimumWidth(0, 260)
        header_layout.setColumnStretch(0, 1)
        header_layout.setColumnStretch(1, 0)
        header_layout.setColumnMinimumWidth(2, 260)
        header_layout.setColumnStretch(2, 1)

        self.page_title = QLabel("غرفة العمليات")
        self.page_title.setObjectName("sectionTitle")
        header_layout.addWidget(self.page_title, 0, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        # Static activity indicator: state changes recolor it, with no pulsing animation.
        self.activity_lamp = QFrame(objectName="activityLamp")
        self.activity_lamp.setFixedSize(8, 8)
        header_status = QHBoxLayout()
        header_status.setSpacing(SP_MD)
        header_status.addWidget(self.activity_lamp, 0, Qt.AlignmentFlag.AlignVCenter)

        self.status_badge = QLabel("جاهز")
        self.status_badge.setObjectName("statusBadge")
        self.status_badge.setProperty("state", "idle")
        header_status.addWidget(self.status_badge)

        self.score_badge = QLabel("الدرجة —")
        self.score_badge.setObjectName("scoreBadge")
        header_status.addWidget(self.score_badge)
        header_layout.addLayout(header_status, 0, 2, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        self.analog_clock = QLabel("AI AYFAM")
        self.analog_clock.setObjectName("headerBrand")
        self.analog_clock.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(self.analog_clock, 0, 1, Qt.AlignmentFlag.AlignCenter)
        self.update_clock()

        main_layout.addWidget(header)
        self.accent_line = AccentLine()
        main_layout.addWidget(self.accent_line)

        # ── Stacked content ──
        self.stack = QStackedWidget()
        self.stack.setContentsMargins(0, 0, 0, 0)

        self.page_dashboard = QWidget()
        self.page_scans = QWidget()
        self.page_findings = FindingsView()
        self.page_timeline = TimelineView()
        self.page_sentinel = SentinelView()
        self.page_attack_graph = AttackChainGraphView()
        self.page_findings.go_to_scans.connect(lambda: self.switch_page("scans"))
        self.page_sentinel.refresh_requested.connect(self.refresh_sentinel_events)
        self.page_usb = QWidget()
        self.page_tools = QWidget()
        self.page_chat = QWidget()
        self.page_library = QWidget()
        self.page_playbooks = QWidget()
        self.page_reports = QWidget()
        self.page_settings = QWidget()

        self.setup_dashboard_page()
        self.setup_scans_page()
        self.setup_usb_page()
        self.setup_tools_page()
        self.setup_chat_page()
        self.setup_playbooks_page()
        self.setup_reports_page()
        self.setup_library_page()
        self.setup_settings_page()

        self.page_widgets_by_key = {
            "dashboard": self.page_dashboard, "scans": self.page_scans,
            "findings": self.page_findings, "timeline": self.page_timeline,
            "sentinel": self.page_sentinel, "attack_graph": self.page_attack_graph,
            "usb": self.page_usb, "tools": self.page_tools, "chat": self.page_chat,
            "library": self.page_library, "playbooks": self.page_playbooks,
            "reports": self.page_reports, "settings": self.page_settings,
        }
        for key, page in self.page_widgets_by_key.items():
            page.setProperty("pageKey", key)
            page.setProperty("pageAccent", PAGE_ACCENTS.get(key, ACCENT))
            page_accent = PAGE_ACCENTS.get(key, ACCENT)
            accent_rgb = QColor(page_accent)
            for table in page.findChildren(QTableWidget):
                table.setProperty("flow", page_accent)
                table.setProperty("pageAccent", page_accent)
                table.setStyleSheet(
                    "QTableWidget::item:selected {"
                    f"background: rgba({accent_rgb.red()}, {accent_rgb.green()}, {accent_rgb.blue()}, 0.20);"
                    "}"
                )

        self.stack.addWidget(self.page_dashboard)
        self.stack.addWidget(self.page_scans)
        self.stack.addWidget(self.page_findings)
        self.stack.addWidget(self.page_timeline)
        self.stack.addWidget(self.page_sentinel)
        self.stack.addWidget(self.page_attack_graph)
        self.stack.addWidget(self.page_usb)
        self.stack.addWidget(self.page_tools)
        self.stack.addWidget(self.page_chat)
        self.stack.addWidget(self.page_library)
        self.stack.addWidget(self.page_playbooks)
        self.stack.addWidget(self.page_reports)
        self.stack.addWidget(self.page_settings)

        # Wrap stack in scroll area for responsiveness
        scroll = QScrollArea()
        scroll.setWidget(self.stack)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        # AmbientSurface paints behind the layout, never occupies a layout slot.
        scroll.viewport().setAutoFillBackground(False)
        self.content_scroll = scroll
        main_layout.addWidget(scroll, 1)

        # ── Dynamic floating status dock ──
        dock = QFrame(objectName="floatingStatusBar")
        dock.setFixedHeight(42)
        dock_layout = QHBoxLayout(dock)
        dock_layout.setContentsMargins(SP_MD, 5, SP_MD, 5)
        dock_layout.setSpacing(SP_SM)
        signal = QLabel("●  الدفاع المباشر أيفام")
        signal.setObjectName("dockSignal")
        dock_layout.addWidget(signal)
        for text in ("معالجة محلية", "حارس USB", "الذكاء الاصطناعي جاهز"):
            item = QLabel(text)
            item.setObjectName("dockItem")
            dock_layout.addWidget(item)
        dock_layout.addStretch()
        self.dock_state = QLabel("النظام جاهز")
        self.dock_state.setObjectName("dockState")
        dock_layout.addWidget(self.dock_state)
        main_layout.addWidget(dock)

        # ── Footer ──
        footer = QLabel(f"  {os.uname().nodename}  |  {APP_VERSION_LABEL}  |  التنفيذ محلي")
        footer.setObjectName("footer")
        footer.setFixedHeight(26)
        main_layout.addWidget(footer)

        root.addWidget(main_area)
        self.setCentralWidget(central)

        # Static logo watermark. The SVG itself contains low-opacity strokes, so
        # no graphics effect or repeated repaint is required.
        self.watermark = QLabel(main_area)
        self.watermark.setObjectName("brandWatermark")
        self.watermark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        watermark_path = ROOT_DIR / "resources" / "brand-watermark.svg"
        if watermark_path.exists():
            self.watermark.setPixmap(QIcon(str(watermark_path)).pixmap(QSize(380, 380)))
        self.watermark.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.watermark.setGeometry(main_area.rect())
        self.watermark.lower()

        # Default page
        self.switch_page("dashboard")

    def _refresh_navigation_wheel(self) -> None:
        """Compatibility hook retained for callers; static navigation needs no refresh."""
        return

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if hasattr(self, "watermark") and hasattr(self, "main_area"):
            self.watermark.setGeometry(self.main_area.rect())
            self.watermark.lower()

    def closeEvent(self, event) -> None:
        for timer in (getattr(self, "timer", None), getattr(self, "event_timer", None)):
            if timer is not None:
                timer.stop()
        # Stop UI animation/refresh timers too while a non-cooperative task
        # finishes; the close handler must never block the GUI thread.
        for timer in self.findChildren(QTimer):
            timer.stop()

        running_workers = [worker for worker in (getattr(self, "worker", None), getattr(self, "telemetry_worker", None))
                           if worker is not None and worker.isRunning()]
        if running_workers:
            if not self._closing_after_workers:
                self._closing_after_workers = True
                for worker in running_workers:
                    worker.finished.connect(self._finish_close_after_workers)
            for worker in running_workers:
                worker.requestInterruption()
                worker.quit()
            self.hide()
            event.ignore()
            # Cover the race where a worker finishes just before its signal is
            # connected, without waiting or terminating a thread unsafely.
            QTimer.singleShot(0, self._finish_close_after_workers)
            return
        super().closeEvent(event)

    def _finish_close_after_workers(self) -> None:
        if not getattr(self, "_closing_after_workers", False):
            return
        running_workers = [
            worker for worker in (getattr(self, "worker", None), getattr(self, "telemetry_worker", None))
            if worker is not None and worker.isRunning()
        ]
        if running_workers:
            return
        self._closing_after_workers = False
        self.close()

    def switch_page(self, key: str) -> None:
        page_map = {
            "dashboard": self.page_dashboard, "scans": self.page_scans,
            "findings": self.page_findings, "timeline": self.page_timeline,
            "sentinel": self.page_sentinel, "attack_graph": self.page_attack_graph,
            "usb": self.page_usb, "tools": self.page_tools,
            "chat": self.page_chat, "library": self.page_library,
            "playbooks": self.page_playbooks, "reports": self.page_reports,
            "settings": self.page_settings,
        }
        title_map = {
            "dashboard": "غرفة العمليات", "scans": "الفحوصات الأمنية",
            "findings": "النتائج الأمنية الموحدة", "timeline": "الخط الزمني للحوادث",
            "sentinel": "الحارس اللحظي", "attack_graph": "سلاسل الهجوم المرتبطة",
            "usb": "الأجهزة المتصلة", "tools": "ترسانة الأدوات المتقدمة",
            "chat": "المحادثة الذكية", "library": "مكتبة المعرفة",
            "playbooks": "خطط العمل الأمنية", "reports": "التقارير",
            "settings": "إعدادات النظام والمفاتيح",
        }
        widget = page_map.get(key)
        if widget:
            changed = self.stack.currentWidget() is not widget
            self.stack.setCurrentWidget(widget)
            if changed:
                self.content_scroll.verticalScrollBar().setValue(0)
            self.page_title.setText(title_map.get(key, ""))
            page_accent = PAGE_ACCENTS.get(key, ACCENT)
            self.page_title.setStyleSheet(f"border-right: 2px solid {page_accent}; padding-right: 8px;")
            self.nav_wheel.set_current(key)
            self.accent_line.set_accent(page_accent)
            for name, page in page_map.items():
                page.setSizePolicy(QSizePolicy.Policy.Preferred if name == key else QSizePolicy.Policy.Ignored,
                                   QSizePolicy.Policy.Preferred if name == key else QSizePolicy.Policy.Ignored)
            self.stack.updateGeometry()
            self._current_nav = key
            if key == "usb" and not self.usb_inventory_loaded:
                self.refresh_usb_inventory()
            elif key == "findings":
                self.page_findings.set_findings(self.all_findings)
            elif key == "timeline":
                self.refresh_timeline()
            elif key == "sentinel":
                self.refresh_sentinel_events()
            elif key == "attack_graph":
                self.refresh_attack_graph()

    def _run_page_transition(self) -> None:
        """Compatibility hook: page navigation is an immediate native Qt switch."""
        return

    def _get_event_store(self):
        """Open the local event database only when an event-history view is requested."""
        if self._event_store is None:
            from engine.events import EventStore
            self._event_store = EventStore()
        return self._event_store

    def refresh_timeline(self) -> None:
        try:
            from engine.finding import Finding
            from engine.timeline import IncidentTimeline

            findings = [Finding.from_dict(item) for item in self.all_findings if isinstance(item, dict)]
            timeline = IncidentTimeline(self._get_event_store()).build_timeline(findings, limit=100)
            self.page_timeline.set_events(timeline)
        except Exception as exc:
            self.page_timeline.set_error(str(exc))

    def refresh_sentinel_events(self) -> None:
        try:
            events = self._get_event_store().query_recent_events(limit=100)
            # This view is intentionally passive; opening it does not start a filesystem watcher.
            self.page_sentinel.set_events(events, monitoring=False)
        except Exception:
            self.page_sentinel.set_events([])
            self.page_sentinel.monitor_status.setText("تعذر تحميل السجل / History unavailable")

    def refresh_attack_graph(self) -> None:
        try:
            from engine.finding import Finding

            chains = [
                item for item in self.all_findings
                if isinstance(item, dict)
                and (item.get("category") == "attack_chain" or "attack_chain" in (item.get("tags") or []))
            ]
            if not chains:
                source = [
                    Finding.from_dict(item) for item in self.all_findings
                    if isinstance(item, dict)
                    and item.get("category") != "attack_chain"
                    and "attack_chain" not in (item.get("tags") or [])
                ]
                chains = self.agent.correlation.analyze(source)
            self.page_attack_graph.render_chain(chains, self.all_findings)
        except Exception:
            self.page_attack_graph.render_chain([], self.all_findings)

    def _sync_control_labels(self) -> None:
        if hasattr(self, "setting_sound_ux"):
            self.setting_sound_ux.setText("أصوات التفاعل متوقفة في وضع توفير الموارد")
            self.setting_sound_ux.setChecked(False)

    def _toggle_sound(self, enabled: bool) -> None:
        # Sound feedback is intentionally disabled in the low-resource profile.
        self.settings.set("sound_ux", False)
        self._sync_control_labels()

    def _toggle_dark_mode(self, enabled: bool) -> None:
        self.settings.set("dark_mode", bool(enabled))
        self.setStyleSheet(QSS if enabled else get_qss("#6d8f8c", "#7d83a6"))
        self.setProperty("darkMode", bool(enabled))
        self.style().unpolish(self)
        self.style().polish(self)
        self._sync_control_labels()
        self.update()

    # ═══════════════════════════════════════════════════════════════════════════
    #  DASHBOARD PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def setup_dashboard_page(self) -> None:
        layout = QVBoxLayout(self.page_dashboard)
        layout.setContentsMargins(SP_XL, SP_LG, SP_XL, SP_LG)
        layout.setSpacing(SP_LG)

        # Mission brief: orient the operator before showing telemetry.
        mission = QFrame(objectName="missionBanner")
        mission_layout = QHBoxLayout(mission)
        mission_layout.setContentsMargins(SP_XL, SP_MD, SP_XL, SP_MD)
        mission_layout.setSpacing(SP_LG)
        mission_copy = QVBoxLayout()
        mission_copy.setSpacing(SP_XS)
        self.mission_kicker = QLabel("حالة الدفاع التكتيكية  •  بانتظار الفحص الأول")
        self.mission_kicker.setObjectName("eyebrow")
        mission_copy.addWidget(self.mission_kicker)
        mission_title = QLabel("مركز المراقبة والتحكم الأمني المتقدم")
        mission_title.setObjectName("missionTitle")
        mission_copy.addWidget(mission_title)
        mission_sub = QLabel("رصد مباشر للشبكة والعمليات • حماية الوسائط المتصلة USB Sentry • استجابة ذكية للتهديدات")
        mission_sub.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
        mission_copy.addWidget(mission_sub)
        mission_layout.addLayout(mission_copy, 1)

        mission_actions = QHBoxLayout()
        mission_actions.setSpacing(SP_SM)
        quick_scan = QPushButton("بدء فحص شامل")
        quick_scan.setObjectName("primary")
        quick_scan.setIcon(glyph_icon("scans", "#ffffff", 18))
        quick_scan.clicked.connect(lambda: self.run_background_task(self.agent._full_scan, "الفحص الشامل"))
        mission_actions.addWidget(quick_scan)
        mission_layout.addLayout(mission_actions)
        layout.addWidget(mission)

        # ── Metric Cards Row ──
        metrics = QGridLayout()
        metrics.setHorizontalSpacing(SP_MD)
        metrics.setVerticalSpacing(SP_MD)
        self.metric_labels: dict[str, QLabel] = {}
        self.metric_tags: dict[str, QLabel] = {}
        metric_data = [
            ("connections", "اتصالات الشبكة", "مقابس الشبكة النشطة والمراقبة", SEV_LOW, "مباشر"),
            ("processes", "العمليات الحية", "أعلى العمليات استهلاكاً للموارد", CARD_ACCENTS["processes"], "نشط"),
            ("findings", "الثغرات المكتشفة", "في آخر فحص مكتمل للمنظومة", SEV_MEDIUM, "لم يُفحص"),
            ("score", "الجاهزية الأمنية", "مؤشر تقييم خطوط الدفاع العام", SEV_SAFE, "غير مقيّم"),
        ]
        for col, (key, label, note, accent, initial_tag) in enumerate(metric_data):
            card = QFrame(objectName="card")
            card.setMinimumHeight(104)
            card.setStyleSheet(f"QFrame#card {{ border: 1px solid {alpha(accent, 140)}; }}")
            box = QVBoxLayout(card)
            box.setContentsMargins(SP_LG, SP_MD, SP_LG, SP_MD)
            box.setSpacing(SP_XS)

            header_row = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setObjectName("metricLabel")
            header_row.addWidget(lbl)
            header_row.addStretch()

            tag = QLabel(initial_tag)
            tag.setStyleSheet(f"""
                color: {accent};
                background: {alpha(accent, 25)};
                border: 1px solid {alpha(accent, 80)};
                border-radius: 8px;
                padding: 2px 6px;
                font-size: 10px;
                font-weight: 700;
            """)
            header_row.addWidget(tag)
            box.addLayout(header_row)

            val = QLabel("—")
            val.setObjectName("metricValue")
            val.setStyleSheet(f"color: {accent};")
            box.addWidget(val)

            nt = QLabel(note)
            nt.setObjectName("metricNote")
            box.addWidget(nt)

            self.metric_labels[key] = val
            self.metric_tags[key] = tag
            metrics.addWidget(card, 0, col)
            metrics.setColumnStretch(col, 1)
        layout.addLayout(metrics)

        # ── Interactive analytics ──
        analytics_row = QHBoxLayout()
        analytics_row.setSpacing(SP_MD)
        self.telemetry_chart = TelemetryChart("مؤشرات الحالة الأمنية")
        self.telemetry_chart.set_data({
            label: (values, "#2dd4bf" if index == 0 else "#a78bfa")
            for index, (label, values) in enumerate(self._telemetry_history.items())
        })
        self.security_gauge = SecurityGauge()
        self.security_gauge.set_pending()
        analytics_row.addWidget(self.telemetry_chart, 3)
        analytics_row.addWidget(self.security_gauge, 1)
        layout.addLayout(analytics_row)

        # ── Live Data Splitter ──
        self.dashboard_splitter = QSplitter(Qt.Orientation.Vertical)
        self.dashboard_splitter.setChildrenCollapsible(False)
        self.dashboard_splitter.setHandleWidth(2)

        # Connections panel
        conn_group = QGroupBox("رادار الاتصالات الحية")
        conn_layout = QVBoxLayout(conn_group)
        conn_layout.setSpacing(SP_SM)
        self.connection_summary = QLabel("جارٍ قراءة حالة الشبكة...")
        self.connection_summary.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px;")
        conn_layout.addWidget(self.connection_summary)
        self.table_conns = QTableWidget(0, 7)
        self.table_conns.setHorizontalHeaderLabels(["البروتوكول", "الحالة", "النطاق", "المحلي", "البعيد", "العملية", "PID"])
        conn_header = self.table_conns.horizontalHeader()
        conn_header.setMinimumSectionSize(76)
        conn_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        conn_header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        conn_header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        conn_header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        prepare_table(self.table_conns)
        for col in (0, 1, 2):
            self.table_conns.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.table_conns.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.table_conns.setMinimumHeight(220)
        conn_layout.addWidget(self.table_conns)
        conn_group.setMinimumHeight(278)
        self.dashboard_splitter.addWidget(conn_group)

        # Processes panel
        proc_group = QGroupBox("أعلى العمليات استهلاكاً")
        proc_layout = QVBoxLayout(proc_group)
        self.table_procs = QTableWidget(0, 5)
        self.table_procs.setHorizontalHeaderLabels(["المستخدم", "PID", "CPU", "RAM", "الأمر"])
        # Command column: fixed relative width so long commands get ellipsized by Qt
        self.table_procs.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table_procs.horizontalHeader().setStretchLastSection(True)
        prepare_table(self.table_procs)
        self.table_procs.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self.table_procs.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_procs.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        for col in (2, 3):
            self.table_procs.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.table_procs.horizontalHeader().setMinimumSectionSize(76)
        self.table_procs.setMinimumHeight(220)
        proc_layout.addWidget(self.table_procs)
        proc_group.setMinimumHeight(278)
        self.dashboard_splitter.addWidget(proc_group)

        self.dashboard_splitter.setStretchFactor(0, 3)
        self.dashboard_splitter.setStretchFactor(1, 2)
        self.dashboard_splitter.setSizes([300, 280])
        self.dashboard_splitter.setMinimumHeight(570)
        layout.addWidget(self.dashboard_splitter, 1)

    # ═══════════════════════════════════════════════════════════════════════════
    #  SCANS PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def setup_scans_page(self) -> None:
        layout = QVBoxLayout(self.page_scans)
        layout.setContentsMargins(SP_XL, SP_LG, SP_XL, SP_LG)
        layout.setSpacing(SP_LG)

        self.scan_tabs = QTabWidget()
        scan_accent = PAGE_ACCENTS["scans"]
        self.scan_tabs.setStyleSheet(f"""
            QTabBar::tab:selected {{
                color: {scan_accent};
                border-color: rgba(103, 183, 255, 0.42);
                background: rgba(103, 183, 255, 0.10);
            }}
        """)

        # Tab 1: Scan Execution
        tab_exec = QWidget()
        l_exec = QVBoxLayout(tab_exec)
        l_exec.setSpacing(SP_MD)

        form = QGroupBox("تهيئة وإطلاق الفحص")
        grid = QGridLayout(form)
        grid.setSpacing(SP_MD)
        self.scan_target = QLineEdit("127.0.0.1")
        self.scan_target.setAccessibleName("هدف فحص المنافذ")
        self.scan_target.setPlaceholderText("IP أو اسم المضيف")
        self.port_range = QLineEdit("1-1024")
        self.port_range.setAccessibleName("نطاق المنافذ")
        self.port_range.setPlaceholderText("مثال: 22,80,443 أو 1-1024")
        self.ip_target = QLineEdit()
        self.ip_target.setPlaceholderText("عنوان IP عام")
        self.website_input = QLineEdit()
        self.website_input.setPlaceholderText("https://example.com")
        self.path_input = QLineEdit(os.path.expanduser("~/Downloads"))
        self.path_input.setAccessibleName("مسار فحص YARA")
        self.path_input.setPlaceholderText("مسار الفحص (افتراضي: ~/Downloads)")

        yara_path_box = QHBoxLayout()
        yara_path_box.setSpacing(SP_SM)
        yara_path_box.addWidget(self.path_input, 1)
        btn_browse_yara = QPushButton("تصفّح")
        btn_browse_yara.setToolTip("اختيار المجلد المطلوب فحصه بقواعد YARA")
        btn_browse_yara.clicked.connect(self._browse_yara_path)
        yara_path_box.addWidget(btn_browse_yara)

        grid.addWidget(QLabel("هدف المنافذ:"), 0, 0)
        grid.addWidget(self.scan_target, 0, 1)
        grid.addWidget(QLabel("نطاق المنافذ:"), 0, 2)
        grid.addWidget(self.port_range, 0, 3)
        grid.addWidget(QLabel("سمعة IP:"), 1, 0)
        grid.addWidget(self.ip_target, 1, 1, 1, 3)
        grid.addWidget(QLabel("فحص موقع:"), 2, 0)
        grid.addWidget(self.website_input, 2, 1, 1, 3)
        grid.addWidget(QLabel("مسار YARA:"), 3, 0)
        grid.addLayout(yara_path_box, 3, 1, 1, 3)

        buttons = [
            ("فحص الشبكة", "primary", lambda: self.run_background_task(lambda: self.agent._scan_network(), "فحص الشبكة")),
            ("فحص المنافذ", "primary", self.start_port_scan),
            ("فحص النظام", "primary", lambda: self.run_background_task(self.agent._scan_system, "فحص النظام")),
            ("تحليل السجلات", "primary", lambda: self.run_background_task(self.agent._scan_logs, "تحليل السجلات")),
            ("الفحص الشامل", "primary", lambda: self.run_background_task(self.agent._full_scan, "الفحص الشامل")),
            ("فحص موقع", "", self.start_website_scan),
            ("سمعة IP", "", self.start_ip_reputation),
        ]
        button_grid = QGridLayout()
        button_grid.setHorizontalSpacing(SP_MD)
        button_grid.setVerticalSpacing(SP_MD)
        for column in range(4):
            button_grid.setColumnStretch(column, 1)
        grid.addLayout(button_grid, 4, 0, 1, 4)
        grid.setColumnMinimumWidth(0, 96)
        grid.setColumnMinimumWidth(2, 96)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)
        for i, (text, btn_style, callback) in enumerate(buttons):
            btn = QPushButton(text)
            btn.setMinimumHeight(40)
            if btn_style:
                btn.setObjectName(btn_style)
            btn.setToolTip(f"تشغيل: {text}")
            btn.clicked.connect(callback)
            self.task_buttons.append(btn)
            button_grid.addWidget(btn, i // 4, i % 4)
        l_exec.addWidget(form)

        # Progress
        self.scan_progress = QProgressBar()
        self.scan_progress.setTextVisible(False)
        self.scan_progress.setRange(0, 0)
        self.scan_progress.hide()
        l_exec.addWidget(self.scan_progress)

        self.scan_hint = QLabel("اختر نوع الفحص المناسب من الأزرار أعلاه.")
        self.scan_hint.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px;")
        l_exec.addWidget(self.scan_hint)
        self.scan_tabs.addTab(tab_exec, "تشغيل الفحوصات")

        # Tab 2: Findings
        tab_results = QWidget()
        l_results = QVBoxLayout(tab_results)
        self.setup_findings_table(l_results)
        self.scan_tabs.addTab(tab_results, "سجل نتائج الفحص")

        layout.addWidget(self.scan_tabs, 1)

    def setup_findings_table(self, layout: QVBoxLayout) -> None:
        group = QGroupBox("نتائج الفحص الأخيرة")
        box = QVBoxLayout(group)
        box.setSpacing(SP_SM)

        top = QHBoxLayout()
        top.setSpacing(SP_SM)
        self.findings_chips = QLabel("لم يُجرَ فحص بعد.")
        self.findings_chips.setTextFormat(Qt.TextFormat.RichText)
        self.findings_chips.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px;")
        top.addWidget(self.findings_chips, 1)
        filter_label = QLabel("عرض:")
        filter_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px;")
        self.sev_filter = QComboBox()
        self.sev_filter.addItem("كل النتائج", "all")
        for key in SEV_ORDER:
            self.sev_filter.addItem(SEV_AR[key], key)
        self.sev_filter.setToolTip("تصفية النتائج حسب الخطورة")
        self.sev_filter.currentIndexChanged.connect(lambda _i: self._apply_findings_filter())
        top.addWidget(filter_label)
        top.addWidget(self.sev_filter)
        box.addLayout(top)

        self.table_findings = QTableWidget(0, 4)
        self.table_findings.setHorizontalHeaderLabels(["الخطورة", "النتيجة", "الفئة", "الثقة"])
        header = self.table_findings.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        prepare_table(self.table_findings, 40)
        self.table_findings.setProperty("flow", "orange")
        self.table_findings.currentCellChanged.connect(lambda row, col, _pr, _pc: self.show_finding_details(row, col))
        self.table_findings.setMinimumHeight(220)

        detail_header = QHBoxLayout()
        detail_label = QLabel("تحليل النتيجة المحددة")
        detail_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-weight: 600; font-size: {FONT_SIZE_SMALL}px;")
        detail_header.addWidget(detail_label)
        self.finding_position = QLabel("")
        self.finding_position.setStyleSheet(f"color: {TEXT_MUTED}; font-size: {FONT_SIZE_SMALL}px;")
        detail_header.addWidget(self.finding_position)
        detail_header.addStretch()
        self.btn_prev_finding = QPushButton("السابقة")
        self.btn_next_finding = QPushButton("التالية")
        self.btn_prev_finding.setToolTip("النتيجة السابقة (Alt+Up)")
        self.btn_next_finding.setToolTip("النتيجة التالية (Alt+Down)")
        self.btn_prev_finding.clicked.connect(lambda: self.step_finding(-1))
        self.btn_next_finding.clicked.connect(lambda: self.step_finding(1))
        QShortcut(QKeySequence("Alt+Up"), self, activated=lambda: self.step_finding(-1))
        QShortcut(QKeySequence("Alt+Down"), self, activated=lambda: self.step_finding(1))
        detail_header.addWidget(self.btn_prev_finding)
        detail_header.addWidget(self.btn_next_finding)

        self.btn_apply_autofix = QPushButton("تطبيق الإصلاح التلقائي")
        self.btn_apply_autofix.setObjectName("primary")
        self.btn_apply_autofix.setToolTip("تطبيق أمر الإصلاح للنتيجة المحددة إن وجد")
        self.btn_apply_autofix.clicked.connect(self.apply_selected_finding_fix)
        detail_header.addWidget(self.btn_apply_autofix)

        self.finding_detail = QTextEdit(readOnly=True)
        self.finding_detail.setPlaceholderText("حدد نتيجة لعرض ما المشكلة ولماذا تهم وكيف تُصلح.")
        self.finding_detail.setMinimumHeight(170)

        findings_splitter = QSplitter(Qt.Orientation.Vertical)
        findings_splitter.setHandleWidth(2)
        findings_splitter.addWidget(self.table_findings)
        detail_panel = QWidget()
        dl = QVBoxLayout(detail_panel)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.setSpacing(SP_XS)
        dl.addLayout(detail_header)
        dl.addWidget(self.finding_detail)
        findings_splitter.addWidget(detail_panel)
        findings_splitter.setStretchFactor(0, 3)
        findings_splitter.setStretchFactor(1, 2)
        findings_splitter.setMinimumHeight(520)
        box.addWidget(findings_splitter)
        layout.addWidget(group)

    def step_finding(self, delta: int) -> None:
        count = self.table_findings.rowCount()
        if not count:
            return
        row = max(0, min(count - 1, (self.table_findings.currentRow() if self.table_findings.currentRow() >= 0 else (-1 if delta > 0 else count)) + delta))
        self.table_findings.selectRow(row)
        self.table_findings.setCurrentCell(row, 0)

    def apply_selected_finding_fix(self) -> None:
        row = self.table_findings.currentRow()
        if row < 0 or row >= len(self.current_findings):
            QMessageBox.information(self, "اختر نتيجة", "حدد نتيجة من القائمة لتطبيق إصلاحها.")
            return
        finding = self.current_findings[row]
        fix_cmd = finding.get("fix", "")
        title = finding.get("title", "النتيجة المحددة")
        if not fix_cmd:
            QMessageBox.information(self, "لا يوجد إصلاح", f"لا يتوفر أمر إصلاح تلقائي مسجل لـ «{title}».")
            return

        answer = QMessageBox.question(
            self, "تأكيد الإصلاح", f"هل تريد تنفيذ الإصلاح التالي؟\n\n{fix_cmd}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        def run_fix():
            from tools.fix import apply_fix, list_available_fixes
            fix_id = finding.get("fix_id", "")
            if fix_id not in list_available_fixes():
                return {
                    "success": False,
                    "error": "هذا الإصلاح نص إرشادي فقط؛ لا يوجد fix_id مسجل وآمن لتنفيذه من الواجهة.",
                    "manual_review": fix_cmd,
                }
            kwargs = finding.get("fix_args", {})
            if not isinstance(kwargs, dict):
                return {"success": False, "error": "معاملات الإصلاح غير صالحة."}
            return apply_fix(fix_id, **kwargs)

        self.run_background_task(
            run_fix,
            f"إصلاح: {title}",
            preserve_findings=True,
            result_handler=lambda res: QMessageBox.information(
                self, "نتيجة الإصلاح", f"تم تنفيذ الإصلاح:\n{json.dumps(res, ensure_ascii=False, indent=2)}"
            )
        )

    # ═══════════════════════════════════════════════════════════════════════════
    #  USB PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def setup_usb_page(self) -> None:
        layout = QVBoxLayout(self.page_usb)
        layout.setContentsMargins(SP_XL, SP_LG, SP_XL, SP_LG)
        layout.setSpacing(SP_LG)

        heading = QHBoxLayout()
        self.usb_status = QLabel("لم يتم تحديث قائمة الأجهزة بعد")
        self.usb_status.setStyleSheet(f"color: {TEXT_SECONDARY}; font-weight: 600;")
        heading.addWidget(self.usb_status)
        heading.addStretch()
        self.usb_refresh_button = QPushButton("تحديث")
        self.usb_refresh_button.setObjectName("primary")
        self.usb_refresh_button.clicked.connect(self.refresh_usb_inventory)
        self.task_buttons.append(self.usb_refresh_button)
        heading.addWidget(self.usb_refresh_button)
        layout.addLayout(heading)

        # Tabbed structure for USB
        usb_tabs = QTabWidget()

        # Tab 1: Devices
        tab_devices = QWidget()
        l_devices = QVBoxLayout(tab_devices)
        devices_group = QGroupBox("الأجهزة المتصلة بالنظام")
        devices_layout = QVBoxLayout(devices_group)
        self.usb_devices_table = QTableWidget(0, 5)
        self.usb_devices_table.setHorizontalHeaderLabels(["Bus/Device", "المنتج", "الفئة", "VID:PID", "المخاطر"])
        self.usb_devices_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.usb_devices_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.usb_devices_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.usb_devices_table.setAlternatingRowColors(True)
        self.usb_devices_table.verticalHeader().setVisible(False)
        self.usb_devices_table.verticalHeader().setDefaultSectionSize(32)
        self.usb_devices_table.cellClicked.connect(self.show_usb_device_details)
        self.usb_devices_table.itemSelectionChanged.connect(self._capture_usb_device_selection)
        devices_layout.addWidget(self.usb_devices_table)
        l_devices.addWidget(devices_group)

        device_actions = QHBoxLayout()
        device_actions.setSpacing(SP_SM)
        self.usb_allow_button = QPushButton("السماح بالجهاز")
        self.usb_allow_button.clicked.connect(lambda: self.control_selected_usb_device(True))
        self.usb_block_button = QPushButton("حجب الجهاز")
        self.usb_block_button.setObjectName("danger")
        self.usb_block_button.clicked.connect(lambda: self.control_selected_usb_device(False))
        for button in (self.usb_allow_button, self.usb_block_button):
            self.task_buttons.append(button)
            device_actions.addWidget(button)
        device_actions.addStretch()
        l_devices.addLayout(device_actions)

        # Tab 2: Drives & Storage Analysis
        tab_drives = QWidget()
        l_drives = QVBoxLayout(tab_drives)
        drives_group = QGroupBox("وحدات التخزين وتحليلها")
        drives_layout = QVBoxLayout(drives_group)
        self.usb_drives_table = QTableWidget(0, 4)
        self.usb_drives_table.setHorizontalHeaderLabels(["الجهاز", "الطراز", "الحجم", "نقطة التوصيل"])
        self.usb_drives_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.usb_drives_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.usb_drives_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.usb_drives_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.usb_drives_table.setAlternatingRowColors(True)
        self.usb_drives_table.verticalHeader().setVisible(False)
        self.usb_drives_table.verticalHeader().setDefaultSectionSize(32)
        self.usb_drives_table.cellClicked.connect(self.show_usb_drive_details)
        self.usb_drives_table.itemSelectionChanged.connect(self._capture_usb_partition_selection)
        drives_layout.addWidget(self.usb_drives_table)

        drive_actions = QHBoxLayout()
        drive_actions.setSpacing(SP_SM)
        self.usb_scan_button = QPushButton("تحليل التخزين")
        self.usb_scan_button.setObjectName("primary")
        self.usb_scan_button.clicked.connect(self.scan_selected_usb_storage)
        self.usb_deep_scan_button = QPushButton("فحص عميق")
        self.usb_deep_scan_button.setObjectName("primary")
        self.usb_deep_scan_button.setToolTip("فحص الملفات والـ Autorun والأنماط الخبيثة وClamAV إن كان متوفراً")
        self.usb_deep_scan_button.clicked.connect(self.deep_scan_selected_usb_storage)
        self.usb_fix_button = QPushButton("إصلاح المحدد")
        self.usb_fix_button.setObjectName("danger")
        self.usb_fix_button.setToolTip("حذف Autorun والملفات ذات السلوك الخبيث المؤكد فقط بعد التأكيد")
        self.usb_fix_button.clicked.connect(self.fix_selected_usb_storage)
        self.usb_eject_button = QPushButton("إخراج آمن")
        self.usb_eject_button.setToolTip("فصل وحدة التخزين وإيقاف طاقتها بأمان")
        self.usb_eject_button.clicked.connect(self.eject_selected_usb_storage)
        for button in (
            self.usb_scan_button, self.usb_deep_scan_button,
            self.usb_fix_button, self.usb_eject_button,
        ):
            self.task_buttons.append(button)
            drive_actions.addWidget(button)
        drives_layout.addLayout(drive_actions)

        self.usb_detail = QPlainTextEdit(readOnly=True)
        self.usb_detail.setPlaceholderText("حدد جهازاً أو وحدة تخزين لعرض التفاصيل والمخاطر.")
        self.usb_detail.setMaximumHeight(140)
        drives_layout.addWidget(self.usb_detail)
        l_drives.addWidget(drives_group)

        usb_tabs.addTab(tab_devices, "الأجهزة والتحكم")
        usb_tabs.addTab(tab_drives, "وحدات التخزين والتحليل")
        layout.addWidget(usb_tabs, 1)

    # ═══════════════════════════════════════════════════════════════════════════
    #  TOOLS PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def setup_tools_page(self) -> None:
        layout = QVBoxLayout(self.page_tools)
        layout.setContentsMargins(SP_XL, SP_LG, SP_XL, SP_LG)
        layout.setSpacing(SP_MD)

        path_row = QHBoxLayout()
        path_row.addWidget(QLabel("مسار الفحص للأدوات:"))
        self.tool_path = QLineEdit(os.path.expanduser("~/Downloads"))
        self.tool_path.setPlaceholderText("مسار الفحص (افتراضي: ~/Downloads)")
        btn_browse_tool_path = QPushButton("تصفّح")
        btn_browse_tool_path.clicked.connect(self._browse_tool_path)
        path_row.addWidget(self.tool_path)
        path_row.addWidget(btn_browse_tool_path)
        layout.addLayout(path_row)

        tools_tabs = QTabWidget()

        # 1. Audit & Hardening Tab
        tab_audit = QWidget()
        l_audit = QVBoxLayout(tab_audit)
        audit_btns = [
            ("فحص CIS Hardening", lambda: self._run_tool_and_display(self.agent._run_deep_audit, "فحص CIS Hardening"), "فحص إعدادات التحصين وفق معايير CIS. يستغرق نحو دقيقة • يتطلب صلاحيات root", True),
            ("فحص Lynis Audit", lambda: self._run_tool_and_display(self.agent._run_lynis_cli, "فحص Lynis"), "تدقيق أمني شامل لمنظومة النظام عبر Lynis. يستغرق 1-2 دقيقة • يتطلب صلاحيات root", True),
            ("تعلّم خط الأساس", lambda: self._run_tool_and_display(self.agent._run_baseline_learn_cli, "تعلّم خط الأساس"), "حفظ الحالة الطبيعية للعمليات والخدمات والمنافذ الحالية. يستغرق بضع ثوانٍ", False),
            ("فحص شذوذ النظام", lambda: self._run_tool_and_display(self.agent._run_baseline_check_cli, "فحص الشذوذ"), "مقارنة حالة النظام الحالية مع خط الأساس المحفوظ لكشف أي تغيير غريب. يستغرق بضع ثوانٍ", False),
            ("خطة المعالجة", lambda: self._run_tool_and_display(self.agent._generate_remediation_plan, "خطة المعالجة"), "توليد خطة خطوة بخطوة لمعالجة الثغرات المكتشفة مؤخراً. يستغرق بضع ثوانٍ", False),
        ]
        grid_audit = QGridLayout()
        grid_audit.setSpacing(SP_SM)
        for idx, (name, fn, tip, needs_root) in enumerate(audit_btns):
            btn = QPushButton(name + (" 🔒" if needs_root else ""))
            btn.setMinimumHeight(38)
            btn.setToolTip(tip)
            btn.clicked.connect(fn)
            self.task_buttons.append(btn)
            grid_audit.addWidget(btn, idx // 2, idx % 2)
        l_audit.addLayout(grid_audit)
        tools_tabs.addTab(tab_audit, "التدقيق والتحصين")

        # 2. Scanning & Malware Tab
        tab_scan = QWidget()
        l_scan = QVBoxLayout(tab_scan)
        scan_btns = [
            ("فحص YARA", lambda: self._run_tool_and_display(lambda: self.agent._run_yara_cli(self.tool_path.text().strip() or "."), "فحص YARA"), "فحص المسار المحدد بقواعد YARA لكشف الملفات الخبيثة. يستغرق 10-30 ثانية", False),
            ("كشف الأسرار", lambda: self._run_tool_and_display(lambda: self.agent._scan_secrets_cli(self.tool_path.text().strip() or "."), "كشف الأسرار"), "البحث عن المفاتيح وكلمات المرور والأسرار المسربة في المسار المحدد. يستغرق 5-15 ثانية", False),
            ("فحص Rootkit", lambda: self._run_tool_and_display(self.agent._run_rootkit_cli, "فحص Rootkit"), "فحص نواة النظام للكشف عن أدوات الإخفاء برمجيات Rootkit. يستغرق نحو دقيقة • يتطلب صلاحيات root", True),
            ("توليد قواعد التفاعل", lambda: self._run_tool_and_display(self.agent._run_synthesize_rules_cli, "توليد قواعد"), "إنشاء قواعد YARA وSuricata تلقائياً من نتائج التحليل المتاحة. يستغرق بضع ثوانٍ", False),
        ]
        grid_scan = QGridLayout()
        grid_scan.setSpacing(SP_SM)
        for idx, (name, fn, tip, needs_root) in enumerate(scan_btns):
            btn = QPushButton(name + (" 🔒" if needs_root else ""))
            btn.setMinimumHeight(38)
            btn.setToolTip(tip)
            btn.clicked.connect(fn)
            self.task_buttons.append(btn)
            grid_scan.addWidget(btn, idx // 2, idx % 2)
        l_scan.addLayout(grid_scan)
        tools_tabs.addTab(tab_scan, "كشف التهديدات والأسرار")

        # 3. Threat Intel & CTI Tab
        tab_intel = QWidget()
        l_intel = QVBoxLayout(tab_intel)
        intel_btns = [
            ("تحديث التهديدات (KEV/Exploit-DB)", lambda: self._run_tool_and_display(self.agent._update_intel, "تحديث التهديدات"), "تحديث قاعدة بيانات الثغرات المستغلة من CISA KEV وExploit-DB. يستغرق 10-20 ثانية", False),
            ("Gemini CTI (48h)", lambda: self._run_tool_and_display(lambda: self.agent.run_gemini_threat_scan(48), "Gemini CTI"), "استعلام الذكاء الاصطناعي عن أحدث التهديدات المستجدة في آخر 48 ساعة. يستغرق 10-20 ثانية", False),
            ("تصدير تقرير HTML", lambda: self._run_tool_and_display(self.agent._export_html_report, "تصدير HTML"), "تصدير تقرير أمني شامل بصيغة HTML مفصلة إلى مجلد التقارير. يستغرق بضع ثوانٍ", False),
        ]
        grid_intel = QGridLayout()
        grid_intel.setSpacing(SP_SM)
        for idx, (name, fn, tip, needs_root) in enumerate(intel_btns):
            btn = QPushButton(name + (" 🔒" if needs_root else ""))
            btn.setMinimumHeight(38)
            if "Gemini" in name:
                btn.setObjectName("primary")
            btn.setToolTip(tip)
            btn.clicked.connect(fn)
            self.task_buttons.append(btn)
            grid_intel.addWidget(btn, idx // 2, idx % 2)
        l_intel.addLayout(grid_intel)
        tools_tabs.addTab(tab_intel, "استخبارات التهديدات CTI")

        layout.addWidget(tools_tabs)

        # Output viewer pane directly on Tools page
        out_box = QGroupBox("نتائج تشغيل الأدوات والمخرجات المباشرة")
        out_layout = QVBoxLayout(out_box)
        self.tool_output = QPlainTextEdit(readOnly=True)
        self.tool_output.setPlaceholderText("اختر أداة تشغيل من التبويبات أعلاه لعرض نتائجها هنا مباشرة...")
        self.tool_output.setMinimumHeight(180)
        out_layout.addWidget(self.tool_output)
        layout.addWidget(out_box, 1)

    def _browse_tool_path(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "اختر مسار الفحص", self.tool_path.text())
        if path:
            self.tool_path.setText(path)

    def _run_tool_and_display(self, fn: Callable[[], Any], title: str) -> None:
        self.tool_output.setPlainText(f"[تشغيل] جارٍ تشغيل {title}...\n")
        def handler(res: Any):
            if isinstance(res, (dict, list)):
                rendered = json.dumps(res, ensure_ascii=False, indent=2, default=str)
            else:
                rendered = str(res)
            self.tool_output.setPlainText(f"[نجاح] اكتمل تشغيل {title}:\n\n{rendered}")
        self.run_background_task(fn, title, preserve_findings=False, result_handler=handler)

    # ═══════════════════════════════════════════════════════════════════════════
    #  CHAT PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def setup_chat_page(self) -> None:
        layout = QVBoxLayout(self.page_chat)
        layout.setContentsMargins(SP_XL, SP_LG, SP_XL, SP_LG)
        layout.setSpacing(SP_MD)

        intro = QLabel("محادثة أمنية — اكتب بالعربية أو الإنجليزية وسيفهمك الوكيل")
        intro.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px;")
        layout.addWidget(intro)

        self.chat_display = ChatView()
        self.chat_display.setPlaceholderText("ستظهر هنا حالة المهام والنتائج...")
        self.chat_display.append("[النظام] مرحباً. اختر فحصاً من تبويب الفحوصات أو اكتب أمراً هنا.")
        layout.addWidget(self.chat_display, 1)

        composer = QFrame(objectName="chatComposer")
        row = QHBoxLayout(composer)
        row.setContentsMargins(10, 8, 10, 8)
        row.setSpacing(SP_SM)
        self.chat_input = QLineEdit()
        self.chat_input.setAccessibleName("رسالة المساعد الأمني")
        self.chat_input.setPlaceholderText("اكتب رسالتك هنا… اضغط Enter للإرسال")
        self.chat_input.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self.chat_input.setMinimumHeight(30)
        self.chat_input.setStyleSheet("QLineEdit { background: transparent; border: none; }")
        self.chat_input.setClearButtonEnabled(True)
        self.chat_input.returnPressed.connect(self.send_chat_message)
        send = QPushButton("إرسال")
        send.setObjectName("primary")
        send.clicked.connect(self.send_chat_message)
        send.setIcon(glyph_icon("send", "#edf5fb", 16))
        row.addWidget(self.chat_input, 1)
        row.addWidget(send)
        layout.addWidget(composer)

        # Quick action prompts
        pills_layout = QHBoxLayout()
        pills_layout.setSpacing(SP_SM)
        quick_prompts = [
            ("فحص النظام", "فحص النظام"),
            ("فحص الشبكة", "فحص الشبكة"),
            ("تأمين SSH", "كيف أؤمن خدمة SSH؟"),
            ("فحص أجهزة USB", "فحص أجهزة USB"),
            ("جدار الحماية UFW", "فحص جدار الحماية"),
            ("ثغرات CTI الحديثة", "ما هي أحدث ثغرات CTI؟"),
        ]
        for pill_label, prompt_text in quick_prompts:
            pill_btn = QPushButton(pill_label)
            pill_btn.setObjectName("pillButton")
            pill_btn.clicked.connect(lambda checked=False, p=prompt_text: self._trigger_quick_chat(p))
            pills_layout.addWidget(pill_btn)
        pills_layout.addStretch()
        layout.addLayout(pills_layout)

    def _trigger_quick_chat(self, text: str) -> None:
        self.chat_input.setText(text)
        self.send_chat_message()

    # ═══════════════════════════════════════════════════════════════════════════
    #  PLAYBOOKS PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def setup_playbooks_page(self) -> None:
        layout = QVBoxLayout(self.page_playbooks)
        layout.setContentsMargins(SP_XL, SP_LG, SP_XL, SP_LG)
        layout.setSpacing(SP_MD)

        intro = QLabel("استخرج خطة عمل أمنية مهيكلة لأي أداة أو موضوع من كتبك المفهرسة")
        intro.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px;")
        layout.addWidget(intro)

        # Preset clickable cards for common playbooks
        presets_label = QLabel("الخطط الجاهزة للأدوات والمهام الشائعة:")
        presets_label.setStyleSheet(f"color: {ACCENT}; font-weight: 700; font-size: {FONT_SIZE_SMALL}px;")
        layout.addWidget(presets_label)

        presets_layout = QHBoxLayout()
        presets_layout.setSpacing(SP_SM)
        preset_items = [
            ("تأمين SSH", "ssh"),
            ("جدار الحماية UFW", "ufw"),
            ("تصعيد الصلاحيات", "privilege_escalation"),
            ("فحص الشبكة Nmap", "nmap"),
            ("تحليل الذاكرة Volatility", "volatility"),
        ]
        for label, topic in preset_items:
            btn = QPushButton(label)
            btn.setObjectName("pillButton")
            btn.setToolTip(f"استخراج خطة عمل لـ {label}")
            btn.clicked.connect(lambda checked=False, t=topic: self._trigger_preset_playbook(t))
            presets_layout.addWidget(btn)
        presets_layout.addStretch()
        layout.addLayout(presets_layout)

        row = QHBoxLayout()
        row.setSpacing(SP_SM)
        self.pb_input = QLineEdit()
        self.pb_input.setPlaceholderText("مثال: nmap أو privilege_escalation أو ufw")
        button = QPushButton("استخراج")
        button.setObjectName("primary")
        button.clicked.connect(self.load_playbook)
        row.addWidget(self.pb_input)
        row.addWidget(button)
        layout.addLayout(row)

        self.pb_text = QPlainTextEdit(readOnly=True)
        self.pb_text.setPlaceholderText("اختر إحدى الخطط الجاهزة أعلاه أو أدخل اسم الأداة/الموضوع لاستخراج خطة العمل المنظمة مع الأوامر والمصادر.")
        layout.addWidget(self.pb_text)

    def _trigger_preset_playbook(self, topic: str) -> None:
        self.pb_input.setText(topic)
        self.load_playbook()

    # ═══════════════════════════════════════════════════════════════════════════
    #  REPORTS PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def setup_reports_page(self) -> None:
        layout = QVBoxLayout(self.page_reports)
        layout.setContentsMargins(SP_XL, SP_LG, SP_XL, SP_LG)
        layout.setSpacing(SP_MD)

        intro = QLabel("إدارة التقارير الأمنية المُنشأة والمعاينة المباشرة")
        intro.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px;")
        layout.addWidget(intro)

        row = QHBoxLayout()
        row.setSpacing(SP_SM)
        self.reports_dir = QLineEdit(self.settings.get("report_dir", os.path.expanduser("~/ayfam-reports")))
        self.reports_dir.setAccessibleName("مجلد التقارير")
        browse = QPushButton("تصفح")
        browse.clicked.connect(self.choose_reports_dir)
        refresh = QPushButton("تحديث")
        refresh.clicked.connect(self.refresh_reports)
        row.addWidget(QLabel("المجلد:"))
        row.addWidget(self.reports_dir)
        row.addWidget(browse)
        row.addWidget(refresh)
        layout.addLayout(row)

        reports_splitter = QSplitter(Qt.Orientation.Vertical)
        reports_splitter.setHandleWidth(2)

        self.reports_table = QTableWidget(0, 3)
        self.reports_table.setHorizontalHeaderLabels(["الملف", "الحجم", "آخر تعديل"])
        self.reports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.reports_table.setAlternatingRowColors(True)
        self.reports_table.verticalHeader().setVisible(False)
        self.reports_table.verticalHeader().setDefaultSectionSize(32)
        self.reports_table.cellClicked.connect(self.preview_selected_report)
        self.reports_table.cellDoubleClicked.connect(self.open_report)
        reports_splitter.addWidget(self.reports_table)

        preview_box = QGroupBox("معاينة التقرير المحدد")
        pv_layout = QVBoxLayout(preview_box)
        self.report_preview = QPlainTextEdit(readOnly=True)
        self.report_preview.setPlaceholderText("حدد تقريراً من الجدول أعلاه لمعاينته هنا مباشرة...")
        pv_layout.addWidget(self.report_preview)
        reports_splitter.addWidget(preview_box)

        reports_splitter.setStretchFactor(0, 2)
        reports_splitter.setStretchFactor(1, 3)
        layout.addWidget(reports_splitter, 1)
        self.refresh_reports()

    def preview_selected_report(self, row: int, _column: int) -> None:
        item = self.reports_table.item(row, 0)
        if not item:
            return
        filepath = Path(item.text())
        if filepath.exists() and filepath.is_file():
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
                self.report_preview.setPlainText(f"[تقرير] [{filepath.name}]\n\n" + content[:50000])
            except Exception as exc:
                self.report_preview.setPlainText(f"تعذر قراءة التقرير: {exc}")

    # ═══════════════════════════════════════════════════════════════════════════
    #  SETTINGS PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def setup_settings_page(self) -> None:
        layout = QVBoxLayout(self.page_settings)
        layout.setContentsMargins(SP_XL, SP_LG, SP_XL, SP_LG)
        layout.setSpacing(SP_LG)

        form_group = QGroupBox("إعدادات النظام ومفاتيح APIs")
        grid = QGridLayout(form_group)
        grid.setSpacing(SP_MD)

        self.setting_ai_provider = QComboBox()
        for label, value in (
            ("تلقائي (OpenAI ثم Gemini)", "auto"),
            ("Google Gemini", "gemini"),
            ("OpenAI", "openai"),
            ("المحرك المحلي فقط", "local"),
        ):
            self.setting_ai_provider.addItem(label, value)
        provider_index = self.setting_ai_provider.findData(self.settings.get("ai_provider", "auto"))
        self.setting_ai_provider.setCurrentIndex(provider_index if provider_index >= 0 else 0)
        self.setting_ai_provider.setToolTip(
            "اختر Gemini صراحةً إذا أردت أن تستخدم واجهة المحادثة Gemini بدلاً من الاختيار التلقائي."
        )

        self.setting_gemini_model = QLineEdit(
            self.settings.get("gemini_model", DEFAULT_GEMINI_MODEL)
        )
        self.setting_gemini_model.setPlaceholderText(DEFAULT_GEMINI_MODEL)

        self.setting_gemini_key = QLineEdit(self.settings.get("gemini_api_key", ""))
        self.setting_gemini_key.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        self.setting_gemini_key.setPlaceholderText("AI Studio Gemini API Key")

        self.setting_openai_model = QLineEdit(
            self.settings.get("openai_model", OPENAI_DEFAULT_MODEL)
        )
        self.setting_openai_model.setPlaceholderText(OPENAI_DEFAULT_MODEL)
        self.setting_openai_model.setToolTip(
            "نماذج API لا تعتمد على اشتراك ChatGPT؛ تُستخدم حصتك المجانية إن كانت متاحة، "
            "وإلا يتطلب الحساب رصيد API موجباً."
        )

        self.setting_openai_key = QLineEdit(self.settings.get("openai_api_key", ""))
        self.setting_openai_key.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        self.setting_openai_key.setPlaceholderText("OpenAI API Key — يبدأ عادةً بـ sk-")

        self.setting_abuseipdb_key = QLineEdit(self.settings.get("abuseipdb_key", ""))
        self.setting_abuseipdb_key.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        self.setting_abuseipdb_key.setPlaceholderText("AbuseIPDB API Key (اختياري)")

        self.setting_nvd_key = QLineEdit(self.settings.get("nvd_api_key", ""))
        self.setting_nvd_key.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        self.setting_nvd_key.setPlaceholderText("NVD API Key (اختياري — يرفع حد طلبات CVE)")

        self.setting_github_token = QLineEdit(self.settings.get("github_token", ""))
        self.setting_github_token.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        self.setting_github_token.setPlaceholderText("GitHub Personal Access Token")

        self.setting_cse_key = QLineEdit(self.settings.get("google_cse_key", ""))
        self.setting_cse_key.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        self.setting_cse_key.setPlaceholderText("Google Programmable Search Key (اختياري)")
        self.setting_cse_cx = QLineEdit(self.settings.get("google_cse_cx", "") or DEFAULT_GOOGLE_CSE_CX)
        self.setting_cse_cx.setPlaceholderText("معرّف محرك البحث cx")

        self.setting_report_dir = QLineEdit(self.settings.get("report_dir", os.path.expanduser("~/ayfam-reports")))

        self.setting_lang_combo = QComboBox()
        self.setting_lang_combo.addItems(["ar", "en"])
        current_lang = self.settings.get("language", "ar")
        self.setting_lang_combo.setCurrentText(current_lang if current_lang in ("ar", "en") else "ar")
        self.setting_sound_ux = QCheckBox("أصوات التفاعل متوقفة في وضع توفير الموارد")
        self.setting_sound_ux.setChecked(False)
        self.setting_sound_ux.setEnabled(False)
        self.setting_sound_ux.setToolTip("أُوقفت أصوات الواجهة لتقليل الخدمات الخلفية أثناء تجهيز التدريب المحلي.")
        self.setting_sound_profile = QComboBox()
        self.setting_sound_profile.addItem("معطل في وضع توفير الموارد", "disabled")
        self.setting_sound_profile.setEnabled(False)
        current_profile = str(self.settings.get("sound_profile", "soft"))
        profile_index = self.setting_sound_profile.findData(current_profile)
        self.setting_sound_profile.setCurrentIndex(profile_index if profile_index >= 0 else 0)
        self.setting_dark_mode = QCheckBox("تفعيل الوضع الليلي الاحترافي")
        self.setting_dark_mode.setChecked(bool(self.settings.get("dark_mode", True)))
        self.setting_dark_mode.setToolTip("يحافظ على واجهة Dark / Obsidian المريحة للعمل الطويل")

        grid.addWidget(QLabel("مزود المحادثة:"), 0, 0)
        grid.addWidget(self.setting_ai_provider, 0, 1)
        grid.addWidget(QLabel("نموذج Gemini:"), 1, 0)
        grid.addWidget(self.setting_gemini_model, 1, 1)
        grid.addWidget(QLabel("Gemini API Key:"), 2, 0)
        grid.addWidget(self.setting_gemini_key, 2, 1)

        grid.addWidget(QLabel("نموذج OpenAI:"), 3, 0)
        grid.addWidget(self.setting_openai_model, 3, 1)
        grid.addWidget(QLabel("OpenAI API Key:"), 4, 0)
        grid.addWidget(self.setting_openai_key, 4, 1)

        grid.addWidget(QLabel("AbuseIPDB Key:"), 5, 0)
        grid.addWidget(self.setting_abuseipdb_key, 5, 1)

        grid.addWidget(QLabel("NVD API Key:"), 6, 0)
        grid.addWidget(self.setting_nvd_key, 6, 1)

        grid.addWidget(QLabel("GitHub Token:"), 7, 0)
        grid.addWidget(self.setting_github_token, 7, 1)

        grid.addWidget(QLabel("Google Search Key:"), 8, 0)
        grid.addWidget(self.setting_cse_key, 8, 1)

        grid.addWidget(QLabel("Google Search cx:"), 9, 0)
        grid.addWidget(self.setting_cse_cx, 9, 1)

        grid.addWidget(QLabel("مجلد التقارير:"), 10, 0)
        grid.addWidget(self.setting_report_dir, 10, 1)

        grid.addWidget(QLabel("اللغة (Language):"), 11, 0)
        grid.addWidget(self.setting_lang_combo, 11, 1)
        grid.addWidget(QLabel("التجربة الحسية:"), 12, 0)
        grid.addWidget(self.setting_sound_ux, 12, 1)
        grid.addWidget(QLabel("نمط النغمة:"), 13, 0)
        grid.addWidget(self.setting_sound_profile, 13, 1)
        grid.addWidget(QLabel("نمط العرض:"), 14, 0)
        grid.addWidget(self.setting_dark_mode, 14, 1)

        layout.addWidget(form_group)

        btns_row = QHBoxLayout()
        btns_row.setSpacing(SP_MD)

        save_btn = QPushButton("حفظ الإعدادات")
        save_btn.setObjectName("primary")
        save_btn.clicked.connect(self.save_settings)

        test_gemini_btn = QPushButton("اختبار مفتاح Gemini")
        test_gemini_btn.clicked.connect(self.test_gemini_settings)

        test_openai_btn = QPushButton("اختبار مفتاح OpenAI")
        test_openai_btn.clicked.connect(self.test_openai_settings)

        test_search_btn = QPushButton("اختبار البحث في الإنترنت")
        test_search_btn.setToolTip("يتحقق من Google وويكيبيديا ويعرض حالة كل محرك")
        test_search_btn.clicked.connect(self.test_search_settings)

        clear_hist_btn = QPushButton("مسح تاريخ المحادثات")
        clear_hist_btn.clicked.connect(self.clear_history_settings)

        btns_row.addWidget(save_btn)
        btns_row.addWidget(test_gemini_btn)
        btns_row.addWidget(test_openai_btn)
        btns_row.addWidget(test_search_btn)
        btns_row.addWidget(clear_hist_btn)
        btns_row.addStretch()

        layout.addLayout(btns_row)

        self.settings_log = QPlainTextEdit(readOnly=True)
        self.settings_log.setPlaceholderText("ستظهر نتائج اختبار الاتصال وحفظ الإعدادات هنا...")
        self.settings_log.setMinimumHeight(180)
        layout.addWidget(self.settings_log, 1)

    def save_settings(self) -> None:
        self.settings.set("ai_provider", str(self.setting_ai_provider.currentData() or "auto"))
        self.settings.set("abuseipdb_key", self.setting_abuseipdb_key.text().strip())
        self.settings.set("nvd_api_key", self.setting_nvd_key.text().strip())
        self.settings.set("github_token", self.setting_github_token.text().strip())
        self.settings.set("google_cse_key", self.setting_cse_key.text().strip())
        self.settings.set("google_cse_cx", self.setting_cse_cx.text().strip())
        self.settings.set("report_dir", self.setting_report_dir.text().strip())
        lang = self.setting_lang_combo.currentText()
        self.settings.set("language", lang)
        self.settings.set("sound_ux", False)
        self.settings.set("sound_profile", "disabled")
        self.agent.lang = lang
        self.agent.intel.language = lang
        self.settings_log.setPlainText("[نجاح] تم حفظ الإعدادات غير الحساسة. تُحفظ مفاتيح ونماذج AI بعد نجاح فحصها / Non-AI settings saved. AI keys and models are saved only after validation.")
        QMessageBox.information(
            self, "حفظ الإعدادات",
            "تم حفظ الإعدادات. تُحفظ مفاتيح ونماذج AI فقط بعد نجاح اختبار اتصالها.\n"
            "Settings saved. AI keys and models are stored only after a successful provider check.",
        )

    def test_search_settings(self) -> None:
        self.save_settings()

        def show(report) -> None:
            lines = ["[حالة محركات البحث]"] + [f"{name}: {status}" for name, status in report.engines.items()]
            lines.append(f"النتائج المقبولة: {len(report.hits)} | المحذوفة لعدم الصلة: {report.dropped}")
            if report.answer:
                lines.append(f"الملخص: {report.answer[:120]}...")
            if not any("يعمل" in str(s) for s in report.engines.values()):
                lines.append("\n• ملاحظة: لتفعيل Google Search البرمجي مباشرة أدخل GOOGLE_CSE_KEY و GOOGLE_CSE_CX أو أدخل GEMINI_API_KEY في الإعدادات.")
            self.settings_log.setPlainText("\n".join(lines))

        self.run_background_task(lambda: self.agent.smart_search("Kali Linux"), "اختبار البحث", preserve_findings=True, result_handler=show)

    def _test_ai_provider_settings(self, provider_name: str) -> None:
        """Validate a provider key/model from its model catalogue before saving it."""
        from engine.ai_assistant import (
            GeminiAssistant, OpenAIAssistant, validate_model_access,
        )

        if provider_name == "gemini":
            key_field = self.setting_gemini_key
            model_field = self.setting_gemini_model
            setting_key = "gemini_api_key"
            model_setting = "gemini_model"
            default_model = DEFAULT_GEMINI_MODEL
            environment_names = ("GOOGLE_API_KEY", "GEMINI_API_KEY")
            env_label = "GOOGLE_API_KEY / GEMINI_API_KEY"
            display_name = "Gemini"
        else:
            key_field = self.setting_openai_key
            model_field = self.setting_openai_model
            setting_key = "openai_api_key"
            model_setting = "openai_model"
            default_model = OPENAI_DEFAULT_MODEL
            environment_names = ("OPENAI_API_KEY",)
            env_label = "OPENAI_API_KEY"
            display_name = "OpenAI"

        configured_key = key_field.text().strip() or self.settings.get(setting_key, "")
        environment_key = next(
            (os.environ.get(name, "").strip() for name in environment_names
             if os.environ.get(name, "").strip()),
            "",
        )
        effective_key = environment_key or configured_key
        if not effective_key:
            self.settings_log.setPlainText(
                f"[missing_key] {display_name}: API key is not configured.\n"
                f"{display_name}: لم يتم إعداد مفتاح API."
            )
            return

        model = model_field.text().strip() or self.settings.get(model_setting, default_model) or default_model
        key_source = env_label if environment_key else "app settings / إعدادات التطبيق"
        self.settings_log.setPlainText(
            f"[check] {display_name}: listing models first; no generation tokens are used.\n"
            f"[فحص] {display_name}: يجري التحقق من قائمة النماذج أولاً دون توليد."
            f"\nModel / النموذج: {model}\nKey source / مصدر المفتاح: {key_source}"
        )

        def run_catalog_check():
            started = time.monotonic()
            try:
                result = validate_model_access(
                    provider_name, effective_key, model, timeout=12.0, force=True,
                )
                result["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
                return {"ok": True, **result}
            except Exception as exc:
                category = getattr(exc, "category", "invalid_response")
                message = str(exc) if hasattr(exc, "diagnostic") else (
                    "Provider model check failed. فشل التحقق من قائمة نماذج المزوّد."
                )
                return {
                    "ok": False, "category": category, "message": message,
                    "latency_ms": round((time.monotonic() - started) * 1000, 1),
                }

        def handle_catalog_result(result: Any) -> None:
            if not isinstance(result, dict) or not result.get("ok"):
                category = result.get("category", "invalid_response") if isinstance(result, dict) else "invalid_response"
                diagnostic = result.get("message", "Invalid diagnostic result.") if isinstance(result, dict) else "Invalid diagnostic result."
                latency = result.get("latency_ms", 0.0) if isinstance(result, dict) else 0.0
                self.settings_log.setPlainText(
                    f"[{category}] {display_name}: model/key check failed.\n"
                    f"{diagnostic}\n"
                    f"Model / النموذج: {model}\nKey source / مصدر المفتاح: {key_source}"
                    f"\nLatency / زمن الاستجابة: {latency:.1f} ms"
                )
                return
            if not isinstance(result, dict) or result.get("category") != "ok" or not result.get("exists"):
                self.settings_log.setPlainText(
                    f"[invalid_response] {display_name}: invalid model-check result.\n"
                    "تعذّر التحقق من بنية نتيجة فحص النموذج."
                )
                return

            # Persist only after the provider confirms the key and explicit model.
            # Environment credentials remain environment-only.
            if not environment_key and key_field.text().strip():
                self.settings.set(setting_key, key_field.text().strip())
            self.settings.set(model_setting, model)
            status = (
                f"[ok] {display_name}: key accepted; model is listed.\n"
                f"[نجاح] {display_name}: المفتاح مقبول والنموذج موجود بالقائمة."
                f"\nModel / النموذج: {model}"
                f"\nKey source / مصدر المفتاح: {key_source}"
                f"\nModels listed / النماذج المدرجة: {result.get('models_count', 0)}"
                f"\nLatency / زمن الاستجابة: {result.get('latency_ms', 0):.1f} ms"
                "\nCategory / فئة التشخيص: ok"
            )
            self.settings_log.setPlainText(status)

            answer = QMessageBox.question(
                self,
                f"{display_name} generation test / اختبار التوليد",
                "Model listing succeeded. Run one optional short generation test?\n"
                "نجح فحص قائمة النماذج. هل تريد تنفيذ اختبار توليد قصير اختياري؟",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

            def run_generation():
                started = time.monotonic()
                try:
                    provider = (
                        GeminiAssistant(effective_key, model, timeout=12.0)
                        if provider_name == "gemini"
                        else OpenAIAssistant(effective_key, model, timeout=12.0)
                    )
                    if provider_name == "gemini":
                        generated = provider.ask(
                            "Reply with: OK",
                            on_wait=lambda remaining: self.agent.ui.info(
                                f"Gemini quota wait / انتظار حصة Gemini: {remaining:.0f}s"
                            ),
                        )
                    else:
                        generated = provider.ask("Reply with: OK")
                    return {
                        "answer": generated,
                        "latency_ms": round((time.monotonic() - started) * 1000, 1),
                        "category": "ok",
                    }
                except Exception as exc:
                    return {
                        "category": getattr(exc, "category", "invalid_response"),
                        "message": str(exc) if hasattr(exc, "diagnostic") else (
                            "Provider generation failed. فشل توليد المزوّد."
                        ),
                        "latency_ms": round((time.monotonic() - started) * 1000, 1),
                    }

            def handle_generation_result(generation: Any) -> None:
                if isinstance(generation, dict) and generation.get("category") != "ok":
                    self.settings_log.setPlainText(
                        status + f"\n[{generation['category']}] Optional generation failed.\n"
                        f"فشل اختبار التوليد الاختياري: {generation.get('message', '')}"
                        f"\nGeneration latency / زمن التوليد: {generation.get('latency_ms', 0):.1f} ms"
                    )
                elif isinstance(generation, dict) and generation.get("category") == "ok":
                    self.settings_log.setPlainText(
                        status
                        + f"\nGeneration latency / زمن التوليد: {generation.get('latency_ms', 0):.1f} ms"
                        + "\nGeneration structure / بنية الاستجابة: valid"
                    )
                else:
                    self.settings_log.setPlainText(
                        status + "\n[invalid_response] Invalid generation result.\nنتيجة اختبار التوليد غير صالحة."
                    )

            self.run_background_task(
                run_generation, self.tr(f"اختبار توليد {display_name} / {display_name} generation test"),
                preserve_findings=True, result_handler=handle_generation_result,
            )

        self.run_background_task(
            run_catalog_check, self.tr(f"فحص قائمة نماذج {display_name} / {display_name} model-list test"),
            preserve_findings=True, result_handler=handle_catalog_result,
        )

    def test_gemini_settings(self) -> None:
        self._test_ai_provider_settings("gemini")

    def test_openai_settings(self) -> None:
        self._test_ai_provider_settings("openai")

    def clear_history_settings(self) -> None:
        answer = QMessageBox.question(
            self, "مسح التاريخ", "هل أنت تأكد من مسح سجّلات المحادثة السابقة؟",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.agent.kb.clear_history()
            self.chat_display.clear()
            self.settings_log.setPlainText("[تم] تم مسح تاريخ المحادثات.")

    # ═══════════════════════════════════════════════════════════════════════════
    #  LIBRARY PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def setup_library_page(self) -> None:
        layout = QVBoxLayout(self.page_library)
        layout.setContentsMargins(SP_XL, SP_LG, SP_XL, SP_LG)
        layout.setSpacing(SP_MD)

        intro = QLabel("مكتبة المعرفة المحلية — أضف كتباً وملفات ويتم استخراج نصها وفهرسته محلياً")
        intro.setWordWrap(True)
        intro.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px; padding: 4px;")
        layout.addWidget(intro)

        actions = QHBoxLayout()
        actions.setSpacing(SP_SM)
        self.add_books_button = QPushButton("إضافة كتب")
        self.add_books_button.setObjectName("primary")
        self.add_books_button.clicked.connect(self.choose_books)
        self.rebuild_index_button = QPushButton("إعادة بناء الفهرس")
        self.rebuild_index_button.clicked.connect(self.rebuild_library_index)
        refresh = QPushButton("تحديث")
        refresh.clicked.connect(self.refresh_library)
        actions.addWidget(self.add_books_button)
        actions.addWidget(self.rebuild_index_button)
        actions.addWidget(refresh)
        actions.addStretch()
        layout.addLayout(actions)

        self.library_status = QLabel("جارٍ تحميل المكتبة...")
        self.library_status.setStyleSheet(f"color: {STATUS_OK}; font-size: {FONT_SIZE_SMALL}px;")
        layout.addWidget(self.library_status)

        self.library_table = QTableWidget(0, 4)
        self.library_table.setHorizontalHeaderLabels(["العنوان", "النوع", "المقاطع", "تاريخ الإضافة"])
        self.library_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.library_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.library_table.setAlternatingRowColors(True)
        self.library_table.verticalHeader().setVisible(False)
        self.library_table.verticalHeader().setDefaultSectionSize(32)
        self.library_table.cellClicked.connect(self.show_library_document)
        layout.addWidget(self.library_table, 2)

        search_row = QHBoxLayout()
        search_row.setSpacing(SP_SM)
        self.library_query = QLineEdit()
        self.library_query.setPlaceholderText("ابحث في نص الكتب التي أضفتها...")
        self.library_query.returnPressed.connect(self.search_library)
        search_button = QPushButton("بحث")
        search_button.setObjectName("primary")
        search_button.clicked.connect(self.search_library)
        search_row.addWidget(self.library_query)
        search_row.addWidget(search_button)
        layout.addLayout(search_row)

        self.library_results = QPlainTextEdit(readOnly=True)
        self.library_results.setPlaceholderText("ستظهر المقاطع المطابقة مع اسم الكتاب ورقم الصفحة هنا.")
        layout.addWidget(self.library_results, 2)
        self.refresh_library()

    # ═══════════════════════════════════════════════════════════════════════════
    #  LIVE CLOCK
    # ═══════════════════════════════════════════════════════════════════════════
    AR_DAYS = {"Monday": "الاثنين", "Tuesday": "الثلاثاء", "Wednesday": "الأربعاء", "Thursday": "الخميس", "Friday": "الجمعة", "Saturday": "السبت", "Sunday": "الأحد"}
    AR_MONTHS = {1: "يناير", 2: "فبراير", 3: "مارس", 4: "أبريل", 5: "مايو", 6: "يونيو", 7: "يوليو", 8: "أغسطس", 9: "سبتمبر", 10: "أكتوبر", 11: "نوفمبر", 12: "ديسمبر"}

    def update_clock(self) -> None:
        from datetime import datetime
        now = datetime.now()
        day = self.AR_DAYS.get(now.strftime("%A"), now.strftime("%A"))
        month = self.AR_MONTHS.get(now.month, now.strftime("%B"))
        self.analog_clock.setToolTip(f"{now.strftime('%H:%M:%S')}  •  {day}، {now.day} {month} {now.year}")

    def show_system_overview(self) -> None:
        dlg = SystemOverviewDialog(self)
        dlg.exec()

    def show_intro_splash(self) -> None:
        self._demo_splash = AyfamIntroSplash(self, auto_close=False)
        self._demo_splash.ready_to_launch.connect(lambda: None)
        self._demo_splash.show()

    # ═══════════════════════════════════════════════════════════════════════════
    #  ACCENT HUE CYCLER (pulsing colors across the UI)
    # ═══════════════════════════════════════════════════════════════════════════
    def cycle_accent_hue(self) -> None:
        """Compatibility hook: color motion is painted smoothly, not by restyling."""
        return

    # ═══════════════════════════════════════════════════════════════════════════
    #  LIVE TELEMETRY
    # ═══════════════════════════════════════════════════════════════════════════
    @staticmethod
    def _table_state(table: QTableWidget, key_col: int) -> tuple[int, str | None]:
        row = table.currentRow()
        key = table.item(row, key_col).text() if row >= 0 and table.item(row, key_col) else None
        return table.verticalScrollBar().value(), key

    @staticmethod
    def _restore_table(table: QTableWidget, state: tuple[int, str | None], key_col: int) -> None:
        scroll, key = state
        if key is not None:
            for row in range(table.rowCount()):
                item = table.item(row, key_col)
                if item and item.text() == key:
                    table.selectRow(row)
                    break
        table.verticalScrollBar().setValue(scroll)

    def update_live_telemetry(self, force: bool = False) -> None:
        if self._training_mode_active and not force:
            return
        if self.telemetry_worker is not None and self.telemetry_worker.isRunning():
            return
        self.telemetry_worker = LiveTelemetryWorker(self)
        self.telemetry_worker.result_ready.connect(self._render_live_telemetry)
        self.telemetry_worker.finished.connect(self._telemetry_finished)
        self.telemetry_worker.start()

    def set_training_mode(self, enabled: bool) -> None:
        """Pause optional UI polling while local model training is active.

        Call this from the Qt GUI thread. It does not stop a user-requested scan;
        it only pauses passive telemetry and event-feed refresh timers.
        """
        self._training_mode_active = bool(enabled)
        if self._training_mode_active:
            self.timer.stop()
            self.event_timer.stop()
            return

        self.timer.start(TELEMETRY_REFRESH_MS)
        self.event_timer.start(EVENT_POLL_INTERVAL_MS)
        self.update_live_telemetry(force=True)
        self.update_agent_events()

    def _telemetry_finished(self) -> None:
        worker = self.telemetry_worker
        if worker is not None:
            worker.deleteLater()
        self.telemetry_worker = None

    def _render_live_telemetry(self, result) -> None:
        try:
            if isinstance(result, Exception):
                message = str(result)
                if message != self._last_telemetry_error:
                    self.chat_display.append(f"[تحذير الرادار] {message}")
                    self._last_telemetry_error = message
                return
            self._last_telemetry_error = ""
            conns = result.get("connections", [])
            procs = result.get("processes", [])
            conn_state = self._table_state(self.table_conns, 3)
            proc_state = self._table_state(self.table_procs, 1)
            for table in (self.table_conns, self.table_procs):
                table.setUpdatesEnabled(False)
            try:
                self.table_conns.setRowCount(len(conns[:60]))
                for row, c in enumerate(conns[:60]):
                    state = str(c.get("state", ""))
                    foreign = bool(c.get("is_foreign"))
                    state_color = CONN_STATE_COLORS.get(state.upper(), TEXT_SECONDARY)
                    remote = str(c.get("remote", ""))
                    cells = [
                        table_cell(c.get("proto", ""), center=True, mono=True),
                        table_cell(state, state_color, center=True, bold=True, tip=f"حالة الاتصال: {state}"),
                        table_cell("خارجي" if foreign else "محلي", SEV_HIGH if foreign else SEV_SAFE, center=True, bold=True,
                                   tip="اتصال بعنوان خارج الشبكة المحلية" if foreign else "اتصال داخل الجهاز أو الشبكة المحلية"),
                        table_cell(c.get("local", ""), mono=True),
                        table_cell(remote, SEV_HIGH if foreign else None, mono=True),
                        table_cell(c.get("process", "") or "—"),
                        table_cell(c.get("pid", ""), center=True, mono=True),
                    ]
                    for col, cell in enumerate(cells):
                        self.table_conns.setItem(row, col, cell)
                self.table_procs.setRowCount(len(procs))
                for row, p in enumerate(procs):
                    cpu, mem = float(p.get("cpu", 0) or 0), float(p.get("mem", 0) or 0)
                    cmd_raw = str(p.get("command", ""))
                    cells = [
                        table_cell(p.get("user", "")),
                        table_cell(p.get("pid", ""), center=True, mono=True),
                        table_cell(f"{cpu:g}%", SEV_CRITICAL if cpu >= 70 else SEV_HIGH if cpu >= 30 else None, center=True, bold=cpu >= 30, mono=True),
                        table_cell(f"{mem:g}%", SEV_CRITICAL if mem >= 70 else SEV_HIGH if mem >= 30 else None, center=True, bold=mem >= 30, mono=True),
                        table_cell(cmd_raw, mono=True),
                    ]
                    for col, cell in enumerate(cells):
                        self.table_procs.setItem(row, col, cell)
                self._restore_table(self.table_conns, conn_state, 3)
                self._restore_table(self.table_procs, proc_state, 1)
            finally:
                for table in (self.table_conns, self.table_procs):
                    table.setUpdatesEnabled(True)
            self.metric_labels["connections"].setText(str(len(conns)))
            self.metric_labels["processes"].setText(str(len(procs)))
            external = sum(1 for c in conns if c.get("is_foreign"))
            listening = sum(1 for c in conns if str(c.get("state", "")).upper() == "LISTEN")
            self.connection_summary.setText(
                f"{len(conns)} اتصال  |  {external} خارجي  |  {listening} منصت  |  تحديث دوري منخفض التواتر")
            activity = max(0.0, min(100.0, len(procs) * 2.6 + len(conns) * 0.7))
            self._telemetry_history["النشاط التشغيلي (%)"].append(activity)
            for values in self._telemetry_history.values():
                del values[:-24]
            if hasattr(self, "telemetry_chart"):
                active_series = {}
                if self._telemetry_history["الجاهزية الأمنية (%)"]:
                    last_score = self._telemetry_history["الجاهزية الأمنية (%)"][-1]
                    active_series["الجاهزية الأمنية (%)"] = (
                        self._telemetry_history["الجاهزية الأمنية (%)"], score_state_color(last_score))
                if self._telemetry_history["النشاط التشغيلي (%)"]:
                    active_series["النشاط التشغيلي (%)"] = (self._telemetry_history["النشاط التشغيلي (%)"], ACCENT_SECONDARY)
                self.telemetry_chart.set_data(active_series)
        except Exception as exc:
            self.chat_display.append(f"[تحذير الرادار] {exc}")

    def update_agent_events(self) -> None:
        events = self.agent.ui.get_events(200)
        overlap = min(len(self.visible_events), len(events))
        while overlap and self.visible_events[-overlap:] != events[:overlap]:
            overlap -= 1
        for timestamp, level, message in events[overlap:]:
            self.chat_display.append(f"[{timestamp}] [{level}] {message}")
        self.visible_events = events

    # ═══════════════════════════════════════════════════════════════════════════
    #  CHAT
    # ═══════════════════════════════════════════════════════════════════════════
    def _say(self, text: str) -> None:
        self.chat_display.append(f"[الوكيل] {text}")
        self.chat_history.append(("assistant", text))
        del self.chat_history[:-20]

    def _submit_text(self, text: str) -> None:
        self.chat_input.setText(text)
        self.send_chat_message()

    def send_chat_message(self) -> None:
        text = self.chat_input.text().strip()
        if not text:
            return
        self.chat_input.clear()
        self.chat_display.append(f"\n[أنت] {text}")
        self.chat_history.append(("user", text))
        turn = self.agent.chat_engine.process(text)
        self.chat_display.append_thinking(turn.steps)
        self._dispatch_turn(turn)

    def _dispatch_turn(self, turn) -> None:
        if turn.action == "reply":
            self._say(turn.reply)
        elif turn.action == "clarify":
            actions = []
            for label, value in turn.suggestions:
                if value:
                    actions.append((label, lambda v=value: self._submit_text(v), "primary" if not actions else ""))
                else:
                    actions.append((label, lambda: self._say("اكتب سؤالك كاملاً وسأحاول فهمه."), ""))
            self.chat_display.append_actions(turn.reply, actions)
            self.chat_history.append(("assistant", turn.reply))
        elif turn.action == "web_search":
            self._run_web_search(turn.query)
        elif turn.action == "learn_online":
            self._run_learning(turn.query)
        elif turn.action == "route":
            self._route_command(turn.cmd, turn.text)
        else:
            self._ask_assistant(turn.text)

    # ── ذكاء المحادثة ──
    def _ask_assistant(self, text: str) -> None:
        history = list(self.chat_history[:-1])
        self.run_background_task(
            lambda: (
                self.agent.ask_ai_or_local(text, history),
                self.agent.last_answer_was_gap,
                self.agent.last_provider_error,
                self.agent.learning_governance.last_report,
            ),
            "المساعد الذكي", preserve_findings=True,
            result_handler=lambda out: self._deliver_answer(out[0], text, out[1], out[2], out[3]),
        )

    def _deliver_answer(self, answer: str, topic: str, gap: bool, provider_error: str = "", learning_report=None) -> None:
        self._say(answer)
        if learning_report:
            self._show_learning_report(learning_report)
        if provider_error:
            self.chat_display.append(
                f"\n[تشخيص الاتصال الخارجي] {provider_error}\n"
                "استخدمت الإجابة المحلية بدلاً من Gemini لهذه الرسالة."
            )
        if gap:
            self.chat_display.append_actions(
                "ما رأيك أن أبحث لك الآن؟",
                [("ابحث في الإنترنت", lambda: self._run_web_search(topic), "primary"),
                 ("تعلّم من الإنترنت", lambda: self._run_learning(topic), "")],
            )

    def _show_learning_report(self, report: dict) -> None:
        """Tell the user what was persisted, proposed, or actually used."""
        if report.get("mode") == "external":
            flags = ", ".join(report.get("flags") or []) or "لا توجد إشارات أولية"
            self.chat_display.append(
                "\n[تقرير التعلم الخارجي]\n"
                f"✓ حُفظت الإجابة للتدقيق: interaction #{report.get('interaction_id')}\n"
                f"✓ اقتراح معرفة: #{report.get('knowledge_proposal_id')} — حجر للمراجعة، لم تُدمج بعد\n"
                f"✓ مرشح وزن أسلوب: #{report.get('weight_profile_id')} — مقترح، غير نشط\n"
                f"• درجة الفحص الأولي: {report.get('screening_score', 0):.2f}\n"
                f"• التنبيهات: {flags}\n"
                "• حقائق معتمدة: 0 | استنتاجات معتمدة: 0"
            )
        elif report.get("mode") == "local":
            keys = ", ".join(report.get("evidence_keys") or []) or "لا توجد مفاتيح معرفة مطابقة"
            self.chat_display.append(
                "\n[تقرير التعلم المحلي]\n"
                f"✓ الأدلة المستخدمة من المعرفة المحلية: {report.get('evidence_count', 0)}\n"
                f"• المفاتيح المطابقة: {keys}\n"
                f"• ملف الأوزان الفعّال: {report.get('active_weight_profile')} "
                f"(#{report.get('active_weight_id')})\n"
                f"• حقائق مكتسبة مستخدمة: {report.get('learned_facts', 0)} | "
                f"استنتاجات موثقة: {report.get('inferences', 0)}"
            )

    # ── البحث الدقيق (Google + ويكيبيديا) ──
    def _run_web_search(self, query: str) -> None:
        self.run_background_task(
            lambda: self.agent.smart_search(query), "بحث في الإنترنت", preserve_findings=True,
            result_handler=self._show_search,
        )

    def _show_search(self, report) -> None:
        if not report.online:
            self._say("لا يوجد اتصال بالإنترنت حالياً. تحقق من الشبكة ثم أعد المحاولة.")
            return
        actions = [("تعلّم من هذه النتائج", lambda: self._run_learning(report.query), "primary")] if report.ok else []
        self.chat_display.append_results(report, actions=actions)
        self.chat_history.append(("assistant", f"نتائج البحث عن {report.query}"))

    # ── التعلم من الإنترنت: يتصل ويبحث عمّا ينقصه، والمستخدم يقرر الحفظ ──
    def _run_learning(self, topic: str) -> None:
        self.run_background_task(
            lambda: self.agent.prepare_learning(topic), "التعلم من الإنترنت", preserve_findings=True,
            result_handler=self._show_learning,
        )

    def _show_learning(self, result: dict) -> None:
        if not result.get("online"):
            self._say("لا يوجد اتصال بالإنترنت، لذلك لا أستطيع التعلم الآن. تحقق من الشبكة وأعد المحاولة.")
            return
        items = result.get("items") or []
        if not items:
            self._say("لا أجد ما ينقصني حالياً. اكتب «تعلم من الإنترنت عن …» وحدد الموضوع.")
            return
        names = "، ".join(item["topic"] for item in items)
        self._say(("اتصلت بالإنترنت تلقائياً وبحثت فيما ينقصني: " if result.get("inferred") else "اتصلت بالإنترنت وبحثت عن: ") + names)
        ready = []
        for item in items:
            self.chat_display.append_results(item["report"], title=f"ما وجدته عن «{item['topic']}»")
            if item.get("path"):
                ready.append(item)
        if not ready:
            self._say("لم أجد مصادر مفيدة، لذلك لن أحفظ شيئاً.")
            return
        first = ready[0]["path"]
        self.chat_display.append_actions(
            f"جهزت {len(ready)} ملف للمراجعة (مثل {Path(first).name}). هل أحفظ ما وجدته في معرفتي وأعتمد عليه في التفكير والإجابة؟",
            [("حفظ وتعلّم", lambda: self._commit_learning(ready), "primary"),
             ("تجاهل", lambda: self._discard_learning(ready), "danger"),
             ("فتح الملف", lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(first)), "", True)],
        )

    def _commit_learning(self, ready: list) -> None:
        self.run_background_task(
            lambda: self.agent.commit_learning(ready), "حفظ ما تعلمته", preserve_findings=True,
            result_handler=self._learning_saved,
        )

    def _learning_saved(self, saved: list) -> None:
        self.refresh_library()
        if saved:
            self._say("تعلمت وحفظت: " + "، ".join(f"{s['topic']} ({s['chunks']} مقطع)" for s in saved)
                      + ". سأستخدمها في الإجابات القادمة، ويمكنك مراجعتها في مكتبة المعرفة.")
        else:
            self._say("لم يتم حفظ شيء: الملفات لم تعد موجودة.")

    def _discard_learning(self, ready: list) -> None:
        removed = self.agent.discard_learning(ready)
        self._say(f"تجاهلت النتائج وحذفت {removed} ملف مؤقت. لم أتعلم منها شيئاً.")

    # ── توجيه الأوامر ──
    def _route_command(self, cmd, text: str) -> None:
        if cmd.intent == "explain":
            target = cmd.explain_target or text

            def deliver(answer: str) -> None:
                gap = "لم أجد شرحاً محدداً" in answer
                if gap:
                    self.agent.phrases.record_gap(target)
                    answer = f"لا أملك شرحاً محدداً لـ«{target}» في معرفتي الحالية."
                self._deliver_answer(answer, target, gap)

            self.run_background_task(lambda: self.agent.nlp.explain(target), "شرح السؤال", preserve_findings=True, result_handler=deliver)
            return

        entities = cmd.entities
        routes: dict[str, tuple[str, Callable[[], Any]]] = {
            "scan_network": ("فحص الشبكة", self.agent._scan_network),
            "scan_system": ("فحص النظام", self.agent._scan_system),
            "scan_logs": ("تحليل السجلات", self.agent._scan_logs),
            "full_scan": ("الفحص الشامل", self.agent._full_scan),
            "usb_control": ("فحص USB", self.agent._usb_control_center),
            "check_firewall": ("جدار الحماية", self.agent._check_firewall),
            "wifi": ("Wi-Fi", self.agent._wifi_status),
            "scan_trend": ("تطور الوضع", self.agent._show_trend),
            "rebuild_index": ("بناء الفهرس", self.agent._rebuild_index),
            "show_learned": ("ما تعلمته", self.agent._show_learned),
            "concept_explore": ("استكشاف مفهوم", lambda: self.agent._concept_explore(entities.get("concept", ""))),
            "concept_link": ("ربط مفهومين", lambda: self.agent._concept_link(entities.get("concept_a", ""), entities.get("concept_b", ""))),
            "summarize_doc": ("تلخيص كتاب", lambda: self.agent._summarize_doc(entities.get("book_title", ""))),
            "teach": ("حفظ معلومة", lambda: self.agent._teach(entities.get("fact", ""))),
            "cve_search": ("بحث CVE", lambda: self.agent._cve_search(entities.get("cve") or entities.get("keyword") or text)),
            "pkg_vuln_search": ("ثغرات حزمة", lambda: self.agent._pkg_vuln_search(entities.get("package", ""))),
            "update_intel": ("تحديث التهديدات", self.agent._update_intel),
        }
        if cmd.intent == "web_search":
            self._run_web_search(text)
            return
        if cmd.intent in routes:
            title, handler = routes[cmd.intent]
            self.run_background_task(handler, title, preserve_findings=cmd.intent in {"rebuild_index", "show_learned"})
            return
        target = entities.get("ip", "")
        if cmd.intent == "scan_ports":
            ports_target = target or self.scan_target.text().strip() or "127.0.0.1"
            port_range = self.port_range.text().strip() or "1-1024"
            self.run_background_task(lambda: self.agent._scan_ports(ports_target, port_range), "فحص المنافذ")
            return
        if cmd.intent == "scan_website":
            url = entities.get("url") or self.website_input.text().strip()
            if url:
                self.run_background_task(lambda: self.agent._test_website(url), "فحص الموقع")
                return
        if cmd.intent == "check_ip" and target:
            self.ip_target.setText(target)
            self.start_ip_reputation()
            return
        if cmd.intent == "learn_file":
            filepath = entities.get("filepath", "")
            if filepath:
                self.run_background_task(
                    lambda: self.agent._learn_from_file(filepath), "استيعاب كتاب",
                    preserve_findings=True, result_handler=lambda _result: self.refresh_library(),
                )
            else:
                self.switch_page("library")
                self._say("اختر «إضافة كتب» من مكتبة المعرفة.")
            return
        self._ask_assistant(text)

    # ═══════════════════════════════════════════════════════════════════════════
    #  BACKGROUND TASK EXECUTION
    # ═══════════════════════════════════════════════════════════════════════════
    def run_background_task(
        self,
        fn: Callable[..., Any],
        title: str,
        preserve_findings: bool = False,
        result_handler: Callable[[Any], None] | None = None,
    ) -> None:
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, "مهمة قيد التنفيذ", "انتظر انتهاء المهمة الحالية قبل تشغيل مهمة أخرى.")
            return
        self.set_activity_state("running", f"يعمل — {title}")
        QApplication.setOverrideCursor(Qt.CursorShape.BusyCursor)
        self._busy_cursor_owned = True
        self.chat_display.append(f"\n[بدء] {title}")
        self.scan_progress.show()
        self.scan_hint.setText(f"جارٍ التنفيذ: {title}")
        self.active_task_title = title
        self.active_result_handler = result_handler
        for button in self.task_buttons:
            button.setEnabled(False)
        self.worker = WorkerThread(self._execute_gui_task, fn, preserve_findings, result_handler is None)
        self.worker.task_result.connect(self.on_worker_result)
        self.worker.start()

    def set_activity_state(self, state: str, text: str) -> None:
        self.status_badge.setText(text)
        if hasattr(self, "dock_state"):
            self.dock_state.setText({"idle": "النظام جاهز", "running": "تحليل مباشر", "error": "انتباه مطلوب"}.get(state, "النظام جاهز"))
            self.dock_state.setProperty("state", state)
            self.dock_state.style().unpolish(self.dock_state)
            self.dock_state.style().polish(self.dock_state)
        status_text = {"idle": "[ جاهز ]", "running": "[ يعمل ]", "error": "[ خطأ ]"}.get(state, "[ جاهز ]")
        status_color = {"idle": STATUS_OK, "running": "#d29922", "error": STATUS_ERROR}.get(state, STATUS_OK)
        self.sidebar_status.setText(status_text)
        self.sidebar_status.setStyleSheet(f"color: {status_color}; font-size: {FONT_SIZE_SMALL}px; padding: 8px 6px;")
        for widget in (self.status_badge, self.activity_lamp):
            widget.setProperty("state", state)
            widget.style().unpolish(widget)
            widget.style().polish(widget)

    def on_worker_result(self, result: Any) -> None:
        self.task_done(result, self.active_task_title)

    def _execute_gui_task(
        self,
        fn: Callable[..., Any],
        preserve_findings: bool = False,
        manage_findings: bool = True,
    ) -> Any:
        if not preserve_findings and manage_findings:
            self.agent._last_findings = []
        result = fn()
        if not manage_findings:
            return result
        findings = result if isinstance(result, list) else self.agent._last_findings
        self.agent._last_findings = findings or []
        return self.agent._last_findings

    # ═══════════════════════════════════════════════════════════════════════════
    #  SCAN STARTERS
    # ═══════════════════════════════════════════════════════════════════════════
    def start_website_scan(self) -> None:
        url = self.website_input.text().strip()
        if not url:
            QMessageBox.warning(self, "رابط مطلوب", "أدخل رابط الموقع قبل بدء الفحص.")
            return
        self.run_background_task(lambda: self.agent._test_website(url), "فحص الموقع")

    def start_port_scan(self) -> None:
        target = self.scan_target.text().strip() or "127.0.0.1"
        port_range = self.port_range.text().strip() or "1-1024"
        self.run_background_task(lambda: self.agent._scan_ports(target, port_range), "فحص المنافذ")

    def start_ip_reputation(self) -> None:
        target = self.ip_target.text().strip()
        try:
            ipaddress.ip_address(target)
        except ValueError:
            QMessageBox.warning(self, "IP غير صالح", "أدخل عنوان IPv4 أو IPv6 صالحاً.")
            return
        self.run_background_task(lambda: self.agent._check_ip(target), "سمعة IP")

    def start_yara_scan(self) -> None:
        path = self.tool_path.text().strip() or "."
        self.run_background_task(lambda: self.agent._run_yara_cli(path), "YARA")

    def _browse_yara_path(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "اختر مسار فحص YARA", self.path_input.text())
        if path:
            self.path_input.setText(path)

    def start_secret_scan(self) -> None:
        path = self.tool_path.text().strip() or "."
        self.run_background_task(lambda: self.agent._scan_secrets_cli(path), "كشف الأسرار")

    # ═══════════════════════════════════════════════════════════════════════════
    #  USB
    # ═══════════════════════════════════════════════════════════════════════════
    def refresh_usb_inventory(self) -> None:
        self.run_background_task(
            lambda: {"devices": list_usb_devices(), "drives": scan_mounted_drives(usb_only=True)},
            "تحديث USB",
            preserve_findings=True,
            result_handler=self.render_usb_inventory,
        )

    def render_usb_inventory(self, inventory: dict) -> None:
        devices = inventory.get("devices", [])
        drives = [d for d in inventory.get("drives", []) if d.get("is_usb")]
        self.usb_inventory_loaded = True
        self._selected_usb_device = {}
        self._selected_usb_partition_data = {}
        self._usb_selection_source = "none"
        self.usb_devices_table.setRowCount(0)
        for device in devices:
            row = self.usb_devices_table.rowCount()
            self.usb_devices_table.insertRow(row)
            name = device.get("product") or device.get("description") or device.get("manufacturer") or "جهاز غير معرّف"
            risk = str(device.get("risk", "low")).lower()
            risk_labels = {"critical": "[حرج]", "high": "[مرتفع]", "medium": "[متوسط]", "low": "[منخفض]"}
            values = [
                f"{device.get('bus', '—')} / {device.get('device', '—')}",
                name,
                device.get("class_name") or device.get("device_class") or "غير محدد",
                f"{device.get('vendor_id', '—')}:{device.get('product_id', '—')}",
                risk_labels.get(risk, risk),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, device)
                if column == 4:
                    item.setForeground(_sev_brush(risk))
                self.usb_devices_table.setItem(row, column, item)

        self.usb_drives_table.setRowCount(0)
        for drive in drives:
            partitions = drive.get("partitions", []) or [{"name": drive.get("name", ""), "mountpoint": drive.get("mountpoint", ""), "analysis": drive.get("analysis", {})}]
            for partition in partitions:
                row = self.usb_drives_table.rowCount()
                self.usb_drives_table.insertRow(row)
                mountpoint = partition.get("mountpoint") or "غير موصول"
                values = [drive.get("name", "—") + (f" / {partition.get('name')}" if partition.get("name") else ""),
                          " ".join(str(p) for p in (drive.get("vendor"), drive.get("model")) if p) or "غير محدد",
                          _storage_size_text(partition.get("size"), partition.get("size_bytes") or drive.get("size_bytes")),
                          mountpoint]
                partition_data = {**partition, "drive": drive}
                for column, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    if column == 0:
                        item.setData(Qt.ItemDataRole.UserRole, partition_data)
                    self.usb_drives_table.setItem(row, column, item)

        self.usb_status.setText(f"[أجهزة] {len(devices)} جهاز  |  [تخزين] {len(drives)} وحدة تخزين  |  [حالة] محدث")
        if not devices and not drives:
            self.usb_detail.setPlainText("لا توجد أجهزة USB أو وحدات تخزين متصلة حالياً.")

    def show_usb_device_details(self, row: int, _column: int) -> None:
        item = self.usb_devices_table.item(row, 0)
        if not item:
            return
        device = item.data(Qt.ItemDataRole.UserRole) or {}
        self._selected_usb_device = device
        details = [
            f"الجهاز: {device.get('product') or device.get('description') or 'غير معروف'}",
            f"الشركة: {device.get('manufacturer') or 'غير محددة'}",
            f"Bus/Device: {device.get('bus', '—')} / {device.get('device', '—')}",
            f"VID:PID: {device.get('vendor_id', '—')}:{device.get('product_id', '—')}",
            f"التصنيف: {device.get('class_name') or device.get('device_class') or 'غير محدد'}",
            f"المخاطر: {device.get('risk', 'low')}",
            f"المؤشرات: {'؛ '.join(device.get('flags', [])) or 'لا توجد'}",
            f"التوصيات: {'؛ '.join(device.get('recommendations', [])) or 'لا توجد'}",
        ]
        if not self._usb_device_is_storage(device):
            details.extend(["", "حالة الفحص: هذا جهاز طرفي وليس وحدة تخزين قابلة للفحص العميق.",
                            "حدد قسمًا موصولًا من جدول وحدات التخزين أدناه."])
        self.usb_detail.setPlainText("\n".join(details))

    def show_usb_drive_details(self, row: int, _column: int) -> None:
        item = self.usb_drives_table.item(row, 0)
        if not item:
            return
        partition = item.data(Qt.ItemDataRole.UserRole) or {}
        self._selected_usb_partition_data = partition
        self._usb_selection_source = "partition"
        self.render_usb_drive_analysis(partition.get("analysis", {}), partition.get("mountpoint", ""))

    def _capture_usb_device_selection(self) -> None:
        row = self.usb_devices_table.currentRow()
        item = self.usb_devices_table.item(row, 0) if row >= 0 else None
        self._selected_usb_device = item.data(Qt.ItemDataRole.UserRole) or {} if item else {}
        self._usb_selection_source = "device"
        if self._selected_usb_device and self._usb_device_is_storage(self._selected_usb_device) and self.usb_drives_table.rowCount() == 1:
            self.usb_drives_table.selectRow(0)
        elif self.usb_drives_table.selectionModel():
            self.usb_drives_table.clearSelection()
            self.usb_drives_table.setCurrentCell(-1, -1)
            self._selected_usb_partition_data = {}

    @staticmethod
    def _usb_device_is_storage(device: dict) -> bool:
        text = " ".join(str(device.get(key) or "") for key in ("product", "description", "class_name", "device_class")).lower()
        return any(token in text for token in ("mass storage", "storage", "flash", "sd/mmc", "card reader", "disk"))

    def _capture_usb_partition_selection(self) -> None:
        row = self.usb_drives_table.currentRow()
        item = self.usb_drives_table.item(row, 0) if row >= 0 else None
        self._selected_usb_partition_data = item.data(Qt.ItemDataRole.UserRole) or {} if item else {}
        self._usb_selection_source = "partition" if self._selected_usb_partition_data else "none"

    def render_usb_drive_analysis(self, analysis: dict, mountpoint: str) -> None:
        suspicious = analysis.get("suspicious_files", [])
        autorun = analysis.get("autorun_files", [])
        malware_hits = analysis.get("malware_hits", [])
        lines = [
            f"نقطة التوصيل: {mountpoint or 'غير موصولة'}",
            f"الملفات المفحوصة: {analysis.get('total_files_checked', analysis.get('total_files', 0))}",
            f"التنفيذية: {analysis.get('executable_count', 0)}",
            f"المشبوهة: {len(suspicious)}",
            f"التشغيل التلقائي: {len(autorun)}",
            f"المؤشرات الخبيثة: {len(malware_hits)}",
        ]
        if "score" in analysis:
            lines.append(f"درجة الخطورة: {analysis.get('score', 0)}")
        if "clamav_used" in analysis:
            lines.append(f"فحص ClamAV: {'مستخدم' if analysis.get('clamav_used') else 'غير مثبت أو غير مستخدم'}")
        for finding in analysis.get("findings", []):
            lines.extend(["", f"[{finding.get('severity', 'info').upper()}] {finding.get('title', '')}",
                          str(finding.get("detail") or ""), f"التوصية: {finding.get('fix') or 'لا توجد'}"])
        if not analysis:
            lines.append("لا يتوفر تحليل مسبق. حدد وحدة تخزين موصولة ثم شغّل التحليل.")
        self.usb_detail.setPlainText("\n".join(lines))

    def control_selected_usb_device(self, allow: bool) -> None:
        device = self._selected_usb_device
        if not device:
            QMessageBox.information(self, "اختر جهازاً", "حدد جهاز USB من القائمة أولاً.")
            return
        action = "السماح" if allow else "الحجب"
        name = device.get("product") or device.get("description") or "الجهاز المحدد"
        answer = QMessageBox.question(
            self, f"تأكيد {action} USB", f"هل تريد {action} «{name}»؟",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        operation = authorize_device if allow else deauthorize_device
        password = self._ask_sudo_password("تحتاج هذه العملية إلى صلاحيات النظام.")
        if password is None:
            return
        self.run_background_task(
            lambda: operation(device.get("bus", ""), device.get("device", ""), sudo_password=password),
            f"{action} USB",
            preserve_findings=True,
            result_handler=self.complete_usb_control,
        )

    def complete_usb_control(self, result: dict) -> None:
        if result.get("success"):
            QMessageBox.information(self, "اكتمل", "تم تحديث حالة الجهاز.")
            QTimer.singleShot(250, self.refresh_usb_inventory)
        else:
            QMessageBox.warning(self, "فشل", result.get("error") or "لم يتمكن النظام من تحديث حالة الجهاز.")

    def scan_selected_usb_storage(self) -> None:
        partition = self._selected_usb_partition()
        mountpoint = partition.get("mountpoint") if partition else ""
        if not mountpoint:
            QMessageBox.information(self, "لا توجد وحدة موصولة", "اختر قسماً موصولاً قبل بدء التحليل.")
            return
        self.run_background_task(
            lambda: analyze_mounted_filesystem(mountpoint),
            "تحليل تخزين USB",
            preserve_findings=True,
            result_handler=lambda analysis: self.render_usb_drive_analysis(analysis, mountpoint),
        )

    def _selected_usb_partition(self) -> dict:
        """إرجاع بيانات القسم المحدد في جدول التخزين، أو قاموساً فارغاً."""
        if self._usb_selection_source != "partition":
            return {}
        row = self.usb_drives_table.currentRow()
        item = self.usb_drives_table.item(row, 0) if row >= 0 else None
        if item:
            self._selected_usb_partition_data = item.data(Qt.ItemDataRole.UserRole) or {}
        elif not self._selected_usb_partition_data and self.usb_drives_table.rowCount() == 1:
            # كثير من المستخدمين يحددون جهاز USB في الجدول العلوي؛ إذا كان له
            # قسم تخزين واحد فقط، اربطه تلقائياً بدلاً من إظهار رسالة مضللة.
            self.usb_drives_table.selectRow(0)
            item = self.usb_drives_table.item(0, 0)
            self._selected_usb_partition_data = item.data(Qt.ItemDataRole.UserRole) or {} if item else {}
        return self._selected_usb_partition_data

    def _ask_sudo_password(self, message: str) -> str | None:
        """اطلب كلمة المرور وتحقق منها فعلياً عبر sudo قبل بدء أي عملية."""
        # بعض الأنظمة تستخدم NOPASSWD أو جلسة sudo صالحة؛ تحقق أولاً حتى لا
        # تبدو الواجهة وكأنها تقبل أي كلمة مرور بينما النظام لا يحتاجها أصلاً.
        if safe_exec.run(["true"], sudo=True, check_binary=False).ok:
            return ""
        for _attempt in range(3):
            password, accepted = QInputDialog.getText(
                self, "صلاحيات النظام", message + "\nأدخل كلمة مرور sudo لمرة واحدة:",
                QLineEdit.EchoMode.Password,
            )
            if not accepted:
                return None
            result = safe_exec.validate_sudo_password(password)
            if result.ok:
                return password
            QMessageBox.warning(self, "كلمة المرور مرفوضة", "كلمة المرور ليست صالحة لـ sudo أو لا يملك المستخدم صلاحية sudo.")
        return None

    def _remember_usb_analysis(self, partition: dict, analysis: dict) -> None:
        """حفظ آخر نتيجة في الصف حتى لا تختفي عند إعادة عرض التفاصيل."""
        partition["analysis"] = analysis
        self._selected_usb_partition_data = partition
        row = self.usb_drives_table.currentRow()
        item = self.usb_drives_table.item(row, 0) if row >= 0 else None
        if item:
            item.setData(Qt.ItemDataRole.UserRole, partition)

    def deep_scan_selected_usb_storage(self) -> None:
        partition = self._selected_usb_partition()
        mountpoint = partition.get("mountpoint", "")
        if not mountpoint:
            device_name = self._selected_usb_device.get("product") or self._selected_usb_device.get("description")
            if device_name and not self._usb_device_is_storage(self._selected_usb_device):
                message = f"الجهاز المحدد «{device_name}» ليس وحدة تخزين قابلة للفحص.\nحدد قسمًا موصولًا من جدول «وحدات التخزين وتحليلها» السفلي."
            elif partition:
                message = f"القسم «{partition.get('name') or 'المحدد'}» موجود لكنه غير موصول بنقطة تركيب.\nافتحه من النظام ثم اضغط تحديث، أو اختر قسمًا موصولًا."
            else:
                message = "حدد قسمًا موصولًا من جدول «وحدات التخزين وتحليلها» السفلي، وليس جهازًا من الجدول العلوي."
            QMessageBox.information(self, "لا توجد وحدة تخزين قابلة للفحص", message)
            return

        def handle_result(analysis: dict) -> None:
            self._remember_usb_analysis(partition, analysis)
            self.render_usb_drive_analysis(analysis, mountpoint)
            self.usb_status.setText(
                f"[فحص عميق] {analysis.get('total_files', 0)} ملف | "
                f"{len(analysis.get('findings', []))} نتيجة | اكتمل"
            )

        password = None if os.geteuid() == 0 else self._ask_sudo_password(
            "الفحص العميق قد يحتاج قراءة ملفات محمية على وحدة USB."
        )
        if os.geteuid() != 0 and password is None:
            return
        scan_fn = lambda: deep_scan_flash_privileged(mountpoint, sudo_password=password)
        self.run_background_task(
            scan_fn,
            "الفحص العميق لـ USB",
            preserve_findings=True,
            result_handler=handle_result,
        )

    def fix_selected_usb_storage(self) -> None:
        partition = self._selected_usb_partition()
        mountpoint = partition.get("mountpoint", "")
        analysis = partition.get("analysis") or {}
        findings = analysis.get("findings", [])
        actionable = [
            finding for finding in findings
            if finding.get("target_path") and finding.get("severity") in ("critical", "high")
        ]
        if not mountpoint or not findings:
            QMessageBox.information(self, "لا توجد نتيجة", "شغّل الفحص العميق أولاً وحدد وحدة تخزين موصولة.")
            return
        if not actionable:
            QMessageBox.information(self, "لا يوجد إصلاح تلقائي", "لم يجد الفحص ملفات Autorun أو سلوكاً خبيثاً مؤكداً قابلاً للإزالة.")
            return
        answer = QMessageBox.warning(
            self, "تأكيد الإصلاح المقيّد",
            f"سيتم حذف {len(actionable)} ملف مؤكد الخطورة داخل الفلاشة فقط.\nلا يمكن التراجع عن الحذف. هل تريد المتابعة؟",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        password = None if os.geteuid() == 0 else self._ask_sudo_password(
            "الإصلاح يحتاج صلاحيات حذف بعض الملفات المحمية."
        )
        if os.geteuid() != 0 and password is None:
            return

        def handle_result(actions: list) -> None:
            QMessageBox.information(self, "نتيجة الإصلاح", "\n".join(a.get("action", "") for a in actions) or "لم تُنفذ إجراءات.")
            QTimer.singleShot(250, self.refresh_usb_inventory)

        self.run_background_task(
            lambda: fix_flash_issues(mountpoint, actionable, sudo_password=password),
            "الإصلاح المقيّد لـ USB",
            preserve_findings=True,
            result_handler=handle_result,
        )

    def eject_selected_usb_storage(self) -> None:
        partition = self._selected_usb_partition()
        drive = partition.get("drive") or {}
        device_name = drive.get("name") or partition.get("name", "")
        device_path = device_name if str(device_name).startswith("/dev/") else f"/dev/{device_name}"
        if not device_name:
            QMessageBox.information(self, "اختر وحدة تخزين", "حدد وحدة تخزين من الجدول أولاً.")
            return
        answer = QMessageBox.question(
            self, "تأكيد الإخراج الآمن", f"هل تريد إخراج {device_path} بأمان؟",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        password = None if os.geteuid() == 0 else self._ask_sudo_password(
            "الإخراج الآمن قد يحتاج صلاحيات فصل وحدة التخزين."
        )
        if os.geteuid() != 0 and password is None:
            return
        self.run_background_task(
            lambda: eject_storage_device(device_path, sudo_password=password),
            "الإخراج الآمن لـ USB",
            preserve_findings=True,
            result_handler=self.complete_usb_eject,
        )

    def complete_usb_eject(self, result: dict) -> None:
        if result.get("success"):
            QMessageBox.information(self, "اكتمل", "تم إخراج وحدة USB بأمان.")
            QTimer.singleShot(250, self.refresh_usb_inventory)
        else:
            steps = "\n".join(str(step.get("out") or step.get("cmd")) for step in result.get("steps", []))
            QMessageBox.warning(self, "فشل الإخراج", result.get("error") or steps or "تعذر إخراج الوحدة بأمان.")

    # ═══════════════════════════════════════════════════════════════════════════
    #  FINDINGS DISPLAY
    # ═══════════════════════════════════════════════════════════════════════════
    def show_finding_details(self, row: int, _column: int = 0) -> None:
        if row < 0 or row >= len(self.current_findings):
            return
        self.finding_detail.setHtml(finding_html(self.current_findings[row]))
        self.finding_position.setText(f"النتيجة {row + 1} من {len(self.current_findings)}")

    def task_done(self, result: Any, title: str) -> None:
        if getattr(self, "_busy_cursor_owned", False):
            QApplication.restoreOverrideCursor()
            self._busy_cursor_owned = False
        self.scan_progress.hide()
        for button in self.task_buttons:
            button.setEnabled(True)
        if isinstance(result, Exception):
            self.active_result_handler = None
            self.set_activity_state("error", "فشل")
            self.chat_display.append(f"[خطأ] {title}: {result}")
            self.scan_hint.setText(f"تعذر إكمال: {title}")
            return
        if self.active_result_handler:
            handler, self.active_result_handler = self.active_result_handler, None
            try:
                handler(result)
            except Exception as exc:
                self.set_activity_state("error", "فشل")
                self.chat_display.append(f"[خطأ عرض] {title}: {exc}")
                return
            self.set_activity_state("idle", "جاهز")
            self.scan_hint.setText(f"[اكتمل] {title}")
            self.chat_display.append(f"[اكتمل] {title}")
            return
        findings = result if isinstance(result, list) else []
        self.render_findings(findings)
        self.set_activity_state("idle", "جاهز")
        self.scan_hint.setText(f"[اكتمل] {title} | النتائج: {len(findings)}")
        self.chat_display.append(f"[اكتمل] {title} | النتائج: {len(findings)}")
        self._say(summarize_findings(findings, title))

    def render_findings(self, findings: list) -> None:
        self.all_findings = sort_findings(findings)
        if hasattr(self, "page_findings"):
            self.page_findings.set_findings(self.all_findings)
        counts = {key: sum(1 for f in findings if _sev_key(f) == key) for key in SEV_ORDER}
        if findings:
            chips = "  ".join(
                f"<span style='color:{severity_color(k)};font-weight:700'>{SEV_AR[k]} {counts[k]}</span>" for k in SEV_ORDER if counts[k])
            self.findings_chips.setText(f"{len(findings)} نتيجة:  {chips}")
        else:
            self.findings_chips.setText("لا توجد نتائج في آخر فحص.")
        self._apply_findings_filter()
        self._update_score(findings)

    def _apply_findings_filter(self) -> None:
        wanted = self.sev_filter.currentData() if hasattr(self, "sev_filter") else "all"
        shown = [f for f in self.all_findings if wanted in ("all", None) or _sev_key(f) == wanted]
        self.current_findings = shown
        table = self.table_findings
        table.setUpdatesEnabled(False)
        try:
            table.setRowCount(len(shown))
            self.finding_detail.clear()
            self.finding_position.setText("")
            for row, finding in enumerate(shown):
                key = _sev_key(finding)
                color = severity_color(key)
                confidence = finding.get("confidence")
                conf = f"{float(confidence):.0%}" if isinstance(confidence, (int, float)) else "—"
                sev_item = table_cell(SEV_AR[key], color, center=True, bold=True, tip=SEV_WHY[key])
                sev_item.setBackground(QColor(alpha(color, 34)))
                title = str(finding.get("title", ""))
                cells = [sev_item, table_cell(title, tip=str(finding.get("detail") or title)),
                         table_cell(finding.get("category", ""), TEXT_SECONDARY), table_cell(conf, center=True)]
                for col, cell in enumerate(cells):
                    table.setItem(row, col, cell)
        finally:
            table.setUpdatesEnabled(True)
        if not shown:
            self.finding_detail.setPlaceholderText("لا توجد نتائج لعرضها بهذا الفلتر." if self.all_findings else "لم يسجل هذا الفحص نتائج أمنية.")
        else:
            table.selectRow(0)
            table.setCurrentCell(0, 0)

    def _update_score(self, findings: list) -> None:
        evaluation = RiskEngine.evaluate(findings)
        self.metric_labels["findings"].setText(str(len(findings)))
        if hasattr(self, "metric_tags"):
            if not findings:
                self.metric_tags["findings"].setText("سليم")
            elif any(_sev_key(f) in ("critical", "high") for f in findings):
                self.metric_tags["findings"].setText("يحتاج مراجعة")
            else:
                self.metric_tags["findings"].setText("ملاحظات خفيفة")

        score = evaluation.get('score', 100)
        grade = evaluation.get('grade', 'A+')
        self.metric_labels["score"].setText(f"{score}/100")
        if hasattr(self, "metric_tags"):
            self.metric_tags["score"].setText("تم التقييم")
        self.score_badge.setText(f"الدرجة: {score}/100 ({grade})")
        self.mission_kicker.setText("حالة الدفاع التكتيكية  •  تم تقييم الوضع الأمني")
        self.security_gauge.set_value(score)
        score_color = score_state_color(score)
        self._telemetry_history["الجاهزية الأمنية (%)"].append(float(score))
        del self._telemetry_history["الجاهزية الأمنية (%)"][:-24]
        if hasattr(self, "telemetry_chart"):
            active_series = {}
            if self._telemetry_history["الجاهزية الأمنية (%)"]:
                active_series["الجاهزية الأمنية (%)"] = (
                    self._telemetry_history["الجاهزية الأمنية (%)"], score_color)
            if self._telemetry_history["النشاط التشغيلي (%)"]:
                active_series["النشاط التشغيلي (%)"] = (self._telemetry_history["النشاط التشغيلي (%)"], ACCENT_SECONDARY)
            self.telemetry_chart.set_data(active_series)
        # Color the score badge based on score
        self.score_badge.setStyleSheet(
            f"color: {score_color}; font-weight: 700; padding: 8px 14px; "
            f"background: {alpha(score_color, 24)}; border: 1px solid {alpha(score_color, 140)}; border-radius: 15px;"
        )

    # ═══════════════════════════════════════════════════════════════════════════
    #  PLAYBOOKS
    # ═══════════════════════════════════════════════════════════════════════════
    def load_playbook(self) -> None:
        topic = self.pb_input.text().strip()
        if not topic:
            return
        from brain.playbook_engine import PlaybookEngine
        pb = PlaybookEngine(kb=self.agent.kb).generate_playbook(topic)
        lines = [f"[خطة العمل] {topic}", f"عدد الأوامر: {pb.get('total_commands', 0)}", ""]
        for stage, steps in pb.get("stages", {}).items():
            if steps:
                lines.append(f"── {stage} ──")
                for step in steps:
                    lines.append(f"  $ {step.get('cmd', '')}\n    المصدر: {step.get('book', '')} — صفحة {step.get('page', '')}")
        self.pb_text.setPlainText("\n".join(lines))

    # ═══════════════════════════════════════════════════════════════════════════
    #  REPORTS
    # ═══════════════════════════════════════════════════════════════════════════
    def choose_reports_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "اختيار مجلد التقارير", self.reports_dir.text())
        if path:
            self.reports_dir.setText(path)
            self.refresh_reports()

    def refresh_reports(self) -> None:
        directory = Path(self.reports_dir.text()).expanduser()
        self.reports_table.setRowCount(0)
        if not directory.exists():
            self.report_preview.setPlaceholderText("المجلد المحدد غير موجود. حدد مجلداً صالحاً للتقارير.")
            return
        files = [p for p in directory.iterdir() if p.is_file()]
        if not files:
            self.report_preview.setPlaceholderText("لا توجد تقارير أمنية في هذا المجلد حالياً. يمكنك تصدير تقرير جديد من تبويب ترسانة الأدوات.")
        for path in sorted(files, key=lambda p: p.stat().st_mtime, reverse=True):
            row = self.reports_table.rowCount()
            self.reports_table.insertRow(row)
            self.reports_table.setItem(row, 0, QTableWidgetItem(str(path)))
            self.reports_table.setItem(row, 1, QTableWidgetItem(f"{path.stat().st_size / 1024:.1f} KB"))
            self.reports_table.setItem(row, 2, QTableWidgetItem(str(path.stat().st_mtime)))

    def open_report(self, row: int, _column: int) -> None:
        path = self.reports_table.item(row, 0)
        if path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path.text()))

    # ═══════════════════════════════════════════════════════════════════════════
    #  LIBRARY
    # ═══════════════════════════════════════════════════════════════════════════
    def choose_books(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "إضافة كتب أو ملفات إلى المكتبة المحلية", str(Path.home()),
            "الكتب والملفات المدعومة (*.pdf *.txt *.md *.markdown)",
        )
        if not paths:
            return

        def ingest_books() -> dict:
            imported, errors = [], []
            for path in paths:
                try:
                    imported.append(library.ingest_file(path, self.agent.kb))
                except Exception as exc:
                    errors.append({"path": path, "error": str(exc)})
            return {"imported": imported, "errors": errors}

        self.run_background_task(
            ingest_books, "استيعاب الكتب",
            preserve_findings=True, result_handler=self.show_ingest_results,
        )

    def show_ingest_results(self, result: dict) -> None:
        self.refresh_library()
        lines = []
        for doc in result.get("imported", []):
            lines.append(f"[تم] أضيفت: {doc['title']} | {doc['chunks']} مقطع | {doc['total_chars']:,} حرف")
            lines.extend(doc.get("diagnostics", []))
        for failure in result.get("errors", []):
            lines.append(f"[خطأ] تعذر: {failure['path']}: {failure['error']}")
        self.library_results.setPlainText("\n\n".join(lines) or "لم تتم إضافة أي ملف.")

    def rebuild_library_index(self) -> None:
        if not self.agent.kb.list_library_documents():
            QMessageBox.information(self, "المكتبة فارغة", "أضف كتاباً أو ملفاً قبل بناء الفهرس.")
            return
        self.run_background_task(
            self.agent._rebuild_index, "بناء الفهرس",
            preserve_findings=True, result_handler=lambda _r: self.refresh_library(),
        )

    def refresh_library(self) -> None:
        documents = self.agent.kb.list_library_documents()
        self.library_table.setRowCount(0)
        if not documents:
            self.library_results.setPlaceholderText("المكتبة المحلية فارغة حالياً. اضغط على «إضافة كتب» لاستيعاب وفهرسة مراجعك الأمنية.")
        else:
            self.library_results.setPlaceholderText("ستظهر المقاطع المطابقة مع اسم الكتاب ورقم الصفحة هنا.")
        for doc in documents:
            row = self.library_table.rowCount()
            self.library_table.insertRow(row)
            title = QTableWidgetItem(str(doc.get("title", "")))
            title.setData(Qt.ItemDataRole.UserRole, doc["id"])
            values = [title, QTableWidgetItem(str(doc.get("file_type", ""))),
                      QTableWidgetItem(str(doc.get("chunk_count", 0))),
                      QTableWidgetItem(str(doc.get("added_at", "")))]
            for col, item in enumerate(values):
                self.library_table.setItem(row, col, item)

        if not documents:
            status = "[المكتبة] لا توجد كتب مفهرسة حتى الآن"
        elif relevance_engine.is_index_current(self.agent.kb):
            meta = relevance_engine.get_index_meta()
            status = f"[المكتبة] {len(documents)} كتاب | الفهرس مبني: {meta.get('chunks_indexed', 0)} مقطع"
        elif relevance_engine.is_index_built():
            status = f"[المكتبة] {len(documents)} كتاب | الفهرس قديم — أعد بناءه"
        else:
            status = f"[المكتبة] {len(documents)} كتاب | البحث النصي متاح"
        self.library_status.setText(status)

    def show_library_document(self, row: int, _column: int) -> None:
        item = self.library_table.item(row, 0)
        if not item:
            return
        document_id = item.data(Qt.ItemDataRole.UserRole)
        content = self.agent.kb.get_doc_full_text(document_id, max_chars=5000)
        self.library_results.setPlainText(f"معاينة من {item.text()}\n\n{content}")

    def search_library(self) -> None:
        query = self.library_query.text().strip()
        if not query:
            return
        if relevance_engine.is_index_current(self.agent.kb):
            results = relevance_engine.search(query, self.agent.kb, top_k=8)
            if any("error" in item for item in results):
                results = self.agent.kb.search_library(query, limit=8)
                ranked = False
            else:
                ranked = True
        else:
            results = self.agent.kb.search_library(query, limit=8)
            ranked = False

        if not results:
            self.library_results.setPlainText("لم أجد مقاطع مطابقة.")
            return
        output = ["نتائج مرتبة حسب الصلة" if ranked else "نتائج بحث نصي — أعد بناء الفهرس للترتيب"]
        for i, result in enumerate(results, 1):
            if "error" in result:
                output.append(result["error"])
                continue
            location = result.get("page_hint") or f"المقطع {result.get('chunk_index', '')}"
            relevance = f" | الصلة: {result['relevance']:.3f}" if ranked and "relevance" in result else ""
            output.append(f"\n{i}. {result.get('title', 'كتاب غير معروف')} | {location}{relevance}\n{result.get('content', '').strip()}")
        self.library_results.setPlainText("\n".join(output))


def load_application_fonts() -> None:
    """Load embedded OFL fonts (Tajawal) before creating UI widgets."""
    from PyQt6.QtGui import QFontDatabase
    fonts_dir = ROOT_DIR / "resources" / "fonts"
    if fonts_dir.exists():
        for font_file in ("Tajawal-Regular.ttf", "Tajawal-Bold.ttf"):
            path = fonts_dir / font_file
            if path.exists():
                QFontDatabase.addApplicationFont(str(path))


def launch_gui() -> None:
    preflight = check_requirements({"gui"})
    if not preflight.ok:
        print(preflight.text(), file=sys.stderr)
        raise SystemExit(2)
    app = QApplication.instance() or QApplication(sys.argv)
    load_application_fonts()
    window = UnifiedCockpitWindow()
    splash = AyfamIntroSplash(auto_close=True)
    splash.ready_to_launch.connect(window.show)
    splash.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    launch_gui()
