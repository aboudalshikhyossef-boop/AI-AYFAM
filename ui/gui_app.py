"""واجهة AI AYFAM الرسومية — مركز تحكم موحّد للفحوصات والتقارير (v2 — redesigned)."""

from __future__ import annotations

import html
import os
import sys
import ipaddress
import json
import math
from pathlib import Path
from typing import Callable, Any

from PyQt6.QtCore import Qt, QTimer, QThread, QPropertyAnimation, pyqtSignal, QUrl, QSize, QRect, QEasingCurve, QRectF
from PyQt6.QtGui import QColor, QDesktopServices, QFont, QIcon, QAction, QShortcut, QKeySequence, QPainter, QPixmap, QPen, QLinearGradient, QRadialGradient
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QGraphicsOpacityEffect, QGridLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QSplitter, QStackedWidget,
    QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget, QScrollArea, QSizePolicy,
    QInputDialog, QCheckBox,
    QSplashScreen,
)

from config.settings import Settings
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
from ui.terminal import TerminalUI
from ui.icons import framed_icon, glyph_icon
from ui.widgets import (
    AccentLine, AmbientSurface, ChatView, HoverController, NavIndicator, PressFeedbackController,
    SecurityGauge, SoundUX, TelemetryChart,
)
from ui.intro_splash import AyfamIntroSplash, SystemOverviewDialog
from ui.theme import (
    QSS, get_qss, ACCENT, ACCENT_SECONDARY, ACCENT_SOFT, ACCENT_HUES, BG_BASE, BG_SURFACE, BG_ELEVATED, BG_HOVER,
    BORDER, BORDER_FOCUS, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO, SEV_SAFE,
    STATUS_OK, STATUS_ERROR, STATUS_IDLE,
    FONT_FAMILY, FONT_SIZE_BASE, FONT_SIZE_SMALL, FONT_SIZE_TITLE, FONT_SIZE_HERO, FONT_SIZE_METRIC,
    SP_XS, SP_SM, SP_MD, SP_LG, SP_XL, SP_2XL,
    CARD_ACCENTS, alpha, severity_color, severity_bg,
)
from utils import safe_exec
from utils.preflight import check_requirements, root_error, is_root


ROOT_DIR = Path(__file__).resolve().parents[1]

# Navigation items: (key, icon, label_ar)
NAV_ITEMS = [
    ("dashboard", "غرفة العمليات"),
    ("scans",     "الفحوصات الأمنية"),
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


def table_cell(text, color: str | None = None, center: bool = False, bold: bool = False, tip: str | None = None) -> QTableWidgetItem:
    item = QTableWidgetItem(str(text))
    if color:
        item.setForeground(QColor(color))
    if bold:
        font = item.font()
        font.setBold(True)
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
        self.nav_buttons: list[QPushButton] = []
        self.page_veil_animation: QPropertyAnimation | None = None
        self._telemetry_history = {
            "الجاهزية الأمنية (%)": [],
            "النشاط التشغيلي (%)": [46, 51, 49, 56, 54, 61, 58, 64, 60, 67, 65, 70],
        }
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_live_telemetry)
        self.timer.start(3000)
        self.event_timer = QTimer(self)
        self.event_timer.timeout.connect(self.update_agent_events)
        self.event_timer.start(300)
        # Ambient light and hover rims animate smoothly; semantic colors stay stable.
        # Avoid restyling the entire window every 15 seconds (flicker/layout churn).
        for table in self.findChildren(QTableWidget):      # كل الجداول بنفس معيار القراءة
            if table.verticalHeader().defaultSectionSize() < 38:
                prepare_table(table)
        self.hover_controller = HoverController(self)
        self.chat_display.hover_controller = self.hover_controller
        self.press_feedback = PressFeedbackController(self)
        self.sound_ux = SoundUX(self, enabled=bool(self.settings.get("sound_ux", True)))
        self.sound_ux.set_profile(str(self.settings.get("sound_profile", "soft")))
        self.sound_ux.bind_buttons(self)
        if hasattr(self, "setting_sound_ux"):
            self.setting_sound_ux.toggled.connect(self.sound_ux.set_enabled)
        if hasattr(self, "setting_dark_mode"):
            self.setting_dark_mode.toggled.connect(self._toggle_dark_mode)
        self._busy_cursor_owned = False
        self.telemetry_worker: LiveTelemetryWorker | None = None
        self._last_telemetry_error = ""
        self._install_accessibility_shortcuts()

        self.update_live_telemetry()
        self._sync_control_labels()

    def _install_accessibility_shortcuts(self) -> None:
        """Keyboard access to common actions without changing mouse workflows."""
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
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Sidebar ──
        sidebar = QFrame(objectName="sidebar")
        sidebar.setFixedWidth(244)
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

        # Navigation grouped by operator intent rather than by implementation detail.
        self.nav_button_map: dict[str, QPushButton] = {}
        icons_dir = ROOT_DIR / "resources" / "icons"
        nav_groups = [
            ("المراقبة", ("dashboard", "scans", "usb")),
            ("التحليل والاستجابة", ("tools", "chat", "playbooks")),
            ("المعرفة والتقارير", ("library", "reports")),
            ("النظام", ("settings",)),
        ]
        labels = dict(NAV_ITEMS)
        for group_title, keys in nav_groups:
            group_label = QLabel(group_title.upper())
            group_label.setObjectName("navGroupLabel")
            sidebar_layout.addWidget(group_label)
            for key in keys:
                btn = QPushButton(f"  {labels[key]}")
                btn.setObjectName("navButton")
                btn.setCheckable(True)
                btn.setIcon(framed_icon(key))
                btn.setIconSize(QSize(30, 30))
                btn.clicked.connect(lambda checked=False, k=key: self.switch_page(k))
                sidebar_layout.addWidget(btn)
                self.nav_button_map[key] = btn
                self.nav_buttons.append(btn)

        assistant_btn = QPushButton("  افتح المساعد الذكي")
        assistant_btn.setObjectName("assistantNavButton")
        assistant_btn.setIcon(glyph_icon("chat", "#34d399", 20))
        assistant_btn.setIconSize(QSize(20, 20))
        assistant_btn.clicked.connect(lambda: self.switch_page("chat"))
        sidebar_layout.addWidget(assistant_btn)

        sidebar_layout.addStretch()

        # Status indicator at bottom of sidebar
        self.sidebar_status = QLabel("[ جاهز ]")
        self.sidebar_status.setStyleSheet(f"color: {STATUS_OK}; font-size: {FONT_SIZE_SMALL}px; padding: 8px 6px;")
        sidebar_layout.addWidget(self.sidebar_status)

        self.nav_indicator = NavIndicator(sidebar)
        root.addWidget(sidebar)

        # ── Main content area ──
        main_area = AmbientSurface()
        self.aurora_bg = main_area  # compatibility: background IS the content container
        main_area.setObjectName("mainArea")
        main_layout = QVBoxLayout(main_area)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Header bar ──
        header = QFrame(objectName="headerBar")
        header.setFixedHeight(78)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(SP_XL, SP_MD, SP_XL, SP_MD)
        header_layout.setSpacing(SP_LG)

        title_box = QVBoxLayout()
        title_box.setSpacing(1)
        page_eyebrow = self.page_eyebrow = QLabel("AI AYFAM  /  DASHBOARD")
        page_eyebrow.setObjectName("eyebrow")
        title_box.addWidget(page_eyebrow)
        self.page_title = QLabel("غرفة العمليات")
        self.page_title.setObjectName("sectionTitle")
        title_box.addWidget(self.page_title)
        header_layout.addLayout(title_box)
        header_layout.addStretch()

        # Quick System Guide & Intro preview buttons
        self.guide_btn = QPushButton("دليل المنظومة")
        self.guide_btn.setObjectName("pillButton")
        self.guide_btn.setIcon(glyph_icon("library", ACCENT, 16))
        self.guide_btn.setToolTip("عرض هيكلية ومكونات المنظومة الأمنية")
        self.guide_btn.clicked.connect(self.show_system_overview)
        header_layout.addWidget(self.guide_btn)

        self.intro_btn = QPushButton("عرض الترحيب")
        self.intro_btn.setObjectName("pillButton")
        self.intro_btn.setIcon(glyph_icon("dashboard", ACCENT_SECONDARY, 16))
        self.intro_btn.setToolTip("إعادة عرض شاشة المقدمة وتسلسل الإقلاع التشخيصي")
        self.intro_btn.clicked.connect(self.show_intro_splash)
        header_layout.addWidget(self.intro_btn)

        # Activity lamp
        self.activity_lamp = QFrame(objectName="activityLamp")
        self.activity_lamp.setFixedSize(10, 10)
        opacity = QGraphicsOpacityEffect(self.activity_lamp)
        self.activity_lamp.setGraphicsEffect(opacity)
        self.activity_animation = QPropertyAnimation(opacity, b"opacity", self)
        self.activity_animation.setStartValue(0.4)
        self.activity_animation.setKeyValueAt(0.5, 1.0)
        self.activity_animation.setEndValue(0.4)
        self.activity_animation.setDuration(1800)
        self.activity_animation.setLoopCount(-1)
        self.activity_animation.start()
        header_layout.addWidget(self.activity_lamp)

        # ── Live clock & date ──
        self.clock_box = QVBoxLayout()
        self.clock_box.setSpacing(0)
        self.clock_time_label = QLabel("--:--:--")
        self.clock_time_label.setObjectName("clockTime")
        self.clock_time_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.clock_date_label = QLabel("")
        self.clock_date_label.setObjectName("clockDate")
        self.clock_date_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.clock_box.addWidget(self.clock_time_label)
        self.clock_box.addWidget(self.clock_date_label)
        header_layout.addLayout(self.clock_box)

        # Update clock every second
        self.clock_timer = QTimer(self)
        self.clock_timer.timeout.connect(self.update_clock)
        self.clock_timer.start(1000)
        self.update_clock()

        self.status_badge = QLabel("جاهز")
        self.status_badge.setObjectName("statusBadge")
        self.status_badge.setProperty("state", "idle")
        header_layout.addWidget(self.status_badge)

        mode_badge = QLabel("DARK / OBSIDIAN")
        mode_badge.setObjectName("modeBadge")
        mode_badge.setToolTip("يمكن تغيير الوضع والصوت من صفحة إعدادات النظام")
        header_layout.addWidget(mode_badge)

        self.score_badge = QLabel("الدرجة —")
        self.score_badge.setObjectName("scoreBadge")
        header_layout.addWidget(self.score_badge)

        main_layout.addWidget(header)
        main_layout.addWidget(AccentLine())

        # ── Stacked content ──
        self.stack = QStackedWidget()
        self.stack.setContentsMargins(0, 0, 0, 0)

        self.page_dashboard = QWidget()
        self.page_scans = QWidget()
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

        self.stack.addWidget(self.page_dashboard)
        self.stack.addWidget(self.page_scans)
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
        self.transition_veil = QFrame(scroll.viewport(), objectName="transitionVeil")
        self.transition_veil.setGeometry(scroll.viewport().rect())
        self.transition_veil.hide()

        main_layout.addWidget(scroll, 1)

        # ── Footer ──
        footer = QLabel(f"  {os.uname().nodename}  |  {APP_VERSION_LABEL}  |  التنفيذ محلي")
        footer.setObjectName("footer")
        footer.setFixedHeight(26)
        main_layout.addWidget(footer)

        root.addWidget(main_area)
        self.setCentralWidget(central)

        # Default page
        self.switch_page("dashboard")

    def _place_nav_indicator(self) -> None:
        button = self.nav_button_map.get(getattr(self, "_current_nav", "dashboard"))
        if button is not None and button.height() > 0:
            self.nav_indicator.move_to(button)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        QTimer.singleShot(60, self._place_nav_indicator)

    def closeEvent(self, event) -> None:
        running_workers = [worker for worker in (getattr(self, "worker", None), getattr(self, "telemetry_worker", None))
                           if worker is not None and worker.isRunning()]
        for worker in running_workers:
            worker.requestInterruption()
            worker.quit()
        if any(not worker.wait(3000) for worker in running_workers):
            self.chat_display.append("[النظام] توجد عملية فحص جارية؛ أوقفها من المصدر ثم أغلق التطبيق لتجنب قطعها قسراً.")
            event.ignore()
            return
        super().closeEvent(event)

    def switch_page(self, key: str) -> None:
        page_map = {
            "dashboard": self.page_dashboard, "scans": self.page_scans,
            "usb": self.page_usb, "tools": self.page_tools,
            "chat": self.page_chat, "library": self.page_library,
            "playbooks": self.page_playbooks, "reports": self.page_reports,
            "settings": self.page_settings,
        }
        title_map = {
            "dashboard": "غرفة العمليات", "scans": "الفحوصات الأمنية",
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
                self._run_page_transition()
                if hasattr(self, "page_animation"):
                    self.page_animation.stop()
                effect = QGraphicsOpacityEffect(self.stack)
                self.stack.setGraphicsEffect(effect)
                animation = QPropertyAnimation(effect, b"opacity", self)
                animation.setDuration(240)
                animation.setStartValue(0.35)
                animation.setEndValue(1.0)
                animation.setEasingCurve(QEasingCurve.Type.OutCubic)
                # Remove the effect afterwards so normal text rendering and hover stay crisp.
                animation.finished.connect(lambda: self.stack.setGraphicsEffect(None))
                self.page_animation = animation
                animation.start()
                self.content_scroll.verticalScrollBar().setValue(0)
            self.page_title.setText(title_map.get(key, ""))
            self.page_eyebrow.setText(f"AI AYFAM  /  {key.upper()}")
            for name, page in page_map.items():
                page.setSizePolicy(QSizePolicy.Policy.Preferred if name == key else QSizePolicy.Policy.Ignored,
                                   QSizePolicy.Policy.Preferred if name == key else QSizePolicy.Policy.Ignored)
            self.stack.updateGeometry()
            for k, btn in self.nav_button_map.items():
                btn.setChecked(k == key)
            self._current_nav = key
            QTimer.singleShot(0, self._place_nav_indicator)
            if key == "usb" and not self.usb_inventory_loaded:
                self.refresh_usb_inventory()

    def _run_page_transition(self) -> None:
        """Reveal the new page through a short, calm veil instead of a hard swap."""
        veil = self.transition_veil
        if self.page_veil_animation is not None:
            self.page_veil_animation.stop()
        veil.setGeometry(self.content_scroll.viewport().rect())
        veil.show()
        veil.raise_()
        effect = QGraphicsOpacityEffect(veil)
        effect.setOpacity(0.76)
        veil.setGraphicsEffect(effect)
        animation = QPropertyAnimation(effect, b"opacity", self)
        animation.setDuration(220)
        animation.setStartValue(0.76)
        animation.setEndValue(0.0)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)

        def finish() -> None:
            veil.hide()
            veil.setGraphicsEffect(None)

        animation.finished.connect(finish)
        self.page_veil_animation = animation
        animation.start()

    def _sync_control_labels(self) -> None:
        if hasattr(self, "setting_sound_ux"):
            self.setting_sound_ux.setText(
                "تفعيل أصوات التفاعل الخفيفة" if self.setting_sound_ux.isChecked()
                else "أصوات التفاعل متوقفة"
            )

    def _toggle_sound(self, enabled: bool) -> None:
        self.sound_ux.set_enabled(enabled)
        self.settings.set("sound_ux", bool(enabled))
        self._sync_control_labels()
        if enabled:
            self.sound_ux.play("success")

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
        self.mission_kicker = QLabel("حالة الدفاع التكتيكية  •  LOCAL DEFENSE POSTURE: AWAITING FIRST SCAN")
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
        metric_data = [
            ("connections", "اتصالات الشبكة", "مقابس الشبكة النشطة والمراقبة", SEV_LOW),
            ("processes", "العمليات الحية", "أعلى العمليات استهلاكاً للموارد", CARD_ACCENTS["processes"]),
            ("findings", "الثغرات المكتشفة", "في آخر فحص مكتمل للمنظومة", SEV_MEDIUM),
            ("score", "الجاهزية الأمنية", "مؤشر تقييم خطوط الدفاع العام", SEV_SAFE),
        ]
        for col, (key, label, note, accent) in enumerate(metric_data):
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

            tag = QLabel("نشط")
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
        self.table_conns.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table_conns.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table_conns.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table_conns.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        prepare_table(self.table_conns)
        for col in (0, 1, 2):
            self.table_conns.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        conn_layout.addWidget(self.table_conns)
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
        proc_layout.addWidget(self.table_procs)
        self.dashboard_splitter.addWidget(proc_group)

        self.dashboard_splitter.setStretchFactor(0, 3)
        self.dashboard_splitter.setStretchFactor(1, 2)
        self.dashboard_splitter.setSizes([400, 260])
        self.dashboard_splitter.setMinimumHeight(500)
        layout.addWidget(self.dashboard_splitter, 1)

    # ═══════════════════════════════════════════════════════════════════════════
    #  SCANS PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def setup_scans_page(self) -> None:
        layout = QVBoxLayout(self.page_scans)
        layout.setContentsMargins(SP_XL, SP_LG, SP_XL, SP_LG)
        layout.setSpacing(SP_LG)

        # Form card
        form = QGroupBox("تهيئة الفحص")
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
        self.path_input = QLineEdit(str(ROOT_DIR))
        self.path_input.setAccessibleName("مسار فحص YARA")
        self.path_input.setPlaceholderText("مسار الفحص")

        grid.addWidget(QLabel("هدف المنافذ:"), 0, 0)
        grid.addWidget(self.scan_target, 0, 1)
        grid.addWidget(QLabel("نطاق المنافذ:"), 0, 2)
        grid.addWidget(self.port_range, 0, 3)
        grid.addWidget(QLabel("سمعة IP:"), 1, 0)
        grid.addWidget(self.ip_target, 1, 1, 1, 3)
        grid.addWidget(QLabel("فحص موقع:"), 2, 0)
        grid.addWidget(self.website_input, 2, 1, 1, 3)
        grid.addWidget(QLabel("مسار YARA:"), 3, 0)
        grid.addWidget(self.path_input, 3, 1, 1, 3)

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
        layout.addWidget(form)

        # Progress
        self.scan_progress = QProgressBar()
        self.scan_progress.setTextVisible(False)
        self.scan_progress.setRange(0, 0)
        self.scan_progress.hide()
        layout.addWidget(self.scan_progress)

        self.scan_hint = QLabel("اختر نوع الفحص المناسب من الأزرار أعلاه.")
        self.scan_hint.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px;")
        layout.addWidget(self.scan_hint)

        # Findings table
        self.setup_findings_table(layout)

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
        layout.addWidget(devices_group, 2)

        actions = QHBoxLayout()
        actions.setSpacing(SP_SM)
        self.usb_allow_button = QPushButton("السماح")
        self.usb_allow_button.clicked.connect(lambda: self.control_selected_usb_device(True))
        self.usb_block_button = QPushButton("حجب")
        self.usb_block_button.setObjectName("danger")
        self.usb_block_button.clicked.connect(lambda: self.control_selected_usb_device(False))
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
            self.usb_allow_button, self.usb_block_button, self.usb_scan_button,
            self.usb_deep_scan_button, self.usb_fix_button, self.usb_eject_button,
        ):
            self.task_buttons.append(button)
            actions.addWidget(button)
        layout.addLayout(actions)

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
        self.usb_detail = QPlainTextEdit(readOnly=True)
        self.usb_detail.setPlaceholderText("حدد جهازاً أو وحدة تخزين لعرض التفاصيل والمخاطر.")
        self.usb_detail.setMaximumHeight(160)
        drives_layout.addWidget(self.usb_detail)
        layout.addWidget(drives_group, 2)

    # ═══════════════════════════════════════════════════════════════════════════
    #  TOOLS PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def setup_tools_page(self) -> None:
        layout = QVBoxLayout(self.page_tools)
        layout.setContentsMargins(SP_XL, SP_LG, SP_XL, SP_LG)
        layout.setSpacing(SP_MD)

        path_row = QHBoxLayout()
        path_row.addWidget(QLabel("مسار الفحص للأدوات:"))
        self.tool_path = QLineEdit(str(ROOT_DIR))
        self.tool_path.setPlaceholderText("مسار الفحص (افتراضي: المجلد الحالي .)")
        path_row.addWidget(self.tool_path)
        layout.addLayout(path_row)

        groups_layout = QHBoxLayout()
        groups_layout.setSpacing(SP_MD)

        # 1. Audit & Hardening
        g_audit = QGroupBox("التدقيق والتحصين")
        l_audit = QVBoxLayout(g_audit)
        audit_btns = [
            ("فحص CIS Hardening", lambda: self._run_tool_and_display(self.agent._run_deep_audit, "فحص CIS Hardening")),
            ("فحص Lynis Audit", lambda: self._run_tool_and_display(self.agent._run_lynis_cli, "فحص Lynis")),
            ("تعلّم خط الأساس", lambda: self._run_tool_and_display(self.agent._run_baseline_learn_cli, "تعلّم خط الأساس")),
            ("فحص شذوذ النظام", lambda: self._run_tool_and_display(self.agent._run_baseline_check_cli, "فحص الشذوذ")),
            ("خطة المعالجة", lambda: self._run_tool_and_display(self.agent._generate_remediation_plan, "خطة المعالجة")),
        ]
        for name, fn in audit_btns:
            btn = QPushButton(name)
            btn.clicked.connect(fn)
            self.task_buttons.append(btn)
            l_audit.addWidget(btn)
        l_audit.addStretch()
        groups_layout.addWidget(g_audit)

        # 2. Scanning & Malware
        g_scan = QGroupBox("كشف التهديدات والأسرار")
        l_scan = QVBoxLayout(g_scan)
        scan_btns = [
            ("فحص YARA", lambda: self._run_tool_and_display(lambda: self.agent._run_yara_cli(self.tool_path.text().strip() or "."), "فحص YARA")),
            ("كشف الأسرار", lambda: self._run_tool_and_display(lambda: self.agent._scan_secrets_cli(self.tool_path.text().strip() or "."), "كشف الأسرار")),
            ("فحص Rootkit", lambda: self._run_tool_and_display(self.agent._run_rootkit_cli, "فحص Rootkit")),
            ("توليد قواعد التفاعل", lambda: self._run_tool_and_display(self.agent._run_synthesize_rules_cli, "توليد قواعد")),
        ]
        for name, fn in scan_btns:
            btn = QPushButton(name)
            btn.clicked.connect(fn)
            self.task_buttons.append(btn)
            l_scan.addWidget(btn)
        l_scan.addStretch()
        groups_layout.addWidget(g_scan)

        # 3. Threat Intel & CTI
        g_intel = QGroupBox("استخبارات التهديدات")
        l_intel = QVBoxLayout(g_intel)
        intel_btns = [
            ("تحديث التهديدات (KEV/Exploit-DB)", lambda: self._run_tool_and_display(self.agent._update_intel, "تحديث التهديدات")),
            ("Gemini CTI (48h)", lambda: self._run_tool_and_display(lambda: self.agent.run_gemini_threat_scan(48), "Gemini CTI")),
            ("تصدير تقرير HTML", lambda: self._run_tool_and_display(self.agent._export_html_report, "تصدير HTML")),
        ]
        for name, fn in intel_btns:
            btn = QPushButton(name)
            if "Gemini" in name:
                btn.setObjectName("primary")
            btn.clicked.connect(fn)
            self.task_buttons.append(btn)
            l_intel.addWidget(btn)
        l_intel.addStretch()
        groups_layout.addWidget(g_intel)

        layout.addLayout(groups_layout)

        # Output viewer pane directly on Tools page
        out_box = QGroupBox("نتائج تشغيل الأدوات والمخرجات المباشرة")
        out_layout = QVBoxLayout(out_box)
        self.tool_output = QPlainTextEdit(readOnly=True)
        self.tool_output.setPlaceholderText("اختر أداة تشغيل من المجموعات أعلاه لعرض نتائجها هنا مباشرة...")
        self.tool_output.setMinimumHeight(200)
        out_layout.addWidget(self.tool_output)
        layout.addWidget(out_box, 1)

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
        self.pb_text.setPlaceholderText("ستظهر هنا خطة العمل المهيكلة مع الأوامر والمصادر.")
        layout.addWidget(self.pb_text)

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

        self.setting_gemini_key = QLineEdit(self.settings.get("gemini_api_key", ""))
        self.setting_gemini_key.setEchoMode(QLineEdit.EchoMode.PasswordEchoOnEdit)
        self.setting_gemini_key.setPlaceholderText("AI Studio Gemini API Key")

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
        self.setting_sound_ux = QCheckBox("تفعيل أصوات التفاعل الخفيفة")
        self.setting_sound_ux.setChecked(bool(self.settings.get("sound_ux", True)))
        self.setting_sound_ux.setToolTip("نقرات قصيرة منخفضة الصوت عند الضغط على الإجراءات")
        self.setting_sound_profile = QComboBox()
        self.setting_sound_profile.addItem("هادئ — نقرة ناعمة", "soft")
        self.setting_sound_profile.addItem("تأكيد — نغمة أوضح", "confirm")
        current_profile = str(self.settings.get("sound_profile", "soft"))
        profile_index = self.setting_sound_profile.findData(current_profile)
        self.setting_sound_profile.setCurrentIndex(profile_index if profile_index >= 0 else 0)
        self.setting_dark_mode = QCheckBox("تفعيل الوضع الليلي الاحترافي")
        self.setting_dark_mode.setChecked(bool(self.settings.get("dark_mode", True)))
        self.setting_dark_mode.setToolTip("يحافظ على واجهة Dark / Obsidian المريحة للعمل الطويل")

        grid.addWidget(QLabel("Gemini API Key:"), 0, 0)
        grid.addWidget(self.setting_gemini_key, 0, 1)

        grid.addWidget(QLabel("AbuseIPDB Key:"), 1, 0)
        grid.addWidget(self.setting_abuseipdb_key, 1, 1)

        grid.addWidget(QLabel("NVD API Key:"), 2, 0)
        grid.addWidget(self.setting_nvd_key, 2, 1)

        grid.addWidget(QLabel("GitHub Token:"), 3, 0)
        grid.addWidget(self.setting_github_token, 3, 1)

        grid.addWidget(QLabel("Google Search Key:"), 4, 0)
        grid.addWidget(self.setting_cse_key, 4, 1)

        grid.addWidget(QLabel("Google Search cx:"), 5, 0)
        grid.addWidget(self.setting_cse_cx, 5, 1)

        grid.addWidget(QLabel("مجلد التقارير:"), 6, 0)
        grid.addWidget(self.setting_report_dir, 6, 1)

        grid.addWidget(QLabel("اللغة (Language):"), 7, 0)
        grid.addWidget(self.setting_lang_combo, 7, 1)
        grid.addWidget(QLabel("التجربة الحسية:"), 8, 0)
        grid.addWidget(self.setting_sound_ux, 8, 1)
        grid.addWidget(QLabel("نمط النغمة:"), 9, 0)
        grid.addWidget(self.setting_sound_profile, 9, 1)
        grid.addWidget(QLabel("نمط العرض:"), 10, 0)
        grid.addWidget(self.setting_dark_mode, 10, 1)

        layout.addWidget(form_group)

        btns_row = QHBoxLayout()
        btns_row.setSpacing(SP_MD)

        save_btn = QPushButton("حفظ الإعدادات")
        save_btn.setObjectName("primary")
        save_btn.clicked.connect(self.save_settings)

        test_gemini_btn = QPushButton("اختبار مفتاح Gemini")
        test_gemini_btn.clicked.connect(self.test_gemini_settings)

        test_search_btn = QPushButton("اختبار البحث في الإنترنت")
        test_search_btn.setToolTip("يتحقق من Google وويكيبيديا ويعرض حالة كل محرك")
        test_search_btn.clicked.connect(self.test_search_settings)

        clear_hist_btn = QPushButton("مسح تاريخ المحادثات")
        clear_hist_btn.clicked.connect(self.clear_history_settings)

        btns_row.addWidget(save_btn)
        btns_row.addWidget(test_gemini_btn)
        btns_row.addWidget(test_search_btn)
        btns_row.addWidget(clear_hist_btn)
        btns_row.addStretch()

        layout.addLayout(btns_row)

        self.settings_log = QPlainTextEdit(readOnly=True)
        self.settings_log.setPlaceholderText("ستظهر نتائج اختبار الاتصال وحفظ الإعدادات هنا...")
        self.settings_log.setMinimumHeight(180)
        layout.addWidget(self.settings_log, 1)

    def save_settings(self) -> None:
        self.settings.set("gemini_api_key", self.setting_gemini_key.text().strip())
        self.settings.set("abuseipdb_key", self.setting_abuseipdb_key.text().strip())
        self.settings.set("nvd_api_key", self.setting_nvd_key.text().strip())
        self.settings.set("github_token", self.setting_github_token.text().strip())
        self.settings.set("google_cse_key", self.setting_cse_key.text().strip())
        self.settings.set("google_cse_cx", self.setting_cse_cx.text().strip())
        self.settings.set("report_dir", self.setting_report_dir.text().strip())
        lang = self.setting_lang_combo.currentText()
        self.settings.set("language", lang)
        self.settings.set("sound_ux", bool(self.setting_sound_ux.isChecked()))
        self.settings.set("sound_profile", str(self.setting_sound_profile.currentData() or "soft"))
        self.agent.lang = lang
        self.agent.intel.language = lang
        if hasattr(self, "sound_ux"):
            self.sound_ux.set_enabled(self.setting_sound_ux.isChecked())
            self.sound_ux.set_profile(str(self.setting_sound_profile.currentData() or "soft"))
            self.sound_ux.play("success")
        self.settings_log.setPlainText("[نجاح] تم حفظ الإعدادات بنجاح!")
        QMessageBox.information(self, "حفظ الإعدادات", "تم حفظ جميع الإعدادات والمفاتيح آمنة محلياً.")

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

    def test_gemini_settings(self) -> None:
        key = self.setting_gemini_key.text().strip() or self.settings.get("gemini_api_key", "")
        if not key:
            self.settings_log.setPlainText("[خطأ] لم يتم إدخال مفتاح Gemini. يرجى إدخال مفتاحك أولاً.")
            return
        self.settings.set("gemini_api_key", key)
        self.settings_log.setPlainText("[فحص] جارٍ فحص الاتصال واكتشاف نماذج Gemini المتاحة لهذا المفتاح...\n")

        def run_test():
            from engine.gemini_cti import GeminiThreatClient
            client = GeminiThreatClient(key)
            models = client.discover_models(force=True)
            return models

        def handle_gemini_result(result: Any):
            if isinstance(result, Exception):
                self.settings_log.setPlainText(
                    f"[خطأ] فشل اختبار الاتصال بـ Gemini API:\n\n{result}\n\n"
                    "• تأكد من صحة المفتاح الصادر من Google AI Studio.\n"
                    "• تأكد من اتصال الجهاز بشبكة الإنترنت.\n"
                    "• سيعمل الوكيل تلقائياً في الوضع المحلي Offline لحين توفر المفتاح."
                )
            elif isinstance(result, list) and result:
                primary = result[0].short_name
                models_list = ", ".join(m.short_name for m in result[:8])
                self.settings_log.setPlainText(
                    f"[نجاح] تم الاتصال بنجاح بـ Google Gemini API!\n\n"
                    f"• النموذج الرئيسي المعتمد: {primary}\n"
                    f"• النماذج النشطة المكتشفة ({len(result)}): {models_list}\n\n"
                    "مساعد الذكاء الاصطناعي واستخبارات التهديدات CTI يعملان الآن بكامل الكفاءة."
                )
            else:
                self.settings_log.setPlainText("[تنبيه] لم يتم العثور على نماذج متوافقة لهذا المفتاح.")

        self.run_background_task(
            run_test,
            "اختبار Gemini",
            preserve_findings=True,
            result_handler=handle_gemini_result,
        )

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
        self.clock_time_label.setText(now.strftime("%H:%M:%S"))
        day = self.AR_DAYS.get(now.strftime("%A"), now.strftime("%A"))
        month = self.AR_MONTHS.get(now.month, now.strftime("%B"))
        self.clock_date_label.setText(f"{day}، {now.day} {month} {now.year}")

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

    def update_live_telemetry(self) -> None:
        if self.telemetry_worker is not None and self.telemetry_worker.isRunning():
            return
        self.telemetry_worker = LiveTelemetryWorker(self)
        self.telemetry_worker.result_ready.connect(self._render_live_telemetry)
        self.telemetry_worker.finished.connect(self._telemetry_finished)
        self.telemetry_worker.start()

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
                        table_cell(c.get("proto", ""), center=True),
                        table_cell(state, state_color, center=True, bold=True, tip=f"حالة الاتصال: {state}"),
                        table_cell("خارجي" if foreign else "محلي", SEV_HIGH if foreign else SEV_SAFE, center=True, bold=True,
                                   tip="اتصال بعنوان خارج الشبكة المحلية" if foreign else "اتصال داخل الجهاز أو الشبكة المحلية"),
                        table_cell(c.get("local", "")),
                        table_cell(remote, SEV_HIGH if foreign else None),
                        table_cell(c.get("process", "") or "—"),
                        table_cell(c.get("pid", ""), center=True),
                    ]
                    for col, cell in enumerate(cells):
                        self.table_conns.setItem(row, col, cell)
                self.table_procs.setRowCount(len(procs))
                for row, p in enumerate(procs):
                    cpu, mem = float(p.get("cpu", 0) or 0), float(p.get("mem", 0) or 0)
                    cmd_raw = str(p.get("command", ""))
                    cells = [
                        table_cell(p.get("user", "")),
                        table_cell(p.get("pid", ""), center=True),
                        table_cell(f"{cpu:g}%", SEV_CRITICAL if cpu >= 70 else SEV_HIGH if cpu >= 30 else None, center=True, bold=cpu >= 30),
                        table_cell(f"{mem:g}%", SEV_CRITICAL if mem >= 70 else SEV_HIGH if mem >= 30 else None, center=True, bold=mem >= 30),
                        table_cell(cmd_raw),
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
                f"{len(conns)} اتصال  |  {external} خارجي  |  {listening} منصت  |  تحديث كل 3 ثوانٍ")
            activity = max(0.0, min(100.0, len(procs) * 2.6 + len(conns) * 0.7))
            self._telemetry_history["النشاط التشغيلي (%)"].append(activity)
            for values in self._telemetry_history.values():
                del values[:-24]
            if hasattr(self, "telemetry_chart"):
                self.telemetry_chart.set_data({
                    "الجاهزية الأمنية (%)": (self._telemetry_history["الجاهزية الأمنية (%)"], "#2dd4bf"),
                    "النشاط التشغيلي (%)": (self._telemetry_history["النشاط التشغيلي (%)"], "#a78bfa"),
                })
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
            lambda: (self.agent.ask_ai_or_local(text, history), self.agent.last_answer_was_gap),
            "المساعد الذكي", preserve_findings=True,
            result_handler=lambda out: self._deliver_answer(out[0], text, out[1]),
        )

    def _deliver_answer(self, answer: str, topic: str, gap: bool) -> None:
        self._say(answer)
        if gap:
            self.chat_display.append_actions(
                "ما رأيك أن أبحث لك الآن؟",
                [("ابحث في الإنترنت", lambda: self._run_web_search(topic), "primary"),
                 ("تعلّم من الإنترنت", lambda: self._run_learning(topic), "")],
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
        self.chat_display.append(f"\n⚙️ [بدء] {title}")
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
        status_text = {"idle": "[ جاهز ]", "running": "[ يعمل ]", "error": "[ خطأ ]"}.get(state, "[ جاهز ]")
        status_color = {"idle": STATUS_OK, "running": "#d29922", "error": STATUS_ERROR}.get(state, STATUS_OK)
        self.sidebar_status.setText(status_text)
        self.sidebar_status.setStyleSheet(f"color: {status_color}; font-size: {FONT_SIZE_SMALL}px; padding: 8px 6px;")
        for widget in (self.status_badge, self.activity_lamp):
            widget.setProperty("state", state)
            widget.style().unpolish(widget)
            widget.style().polish(widget)
        self.activity_animation.setDuration({"idle": 1800, "running": 620, "error": 900}.get(state, 1800))

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
            self.chat_display.append(f"❌ [خطأ] {title}: {result}")
            self.scan_hint.setText(f"تعذر إكمال: {title}")
            return
        if self.active_result_handler:
            handler, self.active_result_handler = self.active_result_handler, None
            try:
                handler(result)
            except Exception as exc:
                self.set_activity_state("error", "فشل")
                self.chat_display.append(f"❌ [خطأ عرض] {title}: {exc}")
                return
            self.set_activity_state("idle", "جاهز")
            self.scan_hint.setText(f"✅ اكتمل: {title}")
            self.chat_display.append(f"✅ [اكتمل] {title}")
            return
        findings = result if isinstance(result, list) else []
        self.render_findings(findings)
        self.set_activity_state("idle", "جاهز")
        self.scan_hint.setText(f"✅ اكتمل: {title} | النتائج: {len(findings)}")
        self.chat_display.append(f"✅ [اكتمل] {title} | النتائج: {len(findings)}")
        self._say(summarize_findings(findings, title))

    def render_findings(self, findings: list) -> None:
        self.all_findings = sort_findings(findings)
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
        score = evaluation.get('score', 100)
        grade = evaluation.get('grade', 'A+')
        self.metric_labels["score"].setText(f"{score}/100")
        self.score_badge.setText(f"الدرجة: {score}/100 ({grade})")
        self.mission_kicker.setText("حالة الدفاع التكتيكية  •  LOCAL DEFENSE POSTURE: ASSESSED")
        self.security_gauge.set_value(score)
        self._telemetry_history["الجاهزية الأمنية (%)"].append(float(score))
        del self._telemetry_history["الجاهزية الأمنية (%)"][:-24]
        if hasattr(self, "telemetry_chart"):
            self.telemetry_chart.set_data({
                "الجاهزية الأمنية (%)": (self._telemetry_history["الجاهزية الأمنية (%)"], "#2dd4bf"),
                "النشاط التشغيلي (%)": (self._telemetry_history["النشاط التشغيلي (%)"], "#a78bfa"),
            })
        # Color the score badge based on score
        score_color = SEV_SAFE if score >= 85 else SEV_MEDIUM if score >= 70 else SEV_HIGH if score >= 50 else SEV_CRITICAL
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
            return
        for path in sorted(directory.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not path.is_file():
                continue
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
            lines.append(f"✅ تمت إضافة: {doc['title']} | {doc['chunks']} مقطع | {doc['total_chars']:,} حرف")
            lines.extend(doc.get("diagnostics", []))
        for failure in result.get("errors", []):
            lines.append(f"❌ تعذر: {failure['path']}: {failure['error']}")
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

        if relevance_engine.is_index_current(self.agent.kb):
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


class AuroraSplash(QSplashScreen):
    """Welcome screen: transparent rounded glass panel, blue/green light, no opaque blocks."""

    def __init__(self) -> None:
        pix = QPixmap(600, 360)
        pix.fill(Qt.GlobalColor.transparent)
        super().__init__(pix)
        self.setWindowFlag(Qt.WindowType.FramelessWindowHint)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self._t = 0
        self._logo = QIcon(str(ROOT_DIR / "resources" / "icon.svg")).pixmap(88, 88)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(16)

    def _tick(self) -> None:
        self._t += 1
        self.update()

    def paintEvent(self, e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        t = self._t / 60
        panel = QRectF(14, 14, w - 28, h - 28)
        base = QLinearGradient(0, 0, w, h)
        base.setColorAt(0, QColor(12, 30, 48, 238))
        base.setColorAt(1, QColor(7, 18, 29, 238))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(base)
        p.drawRoundedRect(panel, 28, 28)
        # Moving light gives life without hiding text.
        for i, color in enumerate(("#2dd4bf", "#a78bfa", "#f59e0b")):
            cx = w * (0.25 + 0.25 * i) + 40 * math.sin(t * 0.9 + i * 2)
            glow = QRadialGradient(cx, h * 0.28, 150)
            c = QColor(color)
            c.setAlpha(34 if i < 2 else 18)
            glow.setColorAt(0, c)
            c.setAlpha(0)
            glow.setColorAt(1, c)
            p.setBrush(glow)
            p.drawRoundedRect(panel, 28, 28)
        rim = QLinearGradient(0, 0, w, h)
        rim.setColorAt(0, QColor(125, 211, 252, 230))
        rim.setColorAt(0.5 + 0.15 * math.sin(t), QColor(220, 245, 255, 235))
        rim.setColorAt(1, QColor(52, 211, 153, 220))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(rim, 1.6))
        p.drawRoundedRect(panel, 28, 28)
        p.drawPixmap(int(w / 2 - 44), 48 + int(3 * math.sin(t * 2)), self._logo)
        p.setPen(QColor(TEXT_PRIMARY))
        title = QFont(FONT_FAMILY.split(",")[0].strip('" '))
        title.setPointSize(25)
        title.setWeight(QFont.Weight.Bold)
        p.setFont(title)
        p.drawText(QRect(0, 150, w, 44), Qt.AlignmentFlag.AlignHCenter, "AI AYFAM")
        sub = QFont(title)
        sub.setPointSize(11)
        sub.setWeight(QFont.Weight.Medium)
        p.setFont(sub)
        p.setPen(QColor(TEXT_SECONDARY))
        p.drawText(QRect(0, 198, w, 28), Qt.AlignmentFlag.AlignHCenter, "مركز العمليات الأمنية الذكي")
        bw, bx, by = 300, (w - 300) // 2, 262
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(56, 189, 248, 45))
        p.drawRoundedRect(QRectF(bx, by, bw, 7), 3.5, 3.5)
        prog = (self._t % 180) / 180
        bar = QLinearGradient(bx, 0, bx + bw, 0)
        bar.setColorAt(0, QColor("#2dd4bf"))
        bar.setColorAt(1, QColor("#a78bfa"))
        p.setBrush(bar)
        p.drawRoundedRect(QRectF(bx, by, max(8, bw * prog), 7), 3.5, 3.5)
        p.setPen(QColor(TEXT_MUTED))
        p.drawText(QRect(0, 282, w, 28), Qt.AlignmentFlag.AlignHCenter, "جارٍ تجهيز الواجهة…")

    def mousePressEvent(self, e) -> None:
        self.close()


def launch_gui() -> None:
    preflight = check_requirements({"gui"})
    if not preflight.ok:
        print(preflight.text(), file=sys.stderr)
        raise SystemExit(2)
    app = QApplication.instance() or QApplication(sys.argv)
    splash = AuroraSplash()
    splash.show()
    app.processEvents()

    # Let splash animate for ~2s while window builds
    import time
    t0 = time.time()

    def finish_splash() -> None:
        if time.time() - t0 >= 2.0:
            splash.close()
        else:
            QTimer.singleShot(80, finish_splash)

    QTimer.singleShot(80, finish_splash)

    window = UnifiedCockpitWindow()
    window.show()
    splash.finish(window)
    sys.exit(app.exec())


if __name__ == "__main__":
    launch_gui()
