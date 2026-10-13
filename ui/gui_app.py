"""واجهة AI AYFAM الرسومية — مركز تحكم موحّد للفحوصات والتقارير (v2 — redesigned)."""

from __future__ import annotations

import os
import sys
import ipaddress
import json
from pathlib import Path
from typing import Callable, Any

from PyQt6.QtCore import Qt, QTimer, QThread, QPropertyAnimation, pyqtSignal, QUrl, QSize
from PyQt6.QtGui import QColor, QDesktopServices, QFont, QIcon, QAction, QShortcut, QKeySequence
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QGraphicsOpacityEffect, QGridLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QSplitter, QStackedWidget,
    QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget, QScrollArea, QSizePolicy,
)

from config.settings import Settings
from core.agent import AYFAMAgent
from brain import library, relevance_engine
from engine.live_recon import LiveReconEngine
from engine.risk import RiskEngine
from tools.usb import analyze_mounted_filesystem, list_usb_devices, scan_mounted_drives
from tools.usb_control import authorize_device, deauthorize_device
from ui.terminal import TerminalUI
from ui.theme import (
    QSS, ACCENT, ACCENT_SOFT, BG_BASE, BG_SURFACE, BG_ELEVATED, BG_HOVER,
    BORDER, BORDER_FOCUS, TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO, SEV_SAFE,
    STATUS_OK, STATUS_ERROR, STATUS_IDLE,
    FONT_FAMILY, FONT_SIZE_BASE, FONT_SIZE_SMALL, FONT_SIZE_TITLE, FONT_SIZE_HERO, FONT_SIZE_METRIC,
    SP_XS, SP_SM, SP_MD, SP_LG, SP_XL, SP_2XL,
    severity_color, severity_bg,
)
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


def _sev_brush(severity: str) -> QColor:
    return QColor(severity_color(severity))


class UnifiedCockpitWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("AI AYFAM — Security Operations Center")
        self.resize(1400, 880)
        self.setMinimumSize(1000, 680)
        self.setStyleSheet(QSS)
        icon_path = ROOT_DIR / "resources" / "icon.svg"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self.settings = Settings()
        self.agent = AYFAMAgent(settings=self.settings, ui=GuiTerminalUI(no_color=True))
        self.worker: WorkerThread | None = None
        self.active_task_title = ""
        self.active_result_handler: Callable[[Any], None] | None = None
        self.visible_events: list[tuple[str, str, str]] = []
        self.current_findings: list[dict] = []
        self.task_buttons: list[QPushButton] = []
        self.usb_inventory_loaded = False
        self.nav_buttons: list[QPushButton] = []
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_live_telemetry)
        self.timer.start(3000)
        self.event_timer = QTimer(self)
        self.event_timer.timeout.connect(self.update_agent_events)
        self.event_timer.start(300)
        self.update_live_telemetry()

    # ═══════════════════════════════════════════════════════════════════════════
    #  LAYOUT: Sidebar + Header + Stacked Content
    # ═══════════════════════════════════════════════════════════════════════════
    def init_ui(self) -> None:
        central = QWidget()
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
        brand_mark = QLabel("◈")
        brand_mark.setObjectName("brandMark")
        brand_row.addWidget(brand_mark, 0, Qt.AlignmentFlag.AlignLeft)
        brand = QLabel("AI AYFAM")
        brand.setStyleSheet(f"color: {TEXT_PRIMARY}; font-size: {FONT_SIZE_TITLE}px; font-weight: 900; padding: 4px 0;")
        brand_row.addWidget(brand)
        brand_row.addStretch()
        sidebar_layout.addLayout(brand_row)

        sub = QLabel("SECURITY OPERATIONS CENTER")
        sub.setObjectName("eyebrow")
        sub.setStyleSheet(f"color: {ACCENT}; font-size: 10px; font-weight: 700; padding: 0 6px 20px 6px;")
        sidebar_layout.addWidget(sub)

        # Nav buttons with SVG icons
        self.nav_button_map: dict[str, QPushButton] = {}
        icons_dir = ROOT_DIR / "resources" / "icons"
        for key, label in NAV_ITEMS:
            btn = QPushButton(f"  {label}")
            btn.setObjectName("navButton")
            btn.setCheckable(True)
            icon_path = icons_dir / f"{key}.svg"
            if icon_path.exists():
                btn.setIcon(QIcon(str(icon_path)))
                btn.setIconSize(QSize(18, 18))
            btn.clicked.connect(lambda checked=False, k=key: self.switch_page(k))
            sidebar_layout.addWidget(btn)
            self.nav_button_map[key] = btn
            self.nav_buttons.append(btn)

        sidebar_layout.addStretch()

        # Status indicator at bottom of sidebar
        self.sidebar_status = QLabel("[ جاهز ]")
        self.sidebar_status.setStyleSheet(f"color: {STATUS_OK}; font-size: {FONT_SIZE_SMALL}px; padding: 8px 6px;")
        sidebar_layout.addWidget(self.sidebar_status)

        root.addWidget(sidebar)

        # ── Main content area ──
        main_area = QWidget()
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
        page_eyebrow = QLabel("AI AYFAM  /  CONTROL ROOM")
        page_eyebrow.setObjectName("eyebrow")
        title_box.addWidget(page_eyebrow)
        self.page_title = QLabel("غرفة العمليات")
        self.page_title.setObjectName("sectionTitle")
        title_box.addWidget(self.page_title)
        header_layout.addLayout(title_box)
        header_layout.addStretch()

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

        self.status_badge = QLabel("جاهز")
        self.status_badge.setObjectName("statusBadge")
        self.status_badge.setProperty("state", "idle")
        header_layout.addWidget(self.status_badge)

        self.score_badge = QLabel("الدرجة —")
        self.score_badge.setObjectName("scoreBadge")
        header_layout.addWidget(self.score_badge)

        main_layout.addWidget(header)

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
        main_layout.addWidget(scroll, 1)

        # ── Footer ──
        footer = QLabel(f"  {os.uname().nodename}  |  AI AYFAM v8  |  التنفيذ محلي")
        footer.setObjectName("footer")
        footer.setFixedHeight(24)
        footer.setStyleSheet(f"background: {BG_ELEVATED}; border-top: 1px solid {BORDER}; padding: 2px 12px;")
        main_layout.addWidget(footer)

        root.addWidget(main_area)
        self.setCentralWidget(central)

        # Default page
        self.switch_page("dashboard")

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
            self.stack.setCurrentWidget(widget)
            self.page_title.setText(title_map.get(key, ""))
            for k, btn in self.nav_button_map.items():
                btn.setChecked(k == key)
            if key == "usb" and not self.usb_inventory_loaded:
                self.refresh_usb_inventory()

    # ═══════════════════════════════════════════════════════════════════════════
    #  DASHBOARD PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def setup_dashboard_page(self) -> None:
        layout = QVBoxLayout(self.page_dashboard)
        layout.setContentsMargins(SP_XL, SP_LG, SP_XL, SP_LG)
        layout.setSpacing(SP_LG)

        # ── Metric Cards Row ──
        metrics = QGridLayout()
        metrics.setHorizontalSpacing(SP_MD)
        metrics.setVerticalSpacing(SP_MD)
        self.metric_labels: dict[str, QLabel] = {}
        metric_data = [
            ("connections", "اتصالات نشطة", "مقابس الشبكة النشطة", SEV_LOW),
            ("processes", "عمليات مراقبة", "أعلى العمليات استهلاكاً", "#a371f7"),
            ("findings", "نتائج الفحص", "في آخر فحص مكتمل", SEV_MEDIUM),
            ("score", "الدرجة الأمنية", "مؤشر المخاطر العام", SEV_SAFE),
        ]
        for col, (key, label, note, accent) in enumerate(metric_data):
            card = QFrame(objectName="card")
            card.setMinimumHeight(110)
            card.setStyleSheet(f"QFrame#card {{ border-top: 3px solid {accent}; }}")
            box = QVBoxLayout(card)
            box.setContentsMargins(SP_LG, SP_MD, SP_LG, SP_MD)
            box.setSpacing(SP_XS)

            lbl = QLabel(label)
            lbl.setObjectName("metricLabel")
            box.addWidget(lbl)

            val = QLabel("—")
            val.setObjectName("metricValue")
            box.addWidget(val)

            nt = QLabel(note)
            nt.setObjectName("metricNote")
            box.addWidget(nt)

            self.metric_labels[key] = val
            metrics.addWidget(card, 0, col)
            metrics.setColumnStretch(col, 1)
        layout.addLayout(metrics)

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
        self.table_conns.setAlternatingRowColors(True)
        self.table_conns.setShowGrid(False)
        self.table_conns.verticalHeader().setVisible(False)
        self.table_conns.verticalHeader().setDefaultSectionSize(32)
        conn_layout.addWidget(self.table_conns)
        self.dashboard_splitter.addWidget(conn_group)

        # Processes panel
        proc_group = QGroupBox("أعلى العمليات استهلاكاً")
        proc_layout = QVBoxLayout(proc_group)
        self.table_procs = QTableWidget(0, 5)
        self.table_procs.setHorizontalHeaderLabels(["المستخدم", "PID", "CPU", "RAM", "الأمر"])
        self.table_procs.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table_procs.setAlternatingRowColors(True)
        self.table_procs.setShowGrid(False)
        self.table_procs.verticalHeader().setVisible(False)
        self.table_procs.verticalHeader().setDefaultSectionSize(32)
        proc_layout.addWidget(self.table_procs)
        self.dashboard_splitter.addWidget(proc_group)

        self.dashboard_splitter.setStretchFactor(0, 3)
        self.dashboard_splitter.setStretchFactor(1, 2)
        self.dashboard_splitter.setSizes([420, 260])
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
        self.scan_target.setPlaceholderText("IP أو اسم المضيف")
        self.port_range = QLineEdit("1-1024")
        self.port_range.setPlaceholderText("مثال: 22,80,443 أو 1-1024")
        self.ip_target = QLineEdit()
        self.ip_target.setPlaceholderText("عنوان IP عام")
        self.website_input = QLineEdit()
        self.website_input.setPlaceholderText("https://example.com")
        self.path_input = QLineEdit(".")
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
        for i, (text, btn_style, callback) in enumerate(buttons):
            btn = QPushButton(text)
            if btn_style:
                btn.setObjectName(btn_style)
            btn.setToolTip(f"تشغيل: {text}")
            btn.clicked.connect(callback)
            self.task_buttons.append(btn)
            grid.addWidget(btn, 4 + i // 4, i % 4)
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

        self.table_findings = QTableWidget(0, 4)
        self.table_findings.setHorizontalHeaderLabels(["الخطورة", "النتيجة", "الفئة", "الثقة"])
        self.table_findings.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_findings.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_findings.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_findings.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_findings.setAlternatingRowColors(True)
        self.table_findings.cellClicked.connect(self.show_finding_details)
        self.table_findings.setMinimumHeight(160)
        self.table_findings.verticalHeader().setVisible(False)
        self.table_findings.verticalHeader().setDefaultSectionSize(32)

        detail_header = QHBoxLayout()
        detail_label = QLabel("تحليل النتيجة المحددة")
        detail_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-weight: 600; font-size: {FONT_SIZE_SMALL}px;")
        detail_header.addWidget(detail_label)
        detail_header.addStretch()

        self.btn_apply_autofix = QPushButton("تطبيق الإصلاح التلقائي")
        self.btn_apply_autofix.setObjectName("primary")
        self.btn_apply_autofix.setToolTip("تطبيق أمر الإصلاح للنتيجة المحددة إن وجد")
        self.btn_apply_autofix.clicked.connect(self.apply_selected_finding_fix)
        detail_header.addWidget(self.btn_apply_autofix)

        self.finding_detail = QPlainTextEdit(readOnly=True)
        self.finding_detail.setPlaceholderText("حدد نتيجة لعرض التفاصيل والدليل والتوصية.")
        self.finding_detail.setMinimumHeight(130)

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
        box.addWidget(findings_splitter)
        layout.addWidget(group)

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
        for button in (self.usb_allow_button, self.usb_block_button, self.usb_scan_button):
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
        self.tool_path = QLineEdit(".")
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

        self.chat_display = QTextEdit(readOnly=True)
        self.chat_display.setPlaceholderText("ستظهر هنا حالة المهام والنتائج...")
        self.chat_display.append("[النظام] مرحباً. اختر فحصاً من تبويب الفحوصات أو اكتب أمراً هنا.")
        layout.addWidget(self.chat_display)

        row = QHBoxLayout()
        row.setSpacing(SP_SM)
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("اكتب أمراً أو سؤالاً...")
        self.chat_input.returnPressed.connect(self.send_chat_message)
        send = QPushButton("إرسال")
        send.setObjectName("primary")
        send.clicked.connect(self.send_chat_message)
        row.addWidget(self.chat_input)
        row.addWidget(send)
        layout.addLayout(row)

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

        self.setting_report_dir = QLineEdit(self.settings.get("report_dir", os.path.expanduser("~/ayfam-reports")))

        self.setting_lang_combo = QComboBox()
        self.setting_lang_combo.addItems(["ar", "en"])
        current_lang = self.settings.get("language", "ar")
        self.setting_lang_combo.setCurrentText(current_lang if current_lang in ("ar", "en") else "ar")

        grid.addWidget(QLabel("Gemini API Key:"), 0, 0)
        grid.addWidget(self.setting_gemini_key, 0, 1)

        grid.addWidget(QLabel("AbuseIPDB Key:"), 1, 0)
        grid.addWidget(self.setting_abuseipdb_key, 1, 1)

        grid.addWidget(QLabel("NVD API Key:"), 2, 0)
        grid.addWidget(self.setting_nvd_key, 2, 1)

        grid.addWidget(QLabel("GitHub Token:"), 3, 0)
        grid.addWidget(self.setting_github_token, 3, 1)

        grid.addWidget(QLabel("مجلد التقارير:"), 4, 0)
        grid.addWidget(self.setting_report_dir, 4, 1)

        grid.addWidget(QLabel("اللغة (Language):"), 5, 0)
        grid.addWidget(self.setting_lang_combo, 5, 1)

        layout.addWidget(form_group)

        btns_row = QHBoxLayout()
        btns_row.setSpacing(SP_MD)

        save_btn = QPushButton("حفظ الإعدادات")
        save_btn.setObjectName("primary")
        save_btn.clicked.connect(self.save_settings)

        test_gemini_btn = QPushButton("اختبار مفتاح Gemini")
        test_gemini_btn.clicked.connect(self.test_gemini_settings)

        clear_hist_btn = QPushButton("مسح تاريخ المحادثات")
        clear_hist_btn.clicked.connect(self.clear_history_settings)

        btns_row.addWidget(save_btn)
        btns_row.addWidget(test_gemini_btn)
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
        self.settings.set("report_dir", self.setting_report_dir.text().strip())
        lang = self.setting_lang_combo.currentText()
        self.settings.set("language", lang)
        self.agent.lang = lang
        self.agent.intel.language = lang
        self.settings_log.setPlainText("[نجاح] تم حفظ الإعدادات بنجاح!")
        QMessageBox.information(self, "حفظ الإعدادات", "تم حفظ جميع الإعدادات والمفاتيح آمنة محلياً.")

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
    #  LIVE TELEMETRY
    # ═══════════════════════════════════════════════════════════════════════════
    def update_live_telemetry(self) -> None:
        try:
            conns = LiveReconEngine.get_live_connections()
            self.table_conns.setRowCount(0)
            for c in conns[:30]:
                values = [c.get("proto", ""), c.get("state", ""),
                          "خارجي" if c.get("is_foreign") else "محلي",
                          c.get("local", ""), c.get("remote", ""),
                          c.get("process", ""), c.get("pid", "")]
                row = self.table_conns.rowCount()
                self.table_conns.insertRow(row)
                for col, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    if col == 2:
                        item.setForeground(QColor(SEV_HIGH if c.get("is_foreign") else SEV_SAFE))
                    self.table_conns.setItem(row, col, item)
            procs = LiveReconEngine.get_top_processes(15)
            self.table_procs.setRowCount(0)
            for p in procs:
                row = self.table_procs.rowCount()
                self.table_procs.insertRow(row)
                values = [p.get("user", ""), p.get("pid", ""),
                          f"{p.get('cpu', 0)}%", f"{p.get('mem', 0)}%", p.get("command", "")]
                for col, value in enumerate(values):
                    self.table_procs.setItem(row, col, QTableWidgetItem(str(value)))
            self.metric_labels["connections"].setText(str(len(conns)))
            self.metric_labels["processes"].setText(str(len(procs)))
            external = sum(1 for c in conns if c.get("is_foreign"))
            self.connection_summary.setText(
                f"{len(conns)} اتصال نشط  |  {external} خارجي  |  تحديث كل 3 ثوانٍ"
            )
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
    def send_chat_message(self) -> None:
        text = self.chat_input.text().strip()
        if not text:
            return
        self.chat_input.clear()
        self.chat_display.append(f"\n[أنت] {text}")
        cmd = self.agent.nlp.parse(text)
        self.chat_display.append(f"[الوكيل] فهمت: {self.agent.nlp.describe_intent(cmd.intent, 'ar')}")
        if cmd.intent == "explain":
            target = cmd.explain_target or text
            self.run_background_task(
                lambda: self.agent.nlp.explain(target),
                "شرح السؤال",
                preserve_findings=True,
                result_handler=lambda answer: self.chat_display.append(f"[الوكيل]\n{answer}"),
            )
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
            "web_search": ("بحث ويب", lambda: self.agent._web_search(entities.get("keyword") or text)),
            "update_intel": ("تحديث التهديدات", self.agent._update_intel),
        }
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
                    lambda: self.agent._learn_from_file(filepath),
                    "استيعاب كتاب",
                    preserve_findings=True,
                    result_handler=lambda _result: self.refresh_library(),
                )
            else:
                self.switch_page("library")
                self.chat_display.append("[الوكيل] اختر «إضافة كتب» من مكتبة المعرفة.")
            return
        # If no specific system action command matched, query AI Assistant (Gemini / Local brain)
        self.run_background_task(
            lambda: self.agent.ask_ai_or_local(text),
            "المساعد الذكي",
            preserve_findings=True,
            result_handler=lambda answer: self.chat_display.append(f"\n{answer}"),
        )

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
                          partition.get("size") or drive.get("size", "—"), mountpoint]
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
        self.usb_detail.setPlainText("\n".join(details))

    def show_usb_drive_details(self, row: int, _column: int) -> None:
        item = self.usb_drives_table.item(row, 0)
        if not item:
            return
        partition = item.data(Qt.ItemDataRole.UserRole) or {}
        self.render_usb_drive_analysis(partition.get("analysis", {}), partition.get("mountpoint", ""))

    def render_usb_drive_analysis(self, analysis: dict, mountpoint: str) -> None:
        suspicious = analysis.get("suspicious_files", [])
        autorun = analysis.get("autorun_files", [])
        lines = [
            f"نقطة التوصيل: {mountpoint or 'غير موصولة'}",
            f"الملفات المفحوصة: {analysis.get('total_files_checked', 0)}",
            f"التنفيذية: {analysis.get('executable_count', 0)}",
            f"المشبوهة: {len(suspicious)}",
            f"التشغيل التلقائي: {len(autorun)}",
        ]
        for finding in analysis.get("findings", []):
            lines.extend(["", f"[{finding.get('severity', 'info').upper()}] {finding.get('title', '')}",
                          str(finding.get("detail") or ""), f"التوصية: {finding.get('fix') or 'لا توجد'}"])
        if not analysis:
            lines.append("لا يتوفر تحليل مسبق. حدد وحدة تخزين موصولة ثم شغّل التحليل.")
        self.usb_detail.setPlainText("\n".join(lines))

    def control_selected_usb_device(self, allow: bool) -> None:
        row = self.usb_devices_table.currentRow()
        item = self.usb_devices_table.item(row, 0) if row >= 0 else None
        device = item.data(Qt.ItemDataRole.UserRole) if item else None
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
        self.run_background_task(
            lambda: operation(device.get("bus", ""), device.get("device", "")),
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
        row = self.usb_drives_table.currentRow()
        item = self.usb_drives_table.item(row, 0) if row >= 0 else None
        partition = item.data(Qt.ItemDataRole.UserRole) if item else None
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

    # ═══════════════════════════════════════════════════════════════════════════
    #  FINDINGS DISPLAY
    # ═══════════════════════════════════════════════════════════════════════════
    def show_finding_details(self, row: int, _column: int) -> None:
        if row >= len(self.current_findings):
            return
        finding = self.current_findings[row]
        confidence = finding.get("confidence")
        confidence_text = f"{float(confidence):.0%}" if isinstance(confidence, (int, float)) else "غير محددة"
        evidence = finding.get("evidence") or {}
        lines = [
            f"النتيجة: {finding.get('title', 'بلا عنوان')}",
            f"الخطورة: {str(finding.get('severity', 'info')).upper()} | الثقة: {confidence_text}",
            f"الفئة: {finding.get('category', 'غير مصنفة')}",
            "",
            "ماذا رُصد:",
            str(finding.get("detail") or "لم يوفر الفاحص تفاصيل إضافية."),
            "",
            "التوصية:",
            str(finding.get("fix") or "لا توجد توصية آلية مسجلة."),
        ]
        if evidence:
            lines.extend(["", "الدليل المسجل:", json.dumps(evidence, ensure_ascii=False, indent=2, default=str)])
        tags = finding.get("tags") or []
        if tags:
            lines.extend(["", f"الوسوم: {', '.join(str(t) for t in tags)}"])
        attack_ids = finding.get("attack_ids") or []
        if attack_ids:
            lines.extend([f"ATT&CK: {', '.join(str(i) for i in attack_ids)}"])
        self.finding_detail.setPlainText("\n".join(lines))

    def task_done(self, result: Any, title: str) -> None:
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

    def render_findings(self, findings: list) -> None:
        self.current_findings = findings
        self.table_findings.setRowCount(0)
        self.finding_detail.clear()
        if not findings:
            self.finding_detail.setPlaceholderText("لم يسجل هذا الفحص نتائج أمنية.")
        for finding in findings:
            row = self.table_findings.rowCount()
            self.table_findings.insertRow(row)
            severity = str(finding.get("severity", "info")).upper()
            sev_item = QTableWidgetItem(severity)
            sev_item.setForeground(_sev_brush(severity))
            confidence = finding.get("confidence")
            confidence_text = f"{float(confidence):.0%}" if isinstance(confidence, (int, float)) else "—"
            values = [sev_item, QTableWidgetItem(str(finding.get("title", ""))),
                      QTableWidgetItem(str(finding.get("category", ""))), QTableWidgetItem(confidence_text)]
            for col, cell in enumerate(values):
                self.table_findings.setItem(row, col, cell)
        evaluation = RiskEngine.evaluate(findings)
        self.metric_labels["findings"].setText(str(len(findings)))
        self.metric_labels["score"].setText(f"{evaluation.get('score', 100)}/100")
        score = evaluation.get('score', 100)
        grade = evaluation.get('grade', 'A+')
        self.score_badge.setText(f"الدرجة: {score}/100 ({grade})")
        # Color the score badge based on score
        score_color = SEV_SAFE if score >= 85 else SEV_MEDIUM if score >= 70 else SEV_HIGH if score >= 50 else SEV_CRITICAL
        self.score_badge.setStyleSheet(
            f"color: {score_color}; font-weight: 700; padding: 8px 14px; "
            f"background: {BG_SURFACE}; border: 1px solid {score_color}44; border-radius: 6px;"
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


def launch_gui() -> None:
    preflight = check_requirements({"gui"})
    if not preflight.ok:
        print(preflight.text(), file=sys.stderr)
        raise SystemExit(2)
    app = QApplication.instance() or QApplication(sys.argv)
    window = UnifiedCockpitWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    launch_gui()
