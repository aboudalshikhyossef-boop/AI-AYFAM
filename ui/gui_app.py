"""واجهة AI AYFAM الرسومية: مركز تحكم موحّد للفحوصات والتقارير."""

from __future__ import annotations

import os
import sys
import ipaddress
import json
from pathlib import Path
from typing import Callable, Any

from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QUrl
from PyQt6.QtGui import QColor, QDesktopServices, QFont, QIcon
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QGridLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QSplitter, QTabWidget,
    QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from config.settings import Settings
from core.agent import AYFAMAgent
from brain import library, relevance_engine
from engine.live_recon import LiveReconEngine
from engine.risk import RiskEngine
from tools.usb import analyze_mounted_filesystem, list_usb_devices, scan_mounted_drives
from tools.usb_control import authorize_device, deauthorize_device
from ui.terminal import TerminalUI
from utils.preflight import check_requirements, root_error, is_root


ROOT_DIR = Path(__file__).resolve().parents[1]

THEME = """
QMainWindow, QWidget { background: #11191f; color: #e7eef0; font-family: "Noto Sans Arabic", "DejaVu Sans", sans-serif; font-size: 13px; }
QFrame#header { background: #182832; border: 1px solid #31505a; border-radius: 5px; }
QGroupBox, QFrame#card { background: #19252d; border: 1px solid #2c3d46; border-radius: 4px; }
QGroupBox { margin-top: 12px; padding: 14px 10px 10px; font-weight: 700; color: #62d7cf; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
QTabWidget::pane { border: 1px solid #2c3d46; border-radius: 4px; background: #131e25; }
QTabBar::tab { background: #17232a; color: #a9bac0; padding: 10px 15px; border: none; border-bottom: 2px solid transparent; margin-right: 2px; }
QTabBar::tab:selected { background: #20343d; color: #72e2d8; border-bottom: 2px solid #39c7bd; font-weight: 700; }
QPushButton { background: #176e70; color: #f1fbfa; border: 1px solid #268a88; border-radius: 3px; padding: 8px 12px; font-weight: 600; }
QPushButton:hover { background: #218487; }
QPushButton#danger { background: #6d343c; border-color: #9b4b52; }
QPushButton#danger:hover { background: #88404a; }
QPushButton:disabled { color: #718188; background: #202c32; border-color: #314149; }
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit { background: #10191f; color: #e7eef0; border: 1px solid #354953; border-radius: 3px; padding: 7px; selection-background-color: #176e70; }
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus { border: 1px solid #39c7bd; }
QTableWidget { background: #131e24; color: #e3ecee; alternate-background-color: #19262e; gridline-color: #263941; border: 1px solid #2c3d46; border-radius: 3px; }
QHeaderView::section { background: #20343d; color: #b9d9dc; padding: 8px; border: none; font-weight: 700; }
QProgressBar { background: #2a3940; border: none; border-radius: 2px; text-align: center; min-height: 5px; max-height: 5px; }
QProgressBar::chunk { background: #e4ac56; border-radius: 2px; }
QScrollBar:vertical { background: #17232a; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #46616a; min-height: 24px; border-radius: 3px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""


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
        except Exception as exc:  # propagate to the GUI thread for a useful message
            self.task_result.emit(exc)


class UnifiedCockpitWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("AI AYFAM — Security Control Center")
        self.resize(1320, 840)
        self.setMinimumSize(980, 660)
        self.setStyleSheet(THEME)
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
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_live_telemetry)
        self.timer.start(3000)
        self.event_timer = QTimer(self)
        self.event_timer.timeout.connect(self.update_agent_events)
        self.event_timer.start(300)
        self.update_live_telemetry()

    def init_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 14, 16, 10)
        root.setSpacing(10)

        header = QFrame(objectName="header")
        header_layout = QHBoxLayout(header)
        title_box = QVBoxLayout()
        title = QLabel("AI AYFAM  |  مركز التحكم الأمني")
        title.setFont(QFont("Noto Sans Arabic", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #ffffff;")
        title_box.addWidget(title)
        subtitle = QLabel("فحوصات النظام والشبكة، التحليل المتقدم، التقارير، وخطط المعالجة في مكان واحد")
        subtitle.setStyleSheet("color: #c7ddd6;")
        title_box.addWidget(subtitle)
        header_layout.addLayout(title_box)
        header_layout.addStretch()
        self.status_badge = QLabel("الحالة: جاهز")
        self.status_badge.setStyleSheet("color: #86efac; font-weight: 700; padding: 8px 12px; border: 1px solid #22c55e; border-radius: 6px;")
        header_layout.addWidget(self.status_badge)
        self.score_badge = QLabel("الدرجة: —")
        self.score_badge.setStyleSheet("color: #fbbf24; font-weight: 700; padding: 8px 12px; border: 1px solid #a16207; border-radius: 6px;")
        header_layout.addWidget(self.score_badge)
        root.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self.tab_dashboard, self.tab_scans = QWidget(), QWidget()
        self.tab_tools, self.tab_chat, self.tab_usb = QWidget(), QWidget(), QWidget()
        self.tab_playbooks, self.tab_reports, self.tab_library = QWidget(), QWidget(), QWidget()
        self.setup_dashboard_tab()
        self.setup_scans_tab()
        self.setup_usb_tab()
        self.setup_tools_tab()
        self.setup_chat_tab()
        self.setup_playbooks_tab()
        self.setup_reports_tab()
        self.setup_library_tab()
        for page, label in (
            (self.tab_dashboard, "غرفة العمليات"), (self.tab_scans, "الفحوصات"),
            (self.tab_usb, "USB والأجهزة"),
            (self.tab_tools, "الترسانة المتقدمة"), (self.tab_chat, "المحادثة"),
            (self.tab_library, "مكتبة المعرفة"), (self.tab_playbooks, "خطط العمل"), (self.tab_reports, "التقارير"),
        ):
            self.tabs.addTab(page, label)
        root.addWidget(self.tabs)
        self.tabs.currentChanged.connect(self.on_tab_changed)

        footer = QLabel(f"المضيف: {os.uname().nodename}  |  الإصدار: v7  |  التنفيذ محليًا")
        footer.setStyleSheet("color: #9aa79f; font-size: 11px;")
        root.addWidget(footer)
        self.setCentralWidget(central)

    def setup_dashboard_tab(self) -> None:
        layout = QVBoxLayout(self.tab_dashboard)
        metrics = QGridLayout()
        self.metric_labels: dict[str, QLabel] = {}
        for col, (key, label) in enumerate((("connections", "اتصالات نشطة"), ("processes", "عمليات مراقبة"), ("findings", "نتائج الفحص"), ("score", "الدرجة الأمنية"))):
            card = QFrame(objectName="card")
            box = QVBoxLayout(card)
            box.addWidget(QLabel(label))
            value = QLabel("—")
            value.setFont(QFont("Noto Sans Arabic", 20, QFont.Weight.Bold))
            value.setStyleSheet("color: #a3dfcd;")
            box.addWidget(value)
            self.metric_labels[key] = value
            metrics.addWidget(card, 0, col)
        layout.addLayout(metrics)

        group = QGroupBox("الاتصالات الحية")
        group_layout = QVBoxLayout(group)
        self.connection_summary = QLabel("جارٍ قراءة حالة الشبكة...")
        self.connection_summary.setStyleSheet("color: #91a8ae; padding: 2px 4px;")
        group_layout.addWidget(self.connection_summary)
        self.table_conns = QTableWidget(0, 7)
        self.table_conns.setHorizontalHeaderLabels(["البروتوكول", "الحالة", "النطاق", "العنوان المحلي", "العنوان البعيد", "العملية", "PID"])
        self.table_conns.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table_conns.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table_conns.setAlternatingRowColors(True)
        group_layout.addWidget(self.table_conns)
        layout.addWidget(group)

        group2 = QGroupBox("أكثر العمليات استهلاكًا")
        group2_layout = QVBoxLayout(group2)
        self.table_procs = QTableWidget(0, 5)
        self.table_procs.setHorizontalHeaderLabels(["المستخدم", "PID", "CPU", "RAM", "الأمر"])
        self.table_procs.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table_procs.setAlternatingRowColors(True)
        group2_layout.addWidget(self.table_procs)
        layout.addWidget(group2)

    def setup_scans_tab(self) -> None:
        layout = QVBoxLayout(self.tab_scans)
        form = QGroupBox("الفحوصات الأساسية")
        grid = QGridLayout(form)
        self.scan_target = QLineEdit("127.0.0.1")
        self.scan_target.setPlaceholderText("IP أو اسم المضيف لفحص المنافذ")
        self.port_range = QLineEdit("1-1024")
        self.port_range.setPlaceholderText("مثال: 22,80,443 أو 1-1024")
        self.ip_target = QLineEdit()
        self.ip_target.setPlaceholderText("عنوان IP عام")
        self.website_input = QLineEdit()
        self.website_input.setPlaceholderText("https://example.com")
        self.path_input = QLineEdit(".")
        grid.addWidget(QLabel("هدف المنافذ:"), 0, 0)
        grid.addWidget(self.scan_target, 0, 1)
        grid.addWidget(QLabel("نطاق المنافذ:"), 0, 2)
        grid.addWidget(self.port_range, 0, 3)
        grid.addWidget(QLabel("عنوان IP للسمعة:"), 1, 0)
        grid.addWidget(self.ip_target, 1, 1, 1, 3)
        grid.addWidget(QLabel("الموقع:"), 2, 0)
        grid.addWidget(self.website_input, 2, 1, 1, 3)
        grid.addWidget(QLabel("مسار YARA / الأسرار:"), 3, 0)
        grid.addWidget(self.path_input, 3, 1, 1, 3)
        buttons = [
            ("فحص الشبكة", lambda: self.run_background_task(lambda: self.agent._scan_network(), "فحص الشبكة")),
            ("فحص المنافذ", self.start_port_scan),
            ("فحص النظام", lambda: self.run_background_task(self.agent._scan_system, "فحص النظام")),
            ("تحليل السجلات", lambda: self.run_background_task(self.agent._scan_logs, "تحليل السجلات")),
            ("الفحص الشامل", lambda: self.run_background_task(self.agent._full_scan, "الفحص الشامل")),
            ("مركز USB والأجهزة", lambda: self.tabs.setCurrentWidget(self.tab_usb)),
            ("فحص الموقع", self.start_website_scan),
            ("سمعة IP", self.start_ip_reputation),
        ]
        scan_help = {
            "فحص الشبكة": "يفحص الواجهات والاتصالات النشطة والجدار الناري وإشارات تسريب البيانات.",
            "فحص المنافذ": "يفحص الهدف والنطاق المحددين. استخدمه فقط على أنظمة لديك تصريح بفحصها.",
            "فحص النظام": "يراجع SSH والمستخدمين والتحديثات والملفات ذات الصلاحيات الخطرة.",
            "تحليل السجلات": "يبحث في السجلات المحلية عن محاولات دخول وأحداث تستحق المراجعة.",
            "الفحص الشامل": "يجمع فحوصات النظام والشبكة والسجلات وقد يستغرق وقتًا أطول.",
            "USB والأجهزة": "يعرض الأجهزة المتصلة؛ لا ينفذ إجراءً تغييريًا دون تأكيد.",
            "فحص الموقع": "يفحص أمان الاتصال والترويسات لموقع تملكه أو لديك تصريح بفحصه.",
            "سمعة IP": "يستعلم من المصادر المتاحة؛ قد تكون البيانات محدودة دون مفتاح API.",
        }
        for i, (text, callback) in enumerate(buttons):
            btn = QPushButton(text)
            btn.setToolTip(scan_help[text])
            btn.clicked.connect(callback)
            self.task_buttons.append(btn)
            grid.addWidget(btn, 4 + i // 4, i % 4)
        layout.addWidget(form)
        self.scan_progress = QProgressBar()
        self.scan_progress.setTextVisible(False)
        self.scan_progress.setRange(0, 0)
        self.scan_progress.hide()
        layout.addWidget(self.scan_progress)
        self.scan_hint = QLabel("مرّر المؤشر على الفحص لمعرفة نطاقه. اضغط على النتيجة لعرض تفاصيلها ودليلها.")
        self.scan_hint.setStyleSheet("color: #aab8b0;")
        layout.addWidget(self.scan_hint)
        self.setup_findings_table(layout)

    def setup_findings_table(self, layout: QVBoxLayout) -> None:
        group = QGroupBox("نتائج الفحص الأخيرة")
        box = QVBoxLayout(group)
        self.table_findings = QTableWidget(0, 4)
        self.table_findings.setHorizontalHeaderLabels(["الخطورة", "النتيجة", "الفئة", "الثقة"])
        self.table_findings.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_findings.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_findings.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_findings.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_findings.setAlternatingRowColors(True)
        self.table_findings.cellClicked.connect(self.show_finding_details)
        self.table_findings.setMinimumHeight(150)
        detail_panel = QWidget()
        detail_layout = QVBoxLayout(detail_panel)
        detail_layout.setContentsMargins(0, 4, 0, 0)
        detail_layout.addWidget(QLabel("تحليل النتيجة المحددة"))
        self.finding_detail = QPlainTextEdit(readOnly=True)
        self.finding_detail.setPlaceholderText("حدد نتيجة لعرض التفاصيل والدليل والتوصية.")
        self.finding_detail.setMinimumHeight(120)
        detail_layout.addWidget(self.finding_detail)
        findings_splitter = QSplitter(Qt.Orientation.Vertical)
        findings_splitter.addWidget(self.table_findings)
        findings_splitter.addWidget(detail_panel)
        findings_splitter.setStretchFactor(0, 3)
        findings_splitter.setStretchFactor(1, 2)
        box.addWidget(findings_splitter)
        layout.addWidget(group)

    def setup_usb_tab(self) -> None:
        layout = QVBoxLayout(self.tab_usb)
        heading = QHBoxLayout()
        self.usb_status = QLabel("لم يتم تحديث قائمة الأجهزة بعد")
        self.usb_status.setStyleSheet("color: #91a8ae; font-weight: 600;")
        heading.addWidget(self.usb_status)
        heading.addStretch()
        self.usb_refresh_button = QPushButton("تحديث الأجهزة")
        self.usb_refresh_button.clicked.connect(self.refresh_usb_inventory)
        self.task_buttons.append(self.usb_refresh_button)
        heading.addWidget(self.usb_refresh_button)
        layout.addLayout(heading)

        devices_group = QGroupBox("الأجهزة المتصلة")
        devices_layout = QVBoxLayout(devices_group)
        self.usb_devices_table = QTableWidget(0, 5)
        self.usb_devices_table.setHorizontalHeaderLabels(["Bus / Device", "الشركة والمنتج", "الفئة", "VID:PID", "مستوى المخاطر"])
        self.usb_devices_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.usb_devices_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.usb_devices_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.usb_devices_table.setAlternatingRowColors(True)
        self.usb_devices_table.cellClicked.connect(self.show_usb_device_details)
        devices_layout.addWidget(self.usb_devices_table)
        layout.addWidget(devices_group, 2)

        actions = QHBoxLayout()
        self.usb_allow_button = QPushButton("السماح بالجهاز المحدد")
        self.usb_allow_button.clicked.connect(lambda: self.control_selected_usb_device(True))
        self.usb_block_button = QPushButton("حجب الجهاز المحدد")
        self.usb_block_button.setObjectName("danger")
        self.usb_block_button.clicked.connect(lambda: self.control_selected_usb_device(False))
        self.usb_scan_button = QPushButton("تحليل وحدة التخزين المحددة")
        self.usb_scan_button.clicked.connect(self.scan_selected_usb_storage)
        for button in (self.usb_allow_button, self.usb_block_button, self.usb_scan_button):
            self.task_buttons.append(button)
            actions.addWidget(button)
        layout.addLayout(actions)

        drives_group = QGroupBox("وحدات التخزين ومؤشرات الفحص")
        drives_layout = QVBoxLayout(drives_group)
        self.usb_drives_table = QTableWidget(0, 4)
        self.usb_drives_table.setHorizontalHeaderLabels(["الجهاز", "الطراز", "الحجم", "نقطة التوصيل"])
        self.usb_drives_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.usb_drives_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.usb_drives_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.usb_drives_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.usb_drives_table.setAlternatingRowColors(True)
        self.usb_drives_table.cellClicked.connect(self.show_usb_drive_details)
        drives_layout.addWidget(self.usb_drives_table)
        self.usb_detail = QPlainTextEdit(readOnly=True)
        self.usb_detail.setPlaceholderText("حدد جهازًا أو وحدة تخزين لعرض التفاصيل والمخاطر والتوصيات.")
        self.usb_detail.setMaximumHeight(150)
        drives_layout.addWidget(self.usb_detail)
        layout.addWidget(drives_group, 2)

    def on_tab_changed(self, index: int) -> None:
        if self.tabs.widget(index) is self.tab_usb and not self.usb_inventory_loaded:
            self.refresh_usb_inventory()

    def refresh_usb_inventory(self) -> None:
        self.run_background_task(
            lambda: {"devices": list_usb_devices(), "drives": scan_mounted_drives(usb_only=True)},
            "تحديث مخزون USB",
            preserve_findings=True,
            result_handler=self.render_usb_inventory,
        )

    def render_usb_inventory(self, inventory: dict) -> None:
        devices = inventory.get("devices", [])
        drives = [drive for drive in inventory.get("drives", []) if drive.get("is_usb")]
        self.usb_inventory_loaded = True
        self.usb_devices_table.setRowCount(0)
        for device in devices:
            row = self.usb_devices_table.rowCount()
            self.usb_devices_table.insertRow(row)
            name = device.get("product") or device.get("description") or device.get("manufacturer") or "جهاز غير معرّف"
            risk = str(device.get("risk", "low")).lower()
            risk_labels = {"critical": "حرج", "high": "مرتفع", "medium": "متوسط", "low": "منخفض"}
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
                    item.setForeground(QColor({"critical": "#ff7078", "high": "#f09b64", "medium": "#e7bd66", "low": "#65d2aa"}.get(risk, "#a9bac0")))
                self.usb_devices_table.setItem(row, column, item)

        self.usb_drives_table.setRowCount(0)
        for drive in drives:
            partitions = drive.get("partitions", []) or [{"name": drive.get("name", ""), "mountpoint": drive.get("mountpoint", ""), "analysis": drive.get("analysis", {})}]
            for partition in partitions:
                row = self.usb_drives_table.rowCount()
                self.usb_drives_table.insertRow(row)
                mountpoint = partition.get("mountpoint") or "غير موصول"
                values = [drive.get("name", "—") + (f" / {partition.get('name')}" if partition.get("name") else ""),
                          " ".join(str(part) for part in (drive.get("vendor"), drive.get("model")) if part) or "غير محدد",
                          partition.get("size") or drive.get("size", "—"), mountpoint]
                partition_data = {**partition, "drive": drive}
                for column, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    if column == 0:
                        item.setData(Qt.ItemDataRole.UserRole, partition_data)
                    self.usb_drives_table.setItem(row, column, item)

        self.usb_status.setText(f"الأجهزة: {len(devices)}  |  وحدات تخزين USB: {len(drives)}  |  الحالة: محدثة الآن")
        if not devices and not drives:
            self.usb_detail.setPlainText("لا توجد أجهزة USB أو وحدات تخزين متصلة حاليًا.")

    def show_usb_device_details(self, row: int, _column: int) -> None:
        item = self.usb_devices_table.item(row, 0)
        if not item:
            return
        device = item.data(Qt.ItemDataRole.UserRole) or {}
        details = [
            f"الجهاز: {device.get('product') or device.get('description') or 'غير معروف'}",
            f"الشركة المصنّعة: {device.get('manufacturer') or 'غير محددة'}",
            f"Bus / Device: {device.get('bus', '—')} / {device.get('device', '—')}",
            f"VID:PID: {device.get('vendor_id', '—')}:{device.get('product_id', '—')}",
            f"التصنيف: {device.get('class_name') or device.get('device_class') or 'غير محدد'}",
            f"مستوى المخاطر: {device.get('risk', 'low')}",
            f"المؤشرات: {'؛ '.join(device.get('flags', [])) or 'لا توجد مؤشرات مسجلة'}",
            f"التوصيات: {'؛ '.join(device.get('recommendations', [])) or 'لا توجد توصيات إضافية'}",
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
            f"الملفات التنفيذية: {analysis.get('executable_count', 0)}",
            f"الملفات المشبوهة: {len(suspicious)}",
            f"ملفات التشغيل التلقائي: {len(autorun)}",
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
            QMessageBox.information(self, "اختر جهازًا", "حدد جهاز USB من القائمة أولًا.")
            return
        action = "السماح" if allow else "الحجب"
        name = device.get("product") or device.get("description") or "الجهاز المحدد"
        answer = QMessageBox.question(
            self, f"تأكيد {action} USB", f"هل تريد {action} «{name}»؟ قد يؤدي الحجب إلى فصل الجهاز فورًا.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        operation = authorize_device if allow else deauthorize_device
        self.run_background_task(
            lambda: operation(device.get("bus", ""), device.get("device", "")),
            f"{action} جهاز USB",
            preserve_findings=True,
            result_handler=self.complete_usb_control,
        )

    def complete_usb_control(self, result: dict) -> None:
        if result.get("success"):
            QMessageBox.information(self, "اكتملت العملية", "تم تحديث حالة الجهاز.")
            QTimer.singleShot(250, self.refresh_usb_inventory)
        else:
            QMessageBox.warning(self, "تعذر تنفيذ العملية", result.get("error") or "لم يتمكن النظام من تحديث حالة الجهاز.")

    def scan_selected_usb_storage(self) -> None:
        row = self.usb_drives_table.currentRow()
        item = self.usb_drives_table.item(row, 0) if row >= 0 else None
        partition = item.data(Qt.ItemDataRole.UserRole) if item else None
        mountpoint = partition.get("mountpoint") if partition else ""
        if not mountpoint:
            QMessageBox.information(self, "لا توجد وحدة موصولة", "اختر قسمًا موصولًا قبل بدء التحليل.")
            return
        self.run_background_task(
            lambda: analyze_mounted_filesystem(mountpoint),
            "تحليل وحدة تخزين USB",
            preserve_findings=True,
            result_handler=lambda analysis: self.render_usb_drive_analysis(analysis, mountpoint),
        )

    def setup_tools_tab(self) -> None:
        layout = QVBoxLayout(self.tab_tools)
        group = QGroupBox("أدوات التدقيق والتحصين")
        grid = QGridLayout(group)
        self.tool_path = QLineEdit(".")
        grid.addWidget(QLabel("المسار:"), 0, 0)
        grid.addWidget(self.tool_path, 0, 1, 1, 3)
        actions = [
            ("CIS / Hardening", self.agent._run_deep_audit, False, False), ("Lynis", self.agent._run_lynis_cli, False, False),
            ("YARA", self.start_yara_scan, False, True),
            ("Rootkit", self.agent._run_rootkit_cli, False, False), ("كشف الأسرار", self.start_secret_scan, False, True),
            ("تعلّم خط الأساس", self.agent._run_baseline_learn_cli, False, False), ("فحص خط الأساس", self.agent._run_baseline_check_cli, False, False),
            ("توليد قواعد دفاعية", self.agent._run_synthesize_rules_cli, True, False), ("خطة المعالجة", self.agent._generate_remediation_plan, True, False),
            ("تقرير HTML", self.agent._export_html_report, True, False), ("تحديث معلومات التهديدات", self.agent._update_intel, False, False),
        ]
        for i, (text, fn, preserve_findings, direct) in enumerate(actions):
            btn = QPushButton(text)
            if direct:
                btn.clicked.connect(fn)
            else:
                btn.clicked.connect(lambda _checked=False, f=fn, t=text, p=preserve_findings: self.run_background_task(f, t, p))
            self.task_buttons.append(btn)
            grid.addWidget(btn, 1 + i // 3, i % 3)
        layout.addWidget(group)
        note = QLabel("تنبيه: أدوات الإصلاح التلقائي قد تغيّر إعدادات النظام. استخدمها من المحادثة أو الطرفية بعد مراجعة النتائج.")
        note.setStyleSheet("color: #9a641b;")
        layout.addWidget(note)
        layout.addStretch()

    def setup_chat_tab(self) -> None:
        layout = QVBoxLayout(self.tab_chat)
        self.chat_display = QTextEdit(readOnly=True)
        self.chat_display.setPlaceholderText("ستظهر هنا حالة المهام والنتائج...")
        self.chat_display.append("[النظام] مرحبًا. اختر فحصًا من مركز الفحوصات أو اكتب أمرًا بسيطًا مثل: افحص الشبكة")
        layout.addWidget(self.chat_display)
        row = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("اكتب أمرًا أو سؤالًا...")
        self.chat_input.returnPressed.connect(self.send_chat_message)
        send = QPushButton("إرسال")
        send.clicked.connect(self.send_chat_message)
        row.addWidget(self.chat_input)
        row.addWidget(send)
        layout.addLayout(row)

    def setup_playbooks_tab(self) -> None:
        layout = QVBoxLayout(self.tab_playbooks)
        row = QHBoxLayout()
        self.pb_input = QLineEdit()
        self.pb_input.setPlaceholderText("مثال: nmap أو privilege_escalation أو ufw")
        button = QPushButton("استخراج الخطة")
        button.clicked.connect(self.load_playbook)
        row.addWidget(self.pb_input)
        row.addWidget(button)
        layout.addLayout(row)
        self.pb_text = QPlainTextEdit(readOnly=True)
        layout.addWidget(self.pb_text)

    def setup_reports_tab(self) -> None:
        layout = QVBoxLayout(self.tab_reports)
        row = QHBoxLayout()
        self.reports_dir = QLineEdit(self.settings.get("report_dir", os.path.expanduser("~/ayfam-reports")))
        browse = QPushButton("اختيار مجلد")
        browse.clicked.connect(self.choose_reports_dir)
        refresh = QPushButton("تحديث القائمة")
        refresh.clicked.connect(self.refresh_reports)
        row.addWidget(self.reports_dir)
        row.addWidget(browse)
        row.addWidget(refresh)
        layout.addLayout(row)
        self.reports_table = QTableWidget(0, 3)
        self.reports_table.setHorizontalHeaderLabels(["الملف", "الحجم", "آخر تعديل"])
        self.reports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.reports_table.cellDoubleClicked.connect(self.open_report)
        layout.addWidget(self.reports_table)
        self.refresh_reports()

    def setup_library_tab(self) -> None:
        layout = QVBoxLayout(self.tab_library)
        intro = QLabel(
            "تُستخرج النصوص من ملفاتك وتُخزّن محليًا في مكتبة الأداة. "
            "البحث النصي يعمل بعد الإضافة مباشرة؛ أعد بناء الفهرس لتفعيل ترتيب الصلة والربط بين الكتب."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #bcc9c1; padding: 4px;")
        layout.addWidget(intro)

        actions = QHBoxLayout()
        self.add_books_button = QPushButton("إضافة كتب أو ملفات")
        self.add_books_button.clicked.connect(self.choose_books)
        self.rebuild_index_button = QPushButton("إعادة بناء فهرس الذكاء")
        self.rebuild_index_button.clicked.connect(self.rebuild_library_index)
        refresh = QPushButton("تحديث المكتبة")
        refresh.clicked.connect(self.refresh_library)
        actions.addWidget(self.add_books_button)
        actions.addWidget(self.rebuild_index_button)
        actions.addWidget(refresh)
        layout.addLayout(actions)

        self.library_status = QLabel("جارٍ تحميل المكتبة...")
        self.library_status.setStyleSheet("color: #a3dfcd;")
        layout.addWidget(self.library_status)
        self.library_table = QTableWidget(0, 4)
        self.library_table.setHorizontalHeaderLabels(["العنوان", "النوع", "المقاطع", "تاريخ الإضافة"])
        self.library_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.library_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.library_table.setAlternatingRowColors(True)
        self.library_table.cellClicked.connect(self.show_library_document)
        layout.addWidget(self.library_table, 2)

        search_row = QHBoxLayout()
        self.library_query = QLineEdit()
        self.library_query.setPlaceholderText("ابحث في نص الكتب التي أضفتها")
        self.library_query.returnPressed.connect(self.search_library)
        search_button = QPushButton("بحث في المكتبة")
        search_button.clicked.connect(self.search_library)
        search_row.addWidget(self.library_query)
        search_row.addWidget(search_button)
        layout.addLayout(search_row)
        self.library_results = QPlainTextEdit(readOnly=True)
        self.library_results.setPlaceholderText("ستظهر المقاطع المطابقة مع اسم الكتاب ورقم الصفحة هنا.")
        layout.addWidget(self.library_results, 2)
        self.refresh_library()

    def update_live_telemetry(self) -> None:
        try:
            conns = LiveReconEngine.get_live_connections()
            self.table_conns.setRowCount(0)
            for c in conns[:30]:
                values = [c.get("proto", ""), c.get("state", ""), "خارجي" if c.get("is_foreign") else "محلي",
                          c.get("local", ""), c.get("remote", ""), c.get("process", ""), c.get("pid", "")]
                row = self.table_conns.rowCount()
                self.table_conns.insertRow(row)
                for col, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    if col == 2:
                        item.setForeground(QColor("#f0a05e" if c.get("is_foreign") else "#65d2aa"))
                    self.table_conns.setItem(row, col, item)
            procs = LiveReconEngine.get_top_processes(15)
            self.table_procs.setRowCount(0)
            for p in procs:
                row = self.table_procs.rowCount()
                self.table_procs.insertRow(row)
                values = [p.get("user", ""), p.get("pid", ""), f"{p.get('cpu', 0)}%", f"{p.get('mem', 0)}%", p.get("command", "")]
                for col, value in enumerate(values):
                    self.table_procs.setItem(row, col, QTableWidgetItem(str(value)))
            self.metric_labels["connections"].setText(str(len(conns)))
            self.metric_labels["processes"].setText(str(len(procs)))
            external = sum(1 for connection in conns if connection.get("is_foreign"))
            self.connection_summary.setText(
                f"{len(conns)} اتصال نشط  |  {external} عنوانًا خارجيًا  |  تحديث تلقائي كل 3 ثوانٍ"
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

    def send_chat_message(self) -> None:
        text = self.chat_input.text().strip()
        if not text:
            return
        self.chat_input.clear()
        self.chat_display.append(f"\n[أنت] {text}")
        cmd = self.agent.nlp.parse(text)
        self.chat_display.append(f"[الوكيل] فهمت الطلب: {self.agent.nlp.describe_intent(cmd.intent, 'ar')}")
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
            "usb_control": ("فحص USB والأجهزة", self.agent._usb_control_center),
            "check_firewall": ("فحص جدار الحماية", self.agent._check_firewall),
            "wifi": ("فحص شبكات Wi-Fi", self.agent._wifi_status),
            "scan_trend": ("مقارنة الفحوص السابقة", self.agent._show_trend),
            "rebuild_index": ("إعادة بناء فهرس الذكاء", self.agent._rebuild_index),
            "show_learned": ("عرض ما تعلمته الأداة", self.agent._show_learned),
            "concept_explore": ("استكشاف مفهوم", lambda: self.agent._concept_explore(entities.get("concept", ""))),
            "concept_link": ("ربط مفهومين", lambda: self.agent._concept_link(entities.get("concept_a", ""), entities.get("concept_b", ""))),
            "summarize_doc": ("تلخيص كتاب", lambda: self.agent._summarize_doc(entities.get("book_title", ""))),
            "teach": ("حفظ معلومة للتذكر", lambda: self.agent._teach(entities.get("fact", ""))),
            "cve_search": ("البحث عن ثغرات CVE", lambda: self.agent._cve_search(entities.get("cve") or entities.get("keyword") or text)),
            "pkg_vuln_search": ("فحص ثغرات حزمة", lambda: self.agent._pkg_vuln_search(entities.get("package", ""))),
            "web_search": ("البحث في الويب", lambda: self.agent._web_search(entities.get("keyword") or text)),
            "update_intel": ("تحديث معلومات التهديدات", self.agent._update_intel),
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
                self.tabs.setCurrentWidget(self.tab_library)
                self.chat_display.append("[الوكيل] اختر «إضافة كتب أو ملفات» من مكتبة المعرفة.")
            return
        self.chat_display.append("[الوكيل] لم أنفذ هذا الطلب تلقائيًا. استخدم التبويب المناسب؛ لا أطبق إصلاحات النظام دون تأكيد.")

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
        self.status_badge.setText(f"الحالة: يعمل — {title}")
        self.status_badge.setStyleSheet("color: #fde68a; font-weight: 700; padding: 8px 12px; border: 1px solid #d97706; border-radius: 6px;")
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

    def start_website_scan(self) -> None:
        url = self.website_input.text().strip()
        if not url:
            QMessageBox.warning(self, "رابط الموقع مطلوب", "أدخل رابط الموقع قبل بدء الفحص.")
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
            QMessageBox.warning(self, "عنوان IP غير صالح", "أدخل عنوان IPv4 أو IPv6 صالحًا لفحص السمعة.")
            return
        self.run_background_task(lambda: self.agent._check_ip(target), "سمعة IP")

    def start_yara_scan(self) -> None:
        path = self.tool_path.text().strip() or "."
        self.run_background_task(lambda: self.agent._run_yara_cli(path), "YARA")

    def start_secret_scan(self) -> None:
        path = self.tool_path.text().strip() or "."
        self.run_background_task(lambda: self.agent._scan_secrets_cli(path), "كشف الأسرار")

    def choose_books(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "إضافة كتب أو ملفات إلى المكتبة المحلية",
            str(Path.home()),
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
            ingest_books,
            "استيعاب الكتب",
            preserve_findings=True,
            result_handler=self.show_ingest_results,
        )

    def show_ingest_results(self, result: dict) -> None:
        self.refresh_library()
        lines = []
        for document in result.get("imported", []):
            lines.append(
                f"تمت إضافة: {document['title']} | "
                f"{document['chunks']} مقطع | {document['total_chars']:,} حرف"
            )
            lines.extend(document.get("diagnostics", []))
        for failure in result.get("errors", []):
            lines.append(f"تعذر استيعاب {failure['path']}: {failure['error']}")
        self.library_results.setPlainText("\n\n".join(lines) or "لم تتم إضافة أي ملف.")

    def rebuild_library_index(self) -> None:
        if not self.agent.kb.list_library_documents():
            QMessageBox.information(self, "المكتبة فارغة", "أضف كتابًا أو ملفًا قبل بناء الفهرس.")
            return
        self.run_background_task(
            self.agent._rebuild_index,
            "إعادة بناء فهرس الذكاء",
            preserve_findings=True,
            result_handler=lambda _result: self.refresh_library(),
        )

    def refresh_library(self) -> None:
        documents = self.agent.kb.list_library_documents()
        self.library_table.setRowCount(0)
        for document in documents:
            row = self.library_table.rowCount()
            self.library_table.insertRow(row)
            title = QTableWidgetItem(str(document.get("title", "")))
            title.setData(Qt.ItemDataRole.UserRole, document["id"])
            values = [title, QTableWidgetItem(str(document.get("file_type", ""))),
                      QTableWidgetItem(str(document.get("chunk_count", 0))),
                      QTableWidgetItem(str(document.get("added_at", "")))]
            for column, item in enumerate(values):
                self.library_table.setItem(row, column, item)

        if relevance_engine.is_index_current(self.agent.kb):
            meta = relevance_engine.get_index_meta()
            status = f"{len(documents)} كتاب | الفهرس مبني: {meta.get('chunks_indexed', 0)} مقطع"
        elif relevance_engine.is_index_built():
            status = f"{len(documents)} كتاب | الفهرس قديم؛ أعد بناءه لإدخال الكتب الجديدة"
        else:
            status = f"{len(documents)} كتاب | البحث النصي متاح، والفهرس المرتب لم يُبنَ بعد"
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
            self.library_results.setPlainText("لم أجد مقاطع مطابقة في الكتب التي أُضيفت.")
            return
        output = ["نتائج مرتبة حسب الصلة" if ranked else "نتائج بحث نصي محلي؛ أعد بناء الفهرس لتحديث ترتيب الصلة"]
        for index, result in enumerate(results, 1):
            if "error" in result:
                output.append(result["error"])
                continue
            location = result.get("page_hint") or f"المقطع {result.get('chunk_index', '')}"
            relevance = f" | الصلة: {result['relevance']:.3f}" if ranked and "relevance" in result else ""
            output.append(
                f"\n{index}. {result.get('title', 'كتاب غير معروف')} | {location}{relevance}\n"
                f"{result.get('content', '').strip()}"
            )
        self.library_results.setPlainText("\n".join(output))

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
            str(finding.get("detail") or "لم يوفر الفاحص تفاصيل إضافية لهذه النتيجة."),
            "",
            "التوصية:",
            str(finding.get("fix") or "لا توجد توصية آلية مسجلة؛ راجع إعداد الخدمة يدويًا."),
        ]
        if evidence:
            lines.extend(["", "الدليل المسجل:", json.dumps(evidence, ensure_ascii=False, indent=2, default=str)])
        tags = finding.get("tags") or []
        if tags:
            lines.extend(["", f"الوسوم: {', '.join(str(tag) for tag in tags)}"])
        attack_ids = finding.get("attack_ids") or []
        if attack_ids:
            lines.extend([f"معرّفات ATT&CK: {', '.join(str(item) for item in attack_ids)}"])
        self.finding_detail.setPlainText("\n".join(lines))

    def task_done(self, result: Any, title: str) -> None:
        self.scan_progress.hide()
        for button in self.task_buttons:
            button.setEnabled(True)
        if isinstance(result, Exception):
            self.active_result_handler = None
            self.status_badge.setText("الحالة: فشل")
            self.status_badge.setStyleSheet("color: #fca5a5; font-weight: 700; padding: 8px 12px; border: 1px solid #ef4444; border-radius: 6px;")
            self.chat_display.append(f"[خطأ] {title}: {result}")
            self.scan_hint.setText(f"تعذر إكمال المهمة: {title}")
            return
        if self.active_result_handler:
            handler, self.active_result_handler = self.active_result_handler, None
            try:
                handler(result)
            except Exception as exc:
                self.status_badge.setText("الحالة: فشل")
                self.chat_display.append(f"[خطأ في عرض نتيجة {title}] {exc}")
                return
            self.status_badge.setText("الحالة: جاهز")
            self.scan_hint.setText(f"اكتملت المهمة: {title}")
            self.chat_display.append(f"[اكتمل] {title}")
            return
        findings = result if isinstance(result, list) else []
        self.render_findings(findings)
        self.status_badge.setText("الحالة: جاهز")
        self.status_badge.setStyleSheet("color: #86efac; font-weight: 700; padding: 8px 12px; border: 1px solid #22c55e; border-radius: 6px;")
        self.scan_hint.setText(f"اكتملت المهمة: {title} | النتائج: {len(findings)}")
        self.chat_display.append(f"[اكتمل] {title} | النتائج: {len(findings)}")

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
            severity_item = QTableWidgetItem(severity)
            severity_item.setForeground(QColor({"CRITICAL": "#ff7780", "HIGH": "#f1a361", "MEDIUM": "#e7c36b", "LOW": "#82b9df"}.get(severity, "#78c6a6")))
            confidence = finding.get("confidence")
            confidence_text = f"{float(confidence):.0%}" if isinstance(confidence, (int, float)) else "—"
            values = [severity_item, QTableWidgetItem(str(finding.get("title", ""))),
                      QTableWidgetItem(str(finding.get("category", ""))), QTableWidgetItem(confidence_text)]
            for col, cell in enumerate(values):
                self.table_findings.setItem(row, col, cell)
        evaluation = RiskEngine.evaluate(findings)
        self.metric_labels["findings"].setText(str(len(findings)))
        self.metric_labels["score"].setText(f"{evaluation.get('score', 100)}/100")
        self.score_badge.setText(f"الدرجة: {evaluation.get('score', 100)}/100 ({evaluation.get('grade', 'A+')})")

    def load_playbook(self) -> None:
        topic = self.pb_input.text().strip()
        if not topic:
            return
        from brain.playbook_engine import PlaybookEngine
        pb = PlaybookEngine(kb=self.agent.kb).generate_playbook(topic)
        lines = [f"خطة العمل: {topic}", f"عدد الأوامر: {pb.get('total_commands', 0)}", ""]
        for stage, steps in pb.get("stages", {}).items():
            if steps:
                lines.append(f"[{stage}]")
                for step in steps:
                    lines.append(f"$ {step.get('cmd', '')}\n  المصدر: {step.get('book', '')} — صفحة {step.get('page', '')}")
        self.pb_text.setPlainText("\n".join(lines))

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


def launch_gui() -> None:
    if not is_root():
        print(f"❌ {root_error()}", file=sys.stderr)
        raise SystemExit(1)
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
