"""واجهة AI AYFAM الرسومية: مركز تحكم موحّد للفحوصات والتقارير."""

from __future__ import annotations

import os
import sys
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
from engine.live_recon import LiveReconEngine
from engine.risk import RiskEngine
from utils.preflight import check_requirements, root_error, is_root


ROOT_DIR = Path(__file__).resolve().parents[1]

THEME = """
QMainWindow, QWidget { background: #080c14; color: #e5e7eb; font-family: Segoe UI, sans-serif; font-size: 13px; }
QFrame#header, QGroupBox, QFrame.card { background: #0e1522; border: 1px solid #26364d; border-radius: 10px; }
QGroupBox { margin-top: 12px; padding: 14px 10px 10px; font-weight: 700; color: #8dd7ff; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
QTabWidget::pane { border: 1px solid #26364d; border-radius: 8px; background: #0b111d; }
QTabBar::tab { background: #0b111d; color: #93a4b8; padding: 11px 18px; border: 1px solid #1f2d40; margin-right: 2px; }
QTabBar::tab:selected { background: #13263a; color: #67d7ff; border-bottom: 2px solid #38bdf8; }
QPushButton { background: #12304a; color: #e6f7ff; border: 1px solid #2675a5; border-radius: 6px; padding: 8px 12px; font-weight: 600; }
QPushButton:hover { background: #1b557b; }
QPushButton:disabled { color: #627386; background: #101923; border-color: #26364d; }
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit { background: #070b12; color: #f3f4f6; border: 1px solid #2d435c; border-radius: 6px; padding: 7px; }
QTableWidget { background: #080d16; alternate-background-color: #0c1420; gridline-color: #1b2b3d; border: 1px solid #26364d; border-radius: 7px; }
QHeaderView::section { background: #132033; color: #9bdcff; padding: 8px; border: none; font-weight: 700; }
QProgressBar { background: #080d16; border: 1px solid #26364d; border-radius: 6px; text-align: center; }
QProgressBar::chunk { background: #22c55e; border-radius: 5px; }
"""


class WorkerThread(QThread):
    finished = pyqtSignal(object)

    def __init__(self, task_fn: Callable[..., Any], *args: Any):
        super().__init__()
        self.task_fn, self.args = task_fn, args

    def run(self) -> None:
        try:
            self.finished.emit(self.task_fn(*self.args))
        except Exception as exc:  # propagate to the GUI thread for a useful message
            self.finished.emit(exc)


class UnifiedCockpitWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("AI AYFAM — Security Control Center")
        self.resize(1400, 900)
        self.setMinimumSize(1100, 700)
        self.setStyleSheet(THEME)
        icon_path = ROOT_DIR / "resources" / "icon.svg"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

        self.settings = Settings()
        # TerminalUI remains the compatibility adapter used by the agent engines.
        from ui.terminal import TerminalUI
        self.agent = AYFAMAgent(settings=self.settings, ui=TerminalUI(no_color=True))
        self.worker: WorkerThread | None = None
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_live_telemetry)
        self.timer.start(3000)
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
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setStyleSheet("color: #67d7ff;")
        title_box.addWidget(title)
        subtitle = QLabel("فحوصات النظام والشبكة، التحليل المتقدم، التقارير، وخطط المعالجة في مكان واحد")
        subtitle.setStyleSheet("color: #93a4b8;")
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
        self.tab_tools, self.tab_chat = QWidget(), QWidget()
        self.tab_playbooks, self.tab_reports = QWidget(), QWidget()
        self.setup_dashboard_tab()
        self.setup_scans_tab()
        self.setup_tools_tab()
        self.setup_chat_tab()
        self.setup_playbooks_tab()
        self.setup_reports_tab()
        for page, label in (
            (self.tab_dashboard, "لوحة المتابعة"), (self.tab_scans, "مركز الفحوصات"),
            (self.tab_tools, "الترسانة المتقدمة"), (self.tab_chat, "المحادثة"),
            (self.tab_playbooks, "خطط العمل"), (self.tab_reports, "التقارير"),
        ):
            self.tabs.addTab(page, label)
        root.addWidget(self.tabs)

        footer = QLabel(f"المضيف: {os.uname().nodename}  |  الإصدار: v7  |  التنفيذ محليًا")
        footer.setStyleSheet("color: #64748b; font-size: 11px;")
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
            value.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
            value.setStyleSheet("color: #67d7ff;")
            box.addWidget(value)
            self.metric_labels[key] = value
            metrics.addWidget(card, 0, col)
        layout.addLayout(metrics)

        group = QGroupBox("الاتصالات الحية")
        group_layout = QVBoxLayout(group)
        self.table_conns = QTableWidget(0, 6)
        self.table_conns.setHorizontalHeaderLabels(["البروتوكول", "الحالة", "العنوان المحلي", "العنوان البعيد", "البرنامج", "PID"])
        self.table_conns.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_conns.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
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
        self.website_input = QLineEdit()
        self.website_input.setPlaceholderText("https://example.com")
        self.path_input = QLineEdit(".")
        grid.addWidget(QLabel("هدف المنافذ:"), 0, 0)
        grid.addWidget(self.scan_target, 0, 1)
        grid.addWidget(QLabel("الموقع:"), 1, 0)
        grid.addWidget(self.website_input, 1, 1)
        grid.addWidget(QLabel("مسار YARA / الأسرار:"), 2, 0)
        grid.addWidget(self.path_input, 2, 1)
        buttons = [
            ("فحص الشبكة", lambda: self.run_background_task(lambda: self.agent._scan_network(), "فحص الشبكة")),
            ("فحص المنافذ", lambda: self.run_background_task(lambda: self.agent._scan_ports(self.scan_target.text().strip() or "127.0.0.1"), "فحص المنافذ")),
            ("فحص النظام", lambda: self.run_background_task(self.agent._scan_system, "فحص النظام")),
            ("تحليل السجلات", lambda: self.run_background_task(self.agent._scan_logs, "تحليل السجلات")),
            ("الفحص الشامل", lambda: self.run_background_task(self.agent._full_scan, "الفحص الشامل")),
            ("USB والأجهزة", lambda: self.run_background_task(self.agent._usb_control_center, "USB والأجهزة")),
            ("فحص الموقع", lambda: self.run_background_task(lambda: self.agent._test_website(self.website_input.text().strip()), "فحص الموقع")),
            ("سمعة IP", lambda: self.run_background_task(lambda: self.agent._check_ip(self.scan_target.text().strip()), "سمعة IP")),
        ]
        for i, (text, callback) in enumerate(buttons):
            btn = QPushButton(text)
            btn.clicked.connect(callback)
            grid.addWidget(btn, 3 + i // 4, i % 4)
        layout.addWidget(form)
        self.scan_hint = QLabel("الفحوصات تعمل في الخلفية حتى تبقى الواجهة مستجيبة. النتائج التفصيلية تظهر في جدول النتائج.")
        self.scan_hint.setStyleSheet("color: #93a4b8;")
        layout.addWidget(self.scan_hint)
        self.setup_findings_table(layout)

    def setup_findings_table(self, layout: QVBoxLayout) -> None:
        group = QGroupBox("نتائج الفحص الأخيرة")
        box = QVBoxLayout(group)
        self.table_findings = QTableWidget(0, 4)
        self.table_findings.setHorizontalHeaderLabels(["الخطورة", "النتيجة", "الفئة", "الإجراء المقترح"])
        self.table_findings.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_findings.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table_findings.setAlternatingRowColors(True)
        box.addWidget(self.table_findings)
        layout.addWidget(group)

    def setup_tools_tab(self) -> None:
        layout = QVBoxLayout(self.tab_tools)
        group = QGroupBox("أدوات التدقيق والتحصين")
        grid = QGridLayout(group)
        self.tool_path = QLineEdit(".")
        grid.addWidget(QLabel("المسار:"), 0, 0)
        grid.addWidget(self.tool_path, 0, 1, 1, 3)
        actions = [
            ("CIS / Hardening", self.agent._run_deep_audit), ("Lynis", self.agent._run_lynis_cli),
            ("YARA", lambda: self.agent._run_yara_cli(self.tool_path.text().strip() or ".")),
            ("Rootkit", self.agent._run_rootkit_cli), ("كشف الأسرار", lambda: self.agent._scan_secrets_cli(self.tool_path.text().strip() or ".")),
            ("تعلّم خط الأساس", self.agent._run_baseline_learn_cli), ("فحص خط الأساس", self.agent._run_baseline_check_cli),
            ("توليد قواعد دفاعية", self.agent._run_synthesize_rules_cli), ("خطة المعالجة", self.agent._generate_remediation_plan),
            ("تقرير HTML", self.agent._export_html_report), ("تحديث معلومات التهديدات", self.agent._update_intel),
        ]
        for i, (text, fn) in enumerate(actions):
            btn = QPushButton(text)
            btn.clicked.connect(lambda _checked=False, f=fn, t=text: self.run_background_task(f, t))
            grid.addWidget(btn, 1 + i // 3, i % 3)
        layout.addWidget(group)
        note = QLabel("تنبيه: أدوات الإصلاح التلقائي قد تغيّر إعدادات النظام. استخدمها من المحادثة أو الطرفية بعد مراجعة النتائج.")
        note.setStyleSheet("color: #fbbf24;")
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

    def update_live_telemetry(self) -> None:
        try:
            conns = LiveReconEngine.get_live_connections()
            self.table_conns.setRowCount(0)
            for c in conns[:30]:
                values = [c.get("proto", ""), c.get("state", ""), c.get("local", ""), c.get("remote", ""), c.get("process", ""), c.get("pid", "")]
                row = self.table_conns.rowCount()
                self.table_conns.insertRow(row)
                for col, value in enumerate(values):
                    item = QTableWidgetItem(str(value))
                    if col == 3 and c.get("is_foreign"):
                        item.setForeground(QColor("#f87171"))
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
        except Exception as exc:
            self.chat_display.append(f"[تحذير الرادار] {exc}")

    def send_chat_message(self) -> None:
        text = self.chat_input.text().strip()
        if not text:
            return
        self.chat_input.clear()
        self.chat_display.append(f"\n[أنت] {text}")
        cmd = self.agent.nlp.parse(text)
        self.chat_display.append(f"[الوكيل] فهمت الطلب: {self.agent.nlp.describe_intent(cmd.intent, 'ar')}")
        if cmd.intent == "explain":
            self.chat_display.append(self.agent.nlp.explain(cmd.explain_target or text))
            return
        self.chat_display.append("[الوكيل] لتنفيذ الفحص استخدم زر الوظيفة المقابل في مركز الفحوصات أو الترسانة.")

    def run_background_task(self, fn: Callable[..., Any], title: str) -> None:
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, "مهمة قيد التنفيذ", "انتظر انتهاء المهمة الحالية قبل تشغيل مهمة أخرى.")
            return
        self.status_badge.setText(f"الحالة: يعمل — {title}")
        self.status_badge.setStyleSheet("color: #fde68a; font-weight: 700; padding: 8px 12px; border: 1px solid #d97706; border-radius: 6px;")
        self.chat_display.append(f"\n[بدء] {title}")
        self.worker = WorkerThread(fn)
        self.worker.finished.connect(lambda result, task=title: self.task_done(result, task))
        self.worker.start()

    def task_done(self, result: Any, title: str) -> None:
        if isinstance(result, Exception):
            self.status_badge.setText("الحالة: فشل")
            self.status_badge.setStyleSheet("color: #fca5a5; font-weight: 700; padding: 8px 12px; border: 1px solid #ef4444; border-radius: 6px;")
            self.chat_display.append(f"[خطأ] {title}: {result}")
            return
        if isinstance(result, list) and result and isinstance(result[0], dict):
            self.agent._last_findings = result
        self.render_findings(getattr(self.agent, "_last_findings", []) or [])
        self.status_badge.setText("الحالة: جاهز")
        self.status_badge.setStyleSheet("color: #86efac; font-weight: 700; padding: 8px 12px; border: 1px solid #22c55e; border-radius: 6px;")
        self.chat_display.append(f"[اكتمل] {title}")
        self.tabs.setCurrentWidget(self.tab_scans)

    def render_findings(self, findings: list) -> None:
        self.table_findings.setRowCount(0)
        for finding in findings:
            row = self.table_findings.rowCount()
            self.table_findings.insertRow(row)
            severity = str(finding.get("severity", "info")).upper()
            item = QTableWidgetItem(severity)
            item.setForeground(QColor({"CRITICAL": "#f87171", "HIGH": "#fb923c", "MEDIUM": "#facc15", "LOW": "#60a5fa"}.get(severity, "#86efac")))
            values = [item, QTableWidgetItem(str(finding.get("title", ""))), QTableWidgetItem(str(finding.get("category", ""))), QTableWidgetItem(str(finding.get("fix", "")))]
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
