#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}[*] جاري تجهيز بيئة التطبيق المكتبي (PyQt6 Desktop Suite)...${NC}"

# 1. التأكد من تثبيت مكتبة PyQt6
if ! python3 -c "import PyQt6" &>/dev/null; then
    echo -e "${YELLOW}[!] تثبيت مكتبة الواجهة الرسومية PyQt6 لنظام لينكس...${NC}"
    sudo apt-get update -q && sudo apt-get install -y python3-pyqt6 || pip3 install PyQt6
fi

mkdir -p ui resources ~/.local/share/applications

# ==============================================================================
# 2. إنشاء أيقونة التطبيق (SVG Shield Icon)
# ==============================================================================
cat << 'SEOF' > resources/icon.svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="128" height="128">
  <path fill="#06b6d4" d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.67-3.13 9.02-7 10.15-3.87-1.13-7-5.48-7-10.15V6.3l7-3.12z"/>
  <path fill="#10b981" d="M12 4.5l-5 2.2v4.3c0 3.6 2.3 6.9 5 7.8 2.7-.9 5-4.2 5-7.8V6.7l-5-2.2z"/>
  <circle cx="12" cy="11" r="2.5" fill="#f8fafc"/>
</svg>
SEOF

# ==============================================================================
# 3. بناء واجهة التطبيق المكتبي الكاملة ui/gui_app.py
# ==============================================================================
cat << 'GEOF' > ui/gui_app.py
"""
AI AYFAM v6 — Native Linux Mint Desktop Security Cockpit
تطبيق سطح المكتب المتكامل والفاخر لـ Linux Mint — مبني بـ PyQt6
معمارية غير حاجبة (Multi-threaded)، عداد أمان تفاعلي، وترسانة فحص متقدمة.
"""

import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QTextEdit, QLineEdit, QFileDialog, QSystemTrayIcon,
    QMenu, QProgressBar, QMessageBox, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QIcon, QFont, QColor

# فئة تنفيذ العمليات في الخلفية لمنع تجميد الواجهة أثناء الفحص
class WorkerThread(QThread):
    finished = pyqtSignal(object)
    log_msg = pyqtSignal(str)

    def __init__(self, task_fn, *args):
        super().__init__()
        self.task_fn = task_fn
        self.args = args

    def run(self):
        try:
            res = self.task_fn(*self.args)
            self.finished.emit(res)
        except Exception as e:
            self.finished.emit(e)


class AyfamMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI AYFAM Enterprise v6 — Security Management Cockpit")
        self.resize(1100, 720)
        self.setMinimumSize(900, 600)
        self.apply_dark_theme()

        # تعيين الأيقونة
        icon_path = os.path.expanduser("~/Downloads/AI-AYFAM/resources/icon.svg")
        if not os.path.exists(icon_path):
            icon_path = os.path.abspath("resources/icon.svg")
        self.app_icon = QIcon(icon_path)
        self.setWindowIcon(self.app_icon)

        # استدعاء الوكيل والمحركات
        from config.settings import Settings
        from ui.terminal import TerminalUI
        from core.agent import AYFAMAgent
        self.settings = Settings()
        self.ui_term = TerminalUI(no_color=True)
        self.agent = AYFAMAgent(settings=self.settings, ui=self.ui_term)

        self.init_tray_icon()
        self.init_ui()

    def apply_dark_theme(self):
        """تطبيق تصميم داكن فاخر مخصص للأمن السيبراني."""
        self.setStyleSheet("""
            QMainWindow { background-color: #0f172a; }
            QWidget { color: #f8fafc; font-family: system-ui, -apple-system, sans-serif; font-size: 13px; }
            QTabWidget::pane { border: 1px solid #334155; background: #1e293b; border-radius: 8px; }
            QTabBar::tab { background: #0f172a; color: #94a3b8; padding: 10px 20px; font-weight: bold; border-top-left-radius: 6px; border-top-right-radius: 6px; }
            QTabBar::tab:selected { background: #1e293b; color: #06b6d4; border-bottom: 2px solid #06b6d4; }
            QTableWidget { background-color: #0f172a; border: 1px solid #334155; gridline-color: #1e293b; border-radius: 6px; selection-background-color: #0891b2; }
            QHeaderView::section { background-color: #1e293b; color: #06b6d4; padding: 6px; border: 1px solid #334155; font-weight: bold; }
            QPushButton { background-color: #0891b2; color: #ffffff; border: none; border-radius: 6px; padding: 8px 16px; font-weight: bold; }
            QPushButton:hover { background-color: #06b6d4; }
            QPushButton:pressed { background-color: #0e7490; }
            QLineEdit, QTextEdit { background-color: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 8px; color: #fff; }
            QProgressBar { border: 1px solid #334155; border-radius: 6px; text-align: center; color: white; background: #0f172a; }
            QProgressBar::chunk { background-color: #10b981; border-radius: 5px; }
        """)

    def init_tray_icon(self):
        """أيقونة الحارس في شريط المهام السفلي بجوار الساعة."""
        self.tray = QSystemTrayIcon(self.app_icon, self)
        tray_menu = QMenu()
        show_action = tray_menu.addAction("فتح اللوحة الرئيسية")
        show_action.triggered.connect(self.showNormal)
        quit_action = tray_menu.addAction("خروج")
        quit_action.triggered.connect(QApplication.instance().quit)
        self.tray.setContextMenu(tray_menu)
        self.tray.show()

    def init_ui(self):
        main_widget = QWidget()
        layout = QVBoxLayout(main_widget)

        # الشريط العلوي
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        app_title = QLabel("AI AYFAM Enterprise v6 — Cockpit")
        app_title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        app_title.setStyleSheet("color: #06b6d4;")
        sub_title = QLabel("وكيل الأمن السيبراني ومنصة الدفاع اللحظي — Linux Mint")
        sub_title.setStyleSheet("color: #94a3b8;")
        title_box.addWidget(app_title)
        title_box.addWidget(sub_title)
        header.addLayout(title_box)
        header.addStretch()

        self.score_card = QLabel("درجة الأمان: --/100")
        self.score_card.setStyleSheet("background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 8px 16px; font-size: 15px; font-weight: bold; color: #10b981;")
        header.addWidget(self.score_card)
        layout.addLayout(header)

        # التبويبات
        self.tabs = QTabWidget()
        self.tabs.setLayoutDirection(Qt.LayoutDirection.RightToLeft)

        self.tab_dashboard = QWidget()
        self.tab_arsenal = QWidget()
        self.tab_playbooks = QWidget()
        self.tab_sentinel = QWidget()

        self.setup_dashboard_tab()
        self.setup_arsenal_tab()
        self.setup_playbook_tab()
        self.setup_sentinel_tab()

        self.tabs.addTab(self.tab_dashboard, "📊 لوحة التحكم")
        self.tabs.addTab(self.tab_arsenal, "🛡️ الترسانة والفحص العميق")
        self.tabs.addTab(self.tab_playbooks, "📖 خطط العمل والمكتبة")
        self.tabs.addTab(self.tab_sentinel, "🚨 الحارس النشط اللحظي")

        layout.addWidget(self.tabs)

        # شريط الحالة السفلي
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setMaximum(0)
        self.progress.hide()
        layout.addWidget(self.progress)

        self.setCentralWidget(main_widget)

    # ── 1) Dashboard Tab ───────────────────────────────────────────────────────
    def setup_dashboard_tab(self):
        lay = QVBoxLayout(self.tab_dashboard)

        quick_btns = QHBoxLayout()
        btn_quick_scan = QPushButton("🔍 فحص أمني سريع")
        btn_quick_scan.clicked.connect(lambda: self.run_background_task(self.agent._scan_network, "فحص الشبكة السريع"))
        btn_cis = QPushButton("🛡️ تدقيق التحصين بنمط CIS")
        btn_cis.clicked.connect(lambda: self.run_background_task(self.agent._run_deep_audit, "فحص التحصين CIS"))
        btn_plan = QPushButton("📋 إنشاء سكريبت الإصلاحات")
        btn_plan.clicked.connect(lambda: self.run_background_task(self.agent._generate_remediation_plan, "توليد الخطة"))
        btn_html = QPushButton("🌐 تصدير تقرير HTML")
        btn_html.clicked.connect(lambda: self.run_background_task(self.agent._export_html_report, "تصدير HTML"))

        quick_btns.addWidget(btn_quick_scan)
        quick_btns.addWidget(btn_cis)
        quick_btns.addWidget(btn_plan)
        quick_btns.addWidget(btn_html)
        lay.addLayout(quick_btns)

        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setStyleSheet("font-family: monospace; background: #0b1120; border: 1px solid #334155; padding: 10px; color: #38bdf8;")
        self.log_console.setPlaceholderText("سجل أحداث النظام والنتائج يظهر هنا فورياً...")
        lay.addWidget(self.log_console)

    # ── 2) Arsenal Tab ─────────────────────────────────────────────────────────
    def setup_arsenal_tab(self):
        lay = QVBoxLayout(self.tab_arsenal)
        btn_bar = QHBoxLayout()

        btn_lynis = QPushButton("تشغيل فحص Lynis القياسي")
        btn_lynis.clicked.connect(lambda: self.run_background_task(self.agent._run_lynis_cli, "فحص Lynis"))
        btn_yara = QPushButton("فحص YARA للبرمجيات الخبيثة")
        btn_yara.clicked.connect(lambda: self.run_background_task(lambda: self.agent._run_yara_cli("."), "فحص YARA"))
        btn_rootkit = QPushButton("كشف الجذور الخفية (Rootkits)")
        btn_rootkit.clicked.connect(lambda: self.run_background_task(self.agent._run_rootkit_cli, "فحص Rootkits"))

        btn_bar.addWidget(btn_lynis)
        btn_bar.addWidget(btn_yara)
        btn_bar.addWidget(btn_rootkit)
        lay.addLayout(btn_bar)

        self.findings_table = QTableWidget(0, 4)
        self.findings_table.setHorizontalHeaderLabels(["الخطورة", "الملاحظة الأمنية", "الفئة", "الحل المقترح"])
        self.findings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.findings_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        lay.addWidget(self.findings_table)

    # ── 3) Playbook Tab ────────────────────────────────────────────────────────
    def setup_playbook_tab(self):
        lay = QVBoxLayout(self.tab_playbooks)
        top = QHBoxLayout()
        self.pb_input = QLineEdit()
        self.pb_input.setPlaceholderText("اكتب أداة أو تقنية (مثال: nmap, privilege_escalation)...")
        btn_gen = QPushButton("استخراج خطة العمل من الكتب")
        btn_gen.clicked.connect(self.extract_playbook_action)
        btn_add_book = QPushButton("📚 إضافة كتاب PDF للمكتبة")
        btn_add_book.clicked.connect(self.browse_and_learn_book)

        top.addWidget(self.pb_input)
        top.addWidget(btn_gen)
        top.addWidget(btn_add_book)
        lay.addLayout(top)

        self.pb_viewer = QTextEdit()
        self.pb_viewer.setReadOnly(True)
        self.pb_viewer.setStyleSheet("background: #0b1120; font-family: monospace; font-size: 13px; color: #a5f3fc;")
        lay.addWidget(self.pb_viewer)

    # ── 4) Sentinel Tab ────────────────────────────────────────────────────────
    def setup_sentinel_tab(self):
        lay = QVBoxLayout(self.tab_sentinel)
        top = QHBoxLayout()
        lbl = QLabel("الحارس النشط (Active Sentinel): يراقب النواة، الاتصالات، وتعديلات الملفات الحساسة لحظياً")
        lbl.setStyleSheet("color: #94a3b8; font-weight: bold;")
        self.btn_toggle_sentinel = QPushButton("تشغيل الحارس النشط")
        self.btn_toggle_sentinel.clicked.connect(self.toggle_sentinel)
        top.addWidget(lbl)
        top.addStretch()
        top.addWidget(self.btn_toggle_sentinel)
        lay.addLayout(top)

        self.sentinel_logs = QTextEdit()
        self.sentinel_logs.setReadOnly(True)
        self.sentinel_logs.setStyleSheet("background: #0b1120; font-family: monospace; color: #6ee7b7;")
        lay.addWidget(self.sentinel_logs)

    # ── Tasks & Threading ──────────────────────────────────────────────────────
    def run_background_task(self, fn, task_title: str):
        self.progress.show()
        self.log_console.append(f"\n[+] بدأ تنفيذ: {task_title}...")
        self.worker = WorkerThread(fn)
        self.worker.finished.connect(lambda res: self.task_completed(res, task_title))
        self.worker.start()

    def task_completed(self, result, task_title: str):
        self.progress.hide()
        self.log_console.append(f"[✓] اكتمل: {task_title} بنجاح.")
        # تحديث الجداول والدرجة
        if getattr(self.agent, "_last_findings", None):
            self.populate_findings_table(self.agent._last_findings)
            from engine.risk import RiskEngine
            eval_res = RiskEngine.evaluate(self.agent._last_findings)
            score = eval_res.get("score", 100)
            grade = eval_res.get("grade", "A+")
            self.score_card.setText(f"درجة الأمان: {score}/100 ({grade})")

    def populate_findings_table(self, findings):
        self.findings_table.setRowCount(0)
        for f in findings:
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)
            sev = f.get("severity", "info").upper()
            title = f.get("title", "")
            cat = f.get("category", "")
            fix = f.get("fix", "")

            item_sev = QTableWidgetItem(sev)
            if sev in ("CRITICAL", "HIGH"):
                item_sev.setForeground(QColor("#ef4444"))
            elif sev == "MEDIUM":
                item_sev.setForeground(QColor("#f59e0b"))
            else:
                item_sev.setForeground(QColor("#10b981"))

            self.findings_table.setItem(row, 0, item_sev)
            self.findings_table.setItem(row, 1, QTableWidgetItem(title))
            self.findings_table.setItem(row, 2, QTableWidgetItem(cat))
            self.findings_table.setItem(row, 3, QTableWidgetItem(fix))

    def extract_playbook_action(self):
        topic = self.pb_input.text().strip()
        if not topic:
            return
        from brain.playbook_engine import PlaybookEngine
        pe = PlaybookEngine(kb=self.agent.kb)
        pb = pe.generate_playbook(topic)
        out = f"=== خطة العمل المستخرجة لـ: {topic} ===\n"
        out += f"إجمالي الأوامر الموثقة: {pb['total_commands']}\n\n"
        for st_name, steps in pb["stages"].items():
            if steps:
                out += f"[{st_name}]\n"
                for s in steps:
                    out += f"  $ {s['cmd']}\n    — المصدر: «{s['book']}» ({s['page']})\n"
                out += "\n"
        self.pb_viewer.setText(out)

    def browse_and_learn_book(self):
        path, _ = QFileDialog.getOpenFileName(self, "اختر كتاب تقني (PDF/TXT)", "", "Security Books (*.pdf *.txt *.md)")
        if path:
            self.pb_viewer.setText(f"جاري استيعاب وفهرسة الكتاب: {path}...\nيرجى الانتظار...")
            self.run_background_task(lambda: self.agent._learn_from_file(path), "استيعاب كتاب")

    def toggle_sentinel(self):
        if not getattr(self, "sentinel_active", False):
            from engine.sentinel import ActiveSentinel
            self.sentinel = ActiveSentinel(check_interval=5)
            self.sentinel.start()
            self.sentinel_active = True
            self.btn_toggle_sentinel.setText("إيقاف الحارس النشط")
            self.btn_toggle_sentinel.setStyleSheet("background-color: #ef4444;")
            self.sentinel_logs.append("[*] تم تفعيل الحارس النشط للمراقبة اللحظية في الخلفية.")
        else:
            if hasattr(self, "sentinel"):
                self.sentinel.stop()
            self.sentinel_active = False
            self.btn_toggle_sentinel.setText("تشغيل الحارس النشط")
            self.btn_toggle_sentinel.setStyleSheet("background-color: #0891b2;")
            self.sentinel_logs.append("[*] تم إيقاف الحارس النشط.")


def launch_gui():
    app = QApplication(sys.argv)
    window = AyfamMainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    launch_gui()
GEOF

# ==============================================================================
# 4. تحديث main.py لدعم تشغيل الواجهة الرسومية عبر --gui
# ==============================================================================
python3 -c '
with open("main.py", "r", encoding="utf-8") as f:
    text = f.read()

if "--gui" not in text:
    text = text.replace(
        "parser.add_argument(\"--audit\", action=\"store_true\", help=\"فحص تحصين شامل بنمط CIS\")",
        "parser.add_argument(\"--gui\", action=\"store_true\", help=\"تشغيل واجهة سطح المكتب الرسومية (GUI Cockpit)\")\n"
        "    parser.add_argument(\"--audit\", action=\"store_true\", help=\"فحص تحصين شامل بنمط CIS\")"
    )
    text = text.replace(
        "if args.set_github_token:",
        "if args.gui:\n"
        "        from ui.gui_app import launch_gui\n"
        "        launch_gui()\n"
        "        return\n\n"
        "    if args.set_github_token:"
    )
    with open("main.py", "w", encoding="utf-8") as f:
        f.write(text)
    print("  [✓] main.py updated to support native Desktop GUI (--gui).")
'

# ==============================================================================
# 5. تسجيل التطبيق رسمياً في نظام Linux Mint (Start Menu & Launcher)
# ==============================================================================
DESKTOP_ENTRY_DIR="$HOME/.local/share/applications"
mkdir -p "$DESKTOP_ENTRY_DIR"

APP_DIR="$(pwd)"
cat << DEOF > "$DESKTOP_ENTRY_DIR/ayfam.desktop"
[Desktop Entry]
Version=1.0
Type=Application
Name=AI AYFAM Security Cockpit
GenericName=Cybersecurity EDR & Sentinel Console
Comment=Enterprise Local Cybersecurity Agent for Linux Mint
Exec=python3 $APP_DIR/main.py --gui
Icon=$APP_DIR/resources/icon.svg
Terminal=false
Categories=System;Security;Settings;
StartupNotify=true
DEOF

chmod +x "$DESKTOP_ENTRY_DIR/ayfam.desktop"

# إنشاء سكريبت تشغيل عالمي ayfam-gui
sudo tee /usr/local/bin/ayfam-gui > /dev/null << LEOF
#!/usr/bin/env bash
exec python3 "$APP_DIR/main.py" --gui "\$@"
LEOF
sudo chmod +x /usr/local/bin/ayfam-gui || true

echo -e "\n${GREEN}======================================================================"
echo -e "  🎉  تم بناء وتثبيت تطبيق سطح المكتب AI AYFAM Cockpit بنجاح تام!"
echo -e "======================================================================${NC}"
echo -e "طرق فتح التطبيق المكتبي الجديد الآن:"
echo -e "  1. من قائمة البرامج في Linux Mint: ستجد ${CYAN}AI AYFAM Security Cockpit${NC} في قسم (System / Security)."
echo -e "  2. أو بكتابة هذا الأمر في أي طرفية: ${YELLOW}ayfam-gui${NC} أو ${YELLOW}python3 main.py --gui${NC}"
echo ""
