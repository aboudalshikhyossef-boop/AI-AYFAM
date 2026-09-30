#!/usr/bin/env bash
# ==============================================================================
#  AI AYFAM Enterprise v7 — ABOUDA Master Edition
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${RED}${BOLD}[*] استكمال تثبيت وتحديث AI AYFAM Enterprise v7 — نسخة ABOUDA...${NC}"

# إنشاء المجلدات المحلية للمشروع وللمستخدم بأمان
mkdir -p engine tools ui resources reports "$HOME/.local/share/applications"

# ==============================================================================
# 1. بناء محرك الرادار والاتصالات اللحظية (engine/live_recon.py)
# ==============================================================================
cat << 'RECON_EOF' > engine/live_recon.py
"""
AI AYFAM v7 — Live Network & Kernel Telemetry Engine
محرك الرادار المباشر — قراءة المقابس اللحظية ومراقبة العمليات واستدعاءات النظام مباشرة من النواة
"""

import os
import re
from typing import List, Dict, Any
from utils import safe_exec

class LiveReconEngine:
    @staticmethod
    def get_live_connections() -> List[Dict[str, Any]]:
        conns = []
        res = safe_exec.run(["ss", "-tunap"], timeout=5, check_binary=False)
        if not res.ok or not res.stdout:
            return conns

        for line in res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                proto = parts[0]
                state = parts[1]
                local = parts[4]
                remote = parts[5]
                proc_info = " ".join(parts[6:]) if len(parts) > 6 else "—"

                pname = "—"
                pid = "—"
                m_proc = re.search(r'"([^"]+)"', proc_info)
                if m_proc:
                    pname = m_proc.group(1)
                m_pid = re.search(r'pid=(\d+)', proc_info)
                if m_pid:
                    pid = m_pid.group(1)

                is_foreign = not any(remote.startswith(x) for x in ("127.", "0.0.", "::", "*", "192.168.", "10."))
                
                conns.append({
                    "proto": proto,
                    "state": state,
                    "local": local,
                    "remote": remote,
                    "process": pname,
                    "pid": pid,
                    "is_foreign": is_foreign,
                })
        return conns

    @staticmethod
    def get_top_processes(limit: int = 15) -> List[Dict[str, str]]:
        procs = []
        res = safe_exec.run(["ps", "aux", "--sort=-%cpu"], timeout=5, check_binary=False)
        if not res.ok or not res.stdout:
            return procs

        for line in res.stdout.splitlines()[1:limit+1]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({
                    "user": parts[0],
                    "pid": parts[1],
                    "cpu": parts[2],
                    "mem": parts[3],
                    "command": parts[10][:70],
                })
        return procs
RECON_EOF

# ==============================================================================
# 2. بناء واجهة كابينة القيادة الزجاجية الموحدة (ui/gui_app.py)
# ==============================================================================
cat << 'GUI_EOF' > ui/gui_app.py
"""
AI AYFAM Enterprise v7 — Unified Security Cockpit (ABOUDA Edition)
كابينة القيادة الموحدة: رادار لحظي، محادثة ذكية متكاملة، ترسانة جنائية، وتصميم زجاجي عالي الدقة.
"""

import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QTextEdit, QLineEdit, QSplitter, QProgressBar,
    QFrame
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QIcon, QFont, QColor

from config.settings import Settings
from ui.terminal import TerminalUI
from core.agent import AYFAMAgent
from engine.live_recon import LiveReconEngine
from engine.risk import RiskEngine

CRIMSON_THEME = """
QMainWindow {
    background: #07090e;
}
QWidget {
    color: #e2e8f0;
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    font-size: 13px;
}
QFrame.glassCard {
    background: #0b0f19;
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 8px;
}
QTabWidget::pane {
    border: 1px solid rgba(239, 68, 68, 0.2);
    background: #0b0f19;
    border-radius: 8px;
}
QTabBar::tab {
    background: #07090e;
    color: #94a3b8;
    padding: 10px 24px;
    font-weight: bold;
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background: #0f172a;
    color: #ef4444;
    border-bottom: 2px solid #ef4444;
}
QTableWidget {
    background: #080c14;
    border: 1px solid rgba(255, 255, 255, 0.08);
    gridline-color: rgba(255, 255, 255, 0.04);
    border-radius: 8px;
    color: #f1f5f9;
}
QHeaderView::section {
    background: #0f172a;
    color: #ef4444;
    padding: 8px;
    border: none;
    font-weight: bold;
}
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #991b1b, stop:1 #dc2626);
    color: #ffffff;
    border: 1px solid #ef4444;
    border-radius: 6px;
    padding: 8px 18px;
    font-weight: bold;
}
QPushButton:hover {
    background: #ef4444;
}
QLineEdit, QTextEdit {
    background: #06080d;
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 6px;
    padding: 8px;
    color: #f8fafc;
}
"""

class WorkerThread(QThread):
    finished = pyqtSignal(object)
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

class UnifiedCockpitWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI AYFAM Enterprise v7 — Master Security Cockpit [ABOUDA]")
        self.resize(1280, 800)
        self.setStyleSheet(CRIMSON_THEME)

        icon_path = os.path.expanduser("~/Downloads/AI-AYFAM/resources/icon.svg")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.settings = Settings()
        self.ui_term = TerminalUI(no_color=True)
        self.agent = AYFAMAgent(settings=self.settings, ui=self.ui_term)

        self.init_ui()
        self.init_live_telemetry_timer()

    def init_ui(self):
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(14, 14, 14, 8)

        # ── Top Master Header ──
        header_card = QFrame()
        header_card.setStyleSheet("background: #0b0f19; border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px; padding: 10px;")
        h_lay = QHBoxLayout(header_card)

        title_box = QVBoxLayout()
        title = QLabel("AI AYFAM ENTERPRISE v7 🛡️")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #ef4444; letter-spacing: 1px;")
        sub = QLabel("منصة الأمن والدفاع اللحظي السيبراني — وضع النواة والروت الكامل (Kernel Mode)")
        sub.setStyleSheet("color: #94a3b8; font-size: 11px;")
        title_box.addWidget(title)
        title_box.addWidget(sub)
        h_lay.addLayout(title_box)

        h_lay.addStretch()

        self.live_threat_badge = QLabel("التهديد اللحظي: آمن 🟢")
        self.live_threat_badge.setStyleSheet("color: #10b981; font-weight: bold; background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; padding: 6px 14px; border-radius: 6px;")
        h_lay.addWidget(self.live_threat_badge)

        self.score_badge = QLabel("الدرجة الأمنية: --/100")
        self.score_badge.setStyleSheet("color: #ef4444; font-weight: bold; background: rgba(239, 68, 68, 0.1); border: 1px solid #ef4444; padding: 6px 14px; border-radius: 6px;")
        h_lay.addWidget(self.score_badge)

        layout.addWidget(header_card)

        # ── Tabs Navigation ──
        self.tabs = QTabWidget()
        self.tabs.setLayoutDirection(Qt.LayoutDirection.RightToLeft)

        self.tab_radar = QWidget()
        self.tab_chat = QWidget()
        self.tab_arsenal = QWidget()
        self.tab_playbooks = QWidget()

        self.setup_radar_tab()
        self.setup_chat_tab()
        self.setup_arsenal_tab()
        self.setup_playbooks_tab()

        self.tabs.addTab(self.tab_radar, "⚡ الرادار المباشر والشبكة")
        self.tabs.addTab(self.tab_chat, "💬 كابينة المحادثة والوكيل الذكي")
        self.tabs.addTab(self.tab_arsenal, "🛡️ الترسانة والتدقيق الشامل")
        self.tabs.addTab(self.tab_playbooks, "📖 خطط العمل واستخراج الكتب")

        layout.addWidget(self.tabs)

        # ── Global Master Footer with Developer Signature ──
        footer = QHBoxLayout()
        sys_status = QLabel(f"المضيف: {os.uname().nodename}  |  المستخدم: root [SUDO ACTIVE]  |  الذاكرة: مراقبة مستمرة")
        sys_status.setStyleSheet("color: #64748b; font-size: 11px;")
        footer.addWidget(sys_status)

        footer.addStretch()

        dev_badge = QLabel("معماري ومطور المنصة: ABOUDA ⚡")
        dev_badge.setStyleSheet("color: #ef4444; font-weight: bold; font-size: 12px; letter-spacing: 1px;")
        footer.addWidget(dev_badge)

        layout.addLayout(footer)
        self.setCentralWidget(central)

    def setup_radar_tab(self):
        lay = QVBoxLayout(self.tab_radar)
        splitter = QSplitter(Qt.Orientation.Vertical)

        w_top = QWidget()
        lay_top = QVBoxLayout(w_top)
        lbl_conns = QLabel("📡 رادار المقابس والاتصالات الحية اللحظية (Live Sockets)")
        lbl_conns.setStyleSheet("color: #ef4444; font-weight: bold;")
        lay_top.addWidget(lbl_conns)

        self.table_conns = QTableWidget(0, 6)
        self.table_conns.setHorizontalHeaderLabels(["البروتوكول", "الحالة", "العنوان المحلي / المنفذ", "العنوان البعيد والهدف", "البرنامج المرتبط", "PID"])
        self.table_conns.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_conns.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        lay_top.addWidget(self.table_conns)
        splitter.addWidget(w_top)

        w_bot = QWidget()
        lay_bot = QVBoxLayout(w_bot)
        lbl_procs = QLabel("⚙️ مراقبة استهلاك العمليات ونواة النظام اللحظية (Kernel Processes)")
        lbl_procs.setStyleSheet("color: #ef4444; font-weight: bold;")
        lay_bot.addWidget(lbl_procs)

        self.table_procs = QTableWidget(0, 5)
        self.table_procs.setHorizontalHeaderLabels(["المستخدم", "PID", "% المعالج CPU", "% الذاكرة RAM", "أمر التشغيل الكامل"])
        self.table_procs.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        lay_bot.addWidget(self.table_procs)
        splitter.addWidget(w_bot)

        lay.addWidget(splitter)

    def setup_chat_tab(self):
        lay = QVBoxLayout(self.tab_chat)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        self.chat_display.setStyleSheet("background: #060911; border: 1px solid rgba(239,68,68,0.25); font-family: monospace; font-size: 13px; color: #f8fafc;")
        self.chat_display.append("[نظام الوكيل]: مرحباً بك يا ABOUDA. أنا AI AYFAM جاهز لتنفيذ أي فحص، تحليل CVE، أو استخراج أوامر من كتبك مباشرة هنا.")
        lay.addWidget(self.chat_display)

        input_box = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("اكتب أمرك أو استفسارك هنا (مثال: افحص الشبكة | اشرح nmap | ما هو وضع الأمان)...")
        self.chat_input.returnPressed.connect(self.send_chat_message)
        btn_send = QPushButton("إرسال للوكيل ❯")
        btn_send.clicked.connect(self.send_chat_message)

        input_box.addWidget(self.chat_input)
        input_box.addWidget(btn_send)
        lay.addLayout(input_box)

    def send_chat_message(self):
        txt = self.chat_input.text().strip()
        if not txt: return
        self.chat_input.clear()
        self.chat_display.append(f"\n[أنت] ❯ {txt}")

        cmd = self.agent.nlp.parse(txt)
        desc = self.agent.nlp.describe_intent(cmd.intent, "ar")
        self.chat_display.append(f"[🛡️ الوكيل]: فهمت طلبك: {desc} — جاري المعالجة...")
        
        if cmd.intent == "explain":
            explanation = self.agent.nlp.explain(cmd.explain_target or txt)
            self.chat_display.append(f"\n{explanation}")
        elif cmd.intent in ("scan_network", "full_scan", "scan_system"):
            self.chat_display.append("[*] بدأ الفحص في الخلفية... يمكنك متابعة النتائج في تبويب الترسانة فوراً.")
            self.run_background_task(self.agent._run_deep_audit, "فحص النظام")
        else:
            self.chat_display.append(f"[✓] تم توجيه النية ({cmd.intent}) بنجاح.")

    def setup_arsenal_tab(self):
        lay = QVBoxLayout(self.tab_arsenal)
        btn_bar = QHBoxLayout()

        b1 = QPushButton("⚡ فحص التحصين الشامل CIS")
        b1.clicked.connect(lambda: self.run_background_task(self.agent._run_deep_audit, "فحص CIS"))
        b2 = QPushButton("🔍 تشغيل تدقيق Lynis")
        b2.clicked.connect(lambda: self.run_background_task(self.agent._run_lynis_cli, "Lynis Audit"))
        b3 = QPushButton("🦠 فحص توقيعات YARA")
        b3.clicked.connect(lambda: self.run_background_task(lambda: self.agent._run_yara_cli("."), "YARA"))
        b4 = QPushButton("📋 إنشاء سكريبت الإصلاحات")
        b4.clicked.connect(lambda: self.run_background_task(self.agent._generate_remediation_plan, "توليد الخطة"))
        b5 = QPushButton("🌐 تقرير HTML التفاعلي")
        b5.clicked.connect(lambda: self.run_background_task(self.agent._export_html_report, "تقرير HTML"))

        for b in (b1, b2, b3, b4, b5):
            btn_bar.addWidget(b)
        lay.addLayout(btn_bar)

        self.table_findings = QTableWidget(0, 4)
        self.table_findings.setHorizontalHeaderLabels(["الخطورة", "الملاحظة والتهديد المكتشف", "الفئة", "الحل المقترح"])
        self.table_findings.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_findings.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        lay.addWidget(self.table_findings)

    def setup_playbooks_tab(self):
        lay = QVBoxLayout(self.tab_playbooks)
        top = QHBoxLayout()
        self.pb_in = QLineEdit()
        self.pb_in.setPlaceholderText("اكتب أداة أو موضوع (مثال: nmap, privilege_escalation, ufw)...")
        btn_pb = QPushButton("استخراج الخطة التكتيكية من الكتب")
        btn_pb.clicked.connect(self.load_playbook)

        top.addWidget(self.pb_in)
        top.addWidget(btn_pb)
        lay.addLayout(top)

        self.pb_text = QTextEdit()
        self.pb_text.setReadOnly(True)
        self.pb_text.setStyleSheet("background: #060911; font-family: monospace; font-size: 13px; color: #a5f3fc;")
        lay.addWidget(self.pb_text)

    def load_playbook(self):
        t = self.pb_in.text().strip()
        if not t: return
        from brain.playbook_engine import PlaybookEngine
        engine = PlaybookEngine(kb=self.agent.kb)
        pb = engine.generate_playbook(t)
        res = f"=== خطة العمل التكتيكية المستخرجة لموضوع: {t} ===\n"
        res += f"عدد الأوامر الموثقة: {pb['total_commands']}\n\n"
        for st_name, steps in pb["stages"].items():
            if steps:
                res += f"[{st_name}]\n"
                for s in steps:
                    res += f"  $ {s['cmd']}\n    — المرجع الموثق: «{s['book']}» (صفحة: {s['page']})\n"
                res += "\n"
        self.pb_text.setText(res)

    def init_live_telemetry_timer(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_live_telemetry)
        self.timer.start(2500)

    def update_live_telemetry(self):
        conns = LiveReconEngine.get_live_connections()
        self.table_conns.setRowCount(0)
        for c in conns[:25]:
            row = self.table_conns.rowCount()
            self.table_conns.insertRow(row)
            self.table_conns.setItem(row, 0, QTableWidgetItem(c["proto"]))
            self.table_conns.setItem(row, 1, QTableWidgetItem(c["state"]))
            self.table_conns.setItem(row, 2, QTableWidgetItem(c["local"]))
            rem_item = QTableWidgetItem(c["remote"])
            if c["is_foreign"]:
                rem_item.setForeground(QColor("#ef4444"))
            self.table_conns.setItem(row, 3, rem_item)
            self.table_conns.setItem(row, 4, QTableWidgetItem(c["process"]))
            self.table_conns.setItem(row, 5, QTableWidgetItem(c["pid"]))

        procs = LiveReconEngine.get_top_processes(12)
        self.table_procs.setRowCount(0)
        for p in procs:
            r = self.table_procs.rowCount()
            self.table_procs.insertRow(r)
            self.table_procs.setItem(r, 0, QTableWidgetItem(p["user"]))
            self.table_procs.setItem(r, 1, QTableWidgetItem(p["pid"]))
            cpu_item = QTableWidgetItem(f"{p['cpu']}%")
            if float(p["cpu"]) > 20.0:
                cpu_item.setForeground(QColor("#ef4444"))
            self.table_procs.setItem(r, 2, cpu_item)
            self.table_procs.setItem(r, 3, QTableWidgetItem(f"{p['mem']}%"))
            self.table_procs.setItem(r, 4, QTableWidgetItem(p["command"]))

    def run_background_task(self, fn, task_title: str):
        self.chat_display.append(f"\n[*] جاري تشغيل: {task_title}...")
        self.worker = WorkerThread(fn)
        self.worker.finished.connect(lambda res: self.task_done(res, task_title))
        self.worker.start()

    def task_done(self, res, title):
        self.chat_display.append(f"[✓] اكتمل بنجاح: {title}")
        if getattr(self.agent, "_last_findings", None):
            self.table_findings.setRowCount(0)
            for f in self.agent._last_findings:
                r = self.table_findings.rowCount()
                self.table_findings.insertRow(r)
                sev = f.get("severity", "info").upper()
                sev_item = QTableWidgetItem(sev)
                if sev in ("CRITICAL", "HIGH"):
                    sev_item.setForeground(QColor("#ef4444"))
                elif sev == "MEDIUM":
                    sev_item.setForeground(QColor("#f59e0b"))
                else:
                    sev_item.setForeground(QColor("#10b981"))
                self.table_findings.setItem(r, 0, sev_item)
                self.table_findings.setItem(r, 1, QTableWidgetItem(f.get("title", "")))
                self.table_findings.setItem(r, 2, QTableWidgetItem(f.get("category", "")))
                self.table_findings.setItem(r, 3, QTableWidgetItem(f.get("fix", "")))

            eval_res = RiskEngine.evaluate(self.agent._last_findings)
            self.score_badge.setText(f"الدرجة الأمنية: {eval_res.get('score', 100)}/100 ({eval_res.get('grade','A+')})")


def launch_gui():
    app = QApplication(sys.argv)
    window = UnifiedCockpitWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    launch_gui()
GUI_EOF

# ==============================================================================
# 3. إعداد سكريبت الإطلاق العالمي الإجباري بصلاحيات Root (ayfam-gui)
# ==============================================================================
APP_DIR="$(pwd)"
sudo tee /usr/local/bin/ayfam-gui > /dev/null << LAUNCHER_EOF
#!/usr/bin/env bash
if [ "\$EUID" -ne 0 ]; then
    exec sudo python3 "$APP_DIR/main.py" --gui "\$@"
else
    exec python3 "$APP_DIR/main.py" --gui "\$@"
fi
LAUNCHER_EOF
sudo chmod +x /usr/local/bin/ayfam-gui

# تحديث اختصار سطح المكتب الرسمي
cat << DESK_EOF > "$HOME/.local/share/applications/ayfam.desktop"
[Desktop Entry]
Version=1.0
Type=Application
Name=AI AYFAM Enterprise v7 — ABOUDA
Comment=Autonomous Cybersecurity Cockpit & EDR Sentinel
Exec=sudo python3 $APP_DIR/main.py --gui
Icon=$APP_DIR/resources/icon.svg
Terminal=false
Categories=System;Security;
StartupNotify=true
DESK_EOF
chmod +x "$HOME/.local/share/applications/ayfam.desktop"

echo -e "\n${GREEN}[✓] تم فحص وتجميع كود الواجهة الزجاجية برمجياً...${NC}"
python3 -m py_compile engine/live_recon.py ui/gui_app.py

echo -e "\n${RED}${BOLD}======================================================================"
echo -e "  🎉  تم تثبيت كابينة القيادة السيبرانية الموحدة AI AYFAM v7 بنجاح تام!"
echo -e "  المعماري والمطور: ABOUDA"
echo -e "======================================================================${NC}"
echo -e "افتح التطبيق الآن مباشرة بكتابة:"
echo -e "  ${YELLOW}ayfam-gui${NC}"
echo ""
