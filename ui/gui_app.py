"""واجهة AI AYFAM الرسومية — minimal restore so app launches (full version via loader)."""
from __future__ import annotations
import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget, QPushButton, QMessageBox

def launch_gui():
    app = QApplication(sys.argv)
    w = QMainWindow()
    w.setWindowTitle("AI AYFAM — استعادة الواجهة")
    central = QWidget()
    layout = QVBoxLayout(central)
    layout.addWidget(QLabel("ui/gui_app.py كان فارغاً.\nتم رفع محمّل الاستعادة.\nشغّل:\n  python3 -m tools.gui_loader\nثم أعد تشغيل التطبيق."))
    btn = QPushButton("تشغيل محمّل الاستعادة الآن")
    def run_loader():
        try:
            import tools.gui_loader
            QMessageBox.information(w, "تم", "تم استعادة الواجهة. أعد تشغيل التطبيق.")
        except Exception as e:
            QMessageBox.critical(w, "خطأ", str(e))
    btn.clicked.connect(run_loader)
    layout.addWidget(btn)
    w.setCentralWidget(central)
    w.resize(500, 300)
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    launch_gui()
