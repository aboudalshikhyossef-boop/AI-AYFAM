"""
AI AYFAM View — Scan View
شاشة بدء وإدارة الفحص الأمني
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QProgressBar
from ui.tokens import Tokens

class ScanView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        title = QLabel("مركز الفحص الذكي")
        title.setStyleSheet(f"font-size: {Tokens.FONT_SIZE_XL}; font-weight: bold;")
        layout.addWidget(title)

        self.btn_scan = QPushButton("بدء الفحص الأمني الشامل")
        layout.addWidget(self.btn_scan)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        layout.addStretch()
