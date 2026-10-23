"""
AI AYFAM View — Findings View
شاشة استعراض النتائج والتفاصيل
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QListWidget, QTextEdit
from ui.tokens import Tokens

class FindingsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        title = QLabel("قائمة النتائج والتنبيهات الأمنية")
        title.setStyleSheet(f"font-size: {Tokens.FONT_SIZE_XL}; font-weight: bold;")
        layout.addWidget(title)

        self.list_findings = QListWidget()
        layout.addWidget(self.list_findings)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        layout.addWidget(self.detail_text)
