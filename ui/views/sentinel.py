"""
AI AYFAM View — Sentinel View
شاشة الحارس اللحظي والأحداث الفورية
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QListWidget
from ui.tokens import Tokens

class SentinelView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        title = QLabel("الحارس اللحظي (Live Sentinel Feed)")
        title.setStyleSheet(f"font-size: {Tokens.FONT_SIZE_XL}; font-weight: bold; color: {Tokens.ACCENT_NEON_GREEN};")
        layout.addWidget(title)

        self.list_feed = QListWidget()
        layout.addWidget(self.list_feed)
