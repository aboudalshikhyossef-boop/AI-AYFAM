"""
AI AYFAM View — Timeline View
شاشة الخط الزمني للحوادث
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QListWidget
from ui.tokens import Tokens

class TimelineView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        title = QLabel("الخط الزمني للحوادث والأحداث")
        title.setStyleSheet(f"font-size: {Tokens.FONT_SIZE_XL}; font-weight: bold;")
        layout.addWidget(title)

        self.list_timeline = QListWidget()
        layout.addWidget(self.list_timeline)
