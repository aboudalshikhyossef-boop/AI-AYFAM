"""
AI AYFAM View — Dashboard View
شاشة لوحة التحكم — مؤشرات الخطر، الرسم البياني، والملخص العام
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QFrame, QHBoxLayout
from ui.tokens import Tokens

class DashboardView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        title = QLabel("لوحة التحكم الأمنية — AI AYFAM Center")
        title.setStyleSheet(f"font-size: {Tokens.FONT_SIZE_XL}; font-weight: bold; color: {Tokens.ACCENT_CYAN};")
        layout.addWidget(title)

        card = QFrame()
        card.setProperty("class", "glass-card")
        card_layout = QHBoxLayout(card)

        gauge_label = QLabel("[آمن] مستوى الخطر العام: 0 (آمن)")
        gauge_label.setStyleSheet(f"font-size: {Tokens.FONT_SIZE_LARGE}; font-weight: bold; color: {Tokens.ACCENT_NEON_GREEN};")
        card_layout.addWidget(gauge_label)

        layout.addWidget(card)
        layout.addStretch()
