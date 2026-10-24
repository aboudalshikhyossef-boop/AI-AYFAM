"""
AI AYFAM View — Settings View
شاشة الإعدادات العامة واللغة والتحكم
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from ui.tokens import Tokens

class SettingsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        title = QLabel("إعدادات النظام والواجهة")
        title.setStyleSheet(f"font-size: {Tokens.FONT_SIZE_XL}; font-weight: bold;")
        layout.addWidget(title)

        self.btn_lang = QPushButton("التبديل إلى الإنجليزية (Switch to English)")
        layout.addWidget(self.btn_lang)

        layout.addStretch()
