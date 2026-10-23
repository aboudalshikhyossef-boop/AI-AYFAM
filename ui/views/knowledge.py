"""
AI AYFAM View — Knowledge Base View
شاشة المعرفة الأمنية وموسوعة ATT&CK
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit
from ui.tokens import Tokens

class KnowledgeView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        title = QLabel("قاعدة المعارف والتكتيكات الأمنية")
        title.setStyleSheet(f"font-size: {Tokens.FONT_SIZE_XL}; font-weight: bold;")
        layout.addWidget(title)

        self.info = QTextEdit()
        self.info.setReadOnly(True)
        self.info.setText("موسوعة التهديدات وتصنيفات MITRE ATT&CK للتعامل مع المخاطر.")
        layout.addWidget(self.info)
