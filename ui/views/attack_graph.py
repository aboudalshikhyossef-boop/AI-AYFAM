"""
AI AYFAM View — Attack-Chain Graph View (QGraphicsScene)
شاشة شجرة سلاسل الهجوم التفاعلية
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsTextItem
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPen, QBrush
from ui.tokens import Tokens

class AttackChainGraphView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        title = QLabel("شجرة سلاسل الهجوم المرتبطة (Attack-Chain Graph)")
        title.setStyleSheet(f"font-size: {Tokens.FONT_SIZE_XL}; font-weight: bold; color: {Tokens.ACCENT_CYAN};")
        layout.addWidget(title)

        self.scene = QGraphicsScene()
        self.view = QGraphicsView(self.scene)
        self.view.setStyleSheet(f"background-color: {Tokens.DARK_BG_PRIMARY}; border: 1px solid {Tokens.DARK_BORDER_GLASS};")
        layout.addWidget(self.view)

    def render_chain(self, attack_chain_findings: list):
        self.scene.clear()
        x, y = 50, 50
        pen = QPen(QColor(Tokens.ACCENT_CYAN))
        brush = QBrush(QColor(Tokens.DARK_BG_SECONDARY))

        for item in attack_chain_findings:
            node = self.scene.addEllipse(x, y, 120, 60, pen, brush)
            text = self.scene.addText(item.get("title", "Chain Step")[:20])
            text.setDefaultTextColor(QColor(Tokens.TEXT_PRIMARY))
            text.setPos(x + 10, y + 15)
            x += 180
            if x > 600:
                x = 50
                y += 100
