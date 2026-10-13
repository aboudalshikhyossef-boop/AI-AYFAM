"""مكونات Qt6: خلفية غير حاجبة، لمعان يتبع المؤشر، وفقاعات محادثة قابلة للنسخ."""
from __future__ import annotations

import html
import math
import re
from datetime import datetime

from PyQt6.QtCore import QEasingCurve, QObject, QPointF, QPropertyAnimation, QRect, QRectF, Qt, QTimer
from PyQt6.QtGui import QColor, QCursor, QTextBlockFormat, QTextCursor, QLinearGradient, QPainter, QPainterPath, QPen, QRadialGradient, QTextOption
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QFrame, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy, QTableWidget, QTextEdit,
    QVBoxLayout, QWidget,
)

from ui.theme import ACCENT, BG_BASE, SEV_SAFE, TEXT_MUTED, TEXT_SECONDARY, alpha


class AmbientSurface(QWidget):
    """Paint the background of the actual content container: zero extra layout space."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(100)  # slow ambient drift; 10 fps is enough and cheap

    def _tick(self):
        if self.isVisible():
            self._phase += 0.016
            self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(BG_BASE))
        w, h = self.width(), self.height()
        # Diffuse light has no solid circles or opaque shapes.
        for color, cx, cy in (("#2387ca", 0.22, 0.1), ("#24a678", 0.94, 0.76)):
            center = QPointF(w * (cx + 0.06 * math.sin(self._phase)), h * cy)
            g = QRadialGradient(center, max(w, h) * 0.8)
            c = QColor(color)
            c.setAlpha(32)
            g.setColorAt(0, c)
            c.setAlpha(0)
            g.setColorAt(1, c)
            p.fillRect(self.rect(), g)
        # One moving, very faint diagonal light band.
        g = QLinearGradient(0, 0, w, h)
        t = 0.5 + 0.18 * math.sin(self._phase * 0.6)
        g.setColorAt(0, QColor(56, 189, 248, 0))
        g.setColorAt(max(0, t - 0.15), QColor(56, 189, 248, 0))
        g.setColorAt(t, QColor(56, 189, 248, 5))
        g.setColorAt(min(1, t + 0.15), QColor(52, 211, 153, 0))
        g.setColorAt(1, QColor(52, 211, 153, 0))
        p.fillRect(self.rect(), g)


class AccentLine(QWidget):
    """Thin animated palette sweep under the header: blue, green, orange, red."""

    COLORS = ("#3b82f6", "#38bdf8", "#22c55e", "#34d399", "#f59e0b", "#ef4444", "#3b82f6")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(3)
        self.phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(40)

    def _tick(self):
        if self.isVisible():
            self.phase = (self.phase + 0.004) % 1.0
            self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        width = max(1, self.width())
        gradient = QLinearGradient(-self.phase * width * 2, 0, (1 - self.phase) * width * 2, 0)
        gradient.setSpread(QLinearGradient.Spread.RepeatSpread)
        last = len(self.COLORS) - 1
        for index, color in enumerate(self.COLORS):
            c = QColor(color)
            c.setAlpha(190)
            gradient.setColorAt(index / last, c)
        p.fillRect(self.rect(), gradient)


class NavIndicator(QWidget):
    """Sliding rim-light marker beside the active navigation button."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setGeometry(3, 0, 5, 0)
        self.animation = QPropertyAnimation(self, b"geometry", self)
        self.animation.setDuration(260)
        self.animation.setEasingCurve(QEasingCurve.Type.OutBack)

    def move_to(self, button):
        target = QRect(3, button.y() + 9, 5, max(10, button.height() - 18))
        if not self.isVisible() or self.height() == 0:
            self.setGeometry(target)
            self.show()
        else:
            self.animation.stop()
            self.animation.setStartValue(self.geometry())
            self.animation.setEndValue(target)
            self.animation.start()
        self.raise_()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        gradient = QLinearGradient(0, 0, 0, max(1, self.height()))
        gradient.setColorAt(0, QColor("#7dd3fc"))
        gradient.setColorAt(1, QColor("#34d399"))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(gradient)
        p.drawRoundedRect(QRectF(self.rect()), 2.5, 2.5)


class HaloOverlay(QWidget):
    """Non-intercepting, clipped highlight; no shadows, no native graphics effects."""

    def __init__(self, target, radius=13):
        super().__init__(target)
        self.radius = radius
        self.pointer = QPointF(0, 0)
        self.strength = 0.0
        self.phase = 0.0
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setGeometry(target.rect())
        self.hide()

    def paintEvent(self, event):
        if self.strength <= 0:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        # GroupBox leaves room above its frame for the title.
        top = 1
        rect = QRectF(1, top, self.width() - 2, self.height() - top - 1)
        path = QPainterPath()
        path.addRoundedRect(rect, self.radius, self.radius)
        p.setClipPath(path)
        light = QRadialGradient(self.pointer, min(180, self.width() * 0.65))
        light.setColorAt(0, QColor(125, 211, 252, int(24 * self.strength)))
        light.setColorAt(1, QColor(125, 211, 252, 0))
        p.fillPath(path, light)
        rim = QLinearGradient(0, 0, self.width(), self.height())
        rim.setColorAt(0, QColor(56, 189, 248, int(200 * self.strength)))
        rim.setColorAt(0.5 + 0.12 * math.sin(self.phase), QColor(185, 235, 255, int(210 * self.strength)))
        rim.setColorAt(1, QColor(52, 211, 153, int(160 * self.strength)))
        p.setPen(QPen(rim, 1.6))
        p.drawPath(path)


class HoverController(QObject):
    """Polls the pointer (no application-wide event filter, so no per-event Python cost)."""

    PANELS = ("card", "missionBanner", "chatComposer", "chatUser", "chatAssistant", "chatSystem")

    def __init__(self, root):
        super().__init__(root)
        self.root = root
        self.overlays = {}
        self.active = set()
        self.animating = set()
        self._last_cursor = None
        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self._tick)
        self._timer.start()
        self.register_tree(root)

    def register_tree(self, root):
        for widget in [root] + root.findChildren(QWidget):
            if isinstance(widget, HaloOverlay) or widget in self.overlays or widget.objectName() == "messageBody":
                continue
            is_panel = isinstance(widget, QGroupBox) or widget.objectName() in self.PANELS
            is_control = isinstance(widget, (QPushButton, QLineEdit, QComboBox, QTableWidget, QPlainTextEdit, QTextEdit))
            if not (is_panel or is_control):
                continue
            if isinstance(widget, QLineEdit) and isinstance(widget.parentWidget(), QFrame) \
                    and widget.parentWidget().objectName() == "chatComposer":
                widget.setCursor(Qt.CursorShape.IBeamCursor)
                continue  # the composer pill already owns the rim
            if isinstance(widget, (QLineEdit, QTextEdit, QPlainTextEdit)):
                widget.setCursor(Qt.CursorShape.IBeamCursor)
            elif isinstance(widget, (QPushButton, QComboBox)):
                self._cursor_for(widget)
            self.overlays[widget] = HaloOverlay(widget, 18 if is_panel else 13)
            widget.destroyed.connect(lambda _=None, key=widget: self._forget(key))

    def _forget(self, key):
        self.overlays.pop(key, None)
        self.active.discard(key)
        self.animating.discard(key)

    @staticmethod
    def _cursor_for(widget):
        shape = Qt.CursorShape.PointingHandCursor if widget.isEnabled() else Qt.CursorShape.ForbiddenCursor
        if widget.cursor().shape() != shape:
            widget.setCursor(shape)

    def _tick(self):
        window = self.root
        pos = QCursor.pos()
        moved = pos != self._last_cursor
        self._last_cursor = pos
        if window.isActiveWindow() and (moved or self.animating):
            chain = set()
            widget = QApplication.widgetAt(pos)
            while widget is not None:
                overlay = self.overlays.get(widget)
                if overlay is not None:
                    self._cursor_for(widget) if isinstance(widget, (QPushButton, QComboBox)) else None
                    if widget.isEnabled():
                        overlay.pointer = QPointF(widget.mapFromGlobal(pos))
                        chain.add(widget)
                widget = widget.parentWidget()
            self.active = chain
        elif not window.isActiveWindow():
            self.active = set()
        for key in self.active:
            overlay = self.overlays[key]
            if overlay.geometry() != key.rect():
                overlay.setGeometry(key.rect())
            overlay.raise_()
            overlay.show()
        self.animating |= self.active
        for key in tuple(self.animating):
            overlay = self.overlays.get(key)
            if overlay is None:
                self.animating.discard(key)
                continue
            target = 1.0 if key in self.active else 0.0
            overlay.strength += (target - overlay.strength) * 0.25
            overlay.phase += 0.05
            if target == 0 and overlay.strength < 0.025:
                overlay.strength = 0
                overlay.hide()
                self.animating.discard(key)
            else:
                overlay.update()


class MessageBody(QTextEdit):
    """Selectable plain text, safe from HTML injection, with auto-sized wrapping."""

    def __init__(self, text, parent=None):
        super().__init__(parent)
        self.setObjectName("messageBody")
        self.setReadOnly(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.document().setDocumentMargin(0)
        option = self.document().defaultTextOption()
        option.setWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self.document().setDefaultTextOption(option)
        # Preserve Arabic joining (no letter spacing); auto direction handles Arabic/English/code.
        self.setPlainText(text)
        cursor = self.textCursor()
        cursor.select(QTextCursor.SelectionType.Document)
        block = QTextBlockFormat()
        block.setLineHeight(100, QTextBlockFormat.LineHeightTypes.ProportionalHeight.value)
        block.setBottomMargin(4)
        cursor.mergeBlockFormat(block)
        cursor.clearSelection()
        self.setTextCursor(cursor)
        self.setCursor(Qt.CursorShape.IBeamCursor)
        self.document().documentLayout().documentSizeChanged.connect(self._fit)

    def _fit(self, *_):
        self.setFixedHeight(max(30, math.ceil(self.document().size().height()) + 6))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.document().setTextWidth(max(50, self.viewport().width()))
        self._fit()


SYSTEM_KINDS = {
    "بدء": ("بدء المهمة", "#38bdf8"), "اكتمل": ("اكتملت المهمة", "#34d399"),
    "خطأ": ("خطأ", "#f87171"), "خطأ عرض": ("خطأ عرض", "#f87171"), "النظام": ("النظام", "#38bdf8"),
    "INFO": ("معلومة", "#38bdf8"), "SUCCESS": ("نجاح", "#34d399"), "DEBUG": ("تفصيل", "#8fb3d1"),
    "WARN": ("تنبيه", "#fb923c"), "WARNING": ("تنبيه", "#fb923c"), "ERROR": ("خطأ", "#f87171"),
}


class ChatBubble(QFrame):
    def __init__(self, text, role, stamp, tag=None):
        super().__init__()
        self.role = role
        self._text = text
        self.setObjectName({"user": "chatUser", "assistant": "chatAssistant", "system": "chatSystem"}[role])
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        if role == "system":
            title, color = SYSTEM_KINDS.get(tag or "النظام", ("النظام", "#38bdf8"))
            self.setStyleSheet(
                f"QFrame#chatSystem {{ background: {alpha(color, 30)}; border: 1px solid {alpha(color, 150)}; border-radius: 14px; }}")
            row = QHBoxLayout(self)
            row.setContentsMargins(14, 7, 14, 7)
            row.setSpacing(10)
            dot = QLabel()
            dot.setFixedSize(8, 8)
            dot.setStyleSheet(f"background: {color}; border-radius: 4px;")
            label = QLabel(title)
            label.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: 700;")
            self.body = QLabel(text)
            self.body.setWordWrap(True)
            self.body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.body.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
            self.body.setCursor(Qt.CursorShape.IBeamCursor)
            stamp_label = QLabel(stamp)
            stamp_label.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px;")
            for widget in (dot, label):
                row.addWidget(widget, 0, Qt.AlignmentFlag.AlignVCenter)
            row.addWidget(self.body, 1)
            row.addWidget(stamp_label, 0, Qt.AlignmentFlag.AlignVCenter)
            return
        accent = ACCENT if role == "user" else SEV_SAFE
        box = QVBoxLayout(self)
        box.setContentsMargins(18, 12, 18, 12)
        box.setSpacing(6)
        header = QHBoxLayout()
        header.setSpacing(12)
        name = QLabel("أنت" if role == "user" else "مساعد AYFAM")
        name.setStyleSheet(f"color: {accent}; font-size: 11px; font-weight: 700;")
        timestamp = QLabel(stamp)
        timestamp.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px;")
        if role == "user":
            header.addWidget(timestamp)
            header.addStretch()
            header.addWidget(name)
        else:
            header.addWidget(name)
            header.addStretch()
            header.addWidget(timestamp)
        box.addLayout(header)
        self.body = MessageBody(text)
        box.addWidget(self.body)

    def fit_width(self, available):
        limit = max(240, min(780, int(available * (0.92 if self.role == "system" else 0.74))))
        longest = max((len(line) for line in self._text.split("\n")), default=1)
        desired = 150 + min(longest, 90) * 8.2 if self.role != "system" else 120 + min(longest, 110) * 7.2
        self.setFixedWidth(int(min(limit, max(270 if self.role == "system" else 280, desired))))


class ChatView(QScrollArea):
    """append()/clear() compatibility with the original QTextEdit event stream."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setMinimumHeight(320)
        self.container = QWidget()
        self.messages = QVBoxLayout(self.container)
        self.messages.setContentsMargins(10, 12, 10, 12)
        self.messages.setSpacing(14)
        self.messages.addStretch(1)
        self.setWidget(self.container)
        self.bubbles = []
        self.placeholder = ""
        self.hover_controller = None

    def setPlaceholderText(self, text):
        self.placeholder = text

    SYSTEM_RE = re.compile(
        r"^[⚙✅❌️\s]*\[(النظام|بدء|خطأ عرض|خطأ|اكتمل|تحذير[^\]]*)\]\s*")
    EVENT_RE = re.compile(r"^\[[^\]]*\]\s*\[(INFO|WARN|WARNING|ERROR|SUCCESS|DEBUG)\]\s*")

    @classmethod
    def parse_message(cls, raw):
        text = str(raw).strip()
        if text.startswith("[أنت]"):
            return "user", text[5:].strip(), None
        if text.startswith("[الوكيل]"):
            return "assistant", text[8:].strip(), None
        # Prefix based: a normal answer containing these words stays an assistant message.
        match = cls.SYSTEM_RE.match(text)
        if match:
            tag = "WARN" if match.group(1).startswith("تحذير") else match.group(1)
            return "system", text[match.end():].strip(), tag
        match = cls.EVENT_RE.match(text)
        if match:
            return "system", text[match.end():].strip(), match.group(1)
        return "assistant", text, None

    def append(self, raw):
        role, text, tag = self.parse_message(raw)
        if not text:
            return
        bar = self.verticalScrollBar()
        follow = bar.maximum() - bar.value() < 70
        bubble = ChatBubble(text, role, datetime.now().strftime("%H:%M"), tag)
        bubble.fit_width(self.viewport().width())
        row = QWidget()
        line = QHBoxLayout(row)
        line.setContentsMargins(0, 0, 0, 0)
        if role == "user":
            line.addStretch()
            line.addWidget(bubble)
        elif role == "assistant":
            line.addWidget(bubble)
            line.addStretch()
        else:
            line.addStretch()
            line.addWidget(bubble)
            line.addStretch()
        self.messages.insertWidget(self.messages.count() - 1, row)
        self.bubbles.append(bubble)
        if self.hover_controller:
            self.hover_controller.register_tree(row)
        # Bound the visual log, preventing unbounded widget/timer growth during long sessions.
        if len(self.bubbles) > 400:
            self.bubbles.pop(0)
            item = self.messages.takeAt(0)
            item.widget().deleteLater()
        if follow:
            QTimer.singleShot(30, lambda: bar.setValue(bar.maximum()))

    def clear(self):
        self.bubbles.clear()
        while self.messages.count() > 1:
            item = self.messages.takeAt(0)
            item.widget().deleteLater()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        for bubble in self.bubbles:
            bubble.fit_width(self.viewport().width())
