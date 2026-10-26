"""مكونات Qt6: محرك الزجاج الحقيقي (Glassmorphism), خلفية شفقية (Aurora), أزرار نيون, ومكونات المحادثة والقياس."""
from __future__ import annotations

import html
import math
import re
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import (QAbstractAnimation, QEasingCurve, QEvent, QObject, QPoint, QPointF,
                            QPropertyAnimation, QRect, QRectF, Qt, QTimer,
                            QUrl, QVariantAnimation, QSize, pyqtSignal)
from PyQt6.QtGui import (QAbstractTextDocumentLayout, QBrush, QColor,
                         QConicalGradient, QCursor, QDesktopServices,
                         QFont, QFontDatabase, QGuiApplication,
                         QImage, QLinearGradient, QPainter, QPainterPath, QPen,
                         QPixmap, QRadialGradient, QTextBlockFormat,
                         QTextCursor, QTextOption)
from PyQt6.QtWidgets import (QAbstractSpinBox, QApplication, QComboBox, QFrame,
                             QGraphicsBlurEffect, QGraphicsOpacityEffect,
                             QGraphicsPixmapItem, QGraphicsScene,
                             QGroupBox, QHBoxLayout, QLabel, QLineEdit,
                             QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy,
                             QTableWidget, QTextEdit, QVBoxLayout, QWidget)

try:
    from PyQt6.QtMultimedia import QSoundEffect
except ImportError:  # pragma: no cover
    QSoundEffect = None

from ui.theme import (
    ACCENT, BG_BASE, SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_SAFE,
    TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY, alpha
)
from ui.tokens import Tokens

T1 = "rgba(255, 255, 255, 0.94)"
T2 = "rgba(226, 238, 250, 0.62)"
T3 = "rgba(226, 238, 250, 0.38)"

# ───────────── الخلفية الشفقية والتمويه الحقيقي ─────────────
def paint_aurora(p: QPainter, w: int, h: int, phase: float = 0.0) -> None:
    """رسم خلفية الفضاء الأورورا الكريستالية مع حركة هادئة وانسيابية."""
    g = QLinearGradient(0, 0, w, h)
    g.setColorAt(0, QColor("#030712"))
    g.setColorAt(1, QColor("#090f1f"))
    p.fillRect(0, 0, w, h, g)
    TEAL, BLUE, VIOLET = Tokens.TEAL, Tokens.BLUE, Tokens.VIOLET

    dx = math.sin(phase) * 0.03
    dy = math.cos(phase * 0.8) * 0.03

    for cx, cy, r, col, a in ((.80 + dx, .12 + dy, .52, TEAL, 65), (.10 - dx, .90 - dy, .62, QColor("#4f46e5"), 55),
                              (.52 + dy, .48 + dx, .42, QColor("#0ea5e9"), 28), (.95 - dy, .95 - dx, .38, VIOLET, 30)):
        rg = QRadialGradient(QPointF(cx * w, cy * h), r * max(w, h))
        rg.setColorAt(0, Tokens.rgba(col, a))
        rg.setColorAt(1, Tokens.rgba(col, 0))
        p.fillRect(0, 0, w, h, rg)


def blur(img: QImage, radius: float) -> QImage:
    """تطبيق تمويه بصري حقيقي على صورة ARGB."""
    if img.isNull() or img.width() <= 0 or img.height() <= 0:
        return img
    scene = QGraphicsScene()
    item = QGraphicsPixmapItem(QPixmap.fromImage(img))
    fx = QGraphicsBlurEffect()
    fx.setBlurRadius(radius)
    fx.setBlurHints(QGraphicsBlurEffect.BlurHint.QualityHint)
    item.setGraphicsEffect(fx)
    scene.addItem(item)
    out = QImage(img.size(), QImage.Format.Format_ARGB32_Premultiplied)
    out.fill(Qt.GlobalColor.transparent)
    p = QPainter(out)
    scene.render(p, QRectF(out.rect()), QRectF(img.rect()))
    p.end()
    return out


class Glass(QWidget):
    """لوح زجاجي حقيقي: تمويه خلفي + لون شبه شفاف + حافة لامعة + بقعة ضوء عند التحويم."""

    def __init__(self, radius: int = 24, tint: float = .07, parent: QWidget | None = None):
        super().__init__(parent)
        self.r, self.tint = radius, tint
        self._cache: QImage | None = None
        self._key = None
        self.pointer, self.hl = QPointF(-999, -999), 0.0
        self.setMouseTracking(True)
        self.anim = QVariantAnimation(self)
        self.anim.setDuration(280)
        self.anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.anim.valueChanged.connect(self._set_hl)

    def _set_hl(self, v) -> None:
        self.hl = float(v)
        self.update()

    def _glow(self, to: float) -> None:
        self.anim.stop()
        self.anim.setStartValue(self.hl)
        self.anim.setEndValue(to)
        self.anim.start()

    def enterEvent(self, e) -> None:
        self._glow(1.0)
        super().enterEvent(e)

    def leaveEvent(self, e) -> None:
        self._glow(0.0)
        super().leaveEvent(e)

    def mouseMoveEvent(self, e) -> None:
        self.pointer = e.position()
        self.update()
        super().mouseMoveEvent(e)

    def _backdrop(self) -> QImage | None:
        root = self.window()
        bg: QImage | None = getattr(root, "bg", None)
        if bg is None or bg.isNull() or self.width() < 4 or self.height() < 4:
            return None
        pos = self.mapTo(root, QPoint(0, 0))
        key = (self.width(), self.height(), pos.x(), pos.y(), bg.cacheKey())
        if key != self._key:
            pad = 44
            x = max(0, min(pos.x() - pad, bg.width() - (self.width() + 2 * pad)))
            y = max(0, min(pos.y() - pad, bg.height() - (self.height() + 2 * pad)))
            w = min(bg.width() - x, self.width() + 2 * pad)
            h = min(bg.height() - y, self.height() + 2 * pad)
            if w <= 0 or h <= 0:
                return None
            region = bg.copy(x, y, w, h)
            self._cache = blur(region, 30).copy(min(pad, region.width()), min(pad, region.height()),
                                                min(self.width(), region.width()), min(self.height(), region.height()))
            self._key = key
        return self._cache

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        path = QPainterPath()
        path.addRoundedRect(QRectF(self.rect()).adjusted(.5, .5, -.5, -.5), self.r, self.r)
        p.setClipPath(path)
        if (bd := self._backdrop()) is not None and not bd.isNull():
            p.drawImage(0, 0, bd)
        else:
            # Fallback translucent tint
            p.fillPath(path, QColor(15, 23, 42, 170))
        g = QLinearGradient(0, 0, 0, max(1, self.height()))
        g.setColorAt(0, QColor(255, 255, 255, int(255 * (self.tint + .05))))
        g.setColorAt(1, QColor(255, 255, 255, int(255 * self.tint * .55)))
        p.fillPath(path, g)
        if self.hl > .01:
            rg = QRadialGradient(self.pointer, 240)
            rg.setColorAt(0, QColor(255, 255, 255, int(40 * self.hl)))
            rg.setColorAt(1, QColor(255, 255, 255, 0))
            p.fillPath(path, rg)
        p.setClipping(False)
        edge = QLinearGradient(0, 0, max(1, self.width()), max(1, self.height()))
        edge.setColorAt(0, QColor(255, 255, 255, 80))
        edge.setColorAt(.5, QColor(255, 255, 255, 16))
        edge.setColorAt(1, QColor(255, 255, 255, 44))
        p.setPen(QPen(QBrush(edge), 1.0))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawPath(path)


# ───────────── منحنيات ورسوم مخصصة ─────────────
def smooth_path(pts: list[QPointF]) -> QPainterPath:
    if not pts:
        return QPainterPath()
    path = QPainterPath(pts[0])
    for i in range(len(pts) - 1):
        p0, p1, p2 = pts[max(i - 1, 0)], pts[i], pts[i + 1]
        p3 = pts[min(i + 2, len(pts) - 1)]
        path.cubicTo(p1 + (p2 - p0) / 6, p2 - (p3 - p1) / 6, p2)
    return path


class Curve(QWidget):
    """منحنى ناعم بتوهج وتعبئة متدرجة."""

    def __init__(self, data: list[float], color: QColor, axes: bool = False, parent=None):
        super().__init__(parent)
        self.data, self.color, self.axes = data or [0.0], color, axes

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        if w <= 10 or h <= 10 or not self.data:
            return
        ml, mb = (8, 26) if self.axes else (2, 4)
        top = 8
        lo, hi = (0, 100) if self.axes else (min(self.data), max(self.data))
        span = max(hi - lo, 1e-6)
        if self.axes:
            p.setFont(QFont("Tajawal", 9))
            for i in range(5):
                y = top + (h - mb - top) * i / 4
                p.setPen(QPen(QColor(255, 255, 255, 16), 1))
                p.drawLine(QPointF(ml, y), QPointF(w - ml, y))
            p.setPen(QColor(226, 238, 250, 95))
            for i, lab in enumerate(("قبل 24 ساعة", "قبل 16 ساعة", "قبل 8 ساعات", "الآن")):
                x = ml + (w - 2 * ml) * i / 3
                p.drawText(QRectF(min(max(x - 40, 0), w - 80), h - 20, 80, 18), Qt.AlignmentFlag.AlignCenter, lab)
        pts = [QPointF(ml + (w - 2 * ml) * i / max(1, len(self.data) - 1),
                       top + (h - mb - top) * (1 - (v - lo) / span)) for i, v in enumerate(self.data)]
        line = smooth_path(pts)
        fill = QPainterPath(line)
        fill.lineTo(pts[-1].x(), h - mb)
        fill.lineTo(pts[0].x(), h - mb)
        fill.closeSubpath()
        fg = QLinearGradient(0, top, 0, h - mb)
        fg.setColorAt(0, Tokens.rgba(self.color, 82))
        fg.setColorAt(1, Tokens.rgba(self.color, 0))
        p.fillPath(fill, fg)
        for wd, a in ((7, 26), (3.6, 60), (2.2, 255)):
            p.setPen(QPen(Tokens.rgba(self.color, a), wd, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.drawPath(line)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(Tokens.rgba(self.color, 70))
        p.drawEllipse(pts[-1], 7, 7)
        p.setBrush(QColor(255, 255, 255))
        p.drawEllipse(pts[-1], 3.2, 3.2)


class Ring(QWidget):
    """حلقة درجة الأمان التقييمية."""

    def __init__(self, value: int, label: str, sub: str, parent=None):
        super().__init__(parent)
        self.value, self.label, self.sub = value, label, sub

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        d = max(20, min(self.width() - 16, self.height() - 44))
        r = QRectF((self.width() - d) / 2, 6, d, d)
        p.setPen(QPen(QColor(255, 255, 255, 22), 13, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawArc(r, 0, 360 * 16)
        cg = QConicalGradient(r.center(), 90)
        cg.setColorAt(0, QColor("#22d3ee"))
        cg.setColorAt(.8, Tokens.TEAL)
        cg.setColorAt(1, QColor("#22d3ee"))
        p.setPen(QPen(QBrush(cg), 13, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawArc(r, 90 * 16, -int(360 * 16 * self.value / 100))
        p.setPen(QColor(255, 255, 255, 240))
        p.setFont(QFont("Tajawal", int(max(10, d / 4.2)), QFont.Weight.Bold))
        p.drawText(r.adjusted(0, -8, 0, -8), Qt.AlignmentFlag.AlignCenter, str(self.value))
        p.setPen(QColor(226, 238, 250, 140))
        p.setFont(QFont("Tajawal", 11))
        p.drawText(r.adjusted(0, d / 3.2, 0, 0), Qt.AlignmentFlag.AlignCenter, self.label)
        p.setFont(QFont("Tajawal", 10))
        p.setPen(QColor(226, 238, 250, 95))
        p.drawText(QRectF(0, d + 12, self.width(), 20), Qt.AlignmentFlag.AlignCenter, self.sub)


def draw_icon(p: QPainter, kind: str, r: QRectF, color: QColor) -> None:
    """رسم متجه أيكون أمنية بدقة قياسية."""
    p.save()
    p.translate(r.center())
    s = r.width() / 24
    p.scale(s, s)
    p.translate(-12, -12)
    pen = QPen(color, 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    a = QPainterPath()
    if kind == "grid":
        for x, y in ((4, 4), (14, 4), (4, 14), (14, 14)):
            a.addRoundedRect(QRectF(x, y, 6, 6), 1.6, 1.6)
    elif kind == "shield":
        a.moveTo(12, 3); a.lineTo(19, 6); a.lineTo(19, 12)
        a.cubicTo(19, 16.5, 16, 19.5, 12, 21); a.cubicTo(8, 19.5, 5, 16.5, 5, 12); a.lineTo(5, 6); a.closeSubpath()
    elif kind == "usb":
        a.moveTo(12, 19); a.lineTo(12, 5); a.moveTo(9.5, 7.5); a.lineTo(12, 4); a.lineTo(14.5, 7.5)
        a.moveTo(12, 14); a.lineTo(7, 11); a.lineTo(7, 8.5); a.addEllipse(QPointF(12, 19.5), 1.8, 1.8)
        a.moveTo(12, 11); a.lineTo(17, 8.5); a.lineTo(17, 7.5)
    elif kind == "term":
        a.addRoundedRect(QRectF(3, 5, 18, 14), 3, 3); a.moveTo(7, 10); a.lineTo(10, 12.5); a.lineTo(7, 15)
        a.moveTo(12, 15); a.lineTo(16, 15)
    elif kind == "chat":
        a.addRoundedRect(QRectF(3, 4, 18, 13), 4.5, 4.5); a.moveTo(8, 17); a.lineTo(8, 21); a.lineTo(12.5, 17)
    elif kind == "flow":
        a.addEllipse(QPointF(7, 6), 2, 2); a.addEllipse(QPointF(17, 12), 2, 2); a.addEllipse(QPointF(7, 18), 2, 2)
        a.moveTo(7, 8); a.lineTo(7, 16); a.moveTo(9, 6); a.cubicTo(14, 6, 15, 8, 15.5, 10.5)
    elif kind == "book":
        a.addRoundedRect(QRectF(5, 3, 14, 18), 2.2, 2.2); a.moveTo(9, 8); a.lineTo(15, 8); a.moveTo(9, 12); a.lineTo(15, 12)
    elif kind == "doc":
        a.addRoundedRect(QRectF(6, 3, 12, 18), 2.2, 2.2); a.moveTo(9, 9); a.lineTo(15, 9); a.moveTo(9, 13); a.lineTo(15, 13)
        a.moveTo(9, 17); a.lineTo(12, 17)
    elif kind == "gear":
        a.addEllipse(QPointF(12, 12), 3.2, 3.2)
        for i in range(8):
            ang = math.radians(i * 45)
            a.moveTo(12 + 6.4 * math.cos(ang), 12 + 6.4 * math.sin(ang)); a.lineTo(12 + 9 * math.cos(ang), 12 + 9 * math.sin(ang))
    elif kind == "spark":
        a.moveTo(12, 3); a.cubicTo(12.6, 8.4, 15.6, 11.4, 21, 12); a.cubicTo(15.6, 12.6, 12.6, 15.6, 12, 21)
        a.cubicTo(11.4, 15.6, 8.4, 12.6, 3, 12); a.cubicTo(8.4, 11.4, 11.4, 8.4, 12, 3)
    p.drawPath(a)
    p.restore()


class NavItem(QWidget):
    """عنصر التنقل الجانبي الفاخر."""

    def __init__(self, label: str, icon: str, selected: bool = False, parent=None):
        super().__init__(parent)
        self.label, self.icon, self.selected, self.hover = label, icon, selected, False
        self.setFixedHeight(46)
        self.setMouseTracking(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def enterEvent(self, e) -> None:
        self.hover = True
        self.update()
        super().enterEvent(e)

    def leaveEvent(self, e) -> None:
        self.hover = False
        self.update()
        super().leaveEvent(e)

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        box = QRectF(self.rect()).adjusted(2, 2, -2, -2)
        if self.selected or self.hover:
            g = QLinearGradient(0, 0, 0, self.height())
            g.setColorAt(0, QColor(255, 255, 255, 40 if self.selected else 18))
            g.setColorAt(1, QColor(255, 255, 255, 18 if self.selected else 8))
            p.setBrush(g)
            p.setPen(QPen(QColor(255, 255, 255, 56 if self.selected else 0), 1))
            p.drawRoundedRect(box, 14, 14)
        col = QColor(255, 255, 255, 245) if self.selected else QColor(226, 238, 250, 150)
        draw_icon(p, self.icon, QRectF(self.width() - 40, 12, 22, 22), Tokens.TEAL if self.selected else col)
        p.setPen(col)
        p.setFont(QFont("Tajawal", 12, QFont.Weight.DemiBold if self.selected else QFont.Weight.Medium))
        p.drawText(QRectF(14, 0, max(10, self.width() - 58), self.height()),
                   Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, self.label)


class AIButton(QWidget):
    """زر المساعد الذكي المخصص."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(52)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        box = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        g = QLinearGradient(0, 0, max(1, self.width()), 0)
        g.setColorAt(0, QColor("#7c6cf0"))
        g.setColorAt(1, QColor("#a78bfa"))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(g)
        p.drawRoundedRect(box, 26, 26)
        sh = QLinearGradient(0, 0, 0, max(1, self.height()))
        sh.setColorAt(0, QColor(255, 255, 255, 70))
        sh.setColorAt(.5, QColor(255, 255, 255, 0))
        p.setBrush(sh)
        p.drawRoundedRect(box, 26, 26)
        draw_icon(p, "spark", QRectF(self.width() - 46, 14, 24, 24), QColor("white"))
        p.setPen(QColor("white"))
        p.setFont(QFont("Tajawal", 12, QFont.Weight.Bold))
        p.drawText(QRectF(10, 0, max(10, self.width() - 62), self.height()),
                   Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, "اسأل المساعد الذكي")


def Dot(color: QColor, size: int = 9) -> QWidget:
    """نقطة حالة نيون مع وهج زجاجي."""
    w = QWidget()
    w.color = color
    w.setFixedSize(size + 8, size + 8)

    def paint(_e):
        p = QPainter(w)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QPointF(w.width() / 2, w.height() / 2)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(Tokens.rgba(color, 60))
        p.drawEllipse(c, w.width() / 2 - 1, w.width() / 2 - 1)
        p.setBrush(color)
        p.drawEllipse(c, w.width() / 2 - 4, w.width() / 2 - 4)

    w.paintEvent = paint
    return w


def chip(text: str, color: QColor) -> QLabel:
    """شارة زجاجية ملونة."""
    lb = QLabel(text)
    lb.setFont(QFont("Tajawal", 9, QFont.Weight.DemiBold))
    lb.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lb.setStyleSheet(f"color:{color.name()};background:{Tokens.css_rgba(color.red(), color.green(), color.blue(), .14)};"
                     f"border:1px solid {Tokens.css_rgba(color.red(), color.green(), color.blue(), .38)};border-radius:10px;padding:2px 10px;")
    return lb


class GlassAnalogClock(QWidget):
    """ساعة زجاجية داكنة بقرص حي وانعكاس يستجيب لحركة المؤشر."""

    def __init__(self, parent=None, size: int = 58):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setMouseTracking(True)
        self.setAccessibleName("ساعة تناظرية زجاجية / Glass analog clock")
        self.now = datetime.now()
        self.pointer = QPointF(size / 2, size / 2)
        self.hover_strength = 0.0
        self.hover_animation = QVariantAnimation(self)
        self.hover_animation.setDuration(220)
        self.hover_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.hover_animation.valueChanged.connect(self._set_hover_strength)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(50)

    def _set_hover_strength(self, value) -> None:
        self.hover_strength = float(value)
        self.update()

    def _animate_hover(self, target: float) -> None:
        self.hover_animation.stop()
        self.hover_animation.setStartValue(self.hover_strength)
        self.hover_animation.setEndValue(target)
        self.hover_animation.start()

    def _tick(self):
        self.now = datetime.now()
        self.update()

    def mouseMoveEvent(self, event) -> None:
        self.pointer = event.position()
        self.update()
        super().mouseMoveEvent(event)

    def enterEvent(self, event) -> None:
        self._animate_hover(1.0)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._animate_hover(0.0)
        super().leaveEvent(event)

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        center = QPointF(w / 2, h / 2)
        r = min(w, h) / 2 - 2

        halo = QRadialGradient(center, r + 8)
        halo.setColorAt(0.82, QColor(45, 212, 191, 16))
        halo.setColorAt(1.0, QColor(45, 212, 191, 0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(halo)
        p.drawEllipse(center, r + 7, r + 7)

        g = QRadialGradient(center, r)
        g.setColorAt(0, QColor(4, 11, 20, 60))
        g.setColorAt(0.78, QColor(4, 11, 20, 42))
        g.setColorAt(1.0, QColor(4, 11, 20, 30))
        p.setPen(QPen(QColor(218, 244, 255, 56), 1.0))
        p.setBrush(g)
        p.drawEllipse(center, r, r)

        rim = QLinearGradient(0, 0, w, h)
        rim.setColorAt(0.0, QColor(226, 250, 255, 142))
        rim.setColorAt(0.48, QColor(45, 212, 191, 76))
        rim.setColorAt(1.0, QColor(226, 250, 255, 92))
        p.setPen(QPen(QBrush(rim), 1.5))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(center, r - 1.5, r - 1.5)

        for i in range(60):
            angle = math.radians(i * 6 - 90)
            major = i % 5 == 0
            outer = r - 5.0
            inner = outer - (7.0 if major else 3.0)
            p1 = QPointF(center.x() + inner * math.cos(angle), center.y() + inner * math.sin(angle))
            p2 = QPointF(center.x() + outer * math.cos(angle), center.y() + outer * math.sin(angle))
            tick_color = QColor(93, 242, 224, 238) if major else QColor(226, 238, 250, 98)
            p.setPen(QPen(tick_color, 1.7 if major else 0.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.drawLine(p1, p2)

        sec = self.now.second + self.now.microsecond / 1_000_000
        mn = self.now.minute + sec / 60.0
        hr = (self.now.hour % 12) + mn / 60.0

        p.setPen(QColor(226, 238, 250, 110))
        p.setFont(QFont("Tajawal", max(6, int(r * 0.16)), QFont.Weight.Medium))
        for value, angle in (("12", -90), ("3", 0), ("6", 90), ("9", 180)):
            rad = math.radians(angle)
            label_radius = r * 0.61
            point = QPointF(center.x() + label_radius * math.cos(rad), center.y() + label_radius * math.sin(rad))
            p.drawText(QRectF(point.x() - 8, point.y() - 7, 16, 14), Qt.AlignmentFlag.AlignCenter, value)

        ang_h = math.radians((hr * 30) - 90)
        ph = QPointF(center.x() + (r * 0.48) * math.cos(ang_h), center.y() + (r * 0.48) * math.sin(ang_h))
        p.setPen(QPen(QColor(248, 250, 252, 238), 2.5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawLine(center, ph)

        ang_m = math.radians((mn * 6) - 90)
        pm = QPointF(center.x() + (r * 0.72) * math.cos(ang_m), center.y() + (r * 0.72) * math.sin(ang_m))
        p.setPen(QPen(QColor(145, 220, 255, 235), 1.7, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawLine(center, pm)

        ang_s = math.radians((sec * 6) - 90)
        ps = QPointF(center.x() + (r * 0.84) * math.cos(ang_s), center.y() + (r * 0.84) * math.sin(ang_s))
        p.setPen(QPen(Tokens.TEAL, 0.9, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawLine(center, ps)

        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(45, 212, 191, 230))
        p.drawEllipse(center, 2.6, 2.6)
        p.setBrush(QColor(240, 255, 255, 220))
        p.drawEllipse(center, 0.9, 0.9)

        if self.hover_strength > 0.01:
            reflection = QRadialGradient(self.pointer, r * 0.8)
            reflection.setColorAt(0, QColor(178, 246, 255, int(34 * self.hover_strength)))
            reflection.setColorAt(1, QColor(178, 246, 255, 0))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(reflection)
            p.drawEllipse(center, r - 1, r - 1)


# ───────────── الكائنات السابقة المتوافقة مع التطبيق ─────────────
class AmbientSurface(QWidget):
    """رسم خلفية المحتوى العامة الأورورا."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(100)

    def _tick(self):
        if self.isVisible():
            self._phase += 0.016
            self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        paint_aurora(p, self.width(), self.height(), self._phase)


class AccentLine(QWidget):
    """خط أفق نيون متدرج."""

    COLORS = ("#0d9488", "#2dd4bf", "#5eead4", "#2dd4bf", "#0d9488", "#2dd4bf", "#0d9488")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(2)
        self.phase = 0.0
        self.accent = QColor(ACCENT)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(40)

    def set_accent(self, color: str) -> None:
        self.accent = QColor(color)
        self.update()

    def _tick(self):
        if self.isVisible():
            self.phase = (self.phase + 0.004) % 1.0
            self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        width = max(1, self.width())
        gradient = QLinearGradient(-self.phase * width * 2, 0, (1 - self.phase) * width * 2, 0)
        gradient.setSpread(QLinearGradient.Spread.RepeatSpread)
        colors = (self.accent.darker(145), self.accent, self.accent.lighter(145), self.accent)
        for index, color in enumerate(colors):
            color.setAlpha(190 if index in (1, 2) else 105)
            gradient.setColorAt(index / (len(colors) - 1), color)
        p.fillRect(self.rect(), gradient)


class GlowReflection(QWidget):
    """انعكاس ضوئي ناعم."""

    def __init__(self, parent=None, color: str = ACCENT):
        super().__init__(parent)
        self.color = QColor(color)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setFixedHeight(9)
        self.setObjectName("glowReflection")

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        gradient = QRadialGradient(QPointF(self.width() / 2, 0), max(12, self.width() * 0.62))
        glow = QColor(self.color)
        glow.setAlpha(88)
        gradient.setColorAt(0.0, glow)
        glow.setAlpha(24)
        gradient.setColorAt(0.42, glow)
        glow.setAlpha(0)
        gradient.setColorAt(1.0, glow)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(gradient)
        painter.drawEllipse(QRectF(2, -3, max(4, self.width() - 4), 12))


class NavIndicator(QWidget):
    """مؤشر التصفح الانسيابي."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setGeometry(3, 0, 4, 0)
        self.color = QColor(ACCENT)
        self.animation = QPropertyAnimation(self, b"geometry", self)
        self.animation.setDuration(260)
        self.animation.setEasingCurve(QEasingCurve.Type.OutBack)

    def move_to(self, button):
        top_left = button.mapTo(self.parentWidget(), QPoint(0, 0))
        target = QRect(3, top_left.y() + 8, 4, max(10, button.height() - 16))
        raw_color = button.property("glowColor")
        if raw_color:
            self.color = QColor(str(raw_color))
        self.update()
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
        start = self.color.lighter(128)
        end = QColor(self.color)
        start.setAlpha(235)
        end.setAlpha(185)
        gradient.setColorAt(0, start)
        gradient.setColorAt(1, end)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(gradient)
        p.drawRoundedRect(QRectF(self.rect()), 2.0, 2.0)


class NavigationWheel(Glass):
    """قائمة تنقل دائرية تعرض الأيقونات على قوس بمنظور وحركة ثلاثية الأبعاد."""

    page_selected = pyqtSignal(str)
    GROUP_LABELS = {
        "dashboard": ("المراقبة", "MONITORING"), "scans": ("المراقبة", "MONITORING"),
        "findings": ("المراقبة", "MONITORING"), "timeline": ("المراقبة", "MONITORING"),
        "sentinel": ("المراقبة", "MONITORING"), "usb": ("المراقبة", "MONITORING"),
        "attack_graph": ("التحليل والاستجابة", "ANALYSIS & RESPONSE"),
        "tools": ("التحليل والاستجابة", "ANALYSIS & RESPONSE"),
        "chat": ("التحليل والاستجابة", "ANALYSIS & RESPONSE"),
        "playbooks": ("التحليل والاستجابة", "ANALYSIS & RESPONSE"),
        "library": ("المعرفة والتقارير", "KNOWLEDGE & REPORTS"),
        "reports": ("المعرفة والتقارير", "KNOWLEDGE & REPORTS"),
        "settings": ("النظام", "SYSTEM"),
    }

    def __init__(self, items: list[tuple[str, str, object, str]], parent=None):
        super().__init__(radius=22, tint=0.07, parent=parent)
        self.items = items
        self.current_index = 0
        self.direction = 0
        self.progress = 0.0
        self.queued_steps: list[int] = []
        self.hovered_index = -1
        self.accent = QColor(items[0][3] if items else ACCENT)
        self.setMinimumSize(154, 420)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setMouseTracking(True)
        self.setAccessibleName("عجلة التنقل بين صفحات التطبيق / Application navigation wheel")
        self.setToolTip("مرر عجلة الفأرة أو استخدم السهمين للتنقل / Scroll or use arrow keys to navigate")
        self.pulse_phase = 0.0
        self.pulse_timer = QTimer(self)
        self.pulse_timer.setInterval(70)
        self.pulse_timer.timeout.connect(self._tick_pulse)
        self.pulse_timer.start()

        self.animation = QVariantAnimation(self)
        self.animation.setDuration(300)
        self.animation.setEasingCurve(QEasingCurve.Type.InOutCubic)
        self.animation.valueChanged.connect(self._set_progress)
        self.animation.finished.connect(self._finish_step)

    def sizeHint(self) -> QSize:
        return QSize(200, 460)

    def _tick_pulse(self) -> None:
        if self.isVisible():
            self.pulse_phase = (self.pulse_phase + 0.055) % math.tau
            self.update()

    def _set_progress(self, value) -> None:
        self.progress = float(value)
        self.update()

    def set_current(self, key: str) -> None:
        for index, item in enumerate(self.items):
            if item[0] == key:
                if index == self.current_index and self.direction == 0:
                    return
                if self.animation.state() == QAbstractAnimation.State.Running:
                    self.animation.stop()
                self.current_index = index
                self.direction = 0
                self.progress = 0.0
                self.queued_steps.clear()
                self.accent = QColor(item[3])
                self.update()
                return

    def _step(self, direction: int) -> None:
        if len(self.items) < 2:
            return
        if self.animation.state() == QAbstractAnimation.State.Running:
            if len(self.queued_steps) < len(self.items):
                self.queued_steps.append(direction)
            return
        self.direction = 1 if direction > 0 else -1
        self.progress = 0.0
        self.animation.setStartValue(0.0)
        self.animation.setEndValue(1.0)
        self.animation.start()

    def _finish_step(self) -> None:
        self.current_index = (self.current_index + self.direction) % len(self.items)
        self.accent = QColor(self.items[self.current_index][3])
        self.direction = 0
        self.progress = 0.0
        self.update()
        self.page_selected.emit(self.items[self.current_index][0])
        if self.queued_steps:
            self._step(self.queued_steps.pop(0))

    def _offset_for(self, index: int) -> float:
        count = len(self.items)
        offset = (index - self.current_index) % count
        if offset > count / 2:
            offset -= count
        if self.direction:
            offset -= self.direction * self.progress
        return offset

    def _item_center(self, index: int) -> QPointF:
        radius = min(148.0, max(82.0, (self.height() - 130) / 2))
        center_y = self.height() / 2 - 40
        angle = self._offset_for(index) * 0.56
        return QPointF(self.width() / 2, center_y + radius * math.sin(angle))

    def _paint_glass_panel(self, painter: QPainter, panel: QRectF, panel_path: QPainterPath) -> None:
        """زجاج حقيقي: تمويه الخلفية خلف اللوحة + طبقة لون شفافة + حافة لامعة + بقعة ضوء عند التحويم."""
        painter.save()
        painter.setClipPath(panel_path)
        backdrop = self._backdrop()
        if backdrop is not None and not backdrop.isNull():
            painter.drawImage(0, 0, backdrop)
        else:
            painter.fillPath(panel_path, QColor(15, 23, 42, 170))
        sheen = QLinearGradient(panel.topLeft(), panel.bottomLeft())
        sheen.setColorAt(0, QColor(255, 255, 255, int(255 * (self.tint + 0.05))))
        sheen.setColorAt(1, QColor(255, 255, 255, int(255 * self.tint * 0.55)))
        painter.fillPath(panel_path, sheen)
        if self.hl > 0.01:
            glow = QRadialGradient(self.pointer, 200)
            glow.setColorAt(0, QColor(255, 255, 255, int(38 * self.hl)))
            glow.setColorAt(1, QColor(255, 255, 255, 0))
            painter.fillPath(panel_path, glow)
        painter.restore()
        edge = QLinearGradient(panel.topLeft(), panel.bottomRight())
        edge.setColorAt(0, QColor(255, 255, 255, 90))
        edge.setColorAt(0.5, QColor(255, 255, 255, 18))
        edge.setColorAt(1, QColor(255, 255, 255, 52))
        painter.setPen(QPen(QBrush(edge), 1.0))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(panel_path)

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        panel = QRectF(12, 8, self.width() - 24, self.height() - 16)
        panel_path = QPainterPath()
        panel_path.addRoundedRect(panel, 22, 22)
        self._paint_glass_panel(painter, panel, panel_path)

        current_key = self.items[self.current_index][0]
        group_ar, group_en = self.GROUP_LABELS.get(current_key, ("التنقل", "NAVIGATION"))
        painter.setPen(QColor(self.accent.red(), self.accent.green(), self.accent.blue(), 225))
        painter.setFont(QFont("Tajawal", 9, QFont.Weight.DemiBold))
        painter.drawText(QRectF(20, 16, self.width() - 40, 18), Qt.AlignmentFlag.AlignCenter, group_ar)
        painter.setPen(QColor(226, 238, 250, 95))
        painter.setFont(QFont("DejaVu Sans", 7, QFont.Weight.Medium))
        painter.drawText(QRectF(20, 32, self.width() - 40, 14), Qt.AlignmentFlag.AlignCenter, group_en)

        painter.setPen(QPen(QColor(self.accent.red(), self.accent.green(), self.accent.blue(), 28), 1.0))
        painter.drawLine(QPointF(self.width() / 2, panel.top() + 24), QPointF(self.width() / 2, panel.bottom() - 50))

        visible = []
        for index, item in enumerate(self.items):
            offset = self._offset_for(index)
            if abs(offset) <= 2.15:
                visible.append((index, item, offset))
        visible.sort(key=lambda entry: abs(entry[2]), reverse=True)

        for index, item, offset in visible:
            _key, _label, icon, color = item
            center = self._item_center(index)
            angle = offset * 0.56
            depth = max(0.0, math.cos(angle))
            active = abs(offset) < 0.12
            hovered = index == self.hovered_index
            pulse = math.sin(self.pulse_phase + index * 0.83)
            scale = 0.76 + 0.24 * depth + 0.018 * pulse + (0.035 if active else 0)
            opacity = 0.52 + 0.48 * depth
            icon_size = 72 * scale
            painter.save()
            painter.setOpacity(opacity)
            painter.translate(center)
            painter.rotate(-offset * 7.0)
            painter.scale(scale, 0.68 + depth * 0.32)
            color_value = QColor(color)
            glow = QRadialGradient(QPointF(0, 0), 48)
            glow.setColorAt(0, QColor(color_value.red(), color_value.green(), color_value.blue(), int(18 + 12 * pulse)))
            glow.setColorAt(1, QColor(color_value.red(), color_value.green(), color_value.blue(), 0))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(glow)
            painter.drawEllipse(QPointF(0, 0), 48, 48)
            if active or hovered:
                fill = QColor(4, 12, 22, 54 if active else 34)
                border = QColor(color_value.red(), color_value.green(), color_value.blue(), 175 if active else 112)
                painter.setPen(QPen(border, 1.25 if active else 0.9))
                painter.setBrush(fill)
                tile_size = 80 if active else 74
                painter.drawRoundedRect(QRectF(-tile_size / 2, -tile_size / 2, tile_size, tile_size), 22, 22)
            pixmap = icon.pixmap(QSize(max(18, int(icon_size)), max(18, int(icon_size))))
            painter.drawPixmap(QRectF(-icon_size / 2, -icon_size / 2, icon_size, icon_size), pixmap, QRectF(pixmap.rect()))
            painter.restore()

        active_item = self.items[self.current_index]
        painter.setPen(QColor(active_item[3]))
        painter.setFont(QFont("Tajawal", 11, QFont.Weight.DemiBold))
        painter.drawText(QRectF(18, self.height() - 58, self.width() - 36, 24), Qt.AlignmentFlag.AlignCenter, active_item[1])
        painter.setPen(QColor(226, 238, 250, 115))
        painter.setFont(QFont("Tajawal", 9))
        painter.drawText(QRectF(18, self.height() - 34, self.width() - 36, 16), Qt.AlignmentFlag.AlignCenter,
                         f"{self.current_index + 1:02d}  /  {len(self.items):02d}")

    def mouseMoveEvent(self, event) -> None:
        nearest_index = min(range(len(self.items)), key=lambda index: abs(self._item_center(index).y() - event.position().y()))
        nearest_center = self._item_center(nearest_index)
        self.hovered_index = nearest_index if abs(nearest_center.y() - event.position().y()) < 34 else -1
        self.setCursor(Qt.CursorShape.PointingHandCursor if self.hovered_index >= 0 else Qt.CursorShape.ArrowCursor)
        self.update()
        super().mouseMoveEvent(event)

    def leaveEvent(self, event) -> None:
        self.hovered_index = -1
        self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.setFocus()
            nearest_index = min(range(len(self.items)), key=lambda index: abs(self._item_center(index).y() - event.position().y()))
            if abs(self._item_center(nearest_index).y() - event.position().y()) < 36:
                offset = self._offset_for(nearest_index)
                steps = round(offset)
                if steps:
                    direction = 1 if steps > 0 else -1
                    for _ in range(abs(steps)):
                        self._step(direction)
                else:
                    self.page_selected.emit(self.items[self.current_index][0])
                event.accept()
                return
        super().mousePressEvent(event)

    def wheelEvent(self, event) -> None:
        delta = event.angleDelta().y()
        if delta:
            self._step(-1 if delta > 0 else 1)
            event.accept()
            return
        super().wheelEvent(event)

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key.Key_Up, Qt.Key.Key_Left):
            self._step(-1)
            event.accept()
        elif event.key() in (Qt.Key.Key_Down, Qt.Key.Key_Right):
            self._step(1)
            event.accept()
        else:
            super().keyPressEvent(event)


class PressFeedbackController(QObject):
    """استجابة لمسية وحركية سريعة للأزرار."""

    def __init__(self, root):
        super().__init__(root)
        self.effects = {}
        self.animations = {}
        self.reflections = {}
        for button in root.findChildren(QPushButton):
            self.attach(button)

    def attach(self, button):
        if button in self.effects:
            return
        effect = QGraphicsOpacityEffect(button)
        effect.setOpacity(1.0)
        button.setGraphicsEffect(effect)
        button.installEventFilter(self)
        self.effects[button] = effect
        reflection = GlowReflection(button, str(button.property("glowColor") or ACCENT))
        reflection.setGeometry(8, max(0, button.height() - 2), max(4, button.width() - 16), 9)
        reflection.show()
        self.reflections[button] = reflection
        button.destroyed.connect(lambda _=None, key=button: self._forget(key))

    def _forget(self, button):
        self.effects.pop(button, None)
        reflection = self.reflections.pop(button, None)
        if reflection is not None:
            reflection.deleteLater()
        animation = self.animations.pop(button, None)
        if animation is not None:
            animation.stop()

    @staticmethod
    def _repolish(button):
        button.style().unpolish(button)
        button.style().polish(button)
        button.update()

    def _animate(self, button, target, duration):
        effect = self.effects.get(button)
        if effect is None:
            return
        animation = self.animations.get(button)
        if animation is None:
            animation = QPropertyAnimation(effect, b"opacity", self)
            self.animations[button] = animation
        animation.stop()
        animation.setDuration(duration)
        animation.setStartValue(effect.opacity())
        animation.setEndValue(target)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        animation.start()

    def eventFilter(self, watched, event):
        if watched not in self.effects:
            return super().eventFilter(watched, event)
        if event.type() in (QEvent.Type.Resize, QEvent.Type.Show):
            reflection = self.reflections.get(watched)
            if reflection is not None:
                reflection.setGeometry(8, max(0, watched.height() - 2), max(4, watched.width() - 16), 9)
        pressed = event.type() in (QEvent.Type.MouseButtonPress, QEvent.Type.KeyPress)
        released = event.type() in (QEvent.Type.MouseButtonRelease, QEvent.Type.KeyRelease)
        if pressed:
            watched.setProperty("pressingFx", True)
            self._repolish(watched)
            self._animate(watched, 0.82, 85)
        elif released:
            watched.setProperty("pressingFx", False)
            self._repolish(watched)
            self._animate(watched, 1.0, 150)
        return super().eventFilter(watched, event)


class TelemetryChart(Glass):
    """مخطط بياني زجاجي تفاعلي لقياسات الشبكة والأنشطة الحية."""

    def __init__(self, title="اتجاه القياسات الحية", parent=None):
        super().__init__(radius=26, tint=0.07, parent=parent)
        self.title = title
        self.series = {}
        self.hover_index = -1
        self.setObjectName("telemetryChart")
        self.setMinimumHeight(180)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_data(self, series: dict[str, tuple[list[float], str]]) -> None:
        self.series = series
        self.update()

    def _plot_rect(self):
        return QRectF(46, 42, max(10, self.width() - 68), max(10, self.height() - 78))

    def mouseMoveEvent(self, event):
        rect = self._plot_rect()
        count = max((len(values) for values, _ in self.series.values()), default=0)
        if count > 1 and rect.contains(event.position()):
            ratio = (event.position().x() - rect.left()) / max(1, rect.width())
            self.hover_index = max(0, min(count - 1, round(ratio * (count - 1))))
        else:
            self.hover_index = -1
        super().mouseMoveEvent(event)

    def leaveEvent(self, event):
        self.hover_index = -1
        super().leaveEvent(event)

    def paintEvent(self, event):
        super().paintEvent(event)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        p.setPen(QColor(TEXT_PRIMARY))
        p.setFont(QFont("Tajawal", 12, QFont.Weight.Bold))
        p.drawText(QRectF(18, 12, self.width() - 36, 24), Qt.AlignmentFlag.AlignRight, self.title)

        rect = self._plot_rect()
        for step in range(5):
            y = rect.bottom() - (rect.height() * step / 4)
            p.setPen(QPen(QColor(255, 255, 255, 15), 1, Qt.PenStyle.DotLine))
            p.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))
            p.setPen(QColor("#64748b"))
            p.drawText(QRectF(8, y - 8, 30, 16), Qt.AlignmentFlag.AlignRight, str(step * 25))

        count = max((len(values) for values, _ in self.series.values()), default=0)
        if count < 2:
            p.setPen(QColor(TEXT_MUTED))
            p.drawText(rect, Qt.AlignmentFlag.AlignCenter, "تظهر حركة القياس بعد نقطتين أو أكثر")
            return
        for series_data in self.series.values():
            if not isinstance(series_data, (tuple, list)) or len(series_data) < 2:
                continue
            values, color_str = series_data[0], series_data[1]
            if not isinstance(values, list) or len(values) < 2:
                continue
            color = QColor(color_str)
            points = []
            for index, value in enumerate(values):
                x = rect.left() + rect.width() * index / max(1, count - 1)
                y = rect.bottom() - rect.height() * max(0, min(100, float(value))) / 100
                points.append(QPointF(x, y))
            path = smooth_path(points)

            area = QPainterPath(path)
            area.lineTo(points[-1].x(), rect.bottom())
            area.lineTo(points[0].x(), rect.bottom())
            area.closeSubpath()
            fill = QLinearGradient(0, rect.top(), 0, rect.bottom())
            fill.setColorAt(0, Tokens.rgba(color, 72))
            fill.setColorAt(1, Tokens.rgba(color, 4))
            p.fillPath(area, fill)

            p.setBrush(Qt.BrushStyle.NoBrush)
            glow = QColor(color)
            glow.setAlpha(35)
            p.setPen(QPen(glow, 12, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.drawPath(path)
            p.setPen(QPen(color, 2.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.drawPath(path)
            p.setBrush(color)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(points[-1], 5.4, 5.4)

        if 0 <= self.hover_index < count:
            x = rect.left() + rect.width() * self.hover_index / max(1, count - 1)
            p.setPen(QPen(QColor("#5eead4"), 1, Qt.PenStyle.DashLine))
            p.drawLine(QPointF(x, rect.top()), QPointF(x, rect.bottom()))


class SecurityGauge(Glass):
    """حلقة درجة الجاهزية الأمنية الزجاجية."""

    def __init__(self, title="الجاهزية الأمنية", parent=None):
        super().__init__(radius=26, tint=0.07, parent=parent)
        self.title = title
        self.value = 0
        self.pending = True
        self.setObjectName("securityGauge")
        self.setMinimumSize(190, 180)

    def set_value(self, value: float) -> None:
        self.value = max(0, min(100, float(value)))
        self.pending = False
        self.setToolTip(f"{self.title}: {self.value:.0f}%")
        self.update()

    def set_pending(self) -> None:
        self.pending = True
        self.setToolTip(f"{self.title}: لم يُجرَ فحص بعد")
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        center = QPointF(self.width() / 2, self.height() / 2 + 8)
        radius = min(self.width(), self.height()) * 0.31
        base = QRectF(center.x() - radius, center.y() - radius, radius * 2, radius * 2)
        p.setPen(QPen(QColor(255, 255, 255, 20), 12, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawArc(base, 225 * 16, -270 * 16)
        color = QColor(
            TEXT_MUTED if self.pending
            else SEV_SAFE if self.value >= 85
            else SEV_MEDIUM if self.value >= 70
            else SEV_HIGH if self.value >= 50
            else SEV_CRITICAL
        )
        if not self.pending:
            glow = QColor(color)
            glow.setAlpha(42)
            p.setPen(QPen(glow, 22, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.drawArc(base, 225 * 16, int(-270 * 16 * self.value / 100))
        p.setPen(QPen(color, 12, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        if not self.pending:
            p.drawArc(base, 225 * 16, int(-270 * 16 * self.value / 100))
        p.setPen(QColor("#f8fafc"))
        p.setFont(QFont("Tajawal", 20, QFont.Weight.Bold))
        p.drawText(QRectF(0, center.y() - 18, self.width(), 34), Qt.AlignmentFlag.AlignCenter, "—" if self.pending else f"{self.value:.0f}%")
        p.setPen(QColor(TEXT_SECONDARY))
        p.setFont(QFont("Tajawal", 12))
        p.drawText(QRectF(12, 16, self.width() - 24, 22), Qt.AlignmentFlag.AlignRight, self.title)


class SoundUX(QObject):
    """أصوات تفاعل خفيفة."""

    def __init__(self, root, enabled=True):
        super().__init__(root)
        self.enabled = bool(enabled)
        self.profile = "soft"
        self.effects = {}
        if QSoundEffect is not None:
            sounds = {
                "click": Path(__file__).resolve().parents[1] / "resources" / "sounds" / "ui-click.wav",
                "success": Path(__file__).resolve().parents[1] / "resources" / "sounds" / "ui-success.wav",
            }
            for name, path in sounds.items():
                if path.exists():
                    effect = QSoundEffect(self)
                    effect.setSource(QUrl.fromLocalFile(str(path)))
                    effect.setVolume(0.12 if name == "click" else 0.20)
                    self.effects[name] = effect

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = bool(enabled)

    def set_profile(self, profile: str) -> None:
        self.profile = profile if profile in {"soft", "confirm"} else "soft"
        click = self.effects.get("click")
        if click is not None:
            click.setVolume(0.12 if self.profile == "soft" else 0.18)

    def play(self, name="click") -> None:
        if not self.enabled:
            return
        effect_name = "success" if name == "success" else "click"
        effect = self.effects.get(effect_name)
        if effect is not None:
            effect.play()
        elif effect_name == "success":
            QApplication.beep()

    def bind_buttons(self, root) -> None:
        for button in root.findChildren(QPushButton):
            button.clicked.connect(lambda _checked=False, sound=self: sound.play("click"))


class HaloOverlay(QWidget):
    def __init__(self, target, radius=13):
        super().__init__(target)
        self.target = target
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
        top = 1
        rect = QRectF(1, top, max(1, self.width() - 2), max(1, self.height() - top - 1))
        path = QPainterPath()
        path.addRoundedRect(rect, self.radius, self.radius)
        p.setClipPath(path)
        base = QColor(str(self.target.property("glowColor") or self.target.property("accentColor") or ACCENT))
        light = QRadialGradient(self.pointer, min(180, self.width() * 0.65))
        center = QColor(base)
        center.setAlpha(int(30 * self.strength))
        light.setColorAt(0, center)
        center.setAlpha(0)
        light.setColorAt(1, center)
        p.fillPath(path, light)
        rim = QLinearGradient(0, 0, self.width(), self.height())
        first = QColor(base)
        first.setAlpha(int(150 * self.strength))
        middle = base.lighter(150)
        middle.setAlpha(int(190 * self.strength))
        last = base.darker(115)
        last.setAlpha(int(135 * self.strength))
        rim.setColorAt(0, first)
        rim.setColorAt(0.5 + 0.12 * math.sin(self.phase), middle)
        rim.setColorAt(1, last)
        p.setPen(QPen(rim, 1.6))
        p.drawPath(path)


FLOW_PAIRS = {
    "blue": ("#2dd4bf", "#5eead4"), "green": ("#34d399", "#2dd4bf"),
    "orange": ("#fb923c", "#f87171"), "red": ("#f87171", "#fb923c"),
}


class FlowBorder(QWidget):
    RING = 2

    def __init__(self, target, radius=13, flow="blue", phase=0.0, speed=38.0):
        super().__init__(target)
        self.target = target
        self.radius = radius
        self.flow = flow if flow in FLOW_PAIRS else "blue"
        self.custom_color = QColor(flow) if flow not in FLOW_PAIRS and QColor(flow).isValid() else None
        self.angle = phase % 360
        self.speed = speed
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.sync()
        self.show()

    def sync(self):
        rect = self.target.rect()
        if self.geometry() != rect:
            self.setGeometry(rect)

    def paintEvent(self, event):
        if not self.target.isEnabled():
            return
        if self.custom_color is not None:
            c1 = QColor(self.custom_color)
            c2 = c1.lighter(138)
        else:
            c1, c2 = (QColor(c) for c in FLOW_PAIRS[self.flow])
        w, h = self.width(), self.height()
        gradient = QConicalGradient(QPointF(w / 2, h / 2), self.angle)

        def stop(pos, color, a):
            col = QColor(color)
            col.setAlpha(a)
            gradient.setColorAt(pos, col)

        stop(0.0, c1, 255)
        stop(0.07, c2, 235)
        stop(0.22, c2, 120)
        stop(0.34, c1, 56)
        stop(0.9, c1, 48)
        stop(0.965, c2, 110)
        stop(0.992, c1, 220)
        stop(1.0, c1, 255)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(gradient, self.RING))
        half = self.RING / 2 + 0.5
        p.drawRoundedRect(QRectF(self.rect()).adjusted(half, half, -half, -half), self.radius - half, self.radius - half)


class FlowController(QObject):
    INTERVAL = 50

    def __init__(self, root):
        super().__init__(root)
        self.root = root
        self.borders = {}
        self._count = 0
        self._timer = QTimer(self)
        self._timer.setInterval(self.INTERVAL)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    @staticmethod
    def flow_for(widget):
        chosen = widget.property("flow")
        if chosen:
            return str(chosen)
        return "green" if isinstance(widget, (QComboBox, QTextEdit, QPlainTextEdit)) else "blue"

    def add(self, widget, radius):
        if widget in self.borders:
            return
        self._count += 1
        border = FlowBorder(widget, radius, self.flow_for(widget), phase=self._count * 67, speed=34 + (self._count % 5) * 5)
        self.borders[widget] = border
        widget.destroyed.connect(lambda _=None, key=widget: self.borders.pop(key, None))

    def _tick(self):
        if not self.root.isActiveWindow():
            return
        step = self.INTERVAL / 1000
        for widget, border in tuple(self.borders.items()):
            try:
                if not widget.isVisible():
                    continue
                border.sync()
                border.angle = (border.angle - border.speed * step) % 360
                border.update()
            except RuntimeError:
                self.borders.pop(widget, None)


class HoverController(QObject):
    PANELS = ("card", "missionBanner", "chatComposer", "chatUser", "chatAssistant", "chatSystem")

    def __init__(self, root):
        super().__init__(root)
        self.root = root
        self.overlays = {}
        self.active = set()
        self.animating = set()
        self._last_cursor = None
        self.flow = FlowController(root)
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
                continue
            if isinstance(widget, (QLineEdit, QTextEdit, QPlainTextEdit)):
                widget.setCursor(Qt.CursorShape.IBeamCursor)
            elif isinstance(widget, (QPushButton, QComboBox)):
                self._cursor_for(widget)
            self.overlays[widget] = HaloOverlay(widget, 18 if is_panel else 13)
            framed = isinstance(widget, (QTableWidget, QLineEdit, QComboBox, QTextEdit, QPlainTextEdit))
            if framed and not isinstance(widget.parentWidget(), (QComboBox, QAbstractSpinBox)):
                self.flow.add(widget, 14 if isinstance(widget, QTableWidget) else 13)
            widget.destroyed.connect(lambda _=None, key=widget: self._forget(key))

    def _forget(self, key):
        getattr(self, "overlays", {}).pop(key, None)
        getattr(self, "active", set()).discard(key)
        getattr(self, "animating", set()).discard(key)

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
    "بدء": ("بدء المهمة", "#2dd4bf"), "اكتمل": ("اكتملت المهمة", "#34d399"),
    "خطأ": ("خطأ", "#f87171"), "خطأ عرض": ("خطأ عرض", "#f87171"), "النظام": ("النظام", "#2dd4bf"),
    "INFO": ("معلومة", "#2dd4bf"), "SUCCESS": ("نجاح", "#34d399"), "DEBUG": ("تفصيل", "#8fb3d1"),
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
            title, color = SYSTEM_KINDS.get(tag or "النظام", ("النظام", "#2dd4bf"))
            self.setStyleSheet(
                f"QFrame#chatSystem {{ background: rgba(30, 41, 59, 0.50); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 12px; }}")
            row = QHBoxLayout(self)
            row.setContentsMargins(14, 7, 14, 7)
            row.setSpacing(10)
            dot = QLabel()
            dot.setFixedSize(8, 8)
            dot.setStyleSheet(f"background: {color}; border-radius: 4px;")
            label = QLabel(title)
            label.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: 600;")
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
        name.setStyleSheet(f"color: {accent}; font-size: 11px; font-weight: 600;")
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


ENGINE_COLORS = {"google": "#2dd4bf", "google-cse": "#2dd4bf", "wikipedia-ar": "#34d399", "wikipedia-en": "#34d399", "duckduckgo": "#fb923c", "bing-rss": "#a78bfa"}
BUTTON_KINDS = {"primary": "#34d399", "danger": "#f87171", "": "#2dd4bf"}


def _action_button(label, kind=""):
    color = BUTTON_KINDS.get(kind, "#2dd4bf")
    button = QPushButton(label)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    button.setMinimumHeight(32)
    button.setStyleSheet(
        f"QPushButton {{ background: rgba(255, 255, 255, 0.08); color: #f8fafc; border: 1px solid rgba(255, 255, 255, 0.16); "
        f"border-radius: 10px; padding: 4px 14px; font-weight: 500; font-size: 12px; }}"
        f"QPushButton:hover {{ background: rgba(255, 255, 255, 0.16); border-color: rgba(255, 255, 255, 0.30); }}"
        f"QPushButton:disabled {{ color: #64748b; background: transparent; border-color: rgba(255, 255, 255, 0.05); }}")
    return button


class ActionBubble(ChatBubble):
    def __init__(self, text, actions, stamp):
        super().__init__(text, "assistant", stamp)
        self.buttons = []
        row = QHBoxLayout()
        row.setSpacing(8)
        for item in actions:
            label, callback = item[0], item[1]
            kind = item[2] if len(item) > 2 else ""
            sticky = item[3] if len(item) > 3 else False
            button = _action_button(label, kind)
            button.clicked.connect(lambda _=False, cb=callback, b=button, st=sticky: self._fire(cb, b, st))
            self.buttons.append(button)
            row.addWidget(button)
        row.addStretch()
        self.layout().addLayout(row)

    def _fire(self, callback, clicked, sticky=False):
        if not sticky:
            for button in self.buttons:
                button.setEnabled(False)
            clicked.setText(f"{clicked.text()}  [تم]")
        callback()


class ResultsCard(QFrame):
    def __init__(self, report, title, stamp, actions):
        super().__init__()
        self.role = "assistant"
        self._text = ""
        self.setObjectName("chatAssistant")
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        box = QVBoxLayout(self)
        box.setContentsMargins(18, 12, 18, 14)
        box.setSpacing(9)

        head = QHBoxLayout()
        name = QLabel(title or f"نتائج البحث عن «{report.query}»")
        name.setWordWrap(True)
        name.setStyleSheet(f"color: {SEV_SAFE}; font-size: 12px; font-weight: 600;")
        stamp_label = QLabel(stamp)
        stamp_label.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px;")
        head.addWidget(name, 1)
        head.addWidget(stamp_label)
        box.addLayout(head)

        chips = QHBoxLayout()
        chips.setSpacing(6)
        for engine, status in report.engines.items():
            good = status.startswith("يعمل")
            color = "#34d399" if good else ("#fb923c" if "غير مفعّل" in status or "لا " in status else "#f87171")
            chip = QLabel(f"{engine}: {status}" if not good else f"{engine}: {status.replace('يعمل — ', '')}")
            chip.setToolTip(f"{engine} — {status}")
            chip.setStyleSheet(f"color: {color}; background: rgba(15, 23, 42, 0.60); border: 1px solid rgba(255, 255, 255, 0.12); "
                               f"border-radius: 8px; padding: 2px 9px; font-size: 10px; font-weight: 600;")
            chips.addWidget(chip)
        chips.addStretch()
        box.addLayout(chips)

        if report.answer:
            answer = MessageBody(report.answer)
            answer.setObjectName("messageBody")
            box.addWidget(answer)
            self._text += report.answer

        if not report.hits and not report.answer:
            empty = QLabel(f"لم أجد نتائج مرتبطة بـ «{report.query}» بعد التصفية"
                           + (f" (حُذفت {report.dropped} نتيجة غير ذات صلة)." if report.dropped else "."))
            empty.setWordWrap(True)
            empty.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px;")
            box.addWidget(empty)

        for index, hit in enumerate(report.hits, 1):
            box.addWidget(self._hit_card(index, hit))
            self._text += hit.title + hit.snippet

        if actions:
            row = QHBoxLayout()
            row.setSpacing(8)
            self.buttons = []
            for item in actions:
                button = _action_button(item[0], item[2] if len(item) > 2 else "")
                button.clicked.connect(lambda _=False, cb=item[1], b=button, st=(item[3] if len(item) > 3 else False): self._fire(cb, b, st))
                self.buttons.append(button)
                row.addWidget(button)
            row.addStretch()
            box.addLayout(row)

    def _fire(self, callback, clicked, sticky=False):
        if not sticky:
            for button in self.buttons:
                button.setEnabled(False)
            clicked.setText(f"{clicked.text()}  [تم]")
        callback()

    def _hit_card(self, index, hit):
        color = ENGINE_COLORS.get(hit.engine, "#2dd4bf")
        card = QFrame()
        card.setObjectName("resultCard")
        card.setStyleSheet(
            f"QFrame#resultCard {{ background: rgba(15, 23, 42, 0.50); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 12px; }}"
            f"QFrame#resultCard:hover {{ background: rgba(30, 41, 59, 0.65); border-color: rgba(255, 255, 255, 0.20); }}")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(5)
        top = QHBoxLayout()
        top.setSpacing(8)
        number = QLabel(str(index))
        number.setFixedSize(22, 22)
        number.setAlignment(Qt.AlignmentFlag.AlignCenter)
        number.setStyleSheet(f"background: rgba(255, 255, 255, 0.10); color: #f8fafc; border-radius: 11px; font-weight: 600; font-size: 11px;")
        title = QLabel(hit.title)
        title.setWordWrap(True)
        title.setStyleSheet("color: #f8fafc; font-weight: 600; font-size: 13px; background: transparent; border: none;")
        badge = QLabel(hit.engine_label)
        badge.setStyleSheet(f"color: {color}; background: rgba(255, 255, 255, 0.06); border: 1px solid rgba(255, 255, 255, 0.10); "
                            f"border-radius: 8px; padding: 1px 9px; font-size: 10px; font-weight: 600;")
        rel = QLabel(f"صلة {int(hit.relevance * 100)}%")
        rel.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px; background: transparent; border: none;")
        top.addWidget(number, 0, Qt.AlignmentFlag.AlignTop)
        top.addWidget(title, 1)
        top.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
        top.addWidget(rel, 0, Qt.AlignmentFlag.AlignTop)
        lay.addLayout(top)
        if hit.snippet:
            snippet = QLabel(hit.snippet if len(hit.snippet) <= 300 else hit.snippet[:297].rstrip() + "…")
            snippet.setWordWrap(True)
            snippet.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            snippet.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 12px; background: transparent; border: none;")
            lay.addWidget(snippet)
        bottom = QHBoxLayout()
        bottom.setSpacing(8)
        shown = hit.url if len(hit.url) <= 62 else hit.url[:59] + "…"
        link = QLabel(shown)
        link.setToolTip(hit.url)
        link.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 10px; background: transparent; border: none;")
        open_btn = _action_button("فتح الرابط", "")
        open_btn.setMinimumHeight(28)
        open_btn.clicked.connect(lambda _=False, u=hit.url: QDesktopServices.openUrl(QUrl(u)))
        copy_btn = _action_button("نسخ", "")
        copy_btn.setMinimumHeight(28)
        copy_btn.clicked.connect(lambda _=False, u=hit.url: QGuiApplication.clipboard().setText(u))
        bottom.addWidget(link, 1)
        bottom.addWidget(copy_btn)
        bottom.addWidget(open_btn)
        lay.addLayout(bottom)
        return card

    def fit_width(self, available):
        self.setFixedWidth(max(320, min(860, int(available * 0.9))))


class ChatView(QScrollArea):
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

    SYSTEM_RE = re.compile(r"^[⚙✅❌️\s]*\[(النظام|بدء|خطأ عرض|خطأ|اكتمل|تحذير[^\]]*)\]\s*")
    EVENT_RE = re.compile(r"^\[[^\]]*\]\s*\[(INFO|WARN|WARNING|ERROR|SUCCESS|DEBUG)\]\s*")

    @classmethod
    def parse_message(cls, raw):
        text = str(raw).strip()
        if text.startswith("[أنت]"):
            return "user", text[5:].strip(), None
        if text.startswith("[الوكيل]"):
            return "assistant", text[8:].strip(), None
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
        bubble = ChatBubble(text, role, datetime.now().strftime("%H:%M"), tag)
        bubble.fit_width(self.viewport().width())
        bar = self.verticalScrollBar()
        follow = bar.maximum() - bar.value() < 70
        self._insert_row(bubble, role, bubble)
        if len(self.bubbles) > 400:
            self.bubbles.pop(0)
            item = self.messages.takeAt(0)
            item.widget().deleteLater()
        if follow:
            QTimer.singleShot(30, lambda: bar.setValue(bar.maximum()))

    def _insert_row(self, widget, role, bubble):
        row = QWidget()
        line = QHBoxLayout(row)
        line.setContentsMargins(0, 0, 0, 0)
        if role == "user":
            line.addStretch()
            line.addWidget(widget)
        elif role == "assistant":
            line.addWidget(widget)
            line.addStretch()
        else:
            line.addStretch()
            line.addWidget(widget)
            line.addStretch()
        self.messages.insertWidget(self.messages.count() - 1, row)
        self.bubbles.append(bubble)
        if self.hover_controller:
            self.hover_controller.register_tree(row)
        return row

    def _push(self, widget, role="assistant"):
        bar = self.verticalScrollBar()
        follow = bar.maximum() - bar.value() < 70
        self._insert_row(widget, role, widget)
        if len(self.bubbles) > 400:
            self.bubbles.pop(0)
            item = self.messages.takeAt(0)
            item.widget().deleteLater()
        if follow:
            QTimer.singleShot(30, lambda: bar.setValue(bar.maximum()))
        return widget

    def append_thinking(self, steps):
        steps = [str(x) for x in steps if x]
        if steps:
            self.append("[النظام] تفكير: " + "  ←  ".join(steps))

    def append_actions(self, text, actions):
        bubble = ActionBubble(text, actions, datetime.now().strftime("%H:%M"))
        bubble.fit_width(self.viewport().width())
        return self._push(bubble)

    def append_results(self, report, title="", actions=None):
        card = ResultsCard(report, title, datetime.now().strftime("%H:%M"), actions or [])
        card.fit_width(self.viewport().width())
        return self._push(card)

    def clear(self):
        self.bubbles.clear()
        while self.messages.count() > 1:
            item = self.messages.takeAt(0)
            item.widget().deleteLater()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        for bubble in self.bubbles:
            if hasattr(bubble, "fit_width"):
                bubble.fit_width(self.viewport().width())
