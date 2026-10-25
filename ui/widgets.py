"""مكونات Qt6: خلفية زجاجية غير حاجبة، لمعان يتبع المؤشر، وفقاعات محادثة قابلة للنسخ بتصميم Dark Glassmorphism."""
from __future__ import annotations

import html
import math
import re
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QEasingCurve, QEvent, QObject, QPoint, QPointF, QPropertyAnimation, QRect, QRectF, Qt, QTimer, QUrl
from PyQt6.QtGui import QColor, QConicalGradient, QCursor, QDesktopServices, QGuiApplication, QRegion, QTextBlockFormat, QTextCursor, QLinearGradient, QPainter, QPainterPath, QPen, QRadialGradient, QTextOption
from PyQt6.QtWidgets import (
    QAbstractSpinBox, QApplication, QComboBox, QFrame, QGraphicsOpacityEffect, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy, QTableWidget, QTextEdit,
    QVBoxLayout, QWidget,
)

try:
    from PyQt6.QtMultimedia import QSoundEffect
except ImportError:  # pragma: no cover - minimal Qt installations may omit Multimedia
    QSoundEffect = None

from ui.theme import (
    ACCENT, BG_BASE, SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_SAFE,
    TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY, alpha,
)


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
        p.fillRect(self.rect(), QColor("#030712"))
        w, h = self.width(), self.height()
        # Diffuse Apple-style glass light pools
        for color, cx, cy in (("#0d9488", 0.22, 0.1), ("#6366f1", 0.94, 0.76)):
            center = QPointF(w * (cx + 0.06 * math.sin(self._phase)), h * cy)
            g = QRadialGradient(center, max(w, h) * 0.8)
            c = QColor(color)
            c.setAlpha(28)
            g.setColorAt(0, c)
            c.setAlpha(0)
            g.setColorAt(1, c)
            p.fillRect(self.rect(), g)
        # One moving, faint diagonal light band.
        g = QLinearGradient(0, 0, w, h)
        t = 0.5 + 0.18 * math.sin(self._phase * 0.6)
        g.setColorAt(0, QColor(45, 212, 191, 0))
        g.setColorAt(max(0, t - 0.15), QColor(45, 212, 191, 0))
        g.setColorAt(t, QColor(45, 212, 191, 6))
        g.setColorAt(min(1, t + 0.15), QColor(167, 139, 250, 0))
        g.setColorAt(1, QColor(167, 139, 250, 0))
        p.fillRect(self.rect(), g)


class AccentLine(QWidget):
    """Thin animated palette sweep under the header using the brand signal colors."""

    COLORS = ("#0d9488", "#2dd4bf", "#5eead4", "#2dd4bf", "#0d9488", "#2dd4bf", "#0d9488")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(2)
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
            c.setAlpha(180)
            gradient.setColorAt(index / last, c)
        p.fillRect(self.rect(), gradient)


class GlowReflection(QWidget):
    """Ambient-only reflection: a soft light pool, never a duplicate of the icon."""

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
    """Sliding rim-light marker beside the active navigation button."""

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


class PressFeedbackController(QObject):
    """Short, low-cost tactile response for mouse and keyboard button presses."""

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


class TelemetryChart(QFrame):
    """Lightweight interactive line chart for live dashboard telemetry with dark glass styling."""

    def __init__(self, title="اتجاه القياسات الحية", parent=None):
        super().__init__(parent)
        self.title = title
        self.series = {}
        self.hover_index = -1
        self.setObjectName("telemetryChart")
        self.setMinimumHeight(220)
        self.setMouseTracking(True)
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
        self.update()
        super().mouseMoveEvent(event)

    def leaveEvent(self, event):
        self.hover_index = -1
        self.update()
        super().leaveEvent(event)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        background = QLinearGradient(0, 0, self.width(), self.height())
        background.setColorAt(0, QColor(91, 137, 183, 32))
        background.setColorAt(0.18, QColor(26, 45, 71, 206))
        background.setColorAt(1, QColor(12, 23, 43, 220))
        p.fillRect(self.rect(), background)
        p.setPen(QPen(QColor(208, 231, 255, 38), 1))
        p.drawRoundedRect(QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5), 14, 14)
        p.setPen(QColor(TEXT_PRIMARY))
        p.setFont(p.font())
        p.drawText(QRectF(18, 8, self.width() - 36, 22), Qt.AlignmentFlag.AlignRight, self.title)
        p.setPen(QColor(TEXT_MUTED))

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
            p.drawText(rect, Qt.AlignmentFlag.AlignCenter, "تظهر حركة القياس بعد نقطتين أو أكثر / Trend appears after two readings")
            return
        colors = [QColor(color) for _, color in self.series.values()]
        for (values, _), color in zip(self.series.values(), colors):
            if len(values) < 2:
                continue
            points = []
            for index, value in enumerate(values):
                x = rect.left() + rect.width() * index / (count - 1)
                y = rect.bottom() - rect.height() * max(0, min(100, float(value))) / 100
                points.append(QPointF(x, y))
            path = QPainterPath(points[0])
            for point in points[1:]:
                path.lineTo(point)

            # Filled, tinted area and layered strokes create a restrained neon-glass glow.
            area = QPainterPath(path)
            area.lineTo(points[-1].x(), rect.bottom())
            area.lineTo(points[0].x(), rect.bottom())
            area.closeSubpath()
            fill = QLinearGradient(0, rect.top(), 0, rect.bottom())
            area_color = QColor(color)
            area_color.setAlpha(72)
            fill.setColorAt(0, area_color)
            area_color.setAlpha(4)
            fill.setColorAt(1, area_color)
            p.fillPath(area, fill)

            p.setBrush(Qt.BrushStyle.NoBrush)
            glow = QColor(color)
            glow.setAlpha(35)
            p.setPen(QPen(glow, 12, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            p.drawPath(path)
            glow.setAlpha(80)
            p.setPen(QPen(glow, 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            p.drawPath(path)
            p.setPen(QPen(color, 2.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            p.drawPath(path)
            p.setBrush(color)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(points[-1], 5.4, 5.4)
            core = QColor("#f8fafc")
            p.setBrush(core)
            p.drawEllipse(points[-1], 2.2, 2.2)

        p.setPen(QColor("#64748b"))
        for index, label in ((0, "قبل 72 ثانية"), (max(0, count // 3), "قبل 48ث"), (max(0, (count * 2) // 3), "قبل 24ث"), (count - 1, "الآن")):
            x = rect.left() + rect.width() * index / (count - 1)
            p.drawText(QRectF(x - 36, rect.bottom() + 8, 72, 16), Qt.AlignmentFlag.AlignCenter, label)

        if 0 <= self.hover_index < count:
            x = rect.left() + rect.width() * self.hover_index / (count - 1)
            p.setPen(QPen(QColor("#5eead4"), 1, Qt.PenStyle.DashLine))
            p.drawLine(QPointF(x, rect.top()), QPointF(x, rect.bottom()))
            tooltip_lines = []
            for label, (values, color) in self.series.items():
                if self.hover_index < len(values):
                    tooltip_lines.append(f"{label}: {values[self.hover_index]:.0f}")
            box = QRectF(max(8, x - 88), rect.top() + 8, 176, 22 + 18 * len(tooltip_lines))
            p.setPen(QPen(QColor(45, 212, 191, 100), 1))
            p.setBrush(QColor(15, 23, 42, 230))
            p.drawRoundedRect(box, 8, 8)
            p.setPen(QColor("#f8fafc"))
            for row, text in enumerate(["نقطة القياس"] + tooltip_lines):
                p.drawText(QRectF(box.left() + 10, box.top() + 7 + row * 18, box.width() - 20, 16), Qt.AlignmentFlag.AlignRight, text)

        # Compact legend aligned to the left of the chart header.
        legend_x = 18
        for label, (_, color) in self.series.items():
            p.setBrush(QColor(color)); p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(legend_x + 4, 22), 3, 3)
            p.setPen(QColor(TEXT_SECONDARY))
            p.drawText(QRectF(legend_x + 12, 12, 180, 20), Qt.AlignmentFlag.AlignLeft, label)
            legend_x += 210


class SecurityGauge(QFrame):
    """Compact posture gauge with dark glass aesthetics and hover details."""

    def __init__(self, title="الجاهزية الأمنية", parent=None):
        super().__init__(parent)
        self.title = title
        self.value = 0
        self.pending = True
        self.setObjectName("securityGauge")
        self.setMinimumSize(210, 220)
        self.setMouseTracking(True)

    def set_value(self, value: float) -> None:
        self.value = max(0, min(100, float(value)))
        self.pending = False
        self.setToolTip(f"{self.title}: {self.value:.0f}% — يتحدث مع القياسات الحية")
        self.update()

    def set_pending(self) -> None:
        """Show that no completed security scan exists yet; never imply a score."""
        self.pending = True
        self.setToolTip(f"{self.title}: لم يُجرَ فحص بعد")
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        background = QLinearGradient(0, 0, self.width(), self.height())
        background.setColorAt(0, QColor(91, 137, 183, 32))
        background.setColorAt(0.18, QColor(26, 45, 71, 206))
        background.setColorAt(1, QColor(12, 23, 43, 220))
        p.fillRect(self.rect(), background)
        p.setPen(QPen(QColor(208, 231, 255, 38), 1))
        p.drawRoundedRect(QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5), 14, 14)
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
            glow.setAlpha(95)
            p.setPen(QPen(glow, 5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            p.drawArc(base, 225 * 16, int(-270 * 16 * self.value / 100))
        p.setPen(QPen(color, 12, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        if not self.pending:
            p.drawArc(base, 225 * 16, int(-270 * 16 * self.value / 100))
        p.setPen(QColor("#f8fafc")); p.setFont(p.font())
        p.drawText(QRectF(0, center.y() - 18, self.width(), 34), Qt.AlignmentFlag.AlignCenter, "—" if self.pending else f"{self.value:.0f}%")
        p.setPen(QColor(TEXT_SECONDARY))
        p.drawText(QRectF(12, 16, self.width() - 24, 22), Qt.AlignmentFlag.AlignRight, self.title)
        p.setPen(QColor(TEXT_MUTED))
        footer = "لم يُجرَ فحص بعد" if self.pending else "تقييم خطوط الدفاع بعد آخر فحص"
        p.drawText(QRectF(12, self.height() - 34, self.width() - 24, 18), Qt.AlignmentFlag.AlignCenter, footer)


class SoundUX(QObject):
    """Subtle local feedback sounds with a persistent mute switch."""

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
        # "confirm" changes click loudness only; success audio is reserved for actual success.
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
    """Non-intercepting, clipped highlight; no shadows, no native graphics effects."""

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
        rect = QRectF(1, top, self.width() - 2, self.height() - top - 1)
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
    """Animated frame: a light comet travels around the border of tables and fields."""

    RING = 2

    def __init__(self, target, radius=13, flow="blue", phase=0.0, speed=38.0):
        super().__init__(target)
        self.target = target
        self.radius = radius
        self.flow = flow if flow in FLOW_PAIRS else "blue"
        self.angle = phase % 360
        self.speed = speed          # degrees per second
        self._mask_size = None
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.sync()
        self.show()

    def sync(self):
        rect = self.target.rect()
        if self.geometry() != rect:
            self.setGeometry(rect)
        size = (rect.width(), rect.height())
        if size != self._mask_size and rect.width() > 8 and rect.height() > 8:
            self._mask_size = size
            ring = self.RING + 1
            outer, inner = QPainterPath(), QPainterPath()
            outer.addRoundedRect(QRectF(rect), self.radius, self.radius)
            inner.addRoundedRect(QRectF(rect).adjusted(ring, ring, -ring, -ring), max(2, self.radius - ring), max(2, self.radius - ring))
            self.setMask(QRegion(outer.toFillPolygon().toPolygon()).subtracted(QRegion(inner.toFillPolygon().toPolygon())))

    def paintEvent(self, event):
        if not self.target.isEnabled():
            return
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
    """One shared timer animates every visible frame (~20 fps, only when the window is active)."""

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
    """Polls the pointer."""

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
    """Assistant bubble followed by action buttons."""

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
    """Tidy search results with dark glass cards."""

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

        # engine status chips
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
        """Insert a custom row, keeping the scroll position unless the user is at the bottom."""
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
        """Compact chip describing how the input was read (no wall of text)."""
        steps = [str(x) for x in steps if x]
        if steps:
            self.append("[النظام] تفكير: " + "  ←  ".join(steps))

    def append_actions(self, text, actions):
        """Assistant bubble with buttons."""
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
