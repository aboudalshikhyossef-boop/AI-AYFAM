"""محرك الزجاج المضبّب الداكن (Dark Frosted Glassmorphism) + الخلفية الشبكية المتحركة.

الفكرة:
  1. ``LiveBackdrop`` يرسم خلفية متحركة (شبكة عُقد متصلة + توهجات + شبكة خطوط خفيفة) خلف كل التطبيق.
  2. في كل إطار تُنتَج نسخة شديدة التمويه (heavy backdrop blur) من الخلفية بتكلفة منخفضة
     (تصغير ثم تكبير ناعم)، وكل لوح زجاجي يقتطع منها الجزء الذي خلفه.
  3. ``paint_frosted`` يرسم اللوح: سطح داكن شبه شفاف فوق الخلفية المموّهة + حبيبات ضباب دقيقة +
     حافة داخلية بيضاء مضيئة خفيفة + انعكاس ضوئي حاد في الأعلى (specular highlight).
  4. ``FrostedGlassController`` يطبّق ذلك تلقائيًا على كل البطاقات والمجموعات والتبويبات والأشرطة.
"""
from __future__ import annotations

import math
import random
import weakref

from PyQt6.QtCore import QEvent, QLineF, QObject, QPoint, QPointF, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (QBrush, QColor, QImage, QLinearGradient, QPainter, QPainterPath, QPen,
                         QPixmap, QRadialGradient)
from PyQt6.QtWidgets import (QAbstractItemView, QComboBox, QGroupBox, QLineEdit, QPlainTextEdit, QPushButton,
                             QTabBar, QTabWidget, QTextEdit, QToolButton, QWidget)

# ───────────── إعدادات المظهر (عدّلها هنا فقط) ─────────────
FROST_TINT = (2, 8, 22)        # لون السطح (أزرق مائي عميق)
FROST_TINT_ALPHA = 0.36         # شفافية السطح الداكن (أقل = أكثر شفافية)
FROST_GRAIN_ALPHA = 2           # قوة حبيبات الضباب
FROST_SHEEN_ALPHA = 26          # لمعان النصف العلوي
FROST_SPECULAR_ALPHA = 215      # قوة الانعكاس الحاد في الحافة العلوية
FROST_BORDER_ALPHA = 120        # قوة الحافة الداخلية المضيئة
BLUR_SCALE = 0.40               # دقة رسم مصدر التمويه (أقل = أسرع)
BLUR_DIVISOR = 7                # قوة التمويه (أكبر = أكثر ضبابية)
WATER_BRIGHTEN = 0.04            # إضاءة/إشباع الخلفية المارّة عبر الزجاج
FRAME_MS = 66                   # زمن الإطار (~15 إطارًا/ثانية)

LIVE_WIDGETS: "weakref.WeakSet[QWidget]" = weakref.WeakSet()
SLOW_WIDGETS: "weakref.WeakSet[QWidget]" = weakref.WeakSet()   # أزرار وحقول: تُحدَّث كل 3 إطارات
_STATE: dict = {"backdrop": None, "canvas": None, "grain": None}


def register_live(widget: QWidget) -> None:
    """سجّل لوحًا زجاجيًا مخصصًا ليُعاد رسمه مع حركة الخلفية."""
    LIVE_WIDGETS.add(widget)


# ───────────── الخلفية المتحركة ─────────────
class LiveBackdrop(QObject):
    """خلفية شبكية متحركة + نسخة مموّهة منها تُستخدم كمصدر للزجاج."""

    updated = pyqtSignal()
    NODES = 62

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        rnd = random.Random(7)
        palette = (QColor(45, 212, 191), QColor(96, 165, 250), QColor(167, 139, 250), QColor(56, 189, 248))
        self.nodes = []
        for i in range(self.NODES):
            ang = rnd.uniform(0, math.tau)
            speed = rnd.uniform(0.006, 0.018)
            self.nodes.append([rnd.random(), rnd.random(), math.cos(ang) * speed, math.sin(ang) * speed,
                               QColor(palette[i % len(palette)]), i % 6 == 0])
        self.t = 0.0
        self.size = QSize(1400, 880)
        self.blurred = QImage()
        self.paused = False
        self._timer = QTimer(self)
        self._timer.setInterval(FRAME_MS)
        self._timer.timeout.connect(self._tick)

    def start(self) -> None:
        self._rebuild()
        self._timer.start()

    def set_size(self, w: int, h: int) -> None:
        if w > 8 and h > 8 and (w, h) != (self.size.width(), self.size.height()):
            self.size = QSize(w, h)
            self._rebuild()

    def _tick(self) -> None:
        if self.paused:
            return
        dt = FRAME_MS / 1000.0
        self.t += dt
        for n in self.nodes:
            n[0] += n[2] * dt
            n[1] += n[3] * dt
            if n[0] < -0.03 or n[0] > 1.03:
                n[2] = -n[2]
            if n[1] < -0.03 or n[1] > 1.03:
                n[3] = -n[3]
        self._rebuild()
        self.updated.emit()

    # ---- الرسم ----
    def paint_scene(self, p: QPainter, w: int, h: int) -> None:
        k = max(0.2, w / 1400.0)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        base = QLinearGradient(0, 0, w, h)
        base.setColorAt(0, QColor("#030712"))
        base.setColorAt(0.55, QColor(4, 13, 32))
        base.setColorAt(1, QColor(7, 12, 40))
        p.fillRect(0, 0, w, h, base)

        t = self.t
        glows = ((0.82 + 0.05 * math.sin(t * 0.17), 0.14 + 0.05 * math.cos(t * 0.13), 0.55, "#14b8a6", 105),
                 (0.10 + 0.05 * math.cos(t * 0.11), 0.88 + 0.04 * math.sin(t * 0.15), 0.62, "#4f46e5", 90),
                 (0.50 + 0.07 * math.sin(t * 0.09), 0.50 + 0.06 * math.cos(t * 0.12), 0.40, "#0ea5e9", 60),
                 (0.94 + 0.03 * math.cos(t * 0.14), 0.92, 0.38, "#a78bfa", 62))
        for cx, cy, r, col, a in glows:
            c = QColor(col)
            c.setAlpha(a)
            g = QRadialGradient(QPointF(cx * w, cy * h), r * max(w, h))
            g.setColorAt(0, c)
            c.setAlpha(0)
            g.setColorAt(1, c)
            p.fillRect(0, 0, w, h, g)

        # شبكة خطوط خفيفة تنساب ببطء
        step = 72 * k
        off = (t * 5 * k) % step
        grid = QColor(140, 200, 255, 16)
        p.setPen(QPen(grid, max(1.0, k)))
        x = -off
        while x < w:
            p.drawLine(QLineF(x, 0, x, h))
            x += step
        y = -off
        while y < h:
            p.drawLine(QLineF(0, y, w, y))
            y += step

        # شبكة العُقد
        pts = [(n[0] * w, n[1] * h, n) for n in self.nodes]
        link = 175 * k
        link2 = link * link
        for i in range(len(pts)):
            xi, yi, ni = pts[i]
            for j in range(i + 1, len(pts)):
                dx, dy = xi - pts[j][0], yi - pts[j][1]
                d2 = dx * dx + dy * dy
                if d2 < link2:
                    c = QColor(ni[4])
                    c.setAlpha(int(140 * (1 - math.sqrt(d2) / link)))
                    p.setPen(QPen(c, 1.3 * k))
                    p.drawLine(QLineF(xi, yi, pts[j][0], pts[j][1]))
        p.setPen(Qt.PenStyle.NoPen)
        for x, y, n in pts:
            col = QColor(n[4])
            if n[5]:  # عقدة رئيسية نابضة
                pulse = 0.75 + 0.25 * math.sin(t * 1.4 + x * 0.01)
                g = QRadialGradient(QPointF(x, y), 20 * k * pulse)
                col.setAlpha(200)
                g.setColorAt(0, col)
                col.setAlpha(0)
                g.setColorAt(1, col)
                p.setBrush(g)
                p.drawEllipse(QPointF(x, y), 20 * k * pulse, 20 * k * pulse)
                col.setAlpha(255)
                p.setBrush(col)
                p.drawEllipse(QPointF(x, y), 3.2 * k, 3.2 * k)
            else:
                col.setAlpha(240)
                p.setBrush(col)
                p.drawEllipse(QPointF(x, y), 2.1 * k, 2.1 * k)

    def _rebuild(self) -> None:
        sw = max(16, int(self.size.width() * BLUR_SCALE))
        sh = max(16, int(self.size.height() * BLUR_SCALE))
        img = QImage(sw, sh, QImage.Format.Format_ARGB32_Premultiplied)
        p = QPainter(img)
        self.paint_scene(p, sw, sh)
        p.end()
        sm = Qt.TransformationMode.SmoothTransformation
        ar = Qt.AspectRatioMode.IgnoreAspectRatio
        tiny = img.scaled(max(4, sw // BLUR_DIVISOR), max(4, sh // BLUR_DIVISOR), ar, sm)
        mid = tiny.scaled(max(8, sw // 3), max(8, sh // 3), ar, sm)
        out = mid.scaled(sw, sh, ar, sm)
        glow = QPainter(out)
        glow.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus)
        glow.setOpacity(WATER_BRIGHTEN)
        glow.drawImage(0, 0, out.copy())
        glow.end()
        self.blurred = out


class BackdropCanvas(QWidget):
    """القماشة الخلفية: تُرسم خلف كل عناصر النافذة وتتبع حجم أبيها."""

    def __init__(self, parent: QWidget, backdrop: LiveBackdrop):
        super().__init__(parent)
        self.backdrop = backdrop
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)
        parent.installEventFilter(self)
        self.setGeometry(parent.rect())
        self.lower()
        backdrop.set_size(max(1, parent.width()), max(1, parent.height()))
        backdrop.updated.connect(self.update)
        _STATE["backdrop"], _STATE["canvas"] = backdrop, self

    def eventFilter(self, obj, ev) -> bool:
        if obj is self.parent() and ev.type() == QEvent.Type.Resize:
            self.setGeometry(obj.rect())
            self.backdrop.set_size(obj.width(), obj.height())
            self.lower()
        return False

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        self.backdrop.paint_scene(p, self.width(), self.height())


# ───────────── رسم الزجاج المضبّب ─────────────
def _grain() -> QPixmap:
    if _STATE["grain"] is None:
        rnd = random.Random(11)
        img = QImage(96, 96, QImage.Format.Format_ARGB32)
        for y in range(96):
            for x in range(96):
                v = rnd.randint(150, 255)
                img.setPixelColor(x, y, QColor(v, v, v, rnd.randint(0, FROST_GRAIN_ALPHA * 2)))
        _STATE["grain"] = QPixmap.fromImage(img)
    return _STATE["grain"]


def paint_frosted(p: QPainter, widget: QWidget, rect: QRectF, radius: float = 18, *, nested: bool = False,
                  border: bool = True, tint_alpha: float | None = None) -> QPainterPath:
    """ارسم لوحًا زجاجيًا داكنًا مضبّبًا داخل ``rect`` من ``widget``. يرجع مسار اللوح."""
    path = QPainterPath()
    inner = rect.adjusted(0.5, 0.5, -0.5, -0.5)
    path.addRoundedRect(inner, radius, radius)
    k = 0.6 if nested else 1.0
    backdrop: LiveBackdrop | None = _STATE["backdrop"]
    canvas: QWidget | None = _STATE["canvas"]

    p.save()
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setClipPath(path)

    # 1) الخلفية المموّهة بشدة
    drawn = False
    if (backdrop is not None and canvas is not None and not backdrop.blurred.isNull() and canvas.width() > 0
            and canvas.window() is widget.window() and canvas.parentWidget().isAncestorOf(widget)):
        try:
            origin = widget.mapTo(canvas.parentWidget(), QPoint(int(rect.x()), int(rect.y())))
            s = backdrop.blurred.width() / canvas.width()
            src = QRectF(origin.x() * s, origin.y() * s, rect.width() * s, rect.height() * s)
            p.drawImage(rect, backdrop.blurred, src)
            drawn = True
        except Exception:
            drawn = False
    if not drawn:
        p.fillPath(path, QColor(10, 16, 30, 200))

    # 2) سطح مائي شفاف (تدرّج أزرق عميق خفيف + وهج سماوي من الأسفل)
    ta = FROST_TINT_ALPHA if tint_alpha is None else tint_alpha
    r, g, b = FROST_TINT
    surface = QLinearGradient(rect.topLeft(), rect.bottomLeft())
    surface.setColorAt(0, QColor(r + 10, g + 20, b + 30, int(255 * ta * k * 0.8)))
    surface.setColorAt(1, QColor(r, g, b, int(255 * ta * k * 1.2)))
    p.fillPath(path, surface)
    aqua = QLinearGradient(rect.bottomLeft(), QPointF(rect.left(), rect.top() + rect.height() * 0.45))
    aqua.setColorAt(0, QColor(70, 220, 255, int(20 * k)))
    aqua.setColorAt(1, QColor(70, 220, 255, 0))
    p.fillPath(path, aqua)

    # 3) حبيبات دقيقة جدًا
    p.setOpacity(0.5 if nested else 0.8)
    p.drawTiledPixmap(rect.toRect(), _grain())
    p.setOpacity(1.0)

    # 4) انعكاس مائي: لمعان علوي + شريط ضوء قطري ناعم
    sheen = QLinearGradient(rect.topLeft(), QPointF(rect.left(), rect.top() + rect.height() * 0.5))
    sheen.setColorAt(0, QColor(220, 248, 255, int(FROST_SHEEN_ALPHA * k)))
    sheen.setColorAt(1, QColor(220, 248, 255, 0))
    p.fillPath(path, sheen)
    band = QLinearGradient(rect.topLeft(), rect.bottomRight())
    band.setColorAt(0.28, QColor(255, 255, 255, 0))
    band.setColorAt(0.40, QColor(255, 255, 255, int(13 * k)))
    band.setColorAt(0.52, QColor(255, 255, 255, 0))
    p.fillPath(path, band)
    p.restore()

    if border:
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        # 5) الحافة الداخلية البيضاء المضيئة
        edge = QLinearGradient(rect.topLeft(), rect.bottomRight())
        edge.setColorAt(0, QColor(225, 250, 255, int(FROST_BORDER_ALPHA * k)))
        edge.setColorAt(0.45, QColor(150, 225, 255, int(34 * k)))
        edge.setColorAt(1, QColor(150, 235, 255, int(70 * k)))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(QBrush(edge), 1.0))
        p.drawPath(path)
        glow = QPainterPath()
        glow.addRoundedRect(rect.adjusted(1.5, 1.5, -1.5, -1.5), max(0, radius - 1), max(0, radius - 1))
        p.setPen(QPen(QColor(255, 255, 255, int(11 * k)), 1.0))
        p.drawPath(glow)

        # 6) الانعكاس الضوئي الحاد في الحافة العلوية
        if rect.width() > radius * 2.4:
            x0, x1 = rect.left() + radius * 0.55, rect.right() - radius * 0.55
            line = QLinearGradient(x0, 0, x1, 0)
            a = int(FROST_SPECULAR_ALPHA * k)
            line.setColorAt(0, QColor(255, 255, 255, 0))
            line.setColorAt(0.18, QColor(255, 255, 255, int(a * 0.55)))
            line.setColorAt(0.5, QColor(255, 255, 255, a))
            line.setColorAt(0.82, QColor(255, 255, 255, int(a * 0.45)))
            line.setColorAt(1, QColor(255, 255, 255, 0))
            p.setPen(QPen(QBrush(line), 1.2))
            p.drawLine(QLineF(x0, rect.top() + 1.1, x1, rect.top() + 1.1))
        p.restore()
    return path


def paint_frosted_bar(p: QPainter, widget: QWidget, rect: QRectF, line_edge: str) -> None:
    """شريط مسطح (الشريط الجانبي/العلوي): زجاج بلا زوايا مع خط فاصل مضيء على حافة واحدة."""
    paint_frosted(p, widget, rect, 0.01, border=False, tint_alpha=FROST_TINT_ALPHA * 0.85)
    p.save()
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(QPen(QColor(255, 255, 255, 46), 1.0))
    if line_edge == "left":
        p.drawLine(QLineF(rect.left() + 0.5, rect.top(), rect.left() + 0.5, rect.bottom()))
    elif line_edge == "bottom":
        p.drawLine(QLineF(rect.left(), rect.bottom() - 0.5, rect.right(), rect.bottom() - 0.5))
    p.restore()


# ───────────── المطبّق التلقائي ─────────────
class FrostedGlassController(QObject):
    """يمرّ على كل ودجات التطبيق ويحوّل الأسطح المحددة إلى زجاج مضبّب داكن."""

    RADII = {
        "card": 20, "pageHero": 20, "emptyGlassCard": 20, "missionBanner": 18, "chatComposer": 16,
        "chatUser": 16, "chatAssistant": 16, "chatSystem": 12, "floatingStatusBar": 14, "clockGlassPill": 30,
    }
    BARS = {"sidebar": "left", "headerBar": "bottom"}

    def __init__(self, root: QWidget, backdrop: LiveBackdrop):
        super().__init__(root)
        self.root = root
        self.backdrop = backdrop
        self._count = 0
        self.scan()
        backdrop.updated.connect(self._on_frame)
        backdrop.start()

    CONTROLS = (QPushButton, QToolButton, QLineEdit, QComboBox)
    VIEWS = (QAbstractItemView, QPlainTextEdit, QTextEdit)

    def scan(self) -> None:
        top = self.root.window()
        for w in self.root.findChildren(QWidget):
            if w.property("_frosted") is not None or w.window() is not top:
                continue
            name = w.objectName()
            if isinstance(w, (QGroupBox, QTabWidget, QTabBar)) or name in self.RADII or name in self.BARS:
                w.setProperty("_frosted", True)
                w.installEventFilter(self)
                LIVE_WIDGETS.add(w)
            elif isinstance(w, self.CONTROLS):
                if isinstance(w.parentWidget(), (QComboBox, QAbstractItemView)) or name == "messageBody":
                    continue
                w.setProperty("_frosted", True)
                w.installEventFilter(self)
                SLOW_WIDGETS.add(w)
            elif isinstance(w, self.VIEWS) and name != "messageBody":
                vp = w.viewport()
                w.setProperty("_frosted", True)
                vp.setProperty("_frosted", True)
                vp.installEventFilter(self)
                SLOW_WIDGETS.add(vp)

    def _on_frame(self) -> None:
        self.backdrop.paused = not self.root.isVisible() or self.root.window().isMinimized()
        self._count += 1
        if self._count % 30 == 0:
            self.scan()
        groups = [LIVE_WIDGETS] + ([SLOW_WIDGETS] if self._count % 3 == 0 else [])
        for group in groups:
            for w in list(group):
                try:
                    if w.isVisible():
                        w.update()
                except RuntimeError:
                    group.discard(w)

    @staticmethod
    def _depth(w: QWidget) -> int:
        d, par = 0, w.parentWidget()
        while par is not None:
            if par.property("_frosted") and not isinstance(par, (QTabWidget, QTabBar)):
                d += 1
            par = par.parentWidget()
        return d

    def eventFilter(self, obj, ev) -> bool:
        if ev.type() != QEvent.Type.Paint or not isinstance(obj, QWidget):
            return False
        try:
            p = QPainter(obj)
            rect = QRectF(obj.rect())
            name = obj.objectName()
            if name in self.BARS:
                paint_frosted_bar(p, obj, rect, self.BARS[name])
            elif isinstance(obj, QTabBar):
                for i in range(obj.count()):
                    tr = QRectF(obj.tabRect(i)).adjusted(3, 0, -3, -1)
                    paint_frosted(p, obj, tr, 10, nested=(i != obj.currentIndex()),
                                  tint_alpha=FROST_TINT_ALPHA * 0.8)
            elif isinstance(obj, QTabWidget):
                top = obj.tabBar().geometry().bottom() + 5
                paint_frosted(p, obj, QRectF(0, top, obj.width(), max(10, obj.height() - top)), 14,
                              nested=self._depth(obj) > 0)
            elif isinstance(obj.parentWidget(), self.VIEWS) and getattr(obj.parentWidget(), "viewport", lambda: None)() is obj:
                paint_frosted(p, obj, rect, 12, nested=True, tint_alpha=FROST_TINT_ALPHA * 0.9)
            elif isinstance(obj, self.CONTROLS):
                paint_frosted(p, obj, rect, 12, nested=True, tint_alpha=FROST_TINT_ALPHA * 0.9)
            else:
                radius = 16 if isinstance(obj, QGroupBox) else self.RADII.get(name, 16)
                paint_frosted(p, obj, rect, radius, nested=self._depth(obj) > 0)
            p.end()
        except Exception:
            pass
        return False
