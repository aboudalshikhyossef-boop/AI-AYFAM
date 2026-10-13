"""أيقونات SVG بإطار زجاجي ملوّن (أزرق/أخضر/برتقالي/أحمر فقط)."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from PyQt6.QtCore import QByteArray, QRectF, Qt
from PyQt6.QtGui import QColor, QIcon, QLinearGradient, QPainter, QPen, QPixmap
from PyQt6.QtSvg import QSvgRenderer

ICON_DIR = Path(__file__).resolve().parents[1] / "resources" / "icons"
ICON_COLORS = {
    "dashboard": "#3b82f6", "scans": "#22c55e", "usb": "#38bdf8", "tools": "#f59e0b",
    "chat": "#34d399", "playbooks": "#fb923c", "library": "#60a5fa", "reports": "#f87171",
    "settings": "#7dd3fc", "send": "#7dd3fc",
}


def _recolor(name: str, color: str) -> QByteArray:
    text = (ICON_DIR / f"{name}.svg").read_text(encoding="utf-8")
    text = re.sub(r'(stroke|fill)="#[0-9a-fA-F]{3,8}"', rf'\1="{color}"', text)
    return QByteArray(text.encode("utf-8"))


def _draw(name: str, color: str, size: int, strength: float, framed: bool) -> QPixmap:
    scale = 2
    pix = QPixmap(size * scale, size * scale)
    pix.setDevicePixelRatio(scale)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    base = QColor(color)
    glyph = size * (0.52 if framed else 0.9)
    if framed:
        rect = QRectF(1.2, 1.2, size - 2.4, size - 2.4)
        fill = QLinearGradient(0, 0, size, size)
        top, bottom = QColor(base), QColor(base)
        top.setAlpha(int(75 * strength))
        bottom.setAlpha(int(24 * strength))
        fill.setColorAt(0, top)
        fill.setColorAt(1, bottom)
        p.setBrush(fill)
        rim = QLinearGradient(0, 0, size, size)
        light = QColor("#e6f6ff")
        light.setAlpha(int(210 * strength))
        edge = QColor(base)
        edge.setAlpha(int(230 * strength))
        rim.setColorAt(0, light)
        rim.setColorAt(1, edge)
        p.setPen(QPen(rim, 1.3))
        p.drawRoundedRect(rect, size * 0.32, size * 0.32)
    renderer = QSvgRenderer(_recolor(name, color))
    offset = (size - glyph) / 2
    renderer.render(p, QRectF(offset, offset, glyph, glyph))
    p.end()
    return pix


@lru_cache(maxsize=128)
def framed_icon(name: str, color: str | None = None, size: int = 30) -> QIcon:
    color = color or ICON_COLORS.get(name, "#38bdf8")
    icon = QIcon()
    icon.addPixmap(_draw(name, color, size, 0.78, True), QIcon.Mode.Normal, QIcon.State.Off)
    icon.addPixmap(_draw(name, color, size, 1.0, True), QIcon.Mode.Active, QIcon.State.Off)
    icon.addPixmap(_draw(name, color, size, 1.0, True), QIcon.Mode.Normal, QIcon.State.On)
    icon.addPixmap(_draw(name, color, size, 1.0, True), QIcon.Mode.Active, QIcon.State.On)
    icon.addPixmap(_draw(name, color, size, 0.35, True), QIcon.Mode.Disabled, QIcon.State.Off)
    return icon


@lru_cache(maxsize=64)
def glyph_icon(name: str, color: str | None = None, size: int = 18) -> QIcon:
    color = color or ICON_COLORS.get(name, "#38bdf8")
    return QIcon(_draw(name, color, size, 1.0, False))
