"""أيقونات SVG بإطار زجاجي تتبع هوية Afyam Teal ودلالات الحالة."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from PyQt6.QtCore import QByteArray, QRectF, Qt
from PyQt6.QtGui import QColor, QIcon, QLinearGradient, QPainter, QPen, QPixmap
from PyQt6.QtSvg import QSvgRenderer

from ui.theme import ACCENT, COLOR_ICON_INACTIVE, COLOR_ICON_ACTIVE

ICON_DIR = Path(__file__).resolve().parents[1] / "resources" / "icons"
ICON_COLORS = {
    "dashboard": COLOR_ICON_INACTIVE, "scans": COLOR_ICON_INACTIVE, "usb": COLOR_ICON_INACTIVE,
    "tools": COLOR_ICON_INACTIVE, "chat": COLOR_ICON_INACTIVE, "playbooks": COLOR_ICON_INACTIVE,
    "library": COLOR_ICON_INACTIVE, "reports": COLOR_ICON_INACTIVE, "settings": COLOR_ICON_INACTIVE,
    "send": COLOR_ICON_ACTIVE,
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
        top.setAlpha(int(24 * strength))
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
    color = color or ICON_COLORS.get(name, COLOR_ICON_INACTIVE)
    icon = QIcon()
    icon.addPixmap(_draw(name, color, size, 0.78, True), QIcon.Mode.Normal, QIcon.State.Off)
    icon.addPixmap(_draw(name, COLOR_ICON_ACTIVE, size, 1.0, True), QIcon.Mode.Active, QIcon.State.Off)
    icon.addPixmap(_draw(name, COLOR_ICON_ACTIVE, size, 1.0, True), QIcon.Mode.Normal, QIcon.State.On)
    icon.addPixmap(_draw(name, COLOR_ICON_ACTIVE, size, 1.0, True), QIcon.Mode.Active, QIcon.State.On)
    icon.addPixmap(_draw(name, color, size, 0.35, True), QIcon.Mode.Disabled, QIcon.State.Off)
    return icon


@lru_cache(maxsize=64)
def glyph_icon(name: str, color: str | None = None, size: int = 18) -> QIcon:
    color = color or ICON_COLORS.get(name, ACCENT)
    return QIcon(_draw(name, color, size, 1.0, False))
