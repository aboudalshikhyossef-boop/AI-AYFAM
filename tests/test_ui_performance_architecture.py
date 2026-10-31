"""Regression coverage for UI theme, paint, and idle-timer behavior."""

import os
from xml.etree import ElementTree

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PyQt6")

from PyQt6.QtCore import QEvent
from PyQt6.QtWidgets import QApplication, QWidget

from ui import icons, widgets
from ui.glass_engine import FrostedGlassController, LiveBackdrop
from ui.theme import (
    ACCENT,
    ACCENT_SECONDARY,
    BG_BASE,
    BG_SURFACE,
    BORDER,
    FONT_FAMILY,
    SEV_CRITICAL,
    SEV_HIGH,
    SEV_LOW,
    SEV_SAFE,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
)
from ui.tokens import Tokens

_APP = QApplication.instance() or QApplication([])


def test_tokens_delegate_visual_identity_to_theme():
    assert Tokens.TEAL_HEX == ACCENT
    assert Tokens.BLUE_HEX == SEV_LOW
    assert Tokens.VIOLET_HEX == ACCENT_SECONDARY
    assert Tokens.AMBER_HEX == SEV_HIGH
    assert Tokens.RED_HEX == SEV_CRITICAL
    assert Tokens.GREEN_HEX == SEV_SAFE
    assert Tokens.DARK_BG_PRIMARY == BG_BASE
    assert Tokens.DARK_BG_GLASS == BG_SURFACE
    assert Tokens.DARK_BORDER_GLASS == BORDER
    assert Tokens.TEXT_PRIMARY == TEXT_PRIMARY
    assert Tokens.TEXT_SECONDARY == TEXT_SECONDARY
    assert Tokens.TEXT_MUTED == TEXT_MUTED
    assert Tokens.FONT_FAMILY == FONT_FAMILY


def test_svg_source_is_cached_and_inline_css_stays_valid(tmp_path, monkeypatch):
    source = (
        '<svg xmlns="http://www.w3.org/2000/svg"><path fill="#112233" '
        'style="fill:#445566;stroke:#778899"/></svg>'
    )
    icon_path = tmp_path / "sample.svg"
    icon_path.write_text(source, encoding="utf-8")
    monkeypatch.setattr(icons, "ICON_DIR", tmp_path)
    icons._read_svg.cache_clear()
    icons._recolor.cache_clear()

    first_read = icons._read_svg("sample")
    icon_path.write_text("<svg/>", encoding="utf-8")
    assert icons._read_svg("sample") == first_read
    assert icons._read_svg.cache_info().maxsize == 64

    icon_path.write_text(source, encoding="utf-8")
    recolored = icons._recolor("sample", "#aabbcc").data().decode("utf-8")
    ElementTree.fromstring(recolored)
    assert 'fill="#aabbcc"' in recolored
    assert 'style="fill:#aabbcc;stroke:#aabbcc"' in recolored

    icons._read_svg.cache_clear()
    icons._recolor.cache_clear()


def test_self_painting_glass_widgets_are_not_overpainted():
    root = QWidget()
    backdrop = LiveBackdrop(root)
    controller = FrostedGlassController(root, backdrop)
    try:
        for class_name in ("Glass", "NavigationWheel", "TelemetryChart", "SecurityGauge"):
            widget_type = type(class_name, (QWidget,), {})
            widget = widget_type(root)
            controller.eventFilter(widget, QEvent(QEvent.Type.Paint))
        assert controller.paints == 0
    finally:
        backdrop.stop()
        root.close()


def test_low_resource_widgets_have_no_repeating_paint_timers():
    accent_line = widgets.AccentLine()
    static_nav = widgets.StaticNavigationMenu([])
    try:
        assert not accent_line.findChildren(widgets.QTimer)
        assert not static_nav.findChildren(widgets.QTimer)
    finally:
        accent_line.close()
        static_nav.close()


def test_flow_controller_skips_inactive_windows():
    root = QWidget()
    flow = widgets.FlowController(root)
    widget = QWidget(root)

    class Border:
        angle = 20
        speed = 30
        synced = False
        updated = False

        def sync(self):
            self.synced = True

        def update(self):
            self.updated = True

    border = Border()
    flow.borders[widget] = border
    try:
        flow._tick()
        assert border.angle == 20
        assert not border.synced
        assert not border.updated
    finally:
        flow._timer.stop()
        root.close()


def test_hover_tick_returns_while_window_is_inactive(monkeypatch):
    root = QWidget()
    controller = widgets.HoverController(root)
    controller.active.add(root)
    monkeypatch.setattr(
        widgets,
        "QCursor",
        type("CursorSpy", (), {"pos": staticmethod(lambda: pytest.fail("inactive tick read cursor"))}),
    )
    try:
        controller._tick()
        assert not controller.active
    finally:
        controller._timer.stop()
        controller.flow._timer.stop()
        root.close()
