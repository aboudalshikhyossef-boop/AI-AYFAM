"""
اختبارات وحدة للتحقق من المكونات الزجاجية والساعة وسلسلة الأوامر.
"""

import pytest
from PyQt6.QtWidgets import QApplication
from ui.gui_app import UnifiedCockpitWindow
from ui.widgets import Glass, GlassAnalogClock


@pytest.fixture
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


def test_glass_widget_rendering(qapp):
    glass = Glass(radius=20, tint=0.1)
    glass.resize(200, 100)
    assert glass.r == 20
    assert glass.tint == 0.1


def test_glass_analog_clock(qapp):
    clock = GlassAnalogClock()
    assert clock.width() == 58
    assert clock.height() == 58


def test_cockpit_window_initialization(qapp):
    window = UnifiedCockpitWindow()
    assert window.windowTitle() == "AI AYFAM — Security Operations Center"
    assert hasattr(window, "analog_clock")
    assert hasattr(window, "open_command_palette")
