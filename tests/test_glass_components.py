"""
اختبارات وحدة للتحقق من المكونات الزجاجية والساعة وسلسلة الأوامر.
"""

from pathlib import Path

import pytest
from PyQt6.QtGui import QIcon
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication
from ui.gui_app import NAV_ITEMS, UnifiedCockpitWindow
from ui.widgets import Glass, GlassAnalogClock, NavigationWheel


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
    assert clock.timer.interval() == 50


def test_navigation_wheel_animates_between_pages(qapp):
    wheel = NavigationWheel([
        ("dashboard", "غرفة العمليات", QIcon(), "#48ded0"),
        ("scans", "الفحوصات الأمنية", QIcon(), "#67b7ff"),
        ("findings", "النتائج الموحدة", QIcon(), "#ff7890"),
    ])
    wheel.resize(188, 390)
    selected = []
    wheel.page_selected.connect(selected.append)

    assert wheel._offset_for(1) == 1
    assert wheel._offset_for(2) == -1
    wheel._step(1)
    QTest.qWait(wheel.animation.duration() + 40)

    assert wheel.current_index == 1
    assert selected == ["scans"]
    assert wheel.accent.name() == "#67b7ff"


def test_navigation_pages_have_distinct_icon_assets():
    icon_dir = Path(__file__).resolve().parents[1] / "resources" / "icons"
    assert all((icon_dir / f"{key}.svg").is_file() for key, _label in NAV_ITEMS)


def test_cockpit_window_initialization(qapp):
    window = UnifiedCockpitWindow()
    assert window.windowTitle() == "AI AYFAM — Security Operations Center"
    assert window.analog_clock.width() == 62
    assert window.nav_wheel.minimumHeight() == 310
    assert window.table_findings.property("flow") == "#67b7ff"
    assert window.page_timeline.table.property("flow") == "#f4c86a"
    assert window.page_timeline.table.verticalHeader().defaultSectionSize() == 44
    assert hasattr(window, "open_command_palette")
