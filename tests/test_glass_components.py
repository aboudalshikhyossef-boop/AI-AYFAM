"""
اختبارات وحدة للتحقق من المكونات الزجاجية والساعة وسلسلة الأوامر.
"""

from pathlib import Path

import pytest

try:
    from PyQt6.QtGui import QIcon
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication
    from ui.gui_app import NAV_ITEMS, UnifiedCockpitWindow
    from ui.icons import _draw
    from ui.widgets import Glass, GlassAnalogClock, NavigationWheel
except (ImportError, OSError) as exc:
    pytest.skip(f"Qt runtime is unavailable ({exc})", allow_module_level=True)


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
    assert clock.timer.interval() == 1000


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
    assert wheel.pulse_timer.interval() == 70


def test_navigation_pages_have_distinct_icon_assets():
    icon_dir = Path(__file__).resolve().parents[1] / "resources" / "icons"
    assert all((icon_dir / f"{key}.svg").is_file() for key, _label in NAV_ITEMS)


def test_navigation_icons_are_rendered_at_high_density():
    pixmap = _draw("dashboard", "#48ded0", 88, 1.0, False)
    assert pixmap.width() == 264
    assert pixmap.height() == 264
    assert pixmap.devicePixelRatioF() == 3.0


def test_cockpit_window_initialization(qapp):
    window = UnifiedCockpitWindow()
    assert window.windowTitle() == "AI AYFAM — Security Operations Center"
    assert window.analog_clock.width() == 96
    assert window.analog_clock.parentWidget().objectName() == "headerBar"
    assert window.analog_clock.parentWidget().layout().columnMinimumWidth(0) == 260
    assert window.analog_clock.parentWidget().layout().columnMinimumWidth(2) == 260
    assert window.nav_wheel.minimumHeight() == 420
    assert window.table_conns.minimumHeight() >= 220
    assert window.table_procs.minimumHeight() >= 220
    assert window.table_findings.property("flow") == "#67b7ff"
    assert window.page_timeline.table.property("flow") == "#f4c86a"
    assert window.page_timeline.table.verticalHeader().defaultSectionSize() == 44
    assert hasattr(window, "open_command_palette")
