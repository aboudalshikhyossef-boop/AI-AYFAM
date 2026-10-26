from __future__ import annotations

from PyQt6.QtWidgets import QApplication

from ui.widgets import NavigationWheel


def test_navigation_wheel_is_glassy() -> None:
    app = QApplication.instance() or QApplication([])
    wheel = NavigationWheel([
        ("dashboard", "المراقبة", QApplication.style().standardIcon(QApplication.style().SP_DesktopIcon), "#48ded0"),
        ("scans", "الفحوصات", QApplication.style().standardIcon(QApplication.style().SP_FileDialogListView), "#67b7ff"),
    ])
    wheel.resize(188, 390)
    assert getattr(NavigationWheel.paintEvent, "__name__", "") == "_glass_navigation_paint_event"
    assert wheel.minimumHeight() >= 420
    app.processEvents()
