"""اختبارات محرك الزجاج المضبّب والخلفية المتحركة."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtGui import QImage, QPainter
from PyQt6.QtCore import QEvent, QRectF
from PyQt6.QtWidgets import QApplication, QGroupBox, QVBoxLayout, QWidget

from ui.glass_engine import BackdropCanvas, FrostedGlassController, LiveBackdrop, paint_frosted

_app = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _cleanup_qt_objects():
    """Release test widgets before the interpreter tears down Qt bindings."""
    yield
    app = QApplication.instance()
    if app is None:
        return
    for widget in list(QApplication.topLevelWidgets()):
        widget.close()
        widget.deleteLater()
    app.processEvents()
    app.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.processEvents()


@pytest.fixture(scope="session", autouse=True)
def _shutdown_qt_session():
    """Stop the shared QApplication cleanly after all Qt tests finish."""
    yield
    app = QApplication.instance()
    if app is None:
        return
    for widget in list(QApplication.topLevelWidgets()):
        widget.close()
        widget.deleteLater()
    app.processEvents()
    app.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    app.quit()
    app.processEvents()


def test_backdrop_builds_blurred_frame_and_moves():
    b = LiveBackdrop()
    b.set_size(600, 400)
    first = [n.x for n in b.nodes]
    b._tick()
    assert not b.blurred.isNull()
    assert [n.x for n in b.nodes] != first


def test_paint_frosted_works_with_and_without_backdrop():
    host = QWidget()
    host.resize(300, 200)
    img = QImage(300, 200, QImage.Format.Format_ARGB32_Premultiplied)
    p = QPainter(img)
    path = paint_frosted(p, host, QRectF(0, 0, 300, 200), 18)
    p.end()
    assert not path.isEmpty()


def test_controller_registers_group_boxes_and_paints():
    root = QWidget()
    root.resize(500, 400)
    lay = QVBoxLayout(root)
    box = QGroupBox("test")
    lay.addWidget(box)
    backdrop = LiveBackdrop()
    BackdropCanvas(root, backdrop)
    ctl = FrostedGlassController(root, backdrop)
    root.show()
    _app.processEvents()
    assert box.property("_frosted") is True
    backdrop._tick()
    _app.processEvents()
    assert not root.grab().isNull()
    backdrop._timer.stop()
    assert ctl is not None


def test_controller_covers_controls_and_views():
    from PyQt6.QtWidgets import QLineEdit, QPushButton, QTableWidget

    root = QWidget()
    root.resize(500, 400)
    lay = QVBoxLayout(root)
    btn, edit, table = QPushButton("x"), QLineEdit(), QTableWidget(2, 2)
    for w in (btn, edit, table):
        lay.addWidget(w)
    backdrop = LiveBackdrop()
    BackdropCanvas(root, backdrop)
    FrostedGlassController(root, backdrop)
    root.show()
    _app.processEvents()
    assert btn.property("_frosted") is True and edit.property("_frosted") is True
    assert table.viewport().property("_frosted") is True
    assert not root.grab().isNull()
    backdrop._timer.stop()
