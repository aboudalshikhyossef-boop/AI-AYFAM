"""اختبارات محرك الزجاج المضبّب والخلفية المتحركة."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QImage, QPainter
from PyQt6.QtCore import QRectF
from PyQt6.QtWidgets import QApplication, QGroupBox, QVBoxLayout, QWidget

from ui.glass_engine import BackdropCanvas, FrostedGlassController, LiveBackdrop, paint_frosted

_app = QApplication.instance() or QApplication([])


def test_backdrop_builds_blurred_frame_and_moves():
    b = LiveBackdrop()
    b.set_size(600, 400)
    first = [n[0] for n in b.nodes]
    b._tick()
    assert not b.blurred.isNull()
    assert [n[0] for n in b.nodes] != first


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
