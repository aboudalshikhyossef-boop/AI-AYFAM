"""إعداد pytest المشترك: حماية Qt من الانهيار القاتل وتنظيف الإغلاق.

1) ``install_exception_guard``: بدونه يقتل PyQt6 العملية (exit 134) عند أي استثناء داخل دالة تستدعيها Qt.
   هنا نسجّل الاستثناء ونجعل الاختبار الذي وقع فيه يفشل بوضوح (باستثناء خطأ «الكائن حُذف» الحميد).
2) عند نهاية الجلسة نوقف المؤقتات والخيوط ونغلق النوافذ، ثم (في CI فقط) ننهي العملية فور طباعة نتيجة
   pytest كي لا تُسقطها أخطاء إغلاق المفسّر مع كائنات Qt وخيوط خلفية بعد أن انتهت الاختبارات فعلاً.
"""
from __future__ import annotations

import gc
import os
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from ui.qt_safety import install_exception_guard, is_deleted_object_error, recorded_exceptions  # noqa: E402

install_exception_guard()
_STATUS = {"code": 0}


@pytest.fixture(autouse=True)
def _qt_callback_exceptions_fail_the_test():
    install_exception_guard()
    recorded_exceptions(clear=True)
    yield
    bad = [exc for _, exc, _ in recorded_exceptions(clear=True) if not is_deleted_object_error(exc)]
    if bad:
        pytest.fail(f"Unhandled exception inside a Qt callback: {bad[0]!r}", pytrace=False)


def _shutdown_qt() -> None:
    try:
        from PyQt6.QtCore import QThread
        from PyQt6.QtWidgets import QApplication
    except Exception:
        return
    app = QApplication.instance()
    if app is None:
        return
    try:
        from ui import glass_engine
        backdrop = glass_engine._STATE.get("backdrop")
        if backdrop is not None:
            backdrop._timer.stop()
    except Exception:
        pass
    for widget in list(app.topLevelWidgets()):
        try:
            widget.close()
        except Exception:
            pass
    for obj in gc.get_objects():
        try:
            if isinstance(obj, QThread) and obj.isRunning():
                obj.requestInterruption()
                obj.quit()
                obj.wait(2000)
        except Exception:
            pass
    app.processEvents()
    gc.collect()


def pytest_sessionfinish(session, exitstatus):
    _STATUS["code"] = int(exitstatus)
    _shutdown_qt()


def pytest_unconfigure(config):
    if os.environ.get("CI") or os.environ.get("AYFAM_HARD_EXIT"):
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(_STATUS["code"])
