"""حماية Qt: لا انهيار قاتل عند استثناء داخل مؤقّت، ويتوقف المؤقّت عند حذف الكائن."""
import subprocess
import sys
import textwrap

from ui.qt_safety import install_exception_guard, is_deleted_object_error, recorded_exceptions, safe_slot


def test_deleted_object_error_detection():
    assert is_deleted_object_error(RuntimeError("wrapped C/C++ object of type X has been deleted"))
    assert not is_deleted_object_error(RuntimeError("other"))
    assert not is_deleted_object_error(ValueError("has been deleted"))


def test_guard_records_instead_of_crashing():
    install_exception_guard()
    recorded_exceptions(clear=True)
    sys.excepthook(RuntimeError, RuntimeError("wrapped C/C++ object of type X has been deleted"), None)
    assert len(recorded_exceptions(clear=True)) == 1


def test_safe_slot_swallows_deleted_object_and_stops_timer():
    class FakeTimer:
        stopped = False

        def stop(self):
            self.stopped = True

    class Owner:
        def __init__(self):
            self._timer = FakeTimer()

        @safe_slot
        def tick(self):
            raise RuntimeError("wrapped C/C++ object of type Y has been deleted")

        @safe_slot
        def other(self):
            raise RuntimeError("real bug")

    owner = Owner()
    assert owner.tick() is None and owner._timer.stopped
    try:
        owner.other()
    except RuntimeError as exc:
        assert "real bug" in str(exc)
    else:
        raise AssertionError("أخطاء حقيقية يجب ألا تُبتلع")


def test_process_survives_exception_inside_qt_timer():
    """السلوك الأصلي (بدون حماية) هو abort؛ مع الحماية تنجو العملية."""
    code = textwrap.dedent("""
        import sys
        from PyQt6.QtCore import QCoreApplication, QTimer
        from ui.qt_safety import install_exception_guard
        install_exception_guard()
        app = QCoreApplication([])
        def boom(): raise RuntimeError("wrapped C/C++ object of type X has been deleted")
        QTimer.singleShot(10, boom)
        QTimer.singleShot(80, app.quit)
        app.exec()
        print("survived")
    """)
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, env={"QT_QPA_PLATFORM": "offscreen", "PYTHONPATH": "."})
    assert result.returncode == 0 and "survived" in result.stdout
