"""حماية التطبيق من انهيار PyQt6 عند استثناء داخل دالة تستدعيها Qt (مؤقّت، حدث رسم، إشارة).

المشكلة الجذرية: PyQt6 يستدعي ``abort()`` ويقتل العملية كلها (exit code 134) إن خرج استثناء بايثون
من دالة تستدعيها Qt ولم يكن لـ ``sys.excepthook`` معالج مخصص. فيكفي استثناء عابر واحد مثل
«wrapped C/C++ object has been deleted» (مؤقّت يعمل بعد إغلاق نافذة) ليسقط التطبيق أو سلسلة الاختبارات.

الحل: ``install_exception_guard`` يضع معالجاً يسجّل الاستثناء ويُبقي العملية حيّة، و``safe_slot``
يغلّف دوال المؤقّتات فيوقف المؤقّت بهدوء عندما يُحذف الكائن الذي يخدمه بدل أن يرمي الاستثناء.
"""
from __future__ import annotations

import functools
import logging
import sys
import traceback

log = logging.getLogger("ayfam.qt")
_RECORDED: list[tuple[type, BaseException, object]] = []
_MAX_RECORDED = 200


def is_deleted_object_error(exc: BaseException) -> bool:
    """خطأ «الكائن C++ حُذف» الحميد الذي يحدث عند إغلاق النوافذ أثناء عمل مؤقّت."""
    return isinstance(exc, RuntimeError) and "has been deleted" in str(exc)


def _guard(exc_type, exc, tb) -> None:
    if len(_RECORDED) < _MAX_RECORDED:
        _RECORDED.append((exc_type, exc, tb))
    if isinstance(exc, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc, tb)
        return
    log.error("Unhandled exception in a Qt callback (process kept alive):\n%s",
              "".join(traceback.format_exception(exc_type, exc, tb)))


_guard._ayfam_guard = True  # type: ignore[attr-defined]


def install_exception_guard() -> None:
    """يثبّت معالج الاستثناءات الآمن مرة واحدة (آمن للاستدعاء المتكرر)."""
    if not getattr(sys.excepthook, "_ayfam_guard", False):
        sys.excepthook = _guard


def recorded_exceptions(clear: bool = False) -> list[tuple[type, BaseException, object]]:
    items = list(_RECORDED)
    if clear:
        _RECORDED.clear()
    return items


def safe_slot(func):
    """يغلّف دالة مؤقّت/إشارة: إن حُذف الكائن الذي تخدمه يوقف المؤقّت بهدوء بدل رمي استثناء قاتل."""
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except RuntimeError as exc:
            if not is_deleted_object_error(exc):
                raise
            for owner in (self, getattr(self, "backdrop", None)):
                timer = getattr(owner, "_timer", None) if owner is not None else None
                if timer is not None:
                    try:
                        timer.stop()
                    except RuntimeError:
                        pass
            return None
    return wrapper
