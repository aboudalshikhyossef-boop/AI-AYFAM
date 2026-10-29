"""محرك الزجاج المضبّب الداكن v2 (Dark Frosted Glassmorphism) + خلفية حيّة متعددة الطبقات.

البنية العامة:
  1. ``LiveBackdrop``  خلفية متحركة من طبقات: قاعدة + فينييت + توهجات + شفق (Aurora) + شبكة خطوط +
     غبار نابض + شبكة عُقد متصلة + حزم بيانات تنساب على الروابط + شعاع مسح خفيف.
     ثم تُنتج نسخة مموّهة منها تُستخدم كمصدر للزجاج (تمويه خلفي منخفض التكلفة).
  2. ``paint_frosted``  يرسم اللوح الزجاجي بمواد (Materials) مختلفة وحالات تفاعل (hover/pressed/focus).
     يأخذ عيّنات من الخلفية خلف اللوح ليلوّن الحافة بلون الضوء المار، ويرفع التعتيم تلقائيًا إن كانت
     الخلفية ساطعة خلف نص (Adaptive Tint)، فيبقى النص مقروءًا دائمًا.
  3. ``FrostedGlassController``  يطبّق الزجاج تلقائيًا على كل البطاقات والمجموعات والتبويبات والأشرطة
     والأزرار والحقول، ويدير حركة المؤشر (hover) والتركيز، ويبطئ الحركة عند خمول النافذة.
  4. ``install_glass`` دالة واحدة لتركيب كل شيء، و``apply_preset`` لتبديل السمة بالكامل أثناء التشغيل.
  5. ضبط تلقائي للجودة (Adaptive Quality) إن كان الجهاز بطيئًا، ولوحة أداء (Ctrl+Shift+G).

التوافق: الدوال القديمة (register_live / LiveBackdrop / BackdropCanvas / paint_frosted /
paint_frosted_bar / FrostedGlassController) محفوظة بنفس التواقيع، والإضافات كلها اختيارية.
"""
from __future__ import annotations

import math
import random
import time
import weakref
from dataclasses import dataclass

from ui.qt_safety import safe_slot
from PyQt6.QtCore import QEvent, QLineF, QObject, QPoint, QPointF, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (QBrush, QColor, QCursor, QImage, QKeySequence, QLinearGradient, QPainter, QPainterPath, QPen,
                         QPixmap, QRadialGradient, QShortcut)
from PyQt6.QtWidgets import (QAbstractButton, QAbstractItemView, QComboBox, QGroupBox, QLabel, QLineEdit,
                             QPlainTextEdit, QPushButton, QTabBar, QTabWidget, QTextEdit, QToolButton, QWidget)

# ═══════════════════════════════ إعدادات المظهر (عدّلها هنا فقط) ═══════════════════════════════
# ---- سطح الزجاج ----
FROST_TINT = (4, 10, 28)          # لون السطح (كحلي مائي عميق)
FROST_TINT_ALPHA = 0.30           # تعتيم السطح (أقل = أشفّ وألوان أحيّ، أعلى = نص أوضح)
FROST_GRAIN_ALPHA = 3             # قوة حبيبات الضباب (0-255)
FROST_SHEEN_ALPHA = 0.10          # لمعان النصف العلوي (مقياس 0-1)
FROST_SPECULAR_ALPHA = 150        # قوة الانعكاس الحاد في الحافة العلوية (0-255)
FROST_BORDER_ALPHA = 110          # قوة الحافة الداخلية المضيئة (0-255)

# ---- التمويه ولون الخلفية المارّة عبر الزجاج ----
BLUR_SCALE = 0.5                  # دقة رسم مصدر التمويه (أقل = أسرع)
BLUR_DIVISOR = 9                  # قوة التمويه (أكبر = أكثر ضبابية)
WATER_SATURATE = 0.45             # حيوية الألوان عبر الزجاج (0 = بدون، 0.3-0.6 مناسب)
WATER_BRIGHTEN = 1.0              # 1.0 = بلا تغيير، <1 يعتّم، >1 يضيء (لا ترفعه فوق 1.15)

# ---- الخلفية ----
BG_GLOW_ALPHA = 0.60              # شدة التوهجات (1.0 = ساطع جدًا)
BG_GLOW_RADIUS = 0.62             # حجم التوهجات (أقل = بقع أصغر وأكثر تركيزًا)
BG_VIGNETTE = 0.55                # تعتيم الأطراف (0 = بلا، 1 = قوي)
AURORA_ALPHA = 0.55               # شدة شرائط الشفق (0 = إيقاف)
GRID_ALPHA = 16                   # شفافية شبكة الخطوط (0 = إيقاف)
DUST_COUNT = 90                   # عدد جسيمات الغبار النابضة (0 = إيقاف)
PACKETS_ENABLED = True            # حزم بيانات تسير على روابط الشبكة
MAX_PACKETS = 14                  # أقصى عدد حزم متزامنة
SCAN_BEAM_ALPHA = 12              # شعاع المسح العمودي البطيء (0 = إيقاف)

# ---- ذكاء القراءة (يحمي النص من الخلفيات الساطعة) ----
ADAPTIVE_TINT = True              # ارفع التعتيم تلقائيًا خلف الأجزاء الساطعة
ADAPTIVE_LUM_TARGET = 0.30        # السطوع المسموح به خلف النص (0-1)
ADAPTIVE_GAIN = 0.90              # حساسية الرفع
ADAPTIVE_MAX = 0.28               # أقصى تعتيم إضافي

# ---- تفاصيل الحافة ----
CHROMATIC_EDGE = True             # تشتّت لوني طفيف على الحافة (مظهر الانكسار)
RIM_HUE_FROM_BACKDROP = True      # لوّن الحافة بلون الضوء خلف اللوح
LIGHT_SWEEP = True                # شريط ضوء قطري يتحرك ببطء على الألواح

# ---- الأداء ----
PERF_PROFILE = "balanced"         # smooth | balanced | beauty | eco | custom (custom = قيمك أدناه كما هي)
FRAME_MS = 50                     # زمن إطار الحركة (50 = 20 إطارًا/ثانية) — يُستعمل مع custom
BLUR_EVERY = 3                    # أعد بناء الخلفية المموّهة كل N إطارات (حركتها بطيئة فلا حاجة لكل إطار)
GLASS_CACHE = True                # خزّن رسم كل لوح زجاجي كصورة (أكبر توفير في المعالج)
IDLE_FRAME_MS = 120               # زمن الإطار عند خمول النافذة (توفير طاقة)
ANIMATED = True                   # False = خلفية ثابتة (أخف ما يمكن)
ADAPTIVE_QUALITY = True           # خفّض التفاصيل تلقائيًا إن كان الجهاز بطيئًا
DEBUG_HUD_SHORTCUT = "Ctrl+Shift+G"

# ---- ألوان الخلفية (تغيّرها السمات الجاهزة) ----
BASE_STOPS = ("#030712", (5, 24, 58), (10, 22, 70))
# (x, y, نصف القطر, اللون, الشفافية 0-255, سعة الحركة, سرعة الحركة)
GLOW_SPECS = (
    (0.82, 0.14, 0.55, "#14b8a6", 175, 0.05, 0.15),
    (0.10, 0.88, 0.62, "#4f46e5", 150, 0.05, 0.12),
    (0.50, 0.50, 0.40, "#0ea5e9", 130, 0.07, 0.10),
    (0.94, 0.92, 0.38, "#a78bfa", 120, 0.03, 0.14),
)
# (اللون, الارتفاع النسبي, السعة, التردد, السرعة, السماكة, الشفافية)
AURORA_BANDS = (
    ("#2dd4bf", 0.22, 0.07, 0.55, 0.20, 0.16, 70),
    ("#60a5fa", 0.55, 0.09, 0.42, 0.15, 0.20, 55),
    ("#a78bfa", 0.80, 0.06, 0.60, 0.18, 0.14, 50),
)
NODE_PALETTE = ("#2dd4bf", "#60a5fa", "#a78bfa", "#38bdf8")
SCAN_COLOR = "#7dd3fc"

_TUNABLES = (
    "FROST_TINT", "FROST_TINT_ALPHA", "FROST_GRAIN_ALPHA", "FROST_SHEEN_ALPHA", "FROST_SPECULAR_ALPHA",
    "FROST_BORDER_ALPHA", "BLUR_SCALE", "BLUR_DIVISOR", "WATER_SATURATE", "WATER_BRIGHTEN", "BG_GLOW_ALPHA",
    "BG_GLOW_RADIUS", "BG_VIGNETTE", "AURORA_ALPHA", "GRID_ALPHA", "DUST_COUNT", "SCAN_BEAM_ALPHA",
    "BASE_STOPS", "GLOW_SPECS", "AURORA_BANDS", "NODE_PALETTE", "SCAN_COLOR", "ADAPTIVE_LUM_TARGET",
    "FRAME_MS", "BLUR_EVERY", "PACKETS_ENABLED", "MAX_PACKETS", "CHROMATIC_EDGE", "LIGHT_SWEEP", "GLASS_CACHE",
)
_DEFAULTS = {name: globals()[name] for name in _TUNABLES}

# ═══════════════════════════════ سمات جاهزة (تُبدَّل أثناء التشغيل) ═══════════════════════════════
PRESETS: dict[str, dict] = {
    "aqua_night": {},   # الافتراضي: أخضر مائي + أزرق + بنفسجي
    "deep_ocean": {
        "FROST_TINT": (2, 8, 24), "FROST_TINT_ALPHA": 0.28, "BG_GLOW_ALPHA": 0.55, "AURORA_ALPHA": 0.45,
        "BASE_STOPS": ("#020611", (4, 16, 46), (6, 16, 60)),
        "GLOW_SPECS": ((0.80, 0.16, 0.55, "#0ea5e9", 170, 0.05, 0.15), (0.12, 0.86, 0.60, "#1d4ed8", 150, 0.05, 0.12),
                       (0.50, 0.50, 0.38, "#06b6d4", 120, 0.07, 0.10), (0.94, 0.92, 0.36, "#6366f1", 110, 0.03, 0.14)),
        "AURORA_BANDS": (("#22d3ee", 0.25, 0.07, 0.50, 0.18, 0.16, 62), ("#3b82f6", 0.58, 0.09, 0.40, 0.14, 0.20, 52),
                         ("#818cf8", 0.82, 0.06, 0.58, 0.16, 0.14, 44)),
        "NODE_PALETTE": ("#22d3ee", "#3b82f6", "#818cf8", "#38bdf8"),
    },
    "aurora": {
        "FROST_TINT": (6, 10, 30), "FROST_TINT_ALPHA": 0.30, "BG_GLOW_ALPHA": 0.70, "AURORA_ALPHA": 0.85,
        "BASE_STOPS": ("#040711", (8, 18, 52), (18, 14, 70)),
        "GLOW_SPECS": ((0.78, 0.12, 0.55, "#34d399", 170, 0.06, 0.15), (0.14, 0.82, 0.60, "#8b5cf6", 160, 0.05, 0.12),
                       (0.52, 0.48, 0.40, "#22d3ee", 120, 0.07, 0.10), (0.92, 0.90, 0.36, "#f472b6", 100, 0.03, 0.14)),
        "AURORA_BANDS": (("#34d399", 0.20, 0.08, 0.50, 0.20, 0.18, 85), ("#a78bfa", 0.52, 0.10, 0.40, 0.15, 0.22, 70),
                         ("#f472b6", 0.80, 0.06, 0.62, 0.18, 0.14, 55)),
        "NODE_PALETTE": ("#34d399", "#a78bfa", "#22d3ee", "#f472b6"),
    },
    "neon_ring": {   # قريبة من صورة Dribbble: خلفية سوداء + توهج أحمر/أزرق مركّز
        "FROST_TINT": (8, 6, 16), "FROST_TINT_ALPHA": 0.24, "FROST_SPECULAR_ALPHA": 170, "BG_GLOW_ALPHA": 0.85,
        "BG_GLOW_RADIUS": 0.50, "BG_VIGNETTE": 0.75, "AURORA_ALPHA": 0.0, "GRID_ALPHA": 8, "WATER_SATURATE": 0.55,
        "BASE_STOPS": ("#010103", (4, 4, 12), (6, 4, 14)),
        "GLOW_SPECS": ((0.50, 0.50, 0.52, "#ff2d55", 190, 0.03, 0.10), (0.56, 0.58, 0.46, "#3b6cff", 170, 0.04, 0.12),
                       (0.40, 0.42, 0.30, "#a855f7", 110, 0.05, 0.09), (0.50, 0.50, 0.20, "#ffffff", 60, 0.02, 0.08)),
        "NODE_PALETTE": ("#ff2d55", "#3b6cff", "#a855f7", "#60a5fa"),
        "SCAN_COLOR": "#ff6b8b",
    },
    "graphite": {   # محايد وهادئ: أقل ألوانًا وأكثر راحة للعين
        "FROST_TINT": (10, 12, 18), "FROST_TINT_ALPHA": 0.34, "BG_GLOW_ALPHA": 0.40, "AURORA_ALPHA": 0.20,
        "WATER_SATURATE": 0.25, "GRID_ALPHA": 10, "DUST_COUNT": 50,
        "BASE_STOPS": ("#05070b", (12, 16, 24), (16, 20, 32)),
        "GLOW_SPECS": ((0.80, 0.15, 0.52, "#64748b", 150, 0.04, 0.14), (0.12, 0.86, 0.58, "#475569", 130, 0.04, 0.11),
                       (0.50, 0.50, 0.38, "#38bdf8", 70, 0.06, 0.09), (0.94, 0.92, 0.34, "#94a3b8", 80, 0.03, 0.13)),
        "AURORA_BANDS": (("#94a3b8", 0.25, 0.06, 0.50, 0.15, 0.14, 40), ("#38bdf8", 0.60, 0.08, 0.40, 0.12, 0.18, 34),
                         ("#a5b4fc", 0.82, 0.05, 0.60, 0.14, 0.12, 30)),
        "NODE_PALETTE": ("#94a3b8", "#38bdf8", "#a5b4fc", "#cbd5e1"),
        "SCAN_COLOR": "#cbd5e1",
    },
}

# ═══════════════════════════════ ملفات الأداء ═══════════════════════════════
# كل ملف يغيّر معدل الإطارات وعدد التأثيرات. جرّب "smooth" إن أردت أقصى سلاسة.
PROFILES: dict[str, dict] = {
    "custom": {},
    "beauty": {"FRAME_MS": 33, "BLUR_EVERY": 1, "DUST_COUNT": 90, "PACKETS_ENABLED": True, "MAX_PACKETS": 14},
    "balanced": {"FRAME_MS": 50, "BLUR_EVERY": 3, "DUST_COUNT": 60, "PACKETS_ENABLED": True, "MAX_PACKETS": 10},
    "smooth": {"FRAME_MS": 66, "BLUR_EVERY": 4, "DUST_COUNT": 30, "PACKETS_ENABLED": False, "GRID_ALPHA": 0,
               "SCAN_BEAM_ALPHA": 0, "BLUR_SCALE": 0.4},
    "eco": {"FRAME_MS": 100, "BLUR_EVERY": 5, "DUST_COUNT": 0, "PACKETS_ENABLED": False, "GRID_ALPHA": 0,
            "SCAN_BEAM_ALPHA": 0, "AURORA_ALPHA": 0.3, "BLUR_SCALE": 0.35, "CHROMATIC_EDGE": False,
            "LIGHT_SWEEP": False},
}
_ACTIVE = {"preset": "aqua_night", "profile": PERF_PROFILE if PERF_PROFILE in PROFILES else "balanced"}


# ═══════════════════════════════ مواد الزجاج وحالاته ═══════════════════════════════
@dataclass(frozen=True)
class GlassMaterial:
    """معاملات ضرب تُطبَّق فوق الإعدادات العامة، فيصبح لكل نوع عنصر طابعه الخاص."""
    tint: float = 1.0       # تعتيم السطح
    sheen: float = 1.0      # لمعان النصف العلوي
    specular: float = 1.0   # الانعكاس الحاد في الأعلى
    border: float = 1.0     # قوة الحافة
    grain: float = 1.0      # الحبيبات
    depth: float = 1.0      # ظل داخلي سفلي (عمق)
    rim: float = 1.0        # توهج داخلي ناعم على الأطراف
    glow: float = 1.0       # وهج الأسفل + ضوء الزاوية
    hover: float = 1.0      # استجابة المؤشر


MATERIALS: dict[str, GlassMaterial] = {
    "panel": GlassMaterial(),
    "card": GlassMaterial(tint=1.0, sheen=1.1, specular=1.0, depth=1.1),
    "hero": GlassMaterial(tint=0.92, sheen=1.35, specular=1.25, border=1.15, glow=1.3, rim=1.2),
    "bubble": GlassMaterial(tint=1.05, sheen=0.9, specular=0.7, border=0.9, depth=0.8),
    "pill": GlassMaterial(tint=1.1, sheen=1.2, specular=1.2, border=1.2, glow=0.8),
    "control": GlassMaterial(tint=1.25, sheen=1.0, specular=0.9, border=1.0, depth=0.9, hover=1.3),
    "input": GlassMaterial(tint=1.35, sheen=0.6, specular=0.5, border=0.9, depth=1.3, hover=0.8, glow=0.5),
    "view": GlassMaterial(tint=1.3, sheen=0.5, specular=0.4, border=0.8, depth=1.0, glow=0.4, grain=0.6),
    "tab": GlassMaterial(tint=1.15, sheen=0.8, specular=0.6, border=0.8, depth=0.8, hover=1.2),
    "tab_active": GlassMaterial(tint=0.85, sheen=1.4, specular=1.2, border=1.3, glow=1.4, rim=1.3),
    "bar": GlassMaterial(tint=0.95, sheen=0.7, specular=0.0, border=0.0, depth=0.6, glow=0.8),
}


@dataclass
class GlassState:
    """حالة التفاعل وقت الرسم."""
    hover: float = 0.0      # 0..1 (متحركة بنعومة)
    pressed: bool = False
    focus: bool = False
    enabled: bool = True


LIVE_WIDGETS: "weakref.WeakSet[QWidget]" = weakref.WeakSet()
SLOW_WIDGETS: "weakref.WeakSet[QWidget]" = weakref.WeakSet()   # أزرار وحقول: تُحدَّث كل 3 إطارات
_HOVER: "weakref.WeakKeyDictionary[QWidget, float]" = weakref.WeakKeyDictionary()
_STATE: dict = {"backdrop": None, "canvas": None, "grain": None, "controller": None}


def register_live(widget: QWidget) -> None:
    """سجّل لوحًا زجاجيًا مخصصًا ليُعاد رسمه مع حركة الخلفية."""
    LIVE_WIDGETS.add(widget)


# ═══════════════════════════════ دوال مساعدة ═══════════════════════════════
def _clamp(v: float, lo: float, hi: float) -> float:
    return lo if v < lo else hi if v > hi else v


def _a(v: float) -> int:
    """حوّل أي رقم إلى قناة صالحة 0-255 (يمنع خطأ القيم الخارجة عن النطاق)."""
    return int(_clamp(v, 0, 255))


def _rgba(r: float, g: float, b: float, a: float = 255) -> QColor:
    return QColor(_a(r), _a(g), _a(b), _a(a))


def _with_alpha(c: QColor, a: float) -> QColor:
    return QColor(c.red(), c.green(), c.blue(), _a(a))


def _as_color(v) -> QColor:
    """يقبل '#hex' أو (r,g,b) أو (r,g,b,a)."""
    if isinstance(v, QColor):
        return QColor(v)
    if isinstance(v, (tuple, list)):
        return _rgba(*v)
    return QColor(v)


def _luminance(r: float, g: float, b: float) -> float:
    return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255.0


def _accent_from(r: float, g: float, b: float) -> QColor:
    """لون مضيء مشبّع بنفس صبغة الخلفية (يُستعمل للحافة والتوهج)."""
    c = QColor(_a(r), _a(g), _a(b)).toHsv()
    h = c.hue()
    if h < 0:           # رمادي بلا صبغة
        h = 200
    return QColor.fromHsv(int(h) % 360, _a(c.saturation() * 1.15 + 40), 255)


def invalidate_theme() -> None:
    """أعد بناء كل ما يعتمد على الإعدادات (الحبيبات والخلفية) بعد تغيير القيم."""
    _STATE["grain"] = None
    bd = _STATE["backdrop"]
    if bd is not None:
        bd.invalidate()


def _reapply() -> None:
    """القيم الأصلية ← السمة ← ملف الأداء (ملف الأداء له الأولوية على معاملات الأداء)."""
    g = globals()
    for key, val in _DEFAULTS.items():
        g[key] = val
    g.update(PRESETS[_ACTIVE["preset"]])
    g.update(PROFILES[_ACTIVE["profile"]])
    invalidate_theme()


def apply_preset(name: str) -> None:
    """بدّل السمة بالكامل أثناء التشغيل: apply_preset('neon_ring')."""
    if name not in PRESETS:
        raise KeyError(f"سمة غير معروفة: {name}. المتاح: {', '.join(PRESETS)}")
    _ACTIVE["preset"] = name
    _reapply()


def apply_profile(name: str) -> None:
    """بدّل ملف الأداء أثناء التشغيل: apply_profile('smooth')."""
    if name not in PROFILES:
        raise KeyError(f"ملف غير معروف: {name}. المتاح: {', '.join(PROFILES)}")
    _ACTIVE["profile"] = name
    _reapply()


# ═══════════════════════════════ الخلفية المتحركة ═══════════════════════════════
class _Node:
    """عقدة في شبكة الخلفية (إحداثياتها نسبية 0..1)."""
    __slots__ = ("x", "y", "vx", "vy", "color", "cidx", "key", "phase")

    def __init__(self, x: float, y: float, vx: float, vy: float, cidx: int, key: bool, phase: float):
        self.x, self.y, self.vx, self.vy = x, y, vx, vy
        self.cidx, self.key, self.phase = cidx, key, phase
        self.color = QColor(NODE_PALETTE[cidx % len(NODE_PALETTE)])


class _Packet:
    """حزمة بيانات تنساب من عقدة إلى أخرى."""
    __slots__ = ("a", "b", "t", "speed", "color")

    def __init__(self, a: _Node, b: _Node, speed: float, color: QColor):
        self.a, self.b, self.t, self.speed, self.color = a, b, 0.0, speed, color


class LiveBackdrop(QObject):
    """خلفية متحركة + نسخة مموّهة منها تُستخدم كمصدر للزجاج.

    تحسينات الأداء:
      * الطبقة الناعمة (قاعدة/توهجات/شفق) تُرسم بنصف الدقة مرة كل ``BLUR_EVERY`` إطارات ثم تُكبَّر.
      * الطبقة الحادة (خطوط/عقد/غبار/حزم) وحدها تُرسم بالدقة الكاملة في كل إطار.
      * الروابط تُحسب مرة واحدة في الإطار وأقلامها مخزّنة (لا إنشاء كائنات في حلقة الرسم).
      * ``version`` يرتفع عند كل إعادة بناء، فتعرف الألواح الزجاجية متى تعيد رسم نفسها.
    """

    updated = pyqtSignal()
    NODES = 62
    LINK_BASE = 175.0
    LINK_LEVELS = 10
    QUALITY_BLUR = (1.0, 0.8, 0.62)     # دقة التمويه لكل مستوى جودة
    QUALITY_SLOW = (1.0, 1.0, 1.6)      # تبطيء الإطار لكل مستوى جودة

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        rnd = random.Random(7)
        self.nodes: list[_Node] = []
        for i in range(self.NODES):
            ang = rnd.uniform(0, math.tau)
            speed = rnd.uniform(0.006, 0.018)
            self.nodes.append(_Node(rnd.random(), rnd.random(), math.cos(ang) * speed, math.sin(ang) * speed,
                                    i % len(NODE_PALETTE), i % 6 == 0, rnd.uniform(0, math.tau)))
        drnd = random.Random(23)
        # غبار: (x, y, نصف القطر, سرعة النبض, الطور, السطوع)
        self.dust = [(drnd.random(), drnd.random(), drnd.uniform(0.6, 1.6), drnd.uniform(0.4, 1.6),
                      drnd.uniform(0, math.tau), drnd.uniform(0.35, 1.0)) for _ in range(240)]
        self.packets: list[_Packet] = []
        self._links: list[tuple[int, int, int]] = []
        self._pens: dict[tuple[int, int, int], QPen] = {}
        self._rnd = random.Random(99)
        self._spawn_acc = 0.0
        self.t = 0.0
        self.size = QSize(1400, 880)
        self.blurred = QImage()
        self.soft = QImage()
        self.version = 0
        self.paused = False
        self.active = True
        self.quality = 0                  # 0 عالية، 1 متوسطة، 2 منخفضة
        self.fps = 0.0
        self.frame_ms = 0.0
        self.lag = 1.0
        self._tick_n = 0
        self._dt_ema = 0.0
        self._slow = 0
        self._fast = 0
        self._last = time.perf_counter()
        self._static: dict[tuple[int, int], QPixmap] = {}
        self._timer = QTimer(self)
        self._timer.setInterval(FRAME_MS)
        self._timer.timeout.connect(self._tick)

    # ---- التحكم ----
    def start(self) -> None:
        self._compute_links()
        self._rebuild()
        if ANIMATED:
            self._last = time.perf_counter()
            self._apply_interval()
            self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def set_active(self, active: bool) -> None:
        """النافذة نشطة؟ إن لم تكن نبطّئ الحركة لتوفير المعالج والبطارية."""
        if active != self.active:
            self.active = active
            self._apply_interval()

    def _apply_interval(self) -> None:
        base = FRAME_MS if self.active else IDLE_FRAME_MS
        ms = max(16, int(base * self.QUALITY_SLOW[min(self.quality, 2)]))
        if self._timer.interval() != ms:
            self._timer.setInterval(ms)

    def set_size(self, w: int, h: int) -> None:
        if w > 8 and h > 8 and (w, h) != (self.size.width(), self.size.height()):
            self.size = QSize(w, h)
            self._compute_links()
            self._rebuild()
            self.updated.emit()

    def invalidate(self) -> None:
        """بعد تغيير السمة أو الملف: لوّن العقد من جديد وامسح الكاش وأعد البناء."""
        self._static.clear()
        self._pens.clear()
        for n in self.nodes:
            n.color = QColor(NODE_PALETTE[n.cidx % len(NODE_PALETTE)])
        self.packets.clear()
        self._apply_interval()
        self._compute_links()
        self._rebuild()
        self.updated.emit()

    # ---- الحركة والمنطق ----
    def _link_dist(self, w: float) -> float:
        return self.LINK_BASE * max(0.2, w / 1400.0)

    @safe_slot
    def _tick(self) -> None:
        if self.paused:
            self._last = time.perf_counter()
            return
        t0 = time.perf_counter()
        dt = _clamp(t0 - self._last, 0.001, 0.5)
        self._last = t0
        self._dt_ema = dt if self._dt_ema == 0 else self._dt_ema * 0.92 + dt * 0.08
        self.fps = 1.0 / self._dt_ema
        self.t += dt
        for n in self.nodes:
            n.x += n.vx * dt
            n.y += n.vy * dt
            if n.x < -0.03 or n.x > 1.03:
                n.vx = -n.vx
            if n.y < -0.03 or n.y > 1.03:
                n.vy = -n.vy
        self._compute_links()
        if PACKETS_ENABLED and self.quality == 0:
            self._update_packets(dt)
        elif self.packets:
            self.packets.clear()
        self._tick_n += 1
        if self._tick_n % max(1, int(BLUR_EVERY)) == 0 or self.soft.isNull():
            self._rebuild()
        self.updated.emit()
        self.frame_ms = (time.perf_counter() - t0) * 1000.0
        if ADAPTIVE_QUALITY:
            self._govern()

    def _govern(self) -> None:
        """يقيس تأخر المؤقّت الفعلي (يشمل زمن الرسم كله): إن تأخر خفّض الجودة، وإن ارتاح أعدها."""
        interval = self._timer.interval() / 1000.0
        self.lag = self._dt_ema / interval if interval > 0 else 1.0
        if self.lag > 1.35:
            self._slow += 1
            self._fast = 0
        elif self.lag < 1.12:
            self._fast += 1
            self._slow = 0
        else:
            self._slow = self._fast = 0
        if self._slow >= 40 and self.quality < 2:
            self.quality += 1
            self._slow, self._dt_ema = 0, 0.0
            self._apply_interval()
        elif self._fast >= 600 and self.quality > 0:
            self.quality -= 1
            self._fast, self._dt_ema = 0, 0.0
            self._apply_interval()

    def _compute_links(self) -> None:
        """احسب الروابط بين العقد مرة واحدة في الإطار (تُستعمل للتمويه وللرسم الحاد)."""
        w, h = self.size.width(), self.size.height()
        link = self._link_dist(w) * (0.85 if self.quality == 2 else 1.0)
        link2 = link * link
        levels = self.LINK_LEVELS
        xs = [n.x * w for n in self.nodes]
        ys = [n.y * h for n in self.nodes]
        count = len(xs)
        links = []
        for i in range(count):
            xi, yi = xs[i], ys[i]
            for j in range(i + 1, count):
                dx = xi - xs[j]
                dy = yi - ys[j]
                d2 = dx * dx + dy * dy
                if d2 < link2:
                    lvl = int(levels * (1.0 - math.sqrt(d2) / link))
                    links.append((i, j, lvl if lvl < levels else levels - 1))
        self._links = links

    def _update_packets(self, dt: float) -> None:
        alive = []
        link = self._link_dist(self.size.width()) * 1.15
        w, h = self.size.width(), self.size.height()
        for pk in self.packets:
            pk.t += dt * pk.speed
            if pk.t >= 1.0:
                continue
            dx = (pk.a.x - pk.b.x) * w
            dy = (pk.a.y - pk.b.y) * h
            if dx * dx + dy * dy > link * link:
                continue
            alive.append(pk)
        self.packets = alive
        self._spawn_acc += dt
        if self._spawn_acc < 0.35 or len(self.packets) >= MAX_PACKETS or not self._links:
            return
        self._spawn_acc = 0.0
        i, j, _lvl = self._rnd.choice(self._links)
        a, b = self.nodes[i], self.nodes[j]
        self.packets.append(_Packet(a, b, self._rnd.uniform(0.35, 0.7), QColor(a.color)))

    def _pen_for(self, cidx: int, lvl: int, width: float) -> QPen:
        """أقلام الروابط مخزّنة (لون × مستوى شفافية × سماكة) بدل إنشاء قلم لكل خط في كل إطار."""
        key = (cidx, lvl, int(width * 8))
        pen = self._pens.get(key)
        if pen is None:
            c = QColor(NODE_PALETTE[cidx % len(NODE_PALETTE)])
            c.setAlpha(_a(170 * (lvl + 0.5) / self.LINK_LEVELS))
            pen = QPen(c, width)
            self._pens[key] = pen
        return pen

    # ---- الطبقة الثابتة (قاعدة + فينييت) ----
    def _static_layer(self, w: int, h: int) -> QPixmap:
        key = (w, h)
        pm = self._static.get(key)
        if pm is not None:
            return pm
        if len(self._static) > 4:
            self._static.clear()
        pm = QPixmap(max(1, w), max(1, h))
        p = QPainter(pm)
        base = QLinearGradient(0, 0, w, h)
        base.setColorAt(0, _as_color(BASE_STOPS[0]))
        base.setColorAt(0.55, _as_color(BASE_STOPS[1]))
        base.setColorAt(1, _as_color(BASE_STOPS[2]))
        p.fillRect(0, 0, w, h, base)
        if BG_VIGNETTE > 0:
            vg = QRadialGradient(QPointF(w * 0.5, h * 0.5), math.hypot(w, h) * 0.62)
            vg.setColorAt(0.0, QColor(0, 0, 0, 0))
            vg.setColorAt(0.65, QColor(0, 0, 0, _a(40 * BG_VIGNETTE)))
            vg.setColorAt(1.0, QColor(0, 0, 0, _a(150 * BG_VIGNETTE)))
            p.fillRect(0, 0, w, h, vg)
        p.end()
        self._static[key] = pm
        return pm

    # ---- الرسم ----
    def paint_scene(self, p: QPainter, w: int, h: int, for_blur: bool = False) -> None:
        """للتوافق مع الكود القديم: ارسم المشهد كاملًا مباشرة بدقة (w, h)."""
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._paint_soft(p, w, h)
        if for_blur:
            self._paint_network(p, w, h, max(0.2, w / 1400.0), True)
        else:
            self._paint_crisp(p, w, h)

    def paint_canvas(self, p: QPainter, w: int, h: int) -> None:
        """رسم القماشة: الطبقة الناعمة المخزّنة مكبّرة + الطبقة الحادة بدقة كاملة."""
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self.soft.isNull():
            self._paint_soft(p, w, h)
        else:
            p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
            p.drawImage(QRectF(0, 0, w, h), self.soft)
            p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, False)
        self._paint_crisp(p, w, h)

    def _paint_soft(self, p: QPainter, w: int, h: int) -> None:
        p.drawPixmap(0, 0, self._static_layer(w, h))
        self._paint_glows(p, w, h, self.t)
        if AURORA_ALPHA > 0 and self.quality < 2:
            self._paint_aurora(p, w, h, self.t)

    def _paint_crisp(self, p: QPainter, w: int, h: int) -> None:
        k = max(0.2, w / 1400.0)
        t = self.t
        if SCAN_BEAM_ALPHA > 0 and self.quality < 2:
            self._paint_scan_beam(p, w, h, t)
        if GRID_ALPHA > 0 and self.quality < 2:
            self._paint_grid(p, w, h, k, t)
        if DUST_COUNT > 0 and self.quality == 0:
            self._paint_dust(p, w, h, k, t)
        self._paint_network(p, w, h, k, False)
        if self.packets:
            self._paint_packets(p, w, h, k)

    def _paint_glows(self, p: QPainter, w: int, h: int, t: float) -> None:
        for i, (cx, cy, r, col, a, amp, spd) in enumerate(GLOW_SPECS):
            x = cx + amp * math.sin(t * spd + i * 1.7)
            y = cy + amp * math.cos(t * spd * 0.8 + i * 2.3)
            c = QColor(col)
            c.setAlpha(_a(a * BG_GLOW_ALPHA))
            g = QRadialGradient(QPointF(x * w, y * h), max(8.0, r * BG_GLOW_RADIUS * max(w, h)))
            g.setColorAt(0, c)
            g.setColorAt(0.55, _with_alpha(c, c.alpha() * 0.35))
            g.setColorAt(1, _with_alpha(c, 0))
            p.fillRect(0, 0, w, h, g)

    def _paint_aurora(self, p: QPainter, w: int, h: int, t: float) -> None:
        """شرائط ضوء متموجة تُدمج بوضع Screen فتضيء دون أن تحرق الألوان."""
        p.save()
        p.setCompositionMode(QPainter.CompositionMode.CompositionMode_Screen)
        steps = 20 if self.quality == 0 else 12
        for i, (col, y0, amp, freq, speed, thick, alpha) in enumerate(AURORA_BANDS):
            top, bot = [], []
            for s in range(steps + 1):
                x = w * s / steps
                wave = math.sin(freq * s + t * speed + i * 2.1) + 0.45 * math.sin(freq * 2.3 * s - t * speed * 0.7)
                y = h * (y0 + amp * wave)
                th = h * thick * (0.72 + 0.28 * math.sin(s * 0.6 + t * 0.3 + i))
                top.append((x, y))
                bot.append((x, y + th))
            path = QPainterPath()
            path.moveTo(*top[0])
            for x, y in top[1:]:
                path.lineTo(x, y)
            for x, y in reversed(bot):
                path.lineTo(x, y)
            path.closeSubpath()
            c = QColor(col)
            g = QLinearGradient(0, h * (y0 - amp * 1.4), 0, h * (y0 + amp * 1.4 + thick))
            g.setColorAt(0.0, _with_alpha(c, 0))
            g.setColorAt(0.5, _with_alpha(c, alpha * AURORA_ALPHA))
            g.setColorAt(1.0, _with_alpha(c, 0))
            p.fillPath(path, g)
        p.restore()

    def _paint_scan_beam(self, p: QPainter, w: int, h: int, t: float) -> None:
        """شعاع مسح أفقي ناعم يمرّ من الأعلى للأسفل كل ~15 ثانية (إحساس مراقبة أمنية)."""
        band = h * 0.20
        y = ((t * 0.065) % 1.35 - 0.2) * h
        c = QColor(SCAN_COLOR)
        g = QLinearGradient(0, y, 0, y + band)
        g.setColorAt(0.0, _with_alpha(c, 0))
        g.setColorAt(0.5, _with_alpha(c, SCAN_BEAM_ALPHA))
        g.setColorAt(1.0, _with_alpha(c, 0))
        p.fillRect(QRectF(0, y, w, band), g)

    def _paint_grid(self, p: QPainter, w: int, h: int, k: float, t: float) -> None:
        """شبكة خطوط تنساب ببطء. بلا تنعيم وعلى بكسلات صحيحة (أرخص بكثير)."""
        step = 72 * k
        off = (t * 5 * k) % step
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        p.setPen(QPen(QColor(140, 200, 255, _a(GRID_ALPHA)), 1.0))
        lines = []
        x = -off
        while x < w:
            xi = round(x)
            lines.append(QLineF(xi, 0, xi, h))
            x += step
        y = -off
        while y < h:
            yi = round(y)
            lines.append(QLineF(0, yi, w, yi))
            y += step
        p.drawLines(lines)
        p.restore()

    def _paint_dust(self, p: QPainter, w: int, h: int, k: float, t: float) -> None:
        """جسيمات صغيرة تنبض ببطء كأنها نجوم بعيدة."""
        count = min(DUST_COUNT, len(self.dust))
        pen = QPen()
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        for idx in range(count):
            x, y, rad, spd, ph, br = self.dust[idx]
            tw = 0.5 + 0.5 * math.sin(t * spd + ph)
            pen.setColor(QColor(200, 230, 255, _a(25 + 150 * br * tw)))
            pen.setWidthF(rad * k * 1.6)
            p.setPen(pen)
            p.drawPoint(QPointF(x * w, y * h))

    def _paint_network(self, p: QPainter, w: int, h: int, k: float, for_blur: bool) -> None:
        t = self.t
        nodes = self.nodes
        width = (1.6 if for_blur else 1.3) * k
        groups: dict[tuple[int, int], list] = {}
        for i, j, lvl in self._links:
            ni, nj = nodes[i], nodes[j]
            groups.setdefault((ni.cidx, lvl), []).append(QLineF(ni.x * w, ni.y * h, nj.x * w, nj.y * h))
        for (cidx, lvl), lines in groups.items():     # دفعة واحدة لكل (لون، شفافية)
            p.setPen(self._pen_for(cidx, lvl, width))
            p.drawLines(lines)
        p.setPen(Qt.PenStyle.NoPen)
        for n in nodes:
            x, y = n.x * w, n.y * h
            col = QColor(n.color)
            if n.key:   # عقدة رئيسية: وهج نابض + حلقة موجية تتسع وتتلاشى
                pulse = 0.75 + 0.25 * math.sin(t * 1.4 + n.phase)
                rad = 20 * k * pulse
                g = QRadialGradient(QPointF(x, y), rad)
                col.setAlpha(200)
                g.setColorAt(0, col)
                col.setAlpha(0)
                g.setColorAt(1, col)
                p.setBrush(g)
                p.drawEllipse(QPointF(x, y), rad, rad)
                if not for_blur and self.quality == 0:
                    ph = (t * 0.45 + n.phase) % 1.0
                    ring = QColor(n.color)
                    ring.setAlpha(_a(120 * (1 - ph)))
                    p.setBrush(Qt.BrushStyle.NoBrush)
                    p.setPen(QPen(ring, 1.0 * k))
                    p.drawEllipse(QPointF(x, y), 6 * k + 34 * k * ph, 6 * k + 34 * k * ph)
                    p.setPen(Qt.PenStyle.NoPen)
                col.setAlpha(255)
                p.setBrush(col)
                p.drawEllipse(QPointF(x, y), 3.2 * k, 3.2 * k)
            elif not for_blur:
                col.setAlpha(240)
                p.setBrush(col)
                p.drawEllipse(QPointF(x, y), 2.1 * k, 2.1 * k)

    def _paint_packets(self, p: QPainter, w: int, h: int, k: float) -> None:
        p.save()
        p.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus)
        p.setPen(Qt.PenStyle.NoPen)
        for pk in self.packets:
            e = pk.t * pk.t * (3 - 2 * pk.t)            # حركة ناعمة (smoothstep)
            x = (pk.a.x + (pk.b.x - pk.a.x) * e) * w
            y = (pk.a.y + (pk.b.y - pk.a.y) * e) * h
            fade = math.sin(pk.t * math.pi)
            c = QColor(pk.color)
            g = QRadialGradient(QPointF(x, y), 9 * k)
            c.setAlpha(_a(210 * fade))
            g.setColorAt(0, c)
            c.setAlpha(0)
            g.setColorAt(1, c)
            p.setBrush(g)
            p.drawEllipse(QPointF(x, y), 9 * k, 9 * k)
            p.setBrush(QColor(255, 255, 255, _a(230 * fade)))
            p.drawEllipse(QPointF(x, y), 1.6 * k, 1.6 * k)
        p.restore()

    # ---- إعادة بناء الطبقة الناعمة + التمويه ----
    def _rebuild(self) -> None:
        scale = BLUR_SCALE * self.QUALITY_BLUR[min(self.quality, 2)]
        sw = max(16, int(self.size.width() * scale))
        sh = max(16, int(self.size.height() * scale))
        soft = QImage(sw, sh, QImage.Format.Format_ARGB32_Premultiplied)
        p = QPainter(soft)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._paint_soft(p, sw, sh)
        p.end()
        self.soft = soft
        img = soft.copy()          # مصدر التمويه = الطبقة الناعمة + الشبكة (بلا التفاصيل الدقيقة)
        p = QPainter(img)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._paint_network(p, sw, sh, max(0.2, sw / 1400.0), True)
        p.end()
        sm = Qt.TransformationMode.SmoothTransformation
        ar = Qt.AspectRatioMode.IgnoreAspectRatio
        div = max(2, int(BLUR_DIVISOR))
        tiny = img.scaled(max(4, sw // div), max(4, sh // div), ar, sm)
        mid = tiny.scaled(max(8, sw // 3), max(8, sh // 3), ar, sm)
        out = mid.scaled(sw, sh, ar, sm)
        CM = QPainter.CompositionMode
        if WATER_SATURATE > 0:   # حيوية الألوان: دمج Overlay للصورة مع نفسها (يرفع التشبّع دون حرق)
            sat = QPainter(out)
            sat.setCompositionMode(CM.CompositionMode_Overlay)
            sat.setOpacity(min(1.0, WATER_SATURATE))
            sat.drawImage(0, 0, out.copy())
            sat.end()
        if WATER_BRIGHTEN > 1.0:
            br = QPainter(out)
            br.setCompositionMode(CM.CompositionMode_Plus)
            br.setOpacity(min(1.0, WATER_BRIGHTEN - 1.0))
            br.drawImage(0, 0, out.copy())
            br.end()
        elif WATER_BRIGHTEN < 1.0:
            dk = QPainter(out)
            dk.fillRect(out.rect(), QColor(0, 0, 0, _a(255 * (1.0 - WATER_BRIGHTEN))))
            dk.end()
        self.blurred = out
        self.version += 1


class BackdropCanvas(QWidget):
    """القماشة الخلفية: تُرسم خلف كل عناصر النافذة وتتبع حجم أبيها."""

    def __init__(self, parent: QWidget, backdrop: LiveBackdrop):
        super().__init__(parent)
        self.backdrop = backdrop
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)
        parent.installEventFilter(self)
        self.setGeometry(parent.rect())
        self.lower()
        backdrop.set_size(max(1, parent.width()), max(1, parent.height()))
        backdrop.updated.connect(self.update)
        _STATE["backdrop"], _STATE["canvas"] = backdrop, self

    def eventFilter(self, obj, ev) -> bool:
        if obj is self.parent() and ev.type() == QEvent.Type.Resize:
            self.setGeometry(obj.rect())
            self.backdrop.set_size(obj.width(), obj.height())
            self.lower()
        return False

    def paintEvent(self, _e) -> None:
        p = QPainter(self)
        self.backdrop.paint_canvas(p, self.width(), self.height())
        p.end()


# ═══════════════════════════════ رسم الزجاج المضبّب ═══════════════════════════════
def _grain() -> QPixmap:
    """نسيج حبيبات دقيقة قابل للتكرار (يُبنى مرة واحدة)."""
    if _STATE["grain"] is None:
        rnd = random.Random(11)
        size = 128
        img = QImage(size, size, QImage.Format.Format_ARGB32)
        top = max(1, min(127, int(FROST_GRAIN_ALPHA) * 2))
        for y in range(size):
            for x in range(size):
                v = rnd.randint(150, 255)
                img.setPixel(x, y, (rnd.randint(0, top) << 24) | (v << 16) | (v << 8) | v)
        _STATE["grain"] = QPixmap.fromImage(img)
    return _STATE["grain"]


_SAMPLE_POINTS = ((0.5, 0.5), (0.2, 0.25), (0.8, 0.25), (0.2, 0.8), (0.8, 0.8))


def _sample_backdrop(img: QImage, src: QRectF) -> tuple[float, float, float] | None:
    """متوسط لون الخلفية المموّهة خلف اللوح (5 نقاط فقط، رخيص جدًا)."""
    iw, ih = img.width(), img.height()
    if iw < 2 or ih < 2:
        return None
    r = g = b = 0
    for fx, fy in _SAMPLE_POINTS:
        x = int(_clamp(src.x() + src.width() * fx, 0, iw - 1))
        y = int(_clamp(src.y() + src.height() * fy, 0, ih - 1))
        c = img.pixelColor(x, y)
        r += c.red()
        g += c.green()
        b += c.blue()
    n = len(_SAMPLE_POINTS)
    return r / n, g / n, b / n


def _paint_frosted_impl(p: QPainter, widget: QWidget, rect: QRectF, radius: float, nested: bool, border: bool,
                        tint_alpha: float | None, material: str, st: GlassState, origin: QPoint | None) -> QPainterPath:
    """الرسم الفعلي للوح الزجاجي (11 طبقة). مكلف؛ لذلك يُستدعى مرة عند الخبز لا في كل إطار."""
    m = MATERIALS.get(material, MATERIALS["panel"])
    k = 0.6 if nested else 1.0
    path = QPainterPath()
    inner = rect.adjusted(0.5, 0.5, -0.5, -0.5)
    path.addRoundedRect(inner, radius, radius)
    backdrop: LiveBackdrop | None = _STATE["backdrop"]
    canvas: QWidget | None = _STATE["canvas"]
    t = backdrop.t if backdrop is not None else 0.0

    p.save()
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setClipPath(path)

    # 1) الخلفية المموّهة بشدة + أخذ عيّنة لونها (لتلوين الحافة وضبط التعتيم)
    drawn = False
    rgb = None
    if origin is not None and backdrop is not None and canvas is not None and not backdrop.blurred.isNull() \
            and canvas.width() > 0:
        try:
            s = backdrop.blurred.width() / canvas.width()
            src = QRectF(origin.x() * s, origin.y() * s, rect.width() * s, rect.height() * s)
            p.drawImage(rect, backdrop.blurred, src)
            rgb = _sample_backdrop(backdrop.blurred, src)
            drawn = True
        except Exception:
            drawn = False
    if not drawn:
        p.fillPath(path, QColor(10, 16, 30, 200))
    if rgb is None:
        rgb = (24.0, 48.0, 96.0)
    lum = _luminance(*rgb)
    acc = _accent_from(*rgb) if RIM_HUE_FROM_BACKDROP else QColor(150, 230, 255)

    # 2) سطح مائي شفاف + تعتيم ذكي يرتفع تلقائيًا خلف الأجزاء الساطعة ليبقى النص مقروءًا
    base_ta = FROST_TINT_ALPHA if tint_alpha is None else tint_alpha
    extra = _clamp((lum - ADAPTIVE_LUM_TARGET) * ADAPTIVE_GAIN, 0.0, ADAPTIVE_MAX) if ADAPTIVE_TINT else 0.0
    ta = _clamp((base_ta + extra) * m.tint, 0.0, 0.88)
    r, g, b = FROST_TINT
    surface = QLinearGradient(rect.topLeft(), rect.bottomLeft())
    surface.setColorAt(0, _rgba(r + 10, g + 20, b + 30, 255 * ta * k * 0.8))
    surface.setColorAt(1, _rgba(r, g, b, 255 * ta * k * 1.2))
    p.fillPath(path, surface)

    # 3) عمق: ظل داخلي سفلي ثم وهج مائي صاعد من الأسفل بلون الضوء خلف اللوح
    if m.depth > 0:
        depth = QLinearGradient(rect.bottomLeft(), QPointF(rect.left(), rect.top() + rect.height() * 0.62))
        depth.setColorAt(0, QColor(0, 0, 0, _a(46 * k * m.depth)))
        depth.setColorAt(1, QColor(0, 0, 0, 0))
        p.fillPath(path, depth)
    if m.glow > 0:
        aqua = QLinearGradient(rect.bottomLeft(), QPointF(rect.left(), rect.top() + rect.height() * 0.45))
        aqua.setColorAt(0, _with_alpha(acc, 34 * k * m.glow))
        aqua.setColorAt(1, _with_alpha(acc, 0))
        p.fillPath(path, aqua)

    # 4) حبيبات دقيقة جدًا
    if m.grain > 0:
        p.setOpacity((0.5 if nested else 0.8) * min(1.0, m.grain))
        p.drawTiledPixmap(rect.toRect(), _grain())
        p.setOpacity(1.0)

    # 5) انعكاس مائي: لمعان علوي + شريط ضوء قطري متحرك + ضوء زاوية
    if m.sheen > 0:
        sheen = QLinearGradient(rect.topLeft(), QPointF(rect.left(), rect.top() + rect.height() * 0.5))
        sheen.setColorAt(0, QColor(220, 248, 255, _a(255 * FROST_SHEEN_ALPHA * k * m.sheen)))
        sheen.setColorAt(1, QColor(220, 248, 255, 0))
        p.fillPath(path, sheen)
        pos = 0.40 + (0.22 * math.sin(t * 0.22 + (id(widget) % 97) * 0.07) if LIGHT_SWEEP else 0.0)
        band = QLinearGradient(rect.topLeft(), rect.bottomRight())
        band.setColorAt(pos - 0.12, QColor(255, 255, 255, 0))
        band.setColorAt(pos, QColor(255, 255, 255, _a(22 * k * m.sheen)))
        band.setColorAt(pos + 0.12, QColor(255, 255, 255, 0))
        p.fillPath(path, band)
    if m.glow > 0 and not nested:
        corner = QRadialGradient(QPointF(rect.left() + radius * 0.8, rect.top() + radius * 0.8),
                                 max(rect.width(), rect.height()) * 0.55)
        corner.setColorAt(0, _with_alpha(acc, 30 * m.glow))
        corner.setColorAt(1, _with_alpha(acc, 0))
        p.fillPath(path, corner)

    # 6) توهج داخلي ناعم على الأطراف (يعطي سماكة للزجاج)
    if m.rim > 0:
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(_with_alpha(acc, 22 * k * m.rim), 6.0))
        p.drawPath(path)

    # 7) حالات التفاعل
    if st.hover > 0.001:
        p.fillPath(path, QColor(255, 255, 255, _a(20 * st.hover * m.hover)))
        p.fillPath(path, _with_alpha(acc, 14 * st.hover * m.hover))
    if st.pressed:
        p.fillPath(path, QColor(0, 0, 0, 48))
    if st.focus:
        p.fillPath(path, _with_alpha(acc, 16))
    if not st.enabled:
        p.fillPath(path, QColor(0, 0, 0, 70))
    p.restore()

    if border and m.border > 0:
        bk = k * m.border * (1.0 if st.enabled else 0.5)
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(Qt.BrushStyle.NoBrush)
        # 8) تشتّت لوني طفيف (مظهر انكسار الضوء في حافة الزجاج)
        if CHROMATIC_EDGE and not nested and radius >= 6 and rect.width() > 24:
            for dx, dy, col in ((-0.45, -0.45, QColor(80, 220, 255, _a(26 * bk))),
                                (0.45, 0.45, QColor(255, 90, 200, _a(20 * bk)))):
                p.save()
                p.translate(dx, dy)
                p.setPen(QPen(col, 1.0))
                p.drawPath(path)
                p.restore()
        # 9) الحافة الداخلية: بيضاء في الزاوية العلوية، وبلون الضوء المار في بقية الحافة
        edge = QLinearGradient(rect.topLeft(), rect.bottomRight())
        edge.setColorAt(0, QColor(225, 250, 255, _a(FROST_BORDER_ALPHA * bk)))
        edge.setColorAt(0.45, _with_alpha(acc, 34 * bk + 22 * st.hover))
        edge.setColorAt(1, _with_alpha(acc, 70 * bk + 34 * st.hover))
        p.setPen(QPen(QBrush(edge), 1.0))
        p.drawPath(path)
        glow = QPainterPath()
        glow.addRoundedRect(rect.adjusted(1.5, 1.5, -1.5, -1.5), max(0, radius - 1), max(0, radius - 1))
        p.setPen(QPen(QColor(255, 255, 255, _a(11 * bk)), 1.0))
        p.drawPath(glow)

        # 10) الانعكاس الضوئي الحاد في الحافة العلوية
        if rect.width() > radius * 2.4 and m.specular > 0:
            x0, x1 = rect.left() + radius * 0.55, rect.right() - radius * 0.55
            line = QLinearGradient(x0, 0, x1, 0)
            a = FROST_SPECULAR_ALPHA * k * m.specular * (1.0 + 0.25 * st.hover)
            line.setColorAt(0, QColor(255, 255, 255, 0))
            line.setColorAt(0.18, QColor(255, 255, 255, _a(a * 0.55)))
            line.setColorAt(0.5, QColor(255, 255, 255, _a(a)))
            line.setColorAt(0.82, QColor(255, 255, 255, _a(a * 0.45)))
            line.setColorAt(1, QColor(255, 255, 255, 0))
            p.setPen(QPen(QBrush(line), 1.2))
            p.drawLine(QLineF(x0, rect.top() + 1.1, x1, rect.top() + 1.1))
            # انعكاس خافت معاكس في الحافة السفلية
            if not nested:
                low = QLinearGradient(x0, 0, x1, 0)
                low.setColorAt(0, _with_alpha(acc, 0))
                low.setColorAt(0.7, _with_alpha(acc, a * 0.22))
                low.setColorAt(1, _with_alpha(acc, 0))
                p.setPen(QPen(QBrush(low), 1.0))
                p.drawLine(QLineF(x0, rect.bottom() - 1.1, x1, rect.bottom() - 1.1))

        # 11) حلقة التركيز للحقول
        if st.focus:
            p.setPen(QPen(_with_alpha(acc, 210), 1.5))
            p.drawPath(path)
            ring = QPainterPath()
            ring.addRoundedRect(rect.adjusted(2.5, 2.5, -2.5, -2.5), max(0, radius - 2), max(0, radius - 2))
            p.setPen(QPen(_with_alpha(acc, 55), 2.0))
            p.drawPath(ring)
        p.restore()
    return path


_CACHE: "weakref.WeakKeyDictionary[QWidget, dict]" = weakref.WeakKeyDictionary()
_STATS = {"hit": 0, "miss": 0}


def _canvas_origin(widget: QWidget, rect: QRectF) -> QPoint | None:
    """موضع اللوح داخل القماشة الخلفية (أو None إن لم تتوفر الخلفية لهذا الودجت)."""
    backdrop: LiveBackdrop | None = _STATE["backdrop"]
    canvas: QWidget | None = _STATE["canvas"]
    try:
        if (backdrop is None or canvas is None or backdrop.blurred.isNull() or canvas.width() <= 0
                or canvas.window() is not widget.window() or not canvas.parentWidget().isAncestorOf(widget)):
            return None
        return widget.mapTo(canvas.parentWidget(), QPoint(int(rect.x()), int(rect.y())))
    except RuntimeError:
        # القماشة أو الخلفية حُذفت (نافذة أُغلقت/اختبار انتهى): انسَ المرجع القديم بدل الانهيار
        _STATE["canvas"] = None
        _STATE["backdrop"] = None
        return None
    except Exception:
        return None


def _bake(widget: QWidget, w_i: int, h_i: int, radius: float, nested: bool, border: bool,
          tint_alpha: float | None, material: str, st: GlassState, origin: QPoint | None) -> QImage:
    """ارسم اللوح مرة واحدة في صورة شفافة جاهزة للنسخ السريع."""
    try:
        dpr = float(widget.devicePixelRatioF())
    except Exception:
        dpr = 1.0
    img = QImage(max(1, int(math.ceil(w_i * dpr))), max(1, int(math.ceil(h_i * dpr))),
                 QImage.Format.Format_ARGB32_Premultiplied)
    img.setDevicePixelRatio(dpr)
    img.fill(Qt.GlobalColor.transparent)
    bp = QPainter(img)
    _paint_frosted_impl(bp, widget, QRectF(0.0, 0.0, float(w_i), float(h_i)), radius, nested, border,
                        tint_alpha, material, st, origin)
    bp.end()
    return img


def paint_frosted(p: QPainter, widget: QWidget, rect: QRectF, radius: float = 18, *, nested: bool = False,
                  border: bool = True, tint_alpha: float | None = None, material: str = "panel",
                  state: GlassState | None = None) -> QPainterPath:
    """ارسم لوحًا زجاجيًا داكنًا مضبّبًا داخل ``rect`` من ``widget``. يرجع مسار اللوح.

    material: اسم من ``MATERIALS`` (panel/card/hero/bubble/pill/control/input/view/tab/tab_active/bar).
    state:    حالة التفاعل (hover/pressed/focus/enabled) لإعطاء إحساس حيّ للأزرار والحقول.

    مع ``GLASS_CACHE`` يُرسم اللوح مرة واحدة ثم يُنسخ كصورة، ولا يُعاد رسمه إلا عند تغيّر الخلفية
    المموّهة (``backdrop.version``) أو الحجم أو الموضع أو حالة التفاعل. وهذا أكبر توفير في المعالج.
    """
    st = state or GlassState()
    origin = _canvas_origin(widget, rect)
    backdrop: LiveBackdrop | None = _STATE["backdrop"]
    w_i, h_i = int(math.ceil(rect.width())), int(math.ceil(rect.height()))
    if GLASS_CACHE and origin is not None and backdrop is not None and w_i >= 2 and h_i >= 2:
        cache = _CACHE.get(widget)
        if cache is None:
            cache = {}
            _CACHE[widget] = cache
        key = (int(rect.x()), int(rect.y()), w_i, h_i, radius, material, nested, border,
               None if tint_alpha is None else round(tint_alpha, 3))
        stamp = (backdrop.version, int(st.hover * 8), st.pressed, st.focus, st.enabled, origin.x(), origin.y())
        ent = cache.get(key)
        if ent is None or ent[0] != stamp:
            if ent is None and len(cache) > 24:
                cache.clear()
            img = _bake(widget, w_i, h_i, radius, nested, border, tint_alpha, material, st, origin)
            cache[key] = (stamp, img)
            _STATS["miss"] += 1
        else:
            img = ent[1]
            _STATS["hit"] += 1
        p.drawImage(QPointF(rect.x(), rect.y()), img)
        path = QPainterPath()
        path.addRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5), radius, radius)
        return path
    return _paint_frosted_impl(p, widget, rect, radius, nested, border, tint_alpha, material, st, origin)


def paint_frosted_bar(p: QPainter, widget: QWidget, rect: QRectF, line_edge: str) -> None:
    """شريط مسطح (الشريط الجانبي/العلوي): زجاج بلا زوايا مع خط فاصل مضيء يتلاشى عند الأطراف."""
    paint_frosted(p, widget, rect, 0.01, border=False, tint_alpha=FROST_TINT_ALPHA * 0.85, material="bar")
    p.save()
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    if line_edge == "left":
        grad = QLinearGradient(rect.left(), rect.top(), rect.left(), rect.bottom())
    else:
        grad = QLinearGradient(rect.left(), rect.top(), rect.right(), rect.top())
    grad.setColorAt(0.0, QColor(255, 255, 255, 8))
    grad.setColorAt(0.25, QColor(255, 255, 255, 58))
    grad.setColorAt(0.5, QColor(255, 255, 255, 36))
    grad.setColorAt(0.75, QColor(255, 255, 255, 58))
    grad.setColorAt(1.0, QColor(255, 255, 255, 8))
    p.setPen(QPen(QBrush(grad), 1.0))
    if line_edge == "left":
        p.drawLine(QLineF(rect.left() + 0.5, rect.top(), rect.left() + 0.5, rect.bottom()))
    elif line_edge == "bottom":
        p.drawLine(QLineF(rect.left(), rect.bottom() - 0.5, rect.right(), rect.bottom() - 0.5))
    p.restore()


# ═══════════════════════════════ لوحة الأداء ═══════════════════════════════
class _DebugHud(QLabel):
    """شارة صغيرة تعرض الأداء (Ctrl+Shift+G): إطارات/ثانية، زمن البناء، مستوى الجودة، عدد الألواح."""

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setStyleSheet("background: rgba(0,0,0,170); color: #7dd3fc; padding: 4px 10px;"
                           "border-radius: 8px; font: 11px 'monospace';")
        self.move(10, 10)
        self.hide()


# ═══════════════════════════════ المطبّق التلقائي ═══════════════════════════════
class FrostedGlassController(QObject):
    """يمرّ على كل ودجات التطبيق ويحوّل الأسطح المحددة إلى زجاج مضبّب داكن."""

    RADII = {
        "card": 20, "pageHero": 20, "emptyGlassCard": 20, "missionBanner": 18, "chatComposer": 16,
        "chatUser": 16, "chatAssistant": 16, "chatSystem": 12, "floatingStatusBar": 14, "clockGlassPill": 30,
    }
    MATERIAL_BY_NAME = {
        "card": "card", "emptyGlassCard": "card", "pageHero": "hero", "missionBanner": "hero",
        "chatComposer": "input", "chatUser": "bubble", "chatAssistant": "bubble", "chatSystem": "bubble",
        "floatingStatusBar": "pill", "clockGlassPill": "pill",
    }
    BARS = {"sidebar": "left", "headerBar": "bottom"}
    CONTROLS = (QPushButton, QToolButton, QLineEdit, QComboBox)
    VIEWS = (QAbstractItemView, QPlainTextEdit, QTextEdit)
    INTERACTIVE_EVENTS = (QEvent.Type.Enter, QEvent.Type.Leave, QEvent.Type.FocusIn, QEvent.Type.FocusOut,
                          QEvent.Type.MouseButtonPress, QEvent.Type.MouseButtonRelease, QEvent.Type.EnabledChange)

    def __init__(self, root: QWidget, backdrop: LiveBackdrop):
        super().__init__(root)
        self.root = root
        self.backdrop = backdrop
        self.hud: _DebugHud | None = None
        self.paints = 0
        self._count = 0
        self._seen = -1
        self._flip = 0
        self._last_scan = 0.0
        _STATE["controller"] = self
        self.scan()
        backdrop.updated.connect(self._on_frame)
        try:
            self._shortcut = QShortcut(QKeySequence(DEBUG_HUD_SHORTCUT), root)
            self._shortcut.activated.connect(self.toggle_hud)
        except Exception:
            self._shortcut = None
        backdrop.start()

    # ---- المسح ----
    def scan(self) -> None:
        top = self.root.window()
        for w in self.root.findChildren(QWidget):
            if w.property("_frosted") is not None or w.window() is not top:
                continue
            name = w.objectName()
            if isinstance(w, (QGroupBox, QTabWidget, QTabBar)) or name in self.RADII or name in self.BARS:
                w.setProperty("_frosted", True)
                w.installEventFilter(self)
                LIVE_WIDGETS.add(w)
            elif isinstance(w, self.CONTROLS):
                if isinstance(w.parentWidget(), (QComboBox, QAbstractItemView)) or name == "messageBody":
                    continue
                w.setProperty("_frosted", True)
                w.installEventFilter(self)
                SLOW_WIDGETS.add(w)
            elif isinstance(w, self.VIEWS) and name != "messageBody":
                vp = w.viewport()
                w.setProperty("_frosted", True)
                vp.setProperty("_frosted", True)
                vp.installEventFilter(self)
                w.installEventFilter(self)       # لالتقاط التركيز على العنصر نفسه
                SLOW_WIDGETS.add(vp)

    # ---- دورة الإطار ----
    @safe_slot
    def _on_frame(self) -> None:
        win = self.root.window()
        bd = self.backdrop
        bd.paused = not self.root.isVisible() or win.isMinimized()
        bd.set_active(win.isActiveWindow())
        self._count += 1
        now = time.monotonic()
        if now - self._last_scan > 2.0:          # مسح الودجات الجديدة كل ثانيتين (لا كل إطار)
            self._last_scan = now
            self.scan()
        if bd.version != self._seen:             # الخلفية المموّهة تغيّرت: أعد رسم الألواح (خبز جديد)
            self._seen = bd.version
            self._flip += 1
            for w in list(LIVE_WIDGETS):
                try:
                    if w.isVisible():
                        w.update()
                except RuntimeError:
                    LIVE_WIDGETS.discard(w)
            if self._flip % 2 == 0:
                for w in list(SLOW_WIDGETS):
                    try:
                        if w.isVisible():
                            w.update()
                    except RuntimeError:
                        SLOW_WIDGETS.discard(w)
        if self.hud is not None and self.hud.isVisible() and self._count % 8 == 0:
            tot = _STATS["hit"] + _STATS["miss"]
            ratio = 100.0 * _STATS["hit"] / tot if tot else 0.0
            self.hud.setText(f"{bd.fps:4.0f} fps | بناء {bd.frame_ms:4.1f} ms | تأخر x{bd.lag:3.2f} | جودة {bd.quality}"
                             f" | كاش {ratio:3.0f}% | حزم {len(bd.packets)} | {_ACTIVE['profile']}")
            self.hud.adjustSize()
            self.hud.raise_()

    def toggle_hud(self) -> None:
        if self.hud is None:
            self.hud = _DebugHud(self.root)
        self.hud.setVisible(not self.hud.isVisible())
        if self.hud.isVisible():
            self.hud.raise_()

    # ---- حالات التفاعل ----
    def _kick_hover(self, obj: QWidget) -> None:
        self._step_hover(weakref.ref(obj), 0)

    def _step_hover(self, ref, n: int) -> None:
        obj = ref()
        if obj is None:
            return
        try:
            target = 1.0 if (obj.underMouse() and obj.isEnabled()) else 0.0
            cur = _HOVER.get(obj, 0.0)
            cur += (target - cur) * 0.38
            if abs(target - cur) < 0.02:
                cur = target
            _HOVER[obj] = cur
            obj.update()
            if cur != target and n < 40:
                QTimer.singleShot(16, lambda: self._step_hover(ref, n + 1))
        except RuntimeError:
            return

    def _state_for(self, obj: QWidget, is_viewport: bool) -> GlassState:
        host = obj.parentWidget() if is_viewport else obj
        pressed = isinstance(obj, QAbstractButton) and obj.isDown()
        focusable = is_viewport or isinstance(obj, (QLineEdit, QComboBox))
        return GlassState(hover=0.0 if is_viewport else _HOVER.get(obj, 0.0), pressed=pressed,
                          focus=bool(focusable and host is not None and host.hasFocus()), enabled=obj.isEnabled())

    @staticmethod
    def _depth(w: QWidget) -> int:
        d, par = 0, w.parentWidget()
        while par is not None:
            if par.property("_frosted") and not isinstance(par, (QTabWidget, QTabBar)):
                d += 1
            par = par.parentWidget()
        return d

    # ---- الأحداث والرسم ----
    def eventFilter(self, obj, ev) -> bool:
        et = ev.type()
        if et != QEvent.Type.Paint:
            if et in self.INTERACTIVE_EVENTS and isinstance(obj, QWidget):
                try:
                    if et in (QEvent.Type.Enter, QEvent.Type.Leave) and isinstance(obj, self.CONTROLS):
                        self._kick_hover(obj)
                    else:
                        (obj.viewport() if isinstance(obj, self.VIEWS) else obj).update()
                except RuntimeError:
                    pass
            return False
        if not isinstance(obj, QWidget) or isinstance(obj, self.VIEWS):
            return False       # الألواح الزجاجية للعروض تُرسم على الـ viewport فقط
        try:
            self.paints += 1
            p = QPainter(obj)
            rect = QRectF(obj.rect())
            name = obj.objectName()
            parent = obj.parentWidget()
            is_vp = parent is not None and isinstance(parent, self.VIEWS) and parent.viewport() is obj
            if name in self.BARS:
                paint_frosted_bar(p, obj, rect, self.BARS[name])
            elif isinstance(obj, QTabBar):
                hover_idx = obj.tabAt(obj.mapFromGlobal(QCursor.pos())) if obj.underMouse() else -1
                for i in range(obj.count()):
                    tr = QRectF(obj.tabRect(i)).adjusted(3, 0, -3, -1)
                    active = i == obj.currentIndex()
                    paint_frosted(p, obj, tr, 10, nested=not active, tint_alpha=FROST_TINT_ALPHA * 0.8,
                                  material="tab_active" if active else "tab",
                                  state=GlassState(hover=1.0 if i == hover_idx else 0.0, enabled=obj.isTabEnabled(i)))
            elif isinstance(obj, QTabWidget):
                top = obj.tabBar().geometry().bottom() + 5
                paint_frosted(p, obj, QRectF(0, top, obj.width(), max(10, obj.height() - top)), 14,
                              nested=self._depth(obj) > 0, material="panel")
            elif is_vp:
                paint_frosted(p, obj, rect, 12, nested=True, tint_alpha=FROST_TINT_ALPHA * 0.9, material="view",
                              state=self._state_for(obj, True))
            elif isinstance(obj, self.CONTROLS):
                mat = "input" if isinstance(obj, (QLineEdit, QComboBox)) else "control"
                paint_frosted(p, obj, rect, 12, nested=True, tint_alpha=FROST_TINT_ALPHA * 0.9, material=mat,
                              state=self._state_for(obj, False))
            else:
                radius = 16 if isinstance(obj, QGroupBox) else self.RADII.get(name, 16)
                paint_frosted(p, obj, rect, radius, nested=self._depth(obj) > 0,
                              material=self.MATERIAL_BY_NAME.get(name, "panel"))
            p.end()
        except Exception:
            pass
        return False


# ═══════════════════════════════ واجهة الاستخدام السريعة ═══════════════════════════════
def install_glass(root: QWidget, preset: str | None = None) -> FrostedGlassController:
    """ركّب الخلفية + الزجاج على نافذتك بسطر واحد: ``glass = install_glass(self, "aqua_night")``."""
    if preset:
        apply_preset(preset)
    backdrop = LiveBackdrop(root)
    canvas = BackdropCanvas(root, backdrop)
    controller = FrostedGlassController(root, backdrop)
    controller.canvas = canvas
    return controller


def set_animated(enabled: bool) -> None:
    """شغّل/أوقف حركة الخلفية في أي وقت (الإيقاف يوفر الطاقة تمامًا)."""
    global ANIMATED
    ANIMATED = bool(enabled)
    bd = _STATE["backdrop"]
    if bd is None:
        return
    if ANIMATED:
        bd.start()
    else:
        bd.stop()


__all__ = [
    "LIVE_WIDGETS", "SLOW_WIDGETS", "PRESETS", "MATERIALS", "GlassMaterial", "GlassState", "LiveBackdrop",
    "BackdropCanvas", "FrostedGlassController", "register_live", "paint_frosted", "paint_frosted_bar",
    "apply_preset", "apply_profile", "invalidate_theme", "install_glass", "set_animated",
]

_reapply()   # طبّق السمة + ملف الأداء المختار (PERF_PROFILE) عند الاستيراد
