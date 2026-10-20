"""نظام تصميم زجاجي وعصري فائق الأناقة لسطح مكتب Qt6 — نمط كابينة العمليات والأمان السيبراني (2026)."""
from __future__ import annotations

# ── الألوان الأساسية لمنظومة العمليات ──
BG_BASE = "#060a12"
BG_SURFACE = "#0b1422"
BG_ELEVATED = "#101d32"
BG_HOVER = "#182a45"
BG_INPUT = "#08111c"

# ── الحدود والتوهج السيبراني ──
BORDER = "#1e374f"
BORDER_LIGHT = "#152838"
BORDER_FOCUS = "#38bdf8"
BORDER_GLOW = "#5538bdf8"

# ── ألوان النصوص والتباين ──
TEXT_PRIMARY = "#f8fafc"
TEXT_SECONDARY = "#94a3b8"
TEXT_MUTED = "#64748b"

# ── ألوان التمييز والتفاعل ──
ACCENT = "#38bdf8"               # أزرق سيان ساطع
ACCENT_HOVER = "#7dd3fc"
ACCENT_PRESSED = "#0284c7"
ACCENT_SOFT = "#2438bdf8"

ACCENT_SECONDARY = "#34d399"     # أخضر زمردي للحماية
ACCENT_SECONDARY_SOFT = "#2434d399"
ACCENT_VIOLET = "#818cf8"        # بنفسجي للذكاء الاصطناعي

# ── درجات الخطورة والتنبيهات الأمنية ──
SEV_CRITICAL = "#f43f5e"         # أحمر ياقوتي للحرج
SEV_HIGH = "#fb923c"             # برتقالي للإنذار العالي
SEV_MEDIUM = "#f59e0b"           # كهرماني للمتوسط
SEV_LOW = "#38bdf8"              # سيان للمنخفض
SEV_INFO = "#8fb3d1"             # أزرق للمعلومات
SEV_SAFE = "#34d399"             # زمردي للآمن والسليم

STATUS_OK = SEV_SAFE
STATUS_WARN = SEV_HIGH
STATUS_ERROR = SEV_CRITICAL
STATUS_IDLE = SEV_INFO

CARD_ACCENTS = {
    "connections": ACCENT,
    "processes": "#60a5fa",
    "findings": SEV_HIGH,
    "score": SEV_SAFE,
}

# ── الخطوط والأبعاد القياسية ──
FONT_FAMILY = '"Noto Sans Arabic", "Cairo", "Segoe UI", "DejaVu Sans", sans-serif'
FONT_SIZE_BASE = 13
FONT_SIZE_SMALL = 11
FONT_SIZE_TITLE = 18
FONT_SIZE_HERO = 22
FONT_SIZE_METRIC = 28

SP_XS, SP_SM, SP_MD, SP_LG, SP_XL, SP_2XL = 4, 8, 12, 16, 20, 24
ACCENT_HUES = [(ACCENT, ACCENT_SECONDARY), ("#60a5fa", "#38bdf8"), ("#34d399", "#38bdf8")]


def alpha(color: str, opacity: int) -> str:
    """إضافة قناة الشفافية بلون سداسي عشري."""
    return f"#{opacity:02x}{color.lstrip('#')}"


def get_qss(accent: str = ACCENT, accent2: str = ACCENT_SECONDARY) -> str:
    """توليد ورقة الأنماط مع استبدال ألوان التمييز المختارة."""
    result = QSS.replace(ACCENT_SOFT, alpha(accent, 36))
    result = result.replace(ACCENT_SECONDARY_SOFT, alpha(accent2, 36))
    return result.replace(ACCENT, accent).replace(ACCENT_SECONDARY, accent2)


# ── ورقة الأنماط الشاملة (QSS) بتصميم كابينة زجاجية معاصرة ──
QSS = f"""
QWidget {{
    background: transparent;
    color: {TEXT_PRIMARY};
    font-family: {FONT_FAMILY};
    font-size: {FONT_SIZE_BASE}px;
}}

QMainWindow, QDialog, QMessageBox {{
    background: {BG_BASE};
}}

QLabel {{
    background: transparent;
    border: none;
}}

QScrollArea, QStackedWidget {{
    background: transparent;
    border: none;
}}

QScrollArea > QWidget > QWidget {{
    background: transparent;
}}

/* ── الشريط الجانبي الفخم ── */
QFrame#sidebar {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #0d1726, stop:0.5 #08111d, stop:1 #060b14);
    border-right: 1px solid #233e56;
}}

QPushButton#navButton {{
    background: transparent;
    color: {TEXT_SECONDARY};
    border: 1px solid transparent;
    border-radius: 12px;
    padding: 10px 14px;
    text-align: left;
    min-height: 24px;
    font-weight: 500;
}}

QPushButton#navButton:hover {{
    color: {TEXT_PRIMARY};
    background: {alpha(ACCENT, 24)};
    border-color: {alpha(ACCENT, 70)};
}}

QPushButton#navButton:checked {{
    color: #ffffff;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {alpha(ACCENT, 70)}, stop:0.85 {alpha(ACCENT_SECONDARY, 40)}, stop:1 transparent);
    border: 1px solid {alpha(ACCENT, 180)};
    font-weight: 700;
}}

QLabel#navGroupLabel {{
    color: {TEXT_MUTED};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.8px;
    padding: 14px 10px 6px;
}}

QPushButton#assistantNavButton {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 {alpha(ACCENT_SECONDARY, 35)}, stop:1 {alpha(ACCENT, 25)});
    color: {SEV_SAFE};
    border: 1px solid {alpha(ACCENT_SECONDARY, 140)};
    border-radius: 12px;
    padding: 11px 14px;
    font-weight: 700;
    margin-top: 12px;
}}

QPushButton#assistantNavButton:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 {alpha(ACCENT_SECONDARY, 60)}, stop:1 {alpha(ACCENT, 45)});
    border-color: {SEV_SAFE};
    color: #ffffff;
}}

/* ── الشريط العلوي ── */
QFrame#headerBar {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #0f1c2d, stop:0.5 #0c1724, stop:1 #08111b);
    border-bottom: 1px solid #233e56;
}}

QLabel#eyebrow {{
    color: {ACCENT};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.5px;
}}

QLabel#brandMark {{
    background: {alpha(ACCENT, 40)};
    border: 1.5px solid {alpha(ACCENT, 140)};
    border-radius: 12px;
    padding: 6px;
}}

QLabel#clockTime {{
    font-family: "DejaVu Sans Mono", monospace;
    font-size: 15px;
    font-weight: 800;
    color: {TEXT_PRIMARY};
}}

QLabel#clockDate {{
    color: {TEXT_SECONDARY};
    font-size: 10px;
    font-weight: 500;
}}

/* ── بانر المهمة التكتيكي ── */
QFrame#missionBanner {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #11263d, stop:0.55 #0c1c2e, stop:1 #081522);
    border: 1px solid {alpha(ACCENT, 110)};
    border-radius: 18px;
}}

QLabel#missionTitle {{
    font-size: 21px;
    font-weight: 800;
    color: {TEXT_PRIMARY};
}}

/* ── بطاقات العمليات والحاويات ── */
QFrame#card {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #122135, stop:1 #0b1523);
    border: 1px solid {alpha(ACCENT, 65)};
    border-radius: 16px;
}}

QFrame#card:hover {{
    border-color: {alpha(ACCENT, 160)};
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #15273e, stop:1 #0d1929);
}}

QGroupBox {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #0f1c2d, stop:1 #0a131f);
    border: 1px solid {alpha(BORDER, 140)};
    border-radius: 16px;
    margin-top: 0;
    padding: 38px 16px 16px;
    font-weight: 700;
}}

QGroupBox::title {{
    subcontrol-origin: padding;
    subcontrol-position: top left;
    left: 18px;
    top: 12px;
    color: {TEXT_PRIMARY};
    background: transparent;
    font-size: 13px;
    font-weight: 700;
}}

QGroupBox:hover {{
    border-color: {alpha(ACCENT_SECONDARY, 140)};
}}

/* ── الأزرار الفاخرة ── */
QPushButton {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #162a3f, stop:1 #0f1c2d);
    color: {TEXT_PRIMARY};
    border: 1px solid {alpha(ACCENT, 70)};
    border-radius: 11px;
    padding: 8px 16px;
    min-height: 24px;
    font-weight: 600;
}}

QPushButton:hover {{
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #1d3752, stop:1 #13243a);
    border-color: {ACCENT};
    color: #ffffff;
}}

QPushButton:pressed {{
    background: {alpha(ACCENT_SECONDARY, 80)};
    border-color: {SEV_SAFE};
}}

QPushButton:focus {{
    border: 2px solid {ACCENT};
}}

QPushButton#primary {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #0284c7, stop:0.5 #0369a1, stop:1 #0f766e);
    color: #ffffff;
    border: 1px solid {alpha('#ffffff', 90)};
    font-weight: 700;
    border-radius: 12px;
}}

QPushButton#primary:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #0ea5e9, stop:0.5 #0284c7, stop:1 #10b981);
    border-color: #ffffff;
}}

QPushButton#danger {{
    color: #fecdd3;
    border-color: {alpha(SEV_CRITICAL, 160)};
    background: {alpha(SEV_CRITICAL, 40)};
}}

QPushButton#danger:hover {{
    background: {alpha(SEV_CRITICAL, 80)};
    border-color: {SEV_CRITICAL};
    color: #ffffff;
}}

QPushButton#pillButton {{
    border-radius: 14px;
    padding: 6px 14px;
    color: {TEXT_SECONDARY};
    font-size: 11px;
    min-height: 20px;
    background: {alpha(ACCENT, 25)};
    border: 1px solid {alpha(ACCENT, 60)};
}}

QPushButton#pillButton:hover {{
    background: {alpha(ACCENT, 55)};
    color: {TEXT_PRIMARY};
    border-color: {ACCENT};
}}

QPushButton#quietAction {{
    background: {alpha(ACCENT, 30)};
    border: 1px solid {alpha(ACCENT, 70)};
}}

QPushButton#quietAction:hover {{
    background: {alpha(ACCENT, 60)};
    border-color: {ACCENT};
}}

QPushButton:disabled {{
    color: {TEXT_MUTED};
    background: {alpha(BG_SURFACE, 70)};
    border-color: {alpha(BORDER, 50)};
}}

/* ── حقول الإدخال والكومبوبوكس ── */
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {{
    background: {BG_INPUT};
    color: {TEXT_PRIMARY};
    border: 1px solid {alpha(BORDER, 150)};
    border-radius: 11px;
    padding: 9px 14px;
    selection-background-color: #0284c7;
    selection-color: #ffffff;
}}

QLineEdit:hover, QComboBox:hover, QPlainTextEdit:hover, QTextEdit:hover {{
    border-color: {alpha(ACCENT, 130)};
}}

QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{
    border-color: {ACCENT};
    background: #0d1928;
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
}}

QComboBox QAbstractItemView {{
    background: {BG_SURFACE};
    border: 1px solid {ACCENT};
    selection-background-color: #17324d;
    border-radius: 8px;
    color: {TEXT_PRIMARY};
}}

/* ── الجداول التكتيكية ── */
QTableWidget {{
    background: {alpha(BG_SURFACE, 180)};
    color: {TEXT_PRIMARY};
    alternate-background-color: {alpha(BG_ELEVATED, 100)};
    gridline-color: transparent;
    border: 1px solid {alpha(BORDER, 140)};
    border-radius: 14px;
    selection-background-color: {alpha(ACCENT, 60)};
    outline: none;
}}

QTableWidget::item {{
    padding: 8px 10px;
    border-bottom: 1px solid {alpha(BORDER_LIGHT, 90)};
}}

QTableWidget::item:hover {{
    background: {alpha(ACCENT_SECONDARY, 35)};
    color: {TEXT_PRIMARY};
}}

QTableWidget::item:selected {{
    background: {alpha(ACCENT, 70)};
    color: #ffffff;
}}

QHeaderView::section {{
    background: #101e30;
    color: {TEXT_SECONDARY};
    padding: 10px 8px;
    border: none;
    border-bottom: 1px solid {alpha(ACCENT_SECONDARY, 140)};
    font-weight: 700;
    font-size: 11px;
}}

QTableCornerButton::section {{
    background: #101e30;
    border: none;
}}

/* ── أشرطة التقدم ── */
QProgressBar {{
    background: {alpha(BG_SURFACE, 200)};
    border: 1px solid {alpha(BORDER, 80)};
    border-radius: 5px;
    min-height: 8px;
    max-height: 8px;
}}

QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {ACCENT}, stop:0.7 {ACCENT_HOVER}, stop:1 {SEV_SAFE});
    border-radius: 4px;
}}

/* ── أشرطة التمرير العصرية الرقيقة ── */
QScrollBar:vertical {{
    background: transparent;
    width: 7px;
    margin: 2px;
}}

QScrollBar::handle:vertical {{
    background: {alpha(ACCENT, 90)};
    min-height: 32px;
    border-radius: 3px;
}}

QScrollBar::handle:vertical:hover {{
    background: {ACCENT};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}

QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
    background: transparent;
}}

QScrollBar:horizontal {{
    background: transparent;
    height: 7px;
    margin: 2px;
}}

QScrollBar::handle:horizontal {{
    background: {alpha(ACCENT, 90)};
    min-width: 32px;
    border-radius: 3px;
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}

QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
    background: transparent;
}}

/* ── شارات الحالة والتقييم ── */
QLabel#statusBadge {{
    color: {STATUS_OK};
    padding: 6px 14px;
    background: {alpha(SEV_SAFE, 28)};
    border: 1px solid {alpha(SEV_SAFE, 120)};
    border-radius: 14px;
    font-weight: 700;
}}

QLabel#statusBadge[state="running"] {{
    color: {STATUS_WARN};
    border-color: {alpha(STATUS_WARN, 160)};
    background: {alpha(STATUS_WARN, 35)};
}}

QLabel#statusBadge[state="error"] {{
    color: #fecdd3;
    border-color: {STATUS_ERROR};
    background: {alpha(STATUS_ERROR, 35)};
}}

QLabel#scoreBadge {{
    color: {SEV_SAFE};
    padding: 6px 14px;
    background: {alpha(SEV_SAFE, 28)};
    border: 1px solid {alpha(SEV_SAFE, 120)};
    border-radius: 14px;
    font-weight: 700;
}}

QLabel#sectionTitle {{
    font-size: {FONT_SIZE_TITLE}px;
    font-weight: 800;
    color: {TEXT_PRIMARY};
}}

QLabel#sectionSubtitle {{
    color: {TEXT_SECONDARY};
    font-size: {FONT_SIZE_SMALL}px;
}}

QLabel#metricValue {{
    font-size: {FONT_SIZE_METRIC}px;
    font-weight: 800;
    color: {TEXT_PRIMARY};
}}

QLabel#metricLabel {{
    color: {TEXT_SECONDARY};
    font-size: 12px;
    font-weight: 600;
}}

QLabel#metricNote {{
    color: {TEXT_MUTED};
    font-size: 10px;
}}

QLabel#footer {{
    color: {TEXT_MUTED};
    font-size: 10px;
}}

QFrame#activityLamp {{
    background: {STATUS_OK};
    border-radius: 5px;
}}

QFrame#activityLamp[state="running"] {{
    background: {STATUS_WARN};
}}

QFrame#activityLamp[state="error"] {{
    background: {STATUS_ERROR};
}}

QSplitter::handle {{
    background: {alpha(BORDER, 100)};
}}

QSplitter::handle:hover {{
    background: {ACCENT};
}}

QToolTip {{
    background: {BG_ELEVATED};
    color: {TEXT_PRIMARY};
    border: 1px solid {ACCENT};
    padding: 8px 12px;
    border-radius: 8px;
}}

QTextEdit#messageBody {{
    background: transparent;
    border: none;
    border-radius: 0;
    padding: 0;
    font-size: 14px;
}}

QFrame#chatComposer {{
    background: #0e1a29;
    border: 1px solid {alpha(ACCENT_SECONDARY, 140)};
    border-radius: 16px;
}}

QFrame#chatUser {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #1a3552, stop:1 #10253c);
    border: 1px solid {alpha(ACCENT, 120)};
    border-radius: 16px;
}}

QFrame#chatAssistant {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #14283b, stop:1 #0c1825);
    border: 1px solid {alpha(ACCENT_SECONDARY, 110)};
    border-radius: 16px;
}}

QFrame#chatSystem {{
    background: #251d18;
    border: 1px solid {alpha(SEV_HIGH, 130)};
    border-radius: 12px;
}}
"""


def severity_color(severity: str) -> str:
    """إرجاع اللون المطابق لمستوى الخطورة الأمني."""
    return {
        "critical": SEV_CRITICAL,
        "high": SEV_HIGH,
        "medium": SEV_MEDIUM,
        "low": SEV_LOW,
        "info": SEV_INFO,
        "safe": SEV_SAFE,
    }.get((severity or "").lower(), SEV_INFO)


def severity_bg(severity: str) -> str:
    """إرجاع خلفية شفافة مطابقة لمستوى الخطورة."""
    return alpha(severity_color(severity), 36)
