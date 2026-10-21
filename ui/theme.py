"""نظام تصميم زجاجي وعصري فائق الأناقة لسطح مكتب Qt6 — نمط كابينة العمليات والأمان السيبراني (2026)."""
from __future__ import annotations

# ── ألوان Obsidian + Afyam Teal الأساسية لمنظومة العمليات ──
BG_BASE = "#061017"
BG_SURFACE = "#0a1822"
BG_ELEVATED = "#102631"
BG_HOVER = "#15333d"
BG_INPUT = "#07131b"

# ── الحدود والتوهج السيبراني ──
BORDER = "#1a3b45"
BORDER_LIGHT = "#16303a"
BORDER_FOCUS = "#5eead4"
BORDER_GLOW = "#522dd4bf"

# ── ألوان النصوص والتباين ──
TEXT_PRIMARY = "#f2fbfa"
TEXT_SECONDARY = "#9cb5bb"
TEXT_MUTED = "#6d8a91"

# ── ألوان التمييز والتفاعل ──
ACCENT = "#2dd4bf"               # Afyam Teal — لون العلامة المميز
ACCENT_HOVER = "#5eead4"
ACCENT_PRESSED = "#0f766e"
ACCENT_SOFT = "#242dd4bf"

ACCENT_SECONDARY = "#a78bfa"     # بنفسجي محدود للتحليل والمساعد
ACCENT_SECONDARY_SOFT = "#24a78bfa"
ACCENT_VIOLET = "#c4b5fd"        # بنفسجي للذكاء الاصطناعي

# ── درجات الخطورة والتنبيهات الأمنية ──
SEV_CRITICAL = "#f43f5e"         # أحمر ياقوتي للحرج
SEV_HIGH = "#fb923c"             # برتقالي للإنذار العالي
SEV_MEDIUM = "#f59e0b"           # كهرماني للمتوسط
SEV_LOW = "#60a5fa"              # أزرق للمنخفض
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
ACCENT_HUES = [(ACCENT, ACCENT_SECONDARY), ("#5eead4", "#60a5fa"), ("#34d399", "#a78bfa")]


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

QMainWindow#cockpitWindow {{
    background: {BG_BASE};
}}

QWidget#appRoot, QWidget#mainArea {{
    background: transparent;
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
    background: #08171e;
    border-right: 1px solid #19353d;
}}

QPushButton#navButton {{
    background: transparent;
    color: {TEXT_SECONDARY};
    border: 1px solid transparent;
    border-radius: 12px;
    padding: 10px 12px;
    text-align: left;
    min-height: 24px;
    font-weight: 500;
}}

QPushButton#navButton:hover {{
    color: {TEXT_PRIMARY};
    background: #102a32;
    border-color: #27505a;
}}

QPushButton#navButton:checked {{
    color: #ffffff;
    background: #123139;
    border: 1px solid #2c7776;
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
    background: #0a1b22;
    border-bottom: 1px solid #193b43;
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
    background: #0d232b;
    border: 1px solid #24515a;
    border-right: 3px solid {ACCENT};
    border-radius: 18px;
}}

QFrame#missionBanner:hover {{
    border-color: #35767a;
    border-right-color: {ACCENT_HOVER};
}}

QLabel#missionTitle {{
    font-size: 21px;
    font-weight: 800;
    color: {TEXT_PRIMARY};
}}

/* ── بطاقات العمليات والحاويات ── */
QFrame#card {{
    background: #0d2028;
    border: 1px solid #1b3b44;
    border-radius: 12px;
}}

QFrame#card:hover {{
    border-color: #2c7776;
    background: #102a31;
}}

QGroupBox {{
    background: #0b1c24;
    border: 1px solid #1b3b44;
    border-radius: 12px;
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
    background: #112a32;
    color: {TEXT_PRIMARY};
    border: 1px solid {alpha(ACCENT, 70)};
    border-radius: 11px;
    padding: 8px 16px;
    min-height: 24px;
    font-weight: 600;
}}

QPushButton:hover {{
    background: #173943;
    border-color: {ACCENT};
    color: #ffffff;
}}

QPushButton:pressed {{
    background: #184a4d;
    border-color: {SEV_SAFE};
}}

QPushButton[pressingFx="true"] {{
    background: #1a4b4e;
    border-color: {ACCENT_HOVER};
    color: #ffffff;
}}

QPushButton:focus {{
    border: 2px solid {ACCENT};
}}

QPushButton#primary {{
    background: #0f766e;
    color: #ffffff;
    border: 1px solid {alpha('#ffffff', 90)};
    font-weight: 700;
    border-radius: 12px;
}}

QPushButton#primary:hover {{
    background: #149b8e;
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
    selection-background-color: #0f766e;
    selection-color: #ffffff;
}}

QLineEdit:hover, QComboBox:hover, QPlainTextEdit:hover, QTextEdit:hover {{
    border-color: {alpha(ACCENT, 130)};
}}

QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{
    border-color: {ACCENT};
    background: #0e252b;
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
}}

QComboBox QAbstractItemView {{
    background: {BG_SURFACE};
    border: 1px solid {ACCENT};
    selection-background-color: #15434a;
    border-radius: 8px;
    color: {TEXT_PRIMARY};
}}

/* ── الجداول التكتيكية ── */
QTableWidget {{
    background: #0a1b22;
    color: {TEXT_PRIMARY};
    alternate-background-color: {alpha(BG_ELEVATED, 100)};
    gridline-color: transparent;
    border: 1px solid {alpha(BORDER, 140)};
    border-radius: 14px;
    selection-background-color: {alpha(ACCENT, 70)};
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
    background: #102a31;
    color: {TEXT_SECONDARY};
    padding: 10px 8px;
    border: none;
    border-bottom: 1px solid {alpha(ACCENT_SECONDARY, 140)};
    font-weight: 700;
    font-size: 11px;
}}

QTableCornerButton::section {{
    background: #102730;
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

QLabel#modeBadge {{
    color: #9cb5bb;
    background: #102a31;
    border: 1px solid #27505a;
    border-radius: 8px;
    padding: 5px 8px;
    font-size: 9px;
    font-weight: 800;
}}

QFrame#telemetryChart, QFrame#securityGauge {{
    background: #0b1c24;
    border: 1px solid #1b3b44;
    border-radius: 12px;
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
    background: #08171f;
    border-top: 1px solid {alpha(ACCENT, 45)};
    padding: 3px 12px;
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
    background: #0d2028;
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

QFrame#transitionVeil {{
    background: #061017;
    border: none;
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
