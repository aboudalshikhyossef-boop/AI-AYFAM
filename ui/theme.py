"""نظام تصميم زجاجي الداكن (Dark Glassmorphism) لسطح مكتب Qt6 — نمط المفهوم الراقي المباشر من Apple Enterprise."""
from __future__ import annotations

# ── ألوان Dark Glassmorphism الأساسية ──
BG_BASE = "#030712"               # Obsidian Deep Space
BG_SURFACE = "rgba(15, 23, 42, 0.65)"   # Slate Dark Glass (65% opacity)
BG_ELEVATED = "rgba(30, 41, 59, 0.70)"  # Elevated Dark Glass (70% opacity)
BG_HOVER = "rgba(51, 65, 85, 0.50)"     # Soft Glass Hover
BG_INPUT = "rgba(15, 23, 42, 0.80)"     # Input Dark Glass

# ── الحدود والتوهج الزجاجي ──
BORDER = "rgba(255, 255, 255, 0.12)"         # Subtitle Glass Border
BORDER_LIGHT = "rgba(255, 255, 255, 0.06)"   # Faint Divider
BORDER_FOCUS = "#2dd4bf"                     # Afyam Teal Focus Accent
BORDER_GLOW = "rgba(45, 212, 191, 0.40)"     # Teal Glow

# ── ألوان النصوص والتباين ──
TEXT_PRIMARY = "#f8fafc"          # Pure White / Slate 50
TEXT_SECONDARY = "#94a3b8"        # Slate 400
TEXT_MUTED = "#64748b"            # Slate 500

# ── ألوان التمييز النيون والذهبي/التكتيكي ──
ACCENT = "#2dd4bf"               # Afyam Teal — لون العلامة المميز
ACCENT_HOVER = "#5eead4"
ACCENT_PRESSED = "#0f766e"
ACCENT_SOFT = "rgba(45, 212, 191, 0.15)"

ACCENT_SECONDARY = "#a78bfa"     # Cyber Violet
ACCENT_SECONDARY_SOFT = "rgba(167, 139, 250, 0.15)"
ACCENT_VIOLET = "#c4b5fd"

# ── درجات الخطورة والتنبيهات الأمنية ──
SEV_CRITICAL = "#f43f5e"         # Ruby Red
SEV_HIGH = "#fb923c"             # Warning Amber/Orange
SEV_MEDIUM = "#f59e0b"           # Gold / Yellow
SEV_LOW = "#60a5fa"              # Azure Blue
SEV_INFO = "#38bdf8"             # Cyan Info
SEV_SAFE = "#34d399"             # Emerald Safe

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

# ── الأيقونات والألوان التكتيكية الموحدة ──
COLOR_ICON_INACTIVE = "#8fb3d1"
COLOR_ICON_ACTIVE = ACCENT
COLOR_PRIMARY_START = "#0d9488"
COLOR_PRIMARY_END = "#0f766e"
COLOR_PRIMARY_HOVER_START = "#14b8a6"
COLOR_PRIMARY_HOVER_END = "#0d9488"

# ── الخطوط والأبعاد القياسية (Apple Enterprise Typography) ──
FONT_FAMILY = '"Tajawal", "Inter", "SF Pro Display", "-apple-system", "BlinkMacSystemFont", "Cairo", "Segoe UI", sans-serif'
FONT_SIZE_BASE = 13
FONT_SIZE_SMALL = 11
FONT_SIZE_TITLE = 18
FONT_SIZE_HERO = 22
FONT_SIZE_METRIC = 28

SP_XS, SP_SM, SP_MD, SP_LG, SP_XL, SP_2XL = 4, 8, 12, 16, 20, 24
ACCENT_HUES = [(ACCENT, ACCENT_SECONDARY), ("#5eead4", "#60a5fa"), ("#34d399", "#a78bfa")]


def alpha(color: str, opacity: int) -> str:
    """إضافة قناة الشفافية بلون سداسي عشري أو تحويل القيم."""
    if color.startswith("#"):
        return f"#{opacity:02x}{color.lstrip('#')}"
    return color


def get_qss(accent: str = ACCENT, accent2: str = ACCENT_SECONDARY) -> str:
    """توليد ورقة الأنماط مع استبدال ألوان التمييز المختارة."""
    result = QSS.replace(ACCENT_SOFT, f"rgba(45, 212, 191, 0.15)")
    result = result.replace(ACCENT_SECONDARY_SOFT, f"rgba(167, 139, 250, 0.15)")
    return result.replace(ACCENT, accent).replace(ACCENT_SECONDARY, accent2)


# ── ورقة الأنماط الشاملة (QSS) بتصميم Glassmorphism الداكن من Apple ──
QSS = f"""
QWidget {{
    background: transparent;
    color: {TEXT_PRIMARY};
    font-family: {FONT_FAMILY};
    font-size: {FONT_SIZE_BASE}px;
    letter-spacing: -0.1px;
}}

QMainWindow, QDialog, QMessageBox {{
    background: {BG_BASE};
}}

QMainWindow#cockpitWindow {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #030712, stop:0.45 #0b1329, stop:1 #030712);
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
    background: rgba(10, 15, 30, 0.72);
    border-right: 1px solid rgba(255, 255, 255, 0.08);
}}

QPushButton#navButton {{
    background: transparent;
    color: {TEXT_SECONDARY};
    border: 1px solid transparent;
    border-radius: 10px;
    padding: 10px 14px;
    text-align: left;
    min-height: 24px;
    font-weight: 500;
}}

QPushButton#navButton:hover {{
    color: {TEXT_PRIMARY};
    background: rgba(255, 255, 255, 0.06);
    border-color: rgba(255, 255, 255, 0.10);
}}

QPushButton#navButton:checked {{
    color: #ffffff;
    background: rgba(45, 212, 191, 0.16);
    border: 1px solid rgba(45, 212, 191, 0.45);
    font-weight: 600;
}}

QLabel#navGroupLabel {{
    color: {TEXT_MUTED};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.8px;
    padding: 16px 12px 6px;
}}

QPushButton#assistantNavButton {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 rgba(167, 139, 250, 0.20), stop:1 rgba(45, 212, 191, 0.15));
    color: {SEV_SAFE};
    border: 1px solid rgba(167, 139, 250, 0.35);
    border-radius: 12px;
    padding: 11px 14px;
    font-weight: 600;
    margin-top: 12px;
}}

QPushButton#assistantNavButton:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 rgba(167, 139, 250, 0.35), stop:1 rgba(45, 212, 191, 0.25));
    border-color: {SEV_SAFE};
    color: #ffffff;
}}

/* ── الشريط العلوي ── */
QFrame#headerBar {{
    background: rgba(15, 23, 42, 0.55);
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}}

QLabel#eyebrow {{
    color: {ACCENT};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.6px;
}}

QLabel#brandMark {{
    background: rgba(45, 212, 191, 0.15);
    border: 1px solid rgba(45, 212, 191, 0.35);
    border-radius: 10px;
    padding: 6px;
}}

QLabel#clockTime {{
    font-family: "SF Mono", "DejaVu Sans Mono", monospace;
    font-size: 15px;
    font-weight: 700;
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
        stop:0 rgba(30, 41, 59, 0.70), stop:1 rgba(15, 23, 42, 0.60));
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-right: 3px solid {ACCENT};
    border-radius: 16px;
}}

QFrame#missionBanner:hover {{
    border-color: rgba(45, 212, 191, 0.40);
    border-right-color: {ACCENT_HOVER};
}}

QLabel#missionTitle {{
    font-size: 20px;
    font-weight: 700;
    color: {TEXT_PRIMARY};
}}

/* ── بطاقات العمليات والحاويات ── */
QFrame#card {{
    background: rgba(30, 41, 59, 0.55);
    border: 1px solid rgba(255, 255, 255, 0.10);
    border-radius: 16px;
}}

QFrame#card:hover {{
    border-color: rgba(45, 212, 191, 0.35);
    background: rgba(30, 41, 59, 0.70);
}}

QGroupBox {{
    background: rgba(15, 23, 42, 0.60);
    border: 1px solid rgba(255, 255, 255, 0.10);
    border-radius: 14px;
    margin-top: 0;
    padding: 38px 16px 16px;
    font-weight: 600;
}}

QGroupBox::title {{
    subcontrol-origin: padding;
    subcontrol-position: top left;
    left: 18px;
    top: 12px;
    color: {TEXT_PRIMARY};
    background: transparent;
    font-size: 13px;
    font-weight: 600;
}}

QGroupBox:hover {{
    border-color: rgba(167, 139, 250, 0.35);
}}

/* ── الأزرار الفاخرة Apple-Style ── */
QPushButton {{
    background: rgba(255, 255, 255, 0.07);
    color: {TEXT_PRIMARY};
    border: 1px solid rgba(255, 255, 255, 0.14);
    border-radius: 10px;
    padding: 8px 16px;
    min-height: 24px;
    font-weight: 500;
}}

QPushButton:hover {{
    background: rgba(255, 255, 255, 0.14);
    border-color: rgba(255, 255, 255, 0.25);
    color: #ffffff;
}}

QPushButton:pressed {{
    background: rgba(45, 212, 191, 0.30);
    border-color: {SEV_SAFE};
}}

QPushButton[pressingFx="true"] {{
    background: rgba(45, 212, 191, 0.25);
    border-color: {ACCENT_HOVER};
    color: #ffffff;
}}

QPushButton:focus {{
    border: 1px solid {ACCENT};
}}

QPushButton#primary {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #0d9488, stop:1 #0f766e);
    color: #ffffff;
    border: 1px solid rgba(255, 255, 255, 0.20);
    font-weight: 600;
    border-radius: 10px;
}}

QPushButton#primary:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #14b8a6, stop:1 #0d9488);
    border-color: rgba(255, 255, 255, 0.40);
}}

QPushButton#danger {{
    color: #fecdd3;
    border-color: rgba(244, 63, 94, 0.35);
    background: rgba(244, 63, 94, 0.20);
}}

QPushButton#danger:hover {{
    background: rgba(244, 63, 94, 0.35);
    border-color: {SEV_CRITICAL};
    color: #ffffff;
}}

QPushButton#pillButton {{
    border-radius: 12px;
    padding: 5px 12px;
    color: {TEXT_SECONDARY};
    font-size: 11px;
    min-height: 20px;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.10);
}}

QPushButton#pillButton:hover {{
    background: rgba(45, 212, 191, 0.18);
    color: {TEXT_PRIMARY};
    border-color: rgba(45, 212, 191, 0.40);
}}

QPushButton#quietAction {{
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.10);
}}

QPushButton#quietAction:hover {{
    background: rgba(255, 255, 255, 0.12);
    border-color: rgba(255, 255, 255, 0.22);
}}

QPushButton:disabled {{
    color: {TEXT_MUTED};
    background: rgba(15, 23, 42, 0.40);
    border-color: rgba(255, 255, 255, 0.05);
}}

/* ── حقول الإدخال والكومبوبوكس ── */
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {{
    background: rgba(15, 23, 42, 0.70);
    color: {TEXT_PRIMARY};
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 10px;
    padding: 9px 14px;
    selection-background-color: #0f766e;
    selection-color: #ffffff;
}}

QLineEdit:hover, QComboBox:hover, QPlainTextEdit:hover, QTextEdit:hover {{
    border-color: rgba(45, 212, 191, 0.35);
}}

QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{
    border-color: {ACCENT};
    background: rgba(15, 23, 42, 0.90);
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
}}

QComboBox QAbstractItemView {{
    background: rgba(15, 23, 42, 0.95);
    border: 1px solid rgba(45, 212, 191, 0.40);
    selection-background-color: rgba(45, 212, 191, 0.25);
    border-radius: 8px;
    color: {TEXT_PRIMARY};
}}

/* ── الجداول التكتيكية الزجاجية ── */
QTableWidget {{
    background: rgba(15, 23, 42, 0.55);
    color: {TEXT_PRIMARY};
    alternate-background-color: rgba(30, 41, 59, 0.30);
    gridline-color: transparent;
    border: 1px solid rgba(255, 255, 255, 0.10);
    border-radius: 14px;
    selection-background-color: rgba(45, 212, 191, 0.25);
    outline: none;
}}

QTableWidget::item {{
    padding: 8px 10px;
    border-bottom: none;
}}

QTableWidget::item:hover {{
    background: rgba(167, 139, 250, 0.15);
    color: {TEXT_PRIMARY};
}}

QTableWidget::item:selected {{
    background: rgba(45, 212, 191, 0.30);
    color: #ffffff;
}}

QHeaderView::section {{
    background: rgba(30, 41, 59, 0.70);
    color: {TEXT_SECONDARY};
    padding: 10px 8px;
    border: none;
    border-bottom: 1px solid rgba(255, 255, 255, 0.10);
    font-weight: 600;
    font-size: 11px;
}}

QTableCornerButton::section {{
    background: rgba(30, 41, 59, 0.70);
    border: none;
}}

/* ── أشرطة التقدم ── */
QProgressBar {{
    background: rgba(15, 23, 42, 0.60);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 4px;
    min-height: 6px;
    max-height: 6px;
}}

QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {ACCENT}, stop:0.7 {ACCENT_HOVER}, stop:1 {SEV_SAFE});
    border-radius: 3px;
}}

/* ── أشرطة التمرير ── */
QScrollBar:vertical {{
    background: transparent;
    width: 6px;
    margin: 2px;
}}

QScrollBar::handle:vertical {{
    background: rgba(255, 255, 255, 0.20);
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
    height: 6px;
    margin: 2px;
}}

QScrollBar::handle:horizontal {{
    background: rgba(255, 255, 255, 0.20);
    min-width: 32px;
    border-radius: 3px;
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}

QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
    background: transparent;
}}

/* ── شارات الحالة والتقييم Apple Glass Style ── */
QLabel#statusBadge {{
    color: {STATUS_OK};
    padding: 5px 12px;
    background: rgba(52, 211, 153, 0.15);
    border: 1px solid rgba(52, 211, 153, 0.35);
    border-radius: 12px;
    font-weight: 600;
}}

QLabel#statusBadge[state="running"] {{
    color: {STATUS_WARN};
    border-color: rgba(251, 146, 60, 0.40);
    background: rgba(251, 146, 60, 0.18);
}}

QLabel#statusBadge[state="error"] {{
    color: #fecdd3;
    border-color: {STATUS_ERROR};
    background: rgba(244, 63, 94, 0.22);
}}

QLabel#scoreBadge {{
    color: {SEV_SAFE};
    padding: 5px 12px;
    background: rgba(52, 211, 153, 0.15);
    border: 1px solid rgba(52, 211, 153, 0.35);
    border-radius: 12px;
    font-weight: 600;
}}

QLabel#modeBadge {{
    color: #94a3b8;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.10);
    border-radius: 8px;
    padding: 4px 8px;
    font-size: 9px;
    font-weight: 700;
}}

QPushButton#headerControl {{
    color: {TEXT_SECONDARY};
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.10);
    border-radius: 8px;
    padding: 5px 9px;
    font-size: 10px;
    font-weight: 600;
}}

QPushButton#headerControl:hover, QPushButton#headerControl:checked {{
    color: {TEXT_PRIMARY};
    background: rgba(255, 255, 255, 0.12);
    border-color: {ACCENT};
}}

QFrame#telemetryChart, QFrame#securityGauge {{
    background: rgba(15, 23, 42, 0.60);
    border: 1px solid rgba(255, 255, 255, 0.10);
    border-radius: 14px;
}}

QLabel#sectionTitle {{
    font-size: {FONT_SIZE_TITLE}px;
    font-weight: 700;
    color: {TEXT_PRIMARY};
}}

QLabel#sectionSubtitle {{
    color: {TEXT_SECONDARY};
    font-size: {FONT_SIZE_SMALL}px;
}}

QLabel#metricValue {{
    font-size: {FONT_SIZE_METRIC}px;
    font-weight: 700;
    color: {TEXT_PRIMARY};
}}

QLabel#metricLabel {{
    color: {TEXT_SECONDARY};
    font-size: 12px;
    font-weight: 500;
}}

QLabel#metricNote {{
    color: {TEXT_MUTED};
    font-size: 10px;
}}

QLabel#footer {{
    color: {TEXT_MUTED};
    font-size: 10px;
    background: rgba(3, 7, 18, 0.85);
    border-top: 1px solid rgba(255, 255, 255, 0.06);
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
    background: rgba(255, 255, 255, 0.08);
}}

QSplitter::handle:hover {{
    background: {ACCENT};
}}

QToolTip {{
    background: rgba(15, 23, 42, 0.95);
    color: {TEXT_PRIMARY};
    border: 1px solid rgba(45, 212, 191, 0.50);
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
    background: rgba(15, 23, 42, 0.75);
    border: 1px solid rgba(255, 255, 255, 0.14);
    border-radius: 16px;
}}

QFrame#chatUser {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 rgba(30, 58, 138, 0.45), stop:1 rgba(15, 23, 42, 0.55));
    border: 1px solid rgba(45, 212, 191, 0.30);
    border-radius: 16px;
}}

QFrame#chatAssistant {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 rgba(30, 41, 59, 0.55), stop:1 rgba(15, 23, 42, 0.65));
    border: 1px solid rgba(167, 139, 250, 0.30);
    border-radius: 16px;
}}

QFrame#chatSystem {{
    background: rgba(30, 41, 59, 0.50);
    border: 1px solid rgba(251, 146, 60, 0.35);
    border-radius: 12px;
}}

QFrame#transitionVeil {{
    background: rgba(3, 7, 18, 0.85);
    border: none;
}}

QFrame#floatingStatusBar {{
    background: rgba(15, 23, 42, 0.80);
    border: 1px solid rgba(255, 255, 255, 0.10);
    border-radius: 14px;
}}

QLabel#dockSignal {{
    color: {ACCENT};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.8px;
}}

QLabel#dockItem {{
    color: {TEXT_SECONDARY};
    font-size: 10px;
    font-weight: 600;
    padding: 4px 9px;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
}}

QLabel#dockState {{
    color: {STATUS_OK};
    font-size: 10px;
    font-weight: 700;
}}
QLabel#dockState[state="running"] {{ color: {STATUS_WARN}; }}
QLabel#dockState[state="error"] {{ color: {STATUS_ERROR}; }}

QWidget#glowReflection {{
    background: transparent;
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
    return f"rgba(45, 212, 191, 0.15)"
