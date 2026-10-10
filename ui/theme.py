"""
AI AYFAM — Professional Design System
نظام تصميم موحّد: ألوان، خطوط، مسافات، وأنماط QSS احترافية.
مستوحى من ثيمات GitHub Dark و VS Code — احترافي، عصري، وواضح.
"""

# ─── Color Palette ────────────────────────────────────────────────────────────
# Backgrounds (layered depth)
BG_BASE      = "#070b14"   # أعمق خلفية (Cyber Abyss)
BG_SURFACE   = "#0c1322"   # خلفية البطاقات والأسطح
BG_ELEVATED = "#121b2d"   # العناصر المرفوعة (header, sidebar)
BG_HOVER     = "#1a253c"   # hover state
BG_INPUT     = "#060911"   # حقول الإدخال

# Borders
BORDER       = "#1e293b"
BORDER_LIGHT = "#152033"
BORDER_FOCUS = "#10b981"

# Text
TEXT_PRIMARY   = "#f8fafc"
TEXT_SECONDARY = "#94a3b8"
TEXT_MUTED     = "#64748b"

# Accent (Cyber Emerald & Telemetry Cyan)
ACCENT        = "#10b981"
ACCENT_HOVER  = "#059669"
ACCENT_PRESSED = "#047857"
ACCENT_SOFT   = "rgba(16, 185, 129, 0.15)"

# Severity Colors (high contrast, clearly distinguishable)
SEV_CRITICAL  = "#f43f5e"
SEV_HIGH      = "#f59e0b"
SEV_MEDIUM    = "#eab308"
SEV_LOW       = "#06b6d4"
SEV_INFO      = "#64748b"
SEV_SAFE      = "#10b981"

# Status Colors
STATUS_OK     = "#10b981"
STATUS_WARN   = "#f59e0b"
STATUS_ERROR  = "#f43f5e"
STATUS_IDLE   = "#64748b"

# Card accent borders (top border per card type)
CARD_ACCENTS = {
    "connections": "#2f81f7",
    "processes": "#a371f7",
    "findings": "#d29922",
    "score": "#3fb950",
}

# ─── Typography ───────────────────────────────────────────────────────────────
FONT_FAMILY = '"Cairo", "Noto Sans Arabic", "Segoe UI", "DejaVu Sans", sans-serif'
FONT_SIZE_BASE   = 13
FONT_SIZE_SMALL  = 11
FONT_SIZE_TITLE  = 16
FONT_SIZE_HERO   = 22
FONT_SIZE_METRIC = 28

# ─── Spacing ──────────────────────────────────────────────────────────────────
SP_XS  = 4
SP_SM  = 8
SP_MD  = 12
SP_LG  = 16
SP_XL  = 20
SP_2XL = 24

# ─── QSS Stylesheet ───────────────────────────────────────────────────────────
QSS = f"""
/* ═══ Base ═══ */
QMainWindow, QWidget {{
    background: {BG_BASE};
    color: {TEXT_PRIMARY};
    font-family: {FONT_FAMILY};
    font-size: {FONT_SIZE_BASE}px;
}}

/* ═══ Sidebar ═══ */
QFrame#sidebar {{
    background: {BG_ELEVATED};
    border-right: 1px solid {BORDER};
}}
QPushButton#navButton {{
    background: transparent;
    color: {TEXT_SECONDARY};
    border: none;
    border-radius: 6px;
    padding: 10px 14px;
    text-align: left;
    font-size: {FONT_SIZE_BASE}px;
    font-weight: 500;
    min-height: 20px;
}}
QPushButton#navButton:hover {{
    background: {BG_HOVER};
    color: {TEXT_PRIMARY};
}}
QPushButton#navButton:checked {{
    background: {ACCENT_SOFT};
    color: {ACCENT};
    font-weight: 600;
    border-left: 3px solid {ACCENT};
    border-radius: 0px 6px 6px 0px;
}}
QPushButton#navButton:checked:hover {{
    background: {ACCENT_SOFT};
}}

/* ═══ Header ═══ */
QFrame#headerBar {{
    background: {BG_ELEVATED};
    border-bottom: 1px solid {BORDER};
}}

/* ═══ Cards ═══ */
QFrame#card {{
    background: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}
QFrame#card:hover {{
    border-color: {BORDER_FOCUS};
}}

/* ═══ Group Boxes ═══ */
QGroupBox {{
    background: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
    margin-top: 14px;
    padding: 16px 14px 12px;
    font-weight: 600;
    color: {TEXT_SECONDARY};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 6px;
}}

/* ═══ Buttons ═══ */
QPushButton {{
    background: {BG_HOVER};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 8px 14px;
    font-weight: 500;
    min-height: 20px;
}}
QPushButton:hover {{
    background: {BORDER};
    border-color: {BORDER_FOCUS};
}}
QPushButton:pressed {{
    background: {BG_BASE};
}}
QPushButton#primary {{
    background: {ACCENT};
    color: #ffffff;
    border: 1px solid {ACCENT};
    font-weight: 600;
}}
QPushButton#primary:hover {{
    background: {ACCENT_HOVER};
    border-color: {ACCENT_HOVER};
}}
QPushButton#primary:pressed {{
    background: {ACCENT_PRESSED};
}}
QPushButton#danger {{
    background: transparent;
    color: {SEV_CRITICAL};
    border: 1px solid #f8514944;
}}
QPushButton#danger:hover {{
    background: #f8514918;
    border-color: {SEV_CRITICAL};
}}
QPushButton:disabled {{
    color: {TEXT_MUTED};
    background: {BG_SURFACE};
    border-color: {BORDER_LIGHT};
}}

/* ═══ Inputs ═══ */
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {{
    background: {BG_INPUT};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 8px 10px;
    selection-background-color: {ACCENT};
    selection-color: #ffffff;
}}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{
    border: 1px solid {BORDER_FOCUS};
}}

/* ═══ Tables ═══ */
QTableWidget {{
    background: {BG_SURFACE};
    color: {TEXT_PRIMARY};
    alternate-background-color: {BG_ELEVATED};
    gridline-color: {BORDER_LIGHT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    selection-background-color: {ACCENT_SOFT};
    selection-color: {TEXT_PRIMARY};
    outline: none;
}}
QTableWidget::item {{
    padding: 6px 10px;
    border-bottom: 1px solid {BORDER_LIGHT};
}}
QTableWidget::item:selected {{
    background: {ACCENT_SOFT};
}}
QHeaderView::section {{
    background: {BG_ELEVATED};
    color: {TEXT_SECONDARY};
    padding: 10px 10px;
    border: none;
    border-bottom: 2px solid {BORDER};
    font-weight: 600;
    font-size: {FONT_SIZE_SMALL}px;
}}

/* ═══ Progress Bar ═══ */
QProgressBar {{
    background: {BG_HOVER};
    border: none;
    border-radius: 4px;
    text-align: center;
    min-height: 6px;
    max-height: 6px;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {ACCENT}, stop:1 #58a6ff);
    border-radius: 4px;
}}

/* ═══ Scrollbar ═══ */
QScrollBar:vertical {{
    background: {BG_BASE};
    width: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    min-height: 30px;
    border-radius: 5px;
}}
QScrollBar::handle:vertical:hover {{
    background: {TEXT_MUTED};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: {BG_BASE};
    height: 10px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {BORDER};
    min-width: 30px;
    border-radius: 5px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}

/* ═══ Stacked Widget (content area) ═══ */
QStackedWidget {{
    background: {BG_BASE};
}}

/* ╀── Status Indicators ─── */
QLabel#statusBadge {{
    color: {STATUS_IDLE};
    font-weight: 600;
    padding: 6px 12px;
    background: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-radius: 6px;
}}
QLabel#statusBadge[state="running"] {{
    color: {STATUS_WARN};
    border-color: #d2992244;
}}
QLabel#statusBadge[state="error"] {{
    color: {STATUS_ERROR};
    border-color: #f8514944;
}}
QLabel#scoreBadge {{
    color: {SEV_MEDIUM};
    font-weight: 700;
    padding: 8px 14px;
    background: {BG_SURFACE};
    border: 1px solid #d2992244;
    border-radius: 6px;
}}
QLabel#sectionTitle {{
    color: {TEXT_PRIMARY};
    font-size: {FONT_SIZE_TITLE}px;
    font-weight: 700;
}}
QLabel#sectionSubtitle {{
    color: {TEXT_SECONDARY};
    font-size: {FONT_SIZE_SMALL}px;
}}
QLabel#metricValue {{
    color: {TEXT_PRIMARY};
    font-size: {FONT_SIZE_METRIC}px;
    font-weight: 800;
}}
QLabel#metricLabel {{
    color: {TEXT_SECONDARY};
    font-size: {FONT_SIZE_SMALL}px;
    font-weight: 500;
}}
QLabel#metricNote {{
    color: {TEXT_MUTED};
    font-size: 10px;
}}
QLabel#footer {{
    color: {TEXT_MUTED};
    font-size: 10px;
    padding: 4px 0;
}}

/* ═══ Activity Lamp (animated) ═══ */
QFrame#activityLamp {{
    background: {STATUS_IDLE};
    border: 2px solid {STATUS_IDLE};
    border-radius: 6px;
    min-width: 8px;
    max-width: 8px;
    min-height: 8px;
    max-height: 8px;
}}
QFrame#activityLamp[state="running"] {{
    background: {STATUS_WARN};
    border-color: {STATUS_WARN};
}}
QFrame#activityLamp[state="error"] {{
    background: {STATUS_ERROR};
    border-color: {STATUS_ERROR};
}}

/* ═══ Splitter ═══ */
QSplitter::handle {{
    background: {BORDER};
}}
QSplitter::handle:hover {{
    background: {BORDER_FOCUS};
}}
"""


def severity_color(severity: str) -> str:
    """Map severity level to its color."""
    return {
        "critical": SEV_CRITICAL,
        "high": SEV_HIGH,
        "medium": SEV_MEDIUM,
        "low": SEV_LOW,
        "info": SEV_INFO,
        "safe": SEV_SAFE,
    }.get((severity or "").lower(), SEV_INFO)


def severity_bg(severity: str) -> str:
    """Semi-transparent background for severity badges."""
    base = severity_color(severity)
    return f"{base}22"
