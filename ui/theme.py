"""AI AYFAM — Desktop product design system.

A restrained operations-console visual language: deep navy surfaces, warm paper
text, one emerald action colour, and severity colours used only as signals.
The stylesheet is intentionally semantic so the existing pages keep their
behaviour while receiving one coherent visual treatment.
"""

BG_BASE = "#08111f"
BG_SURFACE = "#0e1a2b"
BG_ELEVATED = "#122238"
BG_HOVER = "#1a2d45"
BG_INPUT = "#091525"
BORDER = "#223853"
BORDER_LIGHT = "#172a42"
BORDER_FOCUS = "#39d39f"

TEXT_PRIMARY = "#f5f8fc"
TEXT_SECONDARY = "#a6b7c9"
TEXT_MUTED = "#6f849a"

ACCENT = "#39d39f"
ACCENT_HOVER = "#62e0b5"
ACCENT_PRESSED = "#22b982"
ACCENT_SOFT = "#39d39f22"

SEV_CRITICAL = "#ff647c"
SEV_HIGH = "#ffb454"
SEV_MEDIUM = "#f2cf63"
SEV_LOW = "#50c9df"
SEV_INFO = "#8095aa"
SEV_SAFE = "#39d39f"

STATUS_OK = "#39d39f"
STATUS_WARN = "#ffb454"
STATUS_ERROR = "#ff647c"
STATUS_IDLE = "#8095aa"

CARD_ACCENTS = {
    "connections": "#50c9df",
    "processes": "#a78bfa",
    "findings": "#ffb454",
    "score": "#39d39f",
}

FONT_FAMILY = '"Cairo", "Noto Sans Arabic", "Segoe UI", "DejaVu Sans", sans-serif'
FONT_SIZE_BASE = 13
FONT_SIZE_SMALL = 11
FONT_SIZE_TITLE = 18
FONT_SIZE_HERO = 24
FONT_SIZE_METRIC = 30

SP_XS, SP_SM, SP_MD, SP_LG, SP_XL, SP_2XL = 4, 8, 12, 16, 20, 24

QSS = f"""
QMainWindow, QWidget {{
    background: {BG_BASE};
    color: {TEXT_PRIMARY};
    font-family: {FONT_FAMILY};
    font-size: {FONT_SIZE_BASE}px;
}}
QWidget#mainArea {{ background: {BG_BASE}; }}
QScrollArea {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: {BG_BASE}; }}

/* Navigation rail */
QFrame#sidebar {{
    background: {BG_ELEVATED};
    border-right: 1px solid {BORDER};
}}
QPushButton#navButton {{
    background: transparent;
    color: {TEXT_SECONDARY};
    border: 1px solid transparent;
    border-radius: 9px;
    padding: 11px 14px;
    text-align: left;
    font-size: {FONT_SIZE_BASE}px;
    font-weight: 500;
    min-height: 22px;
}}
QPushButton#navButton:hover {{
    background: {BG_HOVER};
    color: {TEXT_PRIMARY};
    border-color: {BORDER};
}}
QPushButton#navButton:checked {{
    background: {ACCENT_SOFT};
    color: {ACCENT};
    border-color: #39d39f55;
    font-weight: 700;
}}
QPushButton#navButton:checked:hover {{ background: #39d39f2d; }}

/* App bar */
QFrame#headerBar {{
    background: {BG_SURFACE};
    border-bottom: 1px solid {BORDER};
}}
QLabel#eyebrow {{ color: {ACCENT}; font-size: 10px; font-weight: 700; letter-spacing: 1px; }}
QLabel#brandMark {{
    background: {ACCENT}; color: {BG_BASE}; border-radius: 10px;
    font-size: 18px; font-weight: 900; padding: 7px 10px;
}}

/* Surfaces */
QFrame#card {{
    background: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-radius: 12px;
}}
QGroupBox {{
    background: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-radius: 12px;
    margin-top: 17px;
    padding: 20px 16px 14px;
    font-weight: 700;
    color: {TEXT_PRIMARY};
}}
QGroupBox::title {{
    subcontrol-origin: margin; left: 14px; padding: 0 8px;
    color: {TEXT_SECONDARY}; background: {BG_SURFACE};
}}

/* Actions */
QPushButton {{
    background: {BG_HOVER}; color: {TEXT_PRIMARY};
    border: 1px solid {BORDER}; border-radius: 8px;
    padding: 9px 15px; font-weight: 600; min-height: 20px;
}}
QPushButton:hover {{ background: #23405d; border-color: #3c5d7b; }}
QPushButton:pressed {{ background: {BG_INPUT}; }}
QPushButton#primary {{ background: {ACCENT}; color: #062016; border-color: {ACCENT}; font-weight: 800; }}
QPushButton#primary:hover {{ background: {ACCENT_HOVER}; border-color: {ACCENT_HOVER}; }}
QPushButton#primary:pressed {{ background: {ACCENT_PRESSED}; }}
QPushButton#danger {{ background: #ff647c12; color: {SEV_CRITICAL}; border-color: #ff647c55; }}
QPushButton#danger:hover {{ background: #ff647c24; border-color: {SEV_CRITICAL}; }}
QPushButton#pillButton {{ background: {BG_INPUT}; color: {TEXT_SECONDARY}; border-radius: 16px; padding: 7px 13px; }}
QPushButton#pillButton:hover {{ color: {ACCENT}; border-color: {ACCENT}; }}
QPushButton:disabled {{ color: {TEXT_MUTED}; background: {BG_SURFACE}; border-color: {BORDER_LIGHT}; }}

/* Inputs */
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {{
    background: {BG_INPUT}; color: {TEXT_PRIMARY};
    border: 1px solid {BORDER}; border-radius: 8px;
    padding: 9px 11px; selection-background-color: {ACCENT}; selection-color: #06130e;
}}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{ border: 1px solid {BORDER_FOCUS}; }}
QComboBox::drop-down {{ border: none; width: 25px; }}

/* Data tables */
QTableWidget {{
    background: {BG_SURFACE}; color: {TEXT_PRIMARY};
    alternate-background-color: #102036; gridline-color: transparent;
    border: 1px solid {BORDER}; border-radius: 9px;
    selection-background-color: #39d39f2b; selection-color: {TEXT_PRIMARY}; outline: none;
}}
QTableWidget::item {{ padding: 8px 10px; border-bottom: 1px solid {BORDER_LIGHT}; }}
QTableWidget::item:selected {{ background: #39d39f2b; }}
QHeaderView::section {{
    background: #13263d; color: {TEXT_SECONDARY}; padding: 11px 10px;
    border: none; border-bottom: 1px solid {BORDER}; font-weight: 700; font-size: {FONT_SIZE_SMALL}px;
}}

QProgressBar {{ background: {BG_HOVER}; border: none; border-radius: 4px; text-align: center; min-height: 7px; max-height: 7px; }}
QProgressBar::chunk {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {ACCENT},stop:1 {SEV_LOW}); border-radius: 4px; }}
QScrollBar:vertical {{ background: {BG_BASE}; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: #29425d; min-height: 32px; border-radius: 5px; }}
QScrollBar::handle:vertical:hover {{ background: #3e607e; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: {BG_BASE}; height: 10px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: #29425d; min-width: 32px; border-radius: 5px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

QLabel#statusBadge {{ color: {STATUS_IDLE}; font-weight: 700; padding: 7px 13px; background: {BG_INPUT}; border: 1px solid {BORDER}; border-radius: 16px; }}
QLabel#statusBadge[state="running"] {{ color: {STATUS_WARN}; border-color: #ffb45466; }}
QLabel#statusBadge[state="error"] {{ color: {STATUS_ERROR}; border-color: #ff647c66; }}
QLabel#scoreBadge {{ color: {SEV_MEDIUM}; font-weight: 800; padding: 7px 13px; background: #f2cf6314; border: 1px solid #f2cf6355; border-radius: 16px; }}
QLabel#sectionTitle {{ color: {TEXT_PRIMARY}; font-size: {FONT_SIZE_TITLE}px; font-weight: 800; }}
QLabel#sectionSubtitle {{ color: {TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px; }}
QLabel#metricValue {{ color: {TEXT_PRIMARY}; font-size: {FONT_SIZE_METRIC}px; font-weight: 900; }}
QLabel#metricLabel {{ color: {TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px; font-weight: 700; }}
QLabel#metricNote {{ color: {TEXT_MUTED}; font-size: 10px; }}
QLabel#footer {{ color: {TEXT_MUTED}; font-size: 10px; padding: 4px 0; }}
QFrame#activityLamp {{ background: {STATUS_IDLE}; border: 2px solid {STATUS_IDLE}; border-radius: 5px; min-width: 8px; max-width: 8px; min-height: 8px; max-height: 8px; }}
QFrame#activityLamp[state="running"] {{ background: {STATUS_WARN}; border-color: {STATUS_WARN}; }}
QFrame#activityLamp[state="error"] {{ background: {STATUS_ERROR}; border-color: {STATUS_ERROR}; }}
QSplitter::handle {{ background: {BORDER}; }}
QSplitter::handle:hover {{ background: {BORDER_FOCUS}; }}
"""


def severity_color(severity: str) -> str:
    return {"critical": SEV_CRITICAL, "high": SEV_HIGH, "medium": SEV_MEDIUM,
            "low": SEV_LOW, "info": SEV_INFO, "safe": SEV_SAFE}.get((severity or "").lower(), SEV_INFO)


def severity_bg(severity: str) -> str:
    return f"{severity_color(severity)}22"
