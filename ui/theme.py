"""AI AYFAM — Desktop product design system (v3 — futuristic dark).

A bold operations-console visual language: deep space-black surfaces, pulsing
cyber-cyan/violet accents, glassmorphic cards, animated aurora background, and
a rich dark palette that feels like a futuristic mission-control terminal.
The stylesheet is semantic so existing pages keep their behaviour while
receiving one coherent visual treatment.
"""

BG_BASE = "#03050c"
BG_SURFACE = "#080a14"
BG_ELEVATED = "#0d101b"
BG_HOVER = "#141a29"
BG_INPUT = "#05070f"
BORDER = "#1c2230"
BORDER_LIGHT = "#141a26"
BORDER_FOCUS = "#22d3ee"

TEXT_PRIMARY = "#f8fafc"
TEXT_SECONDARY = "#cbd5e1"
TEXT_MUTED = "#64748b"

ACCENT = "#22d3ee"
ACCENT_HOVER = "#67e8f9"
ACCENT_PRESSED = "#0ea5b7"
ACCENT_SOFT = "#2222d3ee"
ACCENT_SECONDARY = "#a78bfa"
ACCENT_SECONDARY_SOFT = "#22a78bfa"

SEV_CRITICAL = "#ff647c"
SEV_HIGH = "#ffb454"
SEV_MEDIUM = "#f2cf63"
SEV_LOW = "#50c9df"
SEV_INFO = "#8095aa"
SEV_SAFE = "#22d3ee"

STATUS_OK = "#22d3ee"
STATUS_WARN = "#ffb454"
STATUS_ERROR = "#ff647c"
STATUS_IDLE = "#8095aa"

CARD_ACCENTS = {
    "connections": "#50c9df",
    "processes": "#a78bfa",
    "findings": "#ffb454",
    "score": "#22d3ee",
}

FONT_FAMILY = '"Cairo", "Noto Sans Arabic", "Segoe UI", "DejaVu Sans", sans-serif'
FONT_SIZE_BASE = 13
FONT_SIZE_SMALL = 11
FONT_SIZE_TITLE = 18
FONT_SIZE_HERO = 24
FONT_SIZE_METRIC = 30

SP_XS, SP_SM, SP_MD, SP_LG, SP_XL, SP_2XL = 4, 8, 12, 16, 20, 24

# ─── Accent hue cycling (dynamic UI pulse) ──────────────────────────────
ACCENT_HUES = [
    ("#22d3ee", "#a78bfa"),  # cyan/violet
    ("#4f7cf7", "#a78bfa"),  # blue/violet
    ("#7c4ff7", "#50c9df"),  # violet/cyan
    ("#f75f8a", "#4f7cf7"),  # rose/blue
    ("#f77c4f", "#7c4ff7"),  # orange/violet
    ("#4ff7a8", "#f77c4f"),  # emerald/orange
]

def get_qss(accent: str = ACCENT, accent2: str = ACCENT_SECONDARY) -> str:
    """Return the stylesheet with a given accent pair (for hue cycling)."""
    import re
    qss = QSS
    qss = qss.replace(ACCENT, accent)
    qss = qss.replace(ACCENT_HOVER, _shift_hue(accent, 0.15))
    qss = qss.replace(ACCENT_PRESSED, _shift_hue(accent, -0.15))
    # ACCENT_SOFT is stored in Qt #AARRGGBB order after the alpha fix;
    # build the replacement in the same order.
    qss = qss.replace(ACCENT_SOFT, f"22{accent.lstrip('#').lower()}")
    qss = qss.replace(ACCENT_SECONDARY, accent2)
    return qss

def _shift_hue(hex_color: str, factor: float) -> str:
    """Brighten or darken a hex color slightly for hover/pressed states."""
    r, g, b = (int(hex_color[i:i+2], 16) for i in (1, 3, 5))
    if factor > 0:
        r = min(255, int(r * (1 + factor) + 20))
        g = min(255, int(g * (1 + factor) + 20))
        b = min(255, int(b * (1 + factor) + 20))
    else:
        f = 1 + factor
        r, g, b = int(r * f), int(g * f), int(b * f)
    return f"#{r:02x}{g:02x}{b:02x}"

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

/* ── Navigation rail ────────────────────────────────────────────────── */
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
    border-color: {ACCENT_SOFT};
    font-weight: 700;
}}
QPushButton#navButton:checked:hover {{ background: #2d22d3ee; }}
QLabel#navGroupLabel {{ color: {TEXT_MUTED}; font-size: 9px; font-weight: 800; padding: 14px 8px 4px; letter-spacing: 1px; }}
QPushButton#assistantNavButton {{
    background: #1222d3ee; color: {ACCENT}; border: 1px solid #5522d3ee;
    border-radius: 9px; padding: 10px 12px; font-weight: 700; margin-top: 12px;
}}
QPushButton#assistantNavButton:hover {{ background: #2422d3ee; border-color: {ACCENT}; }}

/* ── App bar ───────────────────────────────────────────────────────── */
QFrame#headerBar {{
    background: {BG_SURFACE};
    border-bottom: 1px solid {BORDER};
}}
QLabel#eyebrow {{ color: {ACCENT}; font-size: 10px; font-weight: 700; letter-spacing: 1px; }}
QLabel#brandMark {{
    background: {ACCENT}; color: {BG_BASE}; border-radius: 10px;
    font-size: 18px; font-weight: 900; padding: 7px 10px;
}}
QLabel#clockTime {{
    color: {TEXT_PRIMARY};
    font-size: 15px;
    font-weight: 800;
    font-family: "JetBrains Mono", "DejaVu Sans Mono", monospace;
    letter-spacing: 1px;
}}
QLabel#clockDate {{
    color: {TEXT_SECONDARY};
    font-size: 10px;
    font-weight: 600;
}}
QFrame#missionBanner {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #0d1f2e,stop:0.5 #1a1130,stop:1 #0d1f2e);
    border: 1px solid #2e5365; border-radius: 14px;
}}
QLabel#missionTitle {{ color: {TEXT_PRIMARY}; font-size: 23px; font-weight: 900; padding-top: 1px; }}
QPushButton#quietAction {{ background: #0bffffff; border-color: #20ffffff; color: {TEXT_PRIMARY}; }}
QPushButton#quietAction:hover {{ background: #18ffffff; border-color: #45ffffff; }}

/* ── Surfaces (glass cards) ───────────────────────────────────────── */
QFrame#card {{
    background: {BG_SURFACE};
    border: 1px solid {BORDER};
    border-radius: 12px;
}}
QFrame#card:hover {{ border-color: #2a3344; }}
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

/* ── Actions ──────────────────────────────────────────────────────── */
QPushButton {{
    background: {BG_HOVER}; color: {TEXT_PRIMARY};
    border: 1px solid {BORDER}; border-radius: 8px;
    padding: 9px 15px; font-weight: 600; min-height: 20px;
}}
QPushButton:hover {{ background: #1e2740; border-color: #2e3d55; }}
QPushButton:pressed {{ background: {BG_INPUT}; }}
QPushButton#primary {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {ACCENT},stop:1 {ACCENT_SECONDARY});
    color: #03050c; border: none; font-weight: 800;
}}
QPushButton#primary:hover {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {ACCENT_HOVER},stop:1 {ACCENT_SECONDARY});
}}
QPushButton#primary:pressed {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {ACCENT_PRESSED},stop:1 {ACCENT_SECONDARY});
}}
QPushButton#danger {{ background: #12ff647c; color: {SEV_CRITICAL}; border-color: #55ff647c; }}
QPushButton#danger:hover {{ background: #24ff647c; border-color: {SEV_CRITICAL}; }}
QPushButton#pillButton {{ background: {BG_INPUT}; color: {TEXT_SECONDARY}; border-radius: 16px; padding: 7px 13px; }}
QPushButton#pillButton:hover {{ color: {ACCENT}; border-color: {ACCENT}; }}
QPushButton:disabled {{ color: {TEXT_MUTED}; background: {BG_SURFACE}; border-color: {BORDER_LIGHT}; }}

/* ── Inputs ───────────────────────────────────────────────────────── */
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {{
    background: {BG_INPUT}; color: {TEXT_PRIMARY};
    border: 1px solid {BORDER}; border-radius: 8px;
    padding: 9px 11px; selection-background-color: {ACCENT}; selection-color: #03050c;
}}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{
    border: 1px solid {BORDER_FOCUS};
    background: {BG_ELEVATED};
}}
QComboBox::drop-down {{ border: none; width: 25px; }}

/* ── Data tables ───────────────────────────────────────────────────── */
QTableWidget {{
    background: {BG_SURFACE}; color: {TEXT_PRIMARY};
    alternate-background-color: #0a0d18; gridline-color: transparent;
    border: 1px solid {BORDER}; border-radius: 9px;
    selection-background-color: #2b22d3ee; selection-color: {TEXT_PRIMARY}; outline: none;
}}
QTableWidget::item {{ padding: 8px 10px; border-bottom: 1px solid {BORDER_LIGHT}; }}
QTableWidget::item:selected {{ background: #2b22d3ee; }}
QHeaderView::section {{
    background: #111524; color: {TEXT_SECONDARY}; padding: 11px 10px;
    border: none; border-bottom: 1px solid {BORDER}; font-weight: 700; font-size: {FONT_SIZE_SMALL}px;
}}

QProgressBar {{ background: {BG_HOVER}; border: none; border-radius: 4px; text-align: center; min-height: 7px; max-height: 7px; }}
QProgressBar::chunk {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {ACCENT},stop:1 {ACCENT_SECONDARY});
    border-radius: 4px;
}}
QScrollBar:vertical {{ background: {BG_BASE}; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: #243044; min-height: 32px; border-radius: 5px; }}
QScrollBar::handle:vertical:hover {{ background: #334460; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: {BG_BASE}; height: 10px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: #243044; min-width: 32px; border-radius: 5px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

QLabel#statusBadge {{ color: {STATUS_IDLE}; font-weight: 700; padding: 7px 13px; background: {BG_INPUT}; border: 1px solid {BORDER}; border-radius: 16px; }}
QLabel#statusBadge[state="running"] {{ color: {STATUS_WARN}; border-color: #66ffb454; }}
QLabel#statusBadge[state="error"] {{ color: {STATUS_ERROR}; border-color: #66ff647c; }}
QLabel#scoreBadge {{ color: {SEV_MEDIUM}; font-weight: 800; padding: 7px 13px; background: #14f2cf63; border: 1px solid #55f2cf63; border-radius: 16px; }}
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
