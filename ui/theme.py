"""نظام تصميم زجاجي موحد لسطح مكتب Qt6 — أزرق، أخضر، برتقالي وأحمر فقط."""

BG_BASE = "#070d16"
BG_SURFACE = "#101f30"
BG_ELEVATED = "#14283b"
BG_HOVER = "#19344a"
BG_INPUT = "#0c1926"
BORDER = "#28516b"
BORDER_LIGHT = "#203b50"
BORDER_FOCUS = "#38bdf8"
TEXT_PRIMARY = "#edf5fb"
TEXT_SECONDARY = "#b5c9d9"
TEXT_MUTED = "#829bb0"
ACCENT = "#38bdf8"
ACCENT_HOVER = "#7dd3fc"
ACCENT_PRESSED = "#0284c7"
ACCENT_SOFT = "#2438bdf8"
ACCENT_SECONDARY = "#34d399"
ACCENT_SECONDARY_SOFT = "#2434d399"
SEV_CRITICAL = "#ef4444"
SEV_HIGH = "#fb923c"
SEV_MEDIUM = "#f59e0b"
SEV_LOW = "#38bdf8"
SEV_INFO = "#8fb3d1"
SEV_SAFE = "#34d399"
STATUS_OK, STATUS_WARN, STATUS_ERROR, STATUS_IDLE = SEV_SAFE, SEV_HIGH, SEV_CRITICAL, SEV_INFO
CARD_ACCENTS = {"connections": ACCENT, "processes": "#60a5fa", "findings": SEV_HIGH, "score": SEV_SAFE}
FONT_FAMILY = '"Noto Sans Arabic", "Cairo", "DejaVu Sans", sans-serif'
FONT_SIZE_BASE, FONT_SIZE_SMALL = 13, 11
FONT_SIZE_TITLE, FONT_SIZE_HERO, FONT_SIZE_METRIC = 19, 24, 30
SP_XS, SP_SM, SP_MD, SP_LG, SP_XL, SP_2XL = 4, 8, 12, 16, 20, 24
ACCENT_HUES = [(ACCENT, ACCENT_SECONDARY), ("#60a5fa", "#38bdf8"), ("#34d399", "#38bdf8")]


def alpha(color: str, opacity: int) -> str:
    """Qt uses #AARRGGBB, not CSS #RRGGBBAA."""
    return f"#{opacity:02x}{color.lstrip('#')}"


def get_qss(accent: str = ACCENT, accent2: str = ACCENT_SECONDARY) -> str:
    # Atomic token replacement avoids accidental substring replacements in alpha colors.
    result = QSS.replace(ACCENT_SOFT, alpha(accent, 36))
    result = result.replace(ACCENT_SECONDARY_SOFT, alpha(accent2, 36))
    return result.replace(ACCENT, accent).replace(ACCENT_SECONDARY, accent2)


QSS = f"""
QWidget {{ background: transparent; color: {TEXT_PRIMARY}; font-family: {FONT_FAMILY}; font-size: {FONT_SIZE_BASE}px; }}
QMainWindow, QDialog, QMessageBox {{ background: {BG_BASE}; }}
QLabel {{ background: transparent; border: none; }}
QScrollArea, QStackedWidget {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QFrame#sidebar {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #ee142638,stop:1 #f00a141f); border-right: 1px solid #6638bdf8; }}
QPushButton#navButton {{ background: transparent; color: {TEXT_SECONDARY}; border: 1px solid #2028516b; border-radius: 13px; padding: 9px 12px; text-align: left; min-height: 20px; font-weight: 500; }}
QPushButton#navButton:hover {{ color: {TEXT_PRIMARY}; background: #2438bdf8; border-color: #8838bdf8; }}
QPushButton#navButton:checked {{ color: {ACCENT}; background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #3538bdf8,stop:1 #1834d399); border-color: #a038bdf8; font-weight: 700; }}
QLabel#navGroupLabel {{ color: {TEXT_MUTED}; font-size: 10px; font-weight: 600; padding: 11px 8px 4px; }}
QPushButton#assistantNavButton {{ background: #2034d399; color: {SEV_SAFE}; border: 1px solid #8034d399; border-radius: 13px; padding: 10px 12px; font-weight: 700; margin-top: 10px; }}
QPushButton#assistantNavButton:hover {{ background: #3534d399; border-color: {SEV_SAFE}; }}
QFrame#headerBar {{ background: #c0122333; border-bottom: 1px solid #5538bdf8; }}
QLabel#eyebrow {{ color: {ACCENT}; font-size: 10px; font-weight: 700; }}
QLabel#brandMark {{ background: #2038bdf8; border: 1px solid #9938bdf8; border-radius: 13px; padding: 8px; }}
QLabel#clockTime {{ font-family: "DejaVu Sans Mono"; font-size: 16px; font-weight: 700; }}
QLabel#clockDate {{ color: {TEXT_SECONDARY}; font-size: 10px; }}
QFrame#missionBanner {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #b8193b55,stop:0.6 #99162939,stop:1 #90203e36); border: 1px solid #a038bdf8; border-radius: 20px; }}
QLabel#missionTitle {{ font-size: 24px; font-weight: 800; }}
QFrame#card {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #be20394d,stop:1 #88112130); border: 1px solid #8038bdf8; border-radius: 18px; }}
QFrame#card:hover {{ border-color: {ACCENT}; }}
QGroupBox {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #a8203547,stop:1 #85101e2c); border: 1px solid #7838bdf8; border-radius: 18px; margin-top: 0; padding: 38px 14px 14px; font-weight: 700; }}
QGroupBox::title {{ subcontrol-origin: padding; subcontrol-position: top left; left: 18px; top: 11px; color: {TEXT_PRIMARY}; background: transparent; font-size: 13px; }}
QGroupBox:hover {{ border-color: #b534d399; }}
QPushButton {{ background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #a3264359,stop:1 #90152939); color: {TEXT_PRIMARY}; border: 1px solid #8038bdf8; border-radius: 12px; padding: 8px 14px; min-height: 22px; font-weight: 600; }}
QPushButton:hover {{ background: #5538bdf8; border-color: {ACCENT}; }}
QPushButton:pressed {{ background: #6034d399; border-color: {SEV_SAFE}; }}
QPushButton:focus {{ border: 2px solid {ACCENT}; }}
QPushButton#primary {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #2674ae,stop:1 #17644c); color: {TEXT_PRIMARY}; border: 1px solid #aa7dd3fc; font-weight: 700; }}
QPushButton#primary:hover {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #298acb,stop:1 #208362); border-color: #a7f3d0; }}
QPushButton#danger {{ color: #fca5a5; border-color: #aaef4444; background: #25ef4444; }}
QPushButton#danger:hover {{ background: #50ef4444; border-color: {SEV_CRITICAL}; }}
QPushButton#pillButton {{ border-radius: 16px; padding: 6px 10px; color: {TEXT_SECONDARY}; font-size: 11px; min-height: 20px; background: #1838bdf8; }}
QPushButton#quietAction {{ background: #1829b4e9; }}
QPushButton:disabled {{ color: {TEXT_MUTED}; background: #40122230; border-color: #40526a7c; }}
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {{ background: #a0102232; color: {TEXT_PRIMARY}; border: 1px solid #8038bdf8; border-radius: 13px; padding: 9px 12px; selection-background-color: #2677ab; selection-color: {TEXT_PRIMARY}; }}
QLineEdit:hover, QComboBox:hover, QPlainTextEdit:hover, QTextEdit:hover {{ border-color: #b334d399; }}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{ border-color: {ACCENT}; background: #bf162d40; }}
QComboBox::drop-down {{ border: none; width: 24px; }}
QComboBox QAbstractItemView {{ background: {BG_SURFACE}; border: 1px solid {ACCENT}; selection-background-color: #244e6c; }}
QTableWidget {{ background: #b2102131; color: {TEXT_PRIMARY}; alternate-background-color: #401f3b4e; gridline-color: transparent; border: 1px solid #b038bdf8; border-radius: 14px; selection-background-color: #4038bdf8; outline: none; }}
QTableWidget::item {{ padding: 5px 9px; border-bottom: 1px solid #252e6685; }}
QTableWidget::item:hover {{ background: #3534d399; color: {TEXT_PRIMARY}; }}
QTableWidget::item:selected {{ background: #5538bdf8; color: {TEXT_PRIMARY}; }}
QHeaderView::section {{ background: #e01b3a51; color: {TEXT_SECONDARY}; padding: 9px; border: none; border-bottom: 1px solid #b034d399; font-weight: 700; font-size: 11px; }}
QTableCornerButton::section {{ background: #1b3a51; border: none; }}
QProgressBar {{ background: #242e6685; border: none; border-radius: 4px; min-height: 7px; max-height: 7px; }}
QProgressBar::chunk {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {ACCENT},stop:1 {SEV_SAFE}); border-radius: 4px; }}
QScrollBar:vertical {{ background: transparent; width: 8px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #7538bdf8; min-height: 32px; border-radius: 3px; }}
QScrollBar::handle:vertical:hover {{ background: {SEV_SAFE}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
QScrollBar:horizontal {{ background: transparent; height: 8px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #7538bdf8; min-width: 32px; border-radius: 3px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: transparent; }}
QLabel#statusBadge {{ color: {STATUS_OK}; padding: 7px 13px; background: #1834d399; border: 1px solid #7034d399; border-radius: 15px; font-weight: 600; }}
QLabel#statusBadge[state="running"] {{ color: {STATUS_WARN}; border-color: #aafb923c; background: #18fb923c; }}
QLabel#statusBadge[state="error"] {{ color: #fca5a5; border-color: {STATUS_ERROR}; }}
QLabel#scoreBadge {{ color: {SEV_SAFE}; padding: 7px 13px; background: #1834d399; border: 1px solid #7034d399; border-radius: 15px; font-weight: 700; }}
QLabel#sectionTitle {{ font-size: {FONT_SIZE_TITLE}px; font-weight: 800; }}
QLabel#sectionSubtitle {{ color: {TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px; }}
QLabel#metricValue {{ font-size: {FONT_SIZE_METRIC}px; font-weight: 800; }}
QLabel#metricLabel {{ color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 600; }}
QLabel#metricNote {{ color: {TEXT_MUTED}; font-size: 10px; }}
QLabel#footer {{ color: {TEXT_MUTED}; font-size: 10px; }}
QFrame#activityLamp {{ background: {STATUS_OK}; border-radius: 5px; }}
QFrame#activityLamp[state="running"] {{ background: {STATUS_WARN}; }}
QFrame#activityLamp[state="error"] {{ background: {STATUS_ERROR}; }}
QSplitter::handle {{ background: #552e6685; }}
QSplitter::handle:hover {{ background: {ACCENT}; }}
QToolTip {{ background: {BG_ELEVATED}; color: {TEXT_PRIMARY}; border: 1px solid {ACCENT}; padding: 7px; border-radius: 8px; }}
QTextEdit#messageBody {{ background: transparent; border: none; border-radius: 0; padding: 0; font-size: 14px; }}
QFrame#chatComposer {{ background: #a51a3347; border: 1px solid #9034d399; border-radius: 18px; }}
QFrame#chatUser {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #cf214b6c,stop:1 #af163e53); border: 1px solid #b038bdf8; border-radius: 18px; }}
QFrame#chatAssistant {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #ba1f3b40,stop:1 #a0122630); border: 1px solid #9034d399; border-radius: 18px; }}
QFrame#chatSystem {{ background: #802d3031; border: 1px solid #70fb923c; border-radius: 12px; }}
"""


def severity_color(severity: str) -> str:
    return {"critical": SEV_CRITICAL, "high": SEV_HIGH, "medium": SEV_MEDIUM,
            "low": SEV_LOW, "info": SEV_INFO, "safe": SEV_SAFE}.get((severity or "").lower(), SEV_INFO)


def severity_bg(severity: str) -> str:
    return alpha(severity_color(severity), 36)
