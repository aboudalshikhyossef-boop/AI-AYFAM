"""نظام تصميم زجاجي موحّد لسطح مكتب Qt6 — أسلوب عصري هادئ (2026)."""

BG_BASE = "#060b12"
BG_SURFACE = "#0d1824"
BG_ELEVATED = "#122033"
BG_HOVER = "#1a2f44"
BG_INPUT = "#0a1520"
BORDER = "#2a4a62"
BORDER_LIGHT = "#1c3348"
BORDER_FOCUS = "#38bdf8"
TEXT_PRIMARY = "#f0f7fc"
TEXT_SECONDARY = "#a8c0d4"
TEXT_MUTED = "#6e8aa0"
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
FONT_FAMILY = '"Noto Sans Arabic", "Cairo", "Segoe UI", "DejaVu Sans", sans-serif'
FONT_SIZE_BASE, FONT_SIZE_SMALL = 13, 11
FONT_SIZE_TITLE, FONT_SIZE_HERO, FONT_SIZE_METRIC = 18, 22, 28
SP_XS, SP_SM, SP_MD, SP_LG, SP_XL, SP_2XL = 4, 8, 12, 16, 20, 24
ACCENT_HUES = [(ACCENT, ACCENT_SECONDARY), ("#60a5fa", "#38bdf8"), ("#34d399", "#38bdf8")]


def alpha(color: str, opacity: int) -> str:
    return f"#{opacity:02x}{color.lstrip('#')}"


def get_qss(accent: str = ACCENT, accent2: str = ACCENT_SECONDARY) -> str:
    result = QSS.replace(ACCENT_SOFT, alpha(accent, 36))
    result = result.replace(ACCENT_SECONDARY_SOFT, alpha(accent2, 36))
    return result.replace(ACCENT, accent).replace(ACCENT_SECONDARY, accent2)


QSS = f"""
QWidget {{ background: transparent; color: {TEXT_PRIMARY}; font-family: {FONT_FAMILY}; font-size: {FONT_SIZE_BASE}px; }}
QMainWindow, QDialog, QMessageBox {{ background: {BG_BASE}; }}
QLabel {{ background: transparent; border: none; }}
QScrollArea, QStackedWidget {{ background: transparent; border: none; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QFrame#sidebar {{ background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #f00e1a28,stop:0.5 #ee0a141f,stop:1 #f0081018); border-right: 1px solid #4028516b; }}
QPushButton#navButton {{ background: transparent; color: {TEXT_SECONDARY}; border: 1px solid transparent; border-radius: 12px; padding: 10px 14px; text-align: left; min-height: 22px; font-weight: 500; }}
QPushButton#navButton:hover {{ color: {TEXT_PRIMARY}; background: #1838bdf8; border-color: #3038bdf8; }}
QPushButton#navButton:checked {{ color: {ACCENT}; background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #4038bdf8,stop:1 #1834d399); border-color: #7038bdf8; font-weight: 700; }}
QLabel#navGroupLabel {{ color: {TEXT_MUTED}; font-size: 10px; font-weight: 700; letter-spacing: 0.6px; padding: 14px 10px 6px; }}
QPushButton#assistantNavButton {{ background: #2034d399; color: {SEV_SAFE}; border: 1px solid #6034d399; border-radius: 12px; padding: 10px 14px; font-weight: 700; margin-top: 12px; }}
QPushButton#assistantNavButton:hover {{ background: #3534d399; border-color: {SEV_SAFE}; }}
QFrame#headerBar {{ background: #c00e1824; border-bottom: 1px solid #3528516b; }}
QLabel#eyebrow {{ color: {ACCENT}; font-size: 10px; font-weight: 700; letter-spacing: 0.4px; }}
QLabel#brandMark {{ background: #2838bdf8; border: 1px solid #6038bdf8; border-radius: 12px; padding: 8px; }}
QLabel#clockTime {{ font-family: "DejaVu Sans Mono", monospace; font-size: 15px; font-weight: 700; }}
QLabel#clockDate {{ color: {TEXT_SECONDARY}; font-size: 10px; }}
QFrame#missionBanner {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #b0182e48,stop:0.55 #90101e30,stop:1 #801a3540); border: 1px solid #5038bdf8; border-radius: 18px; }}
QLabel#missionTitle {{ font-size: 22px; font-weight: 800; }}
QFrame#card {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #b0182a40,stop:1 #880e1824); border: 1px solid #4038bdf8; border-radius: 16px; }}
QFrame#card:hover {{ border-color: #8038bdf8; }}
QGroupBox {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #a0162840,stop:1 #850c1620); border: 1px solid #4038bdf8; border-radius: 16px; margin-top: 0; padding: 36px 16px 16px; font-weight: 700; }}
QGroupBox::title {{ subcontrol-origin: padding; subcontrol-position: top left; left: 16px; top: 12px; color: {TEXT_PRIMARY}; background: transparent; font-size: 13px; }}
QGroupBox:hover {{ border-color: #6034d399; }}
QPushButton {{ background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #a01e3448,stop:1 #90101e30); color: {TEXT_PRIMARY}; border: 1px solid #5038bdf8; border-radius: 11px; padding: 8px 16px; min-height: 22px; font-weight: 600; }}
QPushButton:hover {{ background: #4038bdf8; border-color: {ACCENT}; }}
QPushButton:pressed {{ background: #5034d399; border-color: {SEV_SAFE}; }}
QPushButton:focus {{ border: 2px solid {ACCENT}; }}
QPushButton#primary {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #1e6aa0,stop:1 #14705a); color: {TEXT_PRIMARY}; border: 1px solid #807dd3fc; font-weight: 700; }}
QPushButton#primary:hover {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #2488c0,stop:1 #1a8868); border-color: #a0a7f3d0; }}
QPushButton#danger {{ color: #fca5a5; border-color: #90ef4444; background: #28ef4444; }}
QPushButton#danger:hover {{ background: #50ef4444; border-color: {SEV_CRITICAL}; }}
QPushButton#pillButton {{ border-radius: 14px; padding: 6px 12px; color: {TEXT_SECONDARY}; font-size: 11px; min-height: 20px; background: #1838bdf8; }}
QPushButton#quietAction {{ background: #1829b4e9; }}
QPushButton:disabled {{ color: {TEXT_MUTED}; background: #30101824; border-color: #30304a60; }}
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {{ background: #a00c1620; color: {TEXT_PRIMARY}; border: 1px solid #4038bdf8; border-radius: 12px; padding: 9px 14px; selection-background-color: #206898; selection-color: {TEXT_PRIMARY}; }}
QLineEdit:hover, QComboBox:hover, QPlainTextEdit:hover, QTextEdit:hover {{ border-color: #6034d399; }}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus, QTextEdit:focus {{ border-color: {ACCENT}; background: #b0122030; }}
QComboBox::drop-down {{ border: none; width: 24px; }}
QComboBox QAbstractItemView {{ background: {BG_SURFACE}; border: 1px solid {ACCENT}; selection-background-color: #244e6c; border-radius: 8px; }}
QTableWidget {{ background: #a00e1824; color: {TEXT_PRIMARY}; alternate-background-color: #301a2e40; gridline-color: transparent; border: 1px solid #5038bdf8; border-radius: 14px; selection-background-color: #3538bdf8; outline: none; }}
QTableWidget::item {{ padding: 6px 10px; border-bottom: 1px solid #20204060; }}
QTableWidget::item:hover {{ background: #2834d399; color: {TEXT_PRIMARY}; }}
QTableWidget::item:selected {{ background: #4538bdf8; color: {TEXT_PRIMARY}; }}
QHeaderView::section {{ background: #d0162a40; color: {TEXT_SECONDARY}; padding: 10px 8px; border: none; border-bottom: 1px solid #5034d399; font-weight: 700; font-size: 11px; }}
QTableCornerButton::section {{ background: #162a40; border: none; }}
QProgressBar {{ background: #20204060; border: none; border-radius: 4px; min-height: 6px; max-height: 6px; }}
QProgressBar::chunk {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {ACCENT},stop:1 {SEV_SAFE}); border-radius: 4px; }}
QScrollBar:vertical {{ background: transparent; width: 8px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #6038bdf8; min-height: 32px; border-radius: 4px; }}
QScrollBar::handle:vertical:hover {{ background: {SEV_SAFE}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
QScrollBar:horizontal {{ background: transparent; height: 8px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #6038bdf8; min-width: 32px; border-radius: 4px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: transparent; }}
QLabel#statusBadge {{ color: {STATUS_OK}; padding: 6px 12px; background: #1834d399; border: 1px solid #6034d399; border-radius: 14px; font-weight: 600; }}
QLabel#statusBadge[state="running"] {{ color: {STATUS_WARN}; border-color: #90fb923c; background: #18fb923c; }}
QLabel#statusBadge[state="error"] {{ color: #fca5a5; border-color: {STATUS_ERROR}; }}
QLabel#scoreBadge {{ color: {SEV_SAFE}; padding: 6px 12px; background: #1834d399; border: 1px solid #6034d399; border-radius: 14px; font-weight: 700; }}
QLabel#sectionTitle {{ font-size: {FONT_SIZE_TITLE}px; font-weight: 800; }}
QLabel#sectionSubtitle {{ color: {TEXT_SECONDARY}; font-size: {FONT_SIZE_SMALL}px; }}
QLabel#metricValue {{ font-size: {FONT_SIZE_METRIC}px; font-weight: 800; }}
QLabel#metricLabel {{ color: {TEXT_SECONDARY}; font-size: 12px; font-weight: 600; }}
QLabel#metricNote {{ color: {TEXT_MUTED}; font-size: 10px; }}
QLabel#footer {{ color: {TEXT_MUTED}; font-size: 10px; }}
QFrame#activityLamp {{ background: {STATUS_OK}; border-radius: 5px; }}
QFrame#activityLamp[state="running"] {{ background: {STATUS_WARN}; }}
QFrame#activityLamp[state="error"] {{ background: {STATUS_ERROR}; }}
QSplitter::handle {{ background: #40204060; }}
QSplitter::handle:hover {{ background: {ACCENT}; }}
QToolTip {{ background: {BG_ELEVATED}; color: {TEXT_PRIMARY}; border: 1px solid {ACCENT}; padding: 8px 10px; border-radius: 8px; }}
QTextEdit#messageBody {{ background: transparent; border: none; border-radius: 0; padding: 0; font-size: 14px; }}
QFrame#chatComposer {{ background: #a0162840; border: 1px solid #6034d399; border-radius: 16px; }}
QFrame#chatUser {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #c01e4060,stop:1 #a0123048); border: 1px solid #6038bdf8; border-radius: 16px; }}
QFrame#chatAssistant {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #b0182e38,stop:1 #a00e1824); border: 1px solid #5034d399; border-radius: 16px; }}
QFrame#chatSystem {{ background: #70282830; border: 1px solid #60fb923c; border-radius: 12px; }}
"""


def severity_color(severity: str) -> str:
    return {"critical": SEV_CRITICAL, "high": SEV_HIGH, "medium": SEV_MEDIUM,
            "low": SEV_LOW, "info": SEV_INFO, "safe": SEV_SAFE}.get((severity or "").lower(), SEV_INFO)


def severity_bg(severity: str) -> str:
    return alpha(severity_color(severity), 36)
