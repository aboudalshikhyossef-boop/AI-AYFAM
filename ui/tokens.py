"""
AI AYFAM — Centralized Design Tokens & Glassmorphism Theme Definitions
رموز التصميم والهوية البصرية المركزية — أسلوب الزجاج الحقيقي (Real Glassmorphism)
"""

from PyQt6.QtGui import QColor

class Tokens:
    # Colors (QColor and Hex)
    TEAL_HEX = "#2dd4bf"
    BLUE_HEX = "#60a5fa"
    VIOLET_HEX = "#a78bfa"
    AMBER_HEX = "#fbbf24"
    RED_HEX = "#f87171"
    GREEN_HEX = "#34d399"

    TEAL = QColor(TEAL_HEX)
    BLUE = QColor(BLUE_HEX)
    VIOLET = QColor(VIOLET_HEX)
    AMBER = QColor(AMBER_HEX)
    RED = QColor(RED_HEX)
    GREEN = QColor(GREEN_HEX)

    DARK_BG_PRIMARY = "#0D1117"
    DARK_BG_SECONDARY = "#161B22"
    DARK_BG_GLASS = "rgba(255, 255, 255, 0.07)"
    DARK_BORDER_GLASS = "rgba(255, 255, 255, 0.16)"

    TEXT_PRIMARY = "#f8fafc"
    TEXT_SECONDARY = "rgba(226, 238, 250, 0.62)"
    TEXT_MUTED = "rgba(226, 238, 250, 0.38)"

    # Severity Palette
    SEVERITY_CRITICAL = RED_HEX
    SEVERITY_HIGH = AMBER_HEX
    SEVERITY_MEDIUM = AMBER_HEX
    SEVERITY_LOW = BLUE_HEX
    SEVERITY_INFO = TEAL_HEX
    SEVERITY_SAFE = GREEN_HEX

    # Typography
    FONT_FAMILY = "Tajawal, Inter, SF Pro Display, -apple-system, Cairo, sans-serif"

    FONT_SIZE_XL = "24px"
    FONT_SIZE_LARGE = "18px"
    FONT_SIZE_BODY = "13px"
    FONT_SIZE_SMALL = "11px"

    # Radii
    RADIUS_CARD = 24
    RADIUS_BUTTON = 14
    RADIUS_BADGE = 10

    @classmethod
    def get_qss_stylesheet(cls, dark_mode: bool = True) -> str:
        from ui.theme import get_qss
        return get_qss() if dark_mode else get_qss("#6d8f8c", "#7d83a6")

    @classmethod
    def rgba(cls, color: QColor, alpha_val: int) -> QColor:
        out = QColor(color)
        out.setAlpha(alpha_val)
        return out

    @classmethod
    def css_rgba(cls, r: int, g: int, b: int, a: float) -> str:
        return f"rgba({r},{g},{b},{a})"
