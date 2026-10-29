"""
AI AYFAM — Centralized Design Tokens & Glassmorphism Theme Definitions
رموز التصميم والهوية البصرية المركزية — أسلوب الزجاج الحقيقي (Real Glassmorphism)
"""

from PyQt6.QtGui import QColor
from ui import theme


class Tokens:
    # Colors (QColor and Hex)
    TEAL_HEX = theme.ACCENT
    BLUE_HEX = theme.SEV_LOW
    VIOLET_HEX = theme.ACCENT_SECONDARY
    AMBER_HEX = theme.SEV_HIGH
    RED_HEX = theme.SEV_CRITICAL
    GREEN_HEX = theme.SEV_SAFE

    TEAL = QColor(TEAL_HEX)
    BLUE = QColor(BLUE_HEX)
    VIOLET = QColor(VIOLET_HEX)
    AMBER = QColor(AMBER_HEX)
    RED = QColor(RED_HEX)
    GREEN = QColor(GREEN_HEX)

    DARK_BG_PRIMARY = theme.BG_BASE
    DARK_BG_SECONDARY = theme.BG_ELEVATED
    DARK_BG_GLASS = theme.BG_SURFACE
    DARK_BORDER_GLASS = theme.BORDER
    SPECULAR_REFLECTION = theme.BG_HOVER
    LUMINOUS_INNER_BORDER = theme.BORDER

    TEXT_PRIMARY = theme.TEXT_PRIMARY
    TEXT_SECONDARY = theme.TEXT_SECONDARY
    TEXT_MUTED = theme.TEXT_MUTED

    # Severity Palette
    SEVERITY_CRITICAL = RED_HEX
    SEVERITY_HIGH = AMBER_HEX
    SEVERITY_MEDIUM = theme.SEV_MEDIUM
    SEVERITY_LOW = BLUE_HEX
    SEVERITY_INFO = theme.SEV_INFO
    SEVERITY_SAFE = GREEN_HEX

    # Typography
    FONT_FAMILY = theme.FONT_FAMILY

    FONT_SIZE_XL = f"{theme.SP_2XL}px"
    FONT_SIZE_LARGE = f"{theme.FONT_SIZE_TITLE}px"
    FONT_SIZE_BODY = f"{theme.FONT_SIZE_BASE}px"
    FONT_SIZE_SMALL = f"{theme.FONT_SIZE_SMALL}px"

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
