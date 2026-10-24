"""
AI AYFAM — Centralized Design Tokens & Modern Theme Definitions
رموز التصميم والهوية البصرية المركزية — الألوان، التباين، الأبعاد، وأنماط Glassmorphic
"""

class Tokens:
    # Color Palette - Dark Glassmorphism
    DARK_BG_PRIMARY = "#0D1117"
    DARK_BG_SECONDARY = "#161B22"
    DARK_BG_GLASS = "rgba(22, 27, 34, 0.75)"
    DARK_BORDER_GLASS = "rgba(255, 255, 255, 0.12)"
    LIGHT_BG_PRIMARY = "#F6F8FA"
    LIGHT_BG_SECONDARY = "#FFFFFF"
    LIGHT_BORDER_GLASS = "rgba(27, 31, 36, 0.18)"
    LIGHT_TEXT_PRIMARY = "#1F2328"
    LIGHT_TEXT_SECONDARY = "#59636E"

    TEXT_PRIMARY = "#F0F6FC"
    TEXT_SECONDARY = "#8B949E"
    TEXT_MUTED = "#6E7681"

    ACCENT_CYAN = "#58A6FF"
    ACCENT_NEON_GREEN = "#3FB950"

    # Severity Palette (Color-blind safe with icon shapes)
    SEVERITY_CRITICAL = "#DA3633"  # Red [!]
    SEVERITY_HIGH = "#D29922"      # Orange [▲]
    SEVERITY_MEDIUM = "#E3B341"    # Yellow [●]
    SEVERITY_LOW = "#58A6FF"       # Blue [i]
    SEVERITY_INFO = "#8B949E"      # Gray [✓]

    # Typography Scale
    FONT_FAMILY_AR = "Noto Sans Arabic, Noto Naskh Arabic, Segoe UI, sans-serif"
    FONT_FAMILY_EN = "Inter, Roboto, Segoe UI, sans-serif"

    FONT_SIZE_XL = "22px"
    FONT_SIZE_LARGE = "16px"
    FONT_SIZE_BODY = "14px"
    FONT_SIZE_SMALL = "12px"

    # Spacing & Radii
    RADIUS_CARD = "12px"
    RADIUS_BUTTON = "8px"
    RADIUS_BADGE = "6px"

    PADDING_CARD = "16px"
    PADDING_BUTTON = "8px 16px"

    @classmethod
    def get_qss_stylesheet(cls, dark_mode: bool = True) -> str:
        bg_primary = cls.DARK_BG_PRIMARY if dark_mode else cls.LIGHT_BG_PRIMARY
        bg_secondary = cls.DARK_BG_SECONDARY if dark_mode else cls.LIGHT_BG_SECONDARY
        border = cls.DARK_BORDER_GLASS if dark_mode else cls.LIGHT_BORDER_GLASS
        text_primary = cls.TEXT_PRIMARY if dark_mode else cls.LIGHT_TEXT_PRIMARY
        text_secondary = cls.TEXT_SECONDARY if dark_mode else cls.LIGHT_TEXT_SECONDARY
        return f"""
        QWidget {{
            background-color: {bg_primary};
            color: {text_primary};
            font-family: {cls.FONT_FAMILY_AR};
            font-size: {cls.FONT_SIZE_BODY};
        }}
        QFrame.glass-card {{
            background-color: {bg_secondary};
            border: 1px solid {border};
            border-radius: {cls.RADIUS_CARD};
            padding: {cls.PADDING_CARD};
        }}
        QPushButton {{
            background-color: {cls.ACCENT_CYAN};
            color: #000000;
            border-radius: {cls.RADIUS_BUTTON};
            padding: {cls.PADDING_BUTTON};
            font-weight: bold;
        }}
        QPushButton:hover {{
            background-color: #79C0FF;
        }}
        QLabel, QTextEdit, QListWidget {{
            color: {text_primary};
        }}
        QLineEdit, QTextEdit, QListWidget {{
            background-color: {bg_secondary};
            border: 1px solid {border};
        }}
        QToolTip {{
            color: {text_primary};
            background-color: {bg_secondary};
            border: 1px solid {border};
        }}
        """
