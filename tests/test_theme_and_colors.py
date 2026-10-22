"""Tests for Phase 8: Theme, colors, fonts, and visual tokens enforcement."""

import glob
import os
import re
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]


def test_embedded_fonts_exist():
    fonts_dir = ROOT_DIR / "resources" / "fonts"
    assert (fonts_dir / "Tajawal-Regular.ttf").exists()
    assert (fonts_dir / "Tajawal-Bold.ttf").exists()
    assert (fonts_dir / "OFL.txt").exists()


def test_theme_icon_tokens():
    from ui.theme import COLOR_ICON_INACTIVE, COLOR_ICON_ACTIVE, FONT_FAMILY
    assert COLOR_ICON_INACTIVE == "#8fb3d1"
    assert "Tajawal" in FONT_FAMILY


def test_no_unapproved_hardcoded_hex_colors():
    """Ensure no unapproved raw hex colors appear in UI modules outside ui/theme.py."""
    hex_pattern = re.compile(r'#[0-9a-fA-F]{3,8}\b')
    files = glob.glob(str(ROOT_DIR / "ui" / "*.py"))

    # Whitelisted hex colors (standard dark background, white, common status hues, fallback theme)
    WHITELIST = {
        "#0d1726", "#08101a", "#050a12", "#0d1b2a", "#0f1c2d", "#0f766e", "#14b8a6", "#5eead4",
        "#ffffff", "#030712", "#0d9488", "#2dd4bf", "#34d399", "#6366f1", "#64748b", "#8fb3d1",
        "#a78bfa", "#f59e0b", "#f87171", "#f8fafc", "#fb923c", "#edf5fb", "#d29922", "#6d8f8c",
        "#7d83a6", "#e6f6ff", "#09131e",
    }

    unapproved = []
    for filepath in files:
        if "theme.py" in filepath:
            continue
        content = Path(filepath).read_text(encoding="utf-8")
        matches = set(hex_pattern.findall(content))
        forbidden = matches - WHITELIST
        if forbidden:
            unapproved.append((filepath, forbidden))

    assert not unapproved, f"Found unapproved hex colors outside theme.py: {unapproved}"
