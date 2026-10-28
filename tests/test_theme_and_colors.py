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
        "#7d83a6", "#e6f6ff", "#09131e", "#0a1022", "#050912", "#4f46e5", "#0ea5e9", "#22d3ee", "#7c6cf0",
        "#090f1f", "#02050c", "#060b18", "#090f23", "#4338ca", "#0284c7",
        # Palette used by ui/glass_engine.py presets (deep_ocean, aurora, neon_ring, graphite)
        "#010103", "#020611", "#040711", "#05070b", "#06b6d4", "#1d4ed8",
        "#38bdf8", "#3b6cff", "#3b82f6", "#475569", "#60a5fa", "#7dd3fc", "#818cf8",
        "#8b5cf6", "#94a3b8", "#a5b4fc", "#a855f7", "#cbd5e1", "#f472b6", "#ff2d55", "#ff6b8b",
    }

    unapproved = []
    for filepath in files:
        if "theme.py" in filepath or "tokens.py" in filepath:
            continue
        content = Path(filepath).read_text(encoding="utf-8")
        matches = set(hex_pattern.findall(content))
        forbidden = matches - WHITELIST
        if forbidden:
            unapproved.append((filepath, forbidden))

    assert not unapproved, f"Found unapproved hex colors outside theme.py: {unapproved}"


def test_severity_bg():
    from ui.theme import (
        SEV_CRITICAL,
        SEV_HIGH,
        SEV_MEDIUM,
        SEV_LOW,
        SEV_INFO,
        SEV_SAFE,
        alpha,
        severity_bg,
        severity_color,
    )

    # 1. critical
    assert severity_bg("critical") == alpha(SEV_CRITICAL, 38)
    assert severity_bg("CRITICAL") == alpha(severity_color("critical"), 38)

    # 2. high
    assert severity_bg("high") == alpha(SEV_HIGH, 38)
    assert severity_bg("HIGH") == alpha(severity_color("high"), 38)

    # 3. medium
    assert severity_bg("medium") == alpha(SEV_MEDIUM, 38)
    assert severity_bg("Medium") == alpha(severity_color("medium"), 38)

    # 4. low
    assert severity_bg("low") == alpha(SEV_LOW, 38)
    assert severity_bg("LOW") == alpha(severity_color("low"), 38)

    # 5. info
    assert severity_bg("info") == alpha(SEV_INFO, 38)
    assert severity_bg("INFO") == alpha(severity_color("info"), 38)

    # 6. safe
    assert severity_bg("safe") == alpha(SEV_SAFE, 38)
    assert severity_bg("SAFE") == alpha(severity_color("safe"), 38)

    # 7. unknown value
    assert severity_bg("unknown_level") == alpha(SEV_INFO, 38)
    assert severity_bg("unknown_level") == alpha(severity_color("unknown_level"), 38)

    # 8. empty value
    assert severity_bg("") == alpha(SEV_INFO, 38)
    assert severity_bg(None) == alpha(SEV_INFO, 38)
    assert severity_bg("") == alpha(severity_color(""), 38)

    # Verify that different severities produce distinct background colors matching severity_color
    assert severity_bg("critical") != severity_bg("high")
    assert severity_bg("high") != severity_bg("medium")
    assert severity_bg("medium") != severity_bg("low")
    assert severity_bg("low") != severity_bg("info")
    assert severity_bg("info") != severity_bg("safe")
