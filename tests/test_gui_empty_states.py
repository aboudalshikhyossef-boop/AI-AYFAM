"""Tests for Phase 5: Honest state indicators & empty state views."""

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import QApplication
from ui.gui_app import UnifiedCockpitWindow


def test_honest_state_indicators_and_empty_views():
    app = QApplication.instance() or QApplication([])
    window = UnifiedCockpitWindow()

    # 1. Check metric tags initial states
    assert window.metric_tags["connections"].text() == "مباشر"
    assert window.metric_tags["processes"].text() == "نشط"
    assert window.metric_tags["findings"].text() == "لم يُفحص"
    assert window.metric_tags["score"].text() == "غير مقيّم"

    # 2. Check metric tags dynamic update
    findings = [{"title": "Open SSH Port", "severity": "high", "category": "network"}]
    window._update_score(findings)
    assert window.metric_tags["findings"].text() == "يحتاج مراجعة"
    assert window.metric_tags["score"].text() == "تم التقييم"

    window._update_score([])
    assert window.metric_tags["findings"].text() == "سليم"

    # 3. Check playbooks presets
    window.switch_page("playbooks")
    assert hasattr(window, "pb_input")
    assert "إحدى الخطط الجاهزة" in window.pb_text.placeholderText()

    # 4. Check library empty placeholder
    window.switch_page("library")
    assert "فارغة حالياً" in window.library_results.placeholderText()

    window.close()
