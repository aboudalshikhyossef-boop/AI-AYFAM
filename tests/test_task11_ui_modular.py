"""
Unit tests for Task 11 — UI Tokens, Views, and Offscreen Verification
"""

import os
import pytest
from PyQt6.QtWidgets import QApplication, QWidget
from ui.tokens import Tokens
from ui.views.dashboard import DashboardView
from ui.views.scan import ScanView
from ui.views.findings import FindingsView
from ui.views.timeline import TimelineView
from ui.views.sentinel import SentinelView
from ui.views.knowledge import KnowledgeView
from ui.views.settings import SettingsView
from ui.views.attack_graph import AttackChainGraphView

@pytest.fixture(scope="module")
def qapp():
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance()
    if not app:
        app = QApplication([])
    return app

def test_tokens_definition():
    assert Tokens.DARK_BG_PRIMARY == "#0D1117"
    stylesheet = Tokens.get_qss_stylesheet()
    assert "font-family" in stylesheet

def test_ui_views_instantiation(qapp):
    dashboard = DashboardView()
    assert dashboard is not None

    scan = ScanView()
    assert scan is not None

    findings = FindingsView()
    assert findings is not None

    timeline = TimelineView()
    assert timeline is not None

    sentinel = SentinelView()
    assert sentinel is not None

    knowledge = KnowledgeView()
    assert knowledge is not None

    settings = SettingsView()
    assert settings is not None

    graph = AttackChainGraphView()
    assert graph is not None
