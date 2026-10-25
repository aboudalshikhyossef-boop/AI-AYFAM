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
from ui.gui_app import NAV_ITEMS
from ui.icons import ICON_COLORS
from ui.widgets import SoundUX

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
    assert Tokens.get_qss_stylesheet(dark_mode=False) != stylesheet

def test_views_are_reachable_from_main_navigation():
    nav_keys = {key for key, _label in NAV_ITEMS}
    assert {"findings", "timeline", "sentinel", "attack_graph"}.issubset(nav_keys)

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


def test_navigation_icons_have_distinct_page_accents():
    nav_keys = {key for key, _label in NAV_ITEMS}
    assert nav_keys.issubset(ICON_COLORS)
    assert len({ICON_COLORS[key] for key in nav_keys}) == len(nav_keys)


def test_findings_view_filters_and_displays_selected_evidence(qapp):
    view = FindingsView()
    view.set_findings([
        {
            "id": "finding-1", "severity": "critical", "title": "Weak SSH configuration",
            "category": "system", "detail": "Password login is enabled.",
            "confidence": 0.9, "evidence": {"path": "/etc/ssh/sshd_config"},
        },
        {
            "id": "finding-2", "severity": "low", "title": "Informational package note",
            "category": "package", "detail": "A package update is available.",
            "confidence": 0.7,
        },
    ])
    assert view.table.rowCount() == 2
    assert "Evidence" in view.detail_text.toPlainText()

    view.severity_filter.setCurrentIndex(view.severity_filter.findData("critical"))
    assert view.table.rowCount() == 1
    assert "Weak SSH configuration" in view.detail_text.toPlainText()

    view.search_input.setText("no matching finding")
    assert view.table.rowCount() == 0
    assert not view.empty_state.parentWidget().isHidden()


def test_timeline_sentinel_and_attack_graph_accept_local_data(qapp):
    timeline = TimelineView()
    timeline.set_events([
        {
            "timestamp": 1_700_000_000,
            "item_type": "event",
            "source": "fixture",
            "title": "Firewall state changed",
            "detail": "Fixture event.",
            "severity": "info",
        },
        {
            "timestamp": 1_700_000_100,
            "item_type": "finding",
            "source": "system",
            "title": "Weak SSH configuration",
            "detail": "Fixture finding.",
            "severity": "high",
        },
    ])
    assert timeline.table.rowCount() == 2
    assert "2 timeline items" in timeline.status.text()

    sentinel = SentinelView()
    sentinel.set_events([], monitoring=False)
    assert sentinel.table.rowCount() == 0
    assert "المراقبة غير مفعلة" in sentinel.monitor_status.text()

    graph = AttackChainGraphView()
    graph.render_chain(
        [{
            "severity": "critical",
            "title": "SSH compromise path",
            "detail": "Correlated fixture chain.",
            "evidence": {
                "ssh_title": "Weak SSH configuration",
                "brute_title": "Repeated failed logins",
            },
        }]
    )
    assert len(graph.scene.items()) >= 7
    assert not graph.view.isHidden()


def test_confirm_sound_profile_does_not_play_success_for_each_click(qapp):
    class FakeEffect:
        def __init__(self):
            self.plays = 0
            self.volume = None

        def play(self):
            self.plays += 1

        def setVolume(self, value):
            self.volume = value

    sound = SoundUX(qapp)
    click, success = FakeEffect(), FakeEffect()
    sound.effects = {"click": click, "success": success}
    sound.set_profile("confirm")
    sound.play("click")
    assert click.plays == 1
    assert success.plays == 0
    assert click.volume == 0.18
    sound.play("success")
    assert success.plays == 1
