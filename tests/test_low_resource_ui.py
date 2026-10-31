from pathlib import Path

from ui.performance import EVENT_POLL_INTERVAL_MS, LOW_RESOURCE_UI, TELEMETRY_REFRESH_MS


ROOT = Path(__file__).resolve().parents[1]


def test_low_resource_ui_is_the_default():
    assert LOW_RESOURCE_UI is True


def test_passive_refresh_intervals_are_reduced():
    assert TELEMETRY_REFRESH_MS >= 10_000
    assert EVENT_POLL_INTERVAL_MS >= 2_000


def test_gui_no_longer_installs_continuous_visual_controllers():
    source = (ROOT / "ui" / "gui_app.py").read_text(encoding="utf-8")
    assert "LiveBackdrop(self)" not in source
    assert "FrostedGlassController(" not in source
    assert "HoverController(self)" not in source
    assert "PressFeedbackController(self)" not in source
    assert "NavigationWheel(" not in source


def test_training_mode_hook_pauses_passive_refresh():
    source = (ROOT / "ui" / "gui_app.py").read_text(encoding="utf-8")
    assert "def set_training_mode(self, enabled: bool)" in source
    assert "self.timer.stop()" in source
    assert "self.event_timer.stop()" in source
