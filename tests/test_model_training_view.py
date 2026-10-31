"""Tests for the desktop training workspace's safe idle state."""

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtWidgets import QApplication
    from ui.views.model_training import ModelTrainingView
except (ImportError, OSError) as exc:
    pytest.skip(f"Qt runtime is unavailable ({exc})", allow_module_level=True)


APP = QApplication.instance() or QApplication([])


def test_training_view_does_not_start_training_on_construction():
    view = ModelTrainingView()
    assert view.worker is None
    assert view.start_button.isEnabled()
    assert not view.stop_button.isEnabled()
    assert view.steps_input.value() == 20
    assert view.vocab_input.value() == 512
    view.memory_timer.stop()
    view.close()
    view.deleteLater()
    APP.processEvents()
