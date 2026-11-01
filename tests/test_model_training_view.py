"""Tests for the desktop training workspace's safe idle state."""

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtWidgets import QApplication
    from ui.views.model_training import ModelTrainingView
except (ImportError, OSError) as exc:
    pytest.skip(f"Qt runtime is unavailable ({exc})", allow_module_level=True)


APP = QApplication.instance() or QApplication([])


def test_training_view_does_not_start_import_or_training_on_construction():
    view = ModelTrainingView()
    seed_path = (
        Path(__file__).resolve().parents[1]
        / "data"
        / "seed_corpus"
        / "v0.1"
        / "ayfam-seed-v0.1.jsonl"
    )
    assert view.worker is None
    assert view.prepare_worker is None
    assert view.start_button.isEnabled()
    assert view.prepare_button.isEnabled()
    assert view.raw_corpus_input.text() == str(seed_path)
    assert not view.stop_button.isEnabled()
    assert view.steps_input.value() == 20
    assert view.vocab_input.value() == 512
    view.memory_timer.stop()
    view.close()
    view.deleteLater()
    APP.processEvents()


def test_training_view_supports_multiple_document_inputs_and_license(monkeypatch, tmp_path):
    first = tmp_path / "first.md"
    second = tmp_path / "second.docx"
    first.write_text("# First\nText", encoding="utf-8")
    second.write_bytes(b"docx placeholder")
    selected = [str(first), str(second)]
    monkeypatch.setattr(
        "ui.views.model_training.QFileDialog.getOpenFileNames",
        lambda *args, **kwargs: (selected, ""),
    )

    view = ModelTrainingView()
    view._browse_raw_corpus()

    assert view.raw_document_paths == [first, second]
    assert "2 file(s)" in view.raw_corpus_input.text()
    assert view.license_input.text() == ""
    assert view.prepare_worker is None
    assert view.worker is None
    view.memory_timer.stop()
    view.close()
    view.deleteLater()
    APP.processEvents()
