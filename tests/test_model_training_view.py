"""Tests for the desktop training workspace's safe idle state."""

import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtWidgets import QApplication
    from model_factory.corpus_review import inspect_raw_corpus
    from ui.views.corpus_review_dialog import CorpusReviewDialog
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



def test_corpus_review_dialog_previews_documents_and_accepts_valid_ratios(tmp_path):
    raw_path = tmp_path / "raw.jsonl"
    rows = []
    for index in range(3):
        document_id = f"review-book-{index}"
        rows.append({
            "id": f"{document_id}-chunk-0",
            "text": (
                f"Unique training passage for book {index}. "
                "This text is sufficiently long for a corpus review preview."
            ),
            "source": f"book-{index}.txt",
            "license": "CC-BY-4.0",
            "document_id": document_id,
            "group_id": document_id,
            "title": f"Book {index}",
            "filename": f"book-{index}.txt",
            "file_type": "txt",
            "page": 1,
            "chapter": "Introduction",
            "chunk_index": 0,
            "language": "en",
        })
    raw_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )

    dialog = CorpusReviewDialog(raw_path, inspect_raw_corpus(raw_path))
    assert dialog.table.rowCount() == 3
    assert dialog.preview.toPlainText() == rows[0]["text"]
    assert dialog.chunk_number.minimum() == 1
    assert dialog.chunk_number.maximum() == 1

    dialog._accept_review()

    selection = dialog.selection()
    assert selection["train_ratio"] == 0.90
    assert selection["validation_ratio"] == 0.05
    assert selection["test_ratio"] == 0.05
    assert selection["excluded_documents"] == set()
    dialog.close()
    dialog.deleteLater()
    APP.processEvents()
