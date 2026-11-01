"""Tests for the desktop training workspace's safe idle state."""

import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt6.QtWidgets import QApplication, QDialogButtonBox, QScrollArea
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
    assert not view.start_button.isEnabled()
    assert view.prepare_button.isEnabled()
    assert view.raw_corpus_input.text() == str(seed_path)
    assert isinstance(view.scroll_area, QScrollArea)
    assert view.scroll_area.widget() is not None
    assert not view.stop_button.isEnabled()
    assert view.epochs_input.value() == 3
    assert view.resume_checkbox.isChecked()
    assert "تلقائي" in view.vocab_auto_label.text()
    assert view.active_model_label.text()
    assert not hasattr(view, "steps_input")
    assert not hasattr(view, "vocab_input")
    view.memory_timer.stop()
    view.close()
    view.deleteLater()
    APP.processEvents()


def test_training_workspace_displays_calculated_full_epoch_workload():
    view = ModelTrainingView()
    view._on_training_plan({
        "train_records": 576,
        "train_tokens": 75_000,
        "train_blocks_per_epoch": 586,
        "batches_per_epoch": 586,
        "optimizer_steps_per_epoch": 147,
        "epochs": 3,
        "additional_steps": 441,
        "starting_step": 0,
        "block_size": 128,
        "micro_batch_size": 1,
        "gradient_accumulation_steps": 4,
        "tokenizer_vocab_target": 512,
        "tokenizer_vocab_actual": 512,
    })

    assert view.progress_bar.maximum() == 441
    assert "576 مقطع" in view.workload_label.text()
    assert "147 خطوة Optimizer" in view.workload_label.text()
    assert "3 Epoch" in view.workload_label.text()
    view.memory_timer.stop()
    view.close()
    view.deleteLater()
    APP.processEvents()


def test_training_view_supports_multiple_document_inputs_without_preimport_license(monkeypatch, tmp_path):
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
    assert not hasattr(view, "license_input")
    assert view.prepare_worker is None
    assert view.worker is None
    view.memory_timer.stop()
    view.close()
    view.deleteLater()
    APP.processEvents()



def test_single_book_review_is_scrollable_and_accepts_license_after_extraction(tmp_path):
    raw_path = tmp_path / "one-book.jsonl"
    document_id = "one-book"
    rows = []
    for index in range(12):
        rows.append({
            "id": f"one-book-chunk-{index}",
            "text": (
                f"Unique paragraph {index} from a single imported book. "
                "This passage is long enough for safe train validation and test examples."
            ),
            "source": "one-book.pdf",
            "license": "",
            "document_id": document_id,
            "group_id": document_id,
            "title": "One book",
            "filename": "one-book.pdf",
            "file_type": "pdf",
            "page": index + 1,
            "chapter": "Chapter 1",
            "chunk_index": index,
            "language": "en",
        })
    raw_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )

    report = inspect_raw_corpus(raw_path)
    dialog = CorpusReviewDialog(raw_path, report)

    assert dialog.scroll_area.widget() is not None
    assert dialog.findChild(QDialogButtonBox) is not None
    assert dialog.full_corpus_checkbox.isChecked()
    assert "100%" in dialog.split_notice.text()
    assert dialog.license_input.text() == ""

    dialog.license_input.setText("1 One book")
    dialog._accept_review()
    assert dialog._selection == {}
    assert "عنوان الكتاب" in dialog.error_label.text()

    dialog.license_input.setText("Written permission from the rights holder")
    dialog._accept_review()

    selection = dialog.selection()
    assert selection["full_corpus_training"] is True
    assert selection["train_ratio"] == 1.0
    assert selection["validation_ratio"] == 0.0
    assert selection["test_ratio"] == 0.0
    assert selection["excluded_documents"] == set()
    assert selection["metadata_overrides"][document_id]["license"] == (
        "Written permission from the rights holder"
    )
    dialog.close()
    dialog.deleteLater()
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

    dialog.full_corpus_checkbox.setChecked(False)
    dialog._accept_review()

    selection = dialog.selection()
    assert selection["full_corpus_training"] is False
    assert selection["train_ratio"] == 0.90
    assert selection["validation_ratio"] == 0.05
    assert selection["test_ratio"] == 0.05
    assert selection["excluded_documents"] == set()
    dialog.close()
    dialog.deleteLater()
    APP.processEvents()
