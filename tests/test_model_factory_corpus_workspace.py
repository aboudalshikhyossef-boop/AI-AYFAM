"""Tests for private, content-addressed corpus imports."""

from __future__ import annotations

import os
from pathlib import Path
import stat

import pytest

from model_factory.corpus_workspace import import_raw_corpus


def test_import_copies_jsonl_atomically_with_private_permissions(tmp_path: Path):
    source = tmp_path / "source.jsonl"
    source.write_text('{"text":"hello"}\n', encoding="utf-8")
    workspace = tmp_path / "private-workspace"

    imported = import_raw_corpus(source, workspace=workspace)

    assert imported.parent == workspace
    assert imported.read_text(encoding="utf-8") == source.read_text(encoding="utf-8")
    assert imported != source
    assert stat.S_IMODE(imported.stat().st_mode) == 0o600
    assert import_raw_corpus(source, workspace=workspace) == imported

    source.write_text('{"text":"different"}\n', encoding="utf-8")
    second = import_raw_corpus(source, workspace=workspace)
    assert second != imported
    assert second.read_text(encoding="utf-8") == source.read_text(encoding="utf-8")


def test_import_rejects_symlinks_and_non_jsonl_files(tmp_path: Path):
    source = tmp_path / "source.jsonl"
    source.write_text('{"text":"hello"}\n', encoding="utf-8")
    link = tmp_path / "linked.jsonl"
    link.symlink_to(source)
    with pytest.raises(OSError):
        import_raw_corpus(link, workspace=tmp_path / "workspace")

    wrong_extension = tmp_path / "source.txt"
    wrong_extension.write_text("text", encoding="utf-8")
    with pytest.raises(ValueError, match=r"\.jsonl"):
        import_raw_corpus(wrong_extension, workspace=tmp_path / "workspace")


def test_import_rejects_empty_files(tmp_path: Path):
    source = tmp_path / "empty.jsonl"
    source.write_bytes(b"")
    with pytest.raises(ValueError, match="empty"):
        import_raw_corpus(source, workspace=tmp_path / "workspace")
