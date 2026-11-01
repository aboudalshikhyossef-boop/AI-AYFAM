"""Tests for local multi-format document ingestion into the training corpus."""

from __future__ import annotations

import json
from pathlib import Path
import zipfile

import pytest

from model_factory.corpus_tools import prepare_corpus, validate_prepared_corpus
from model_factory.data import iter_records
from model_factory.document_ingestion import (
    DocumentIngestionError,
    DocumentInput,
    ingest_documents,
)


LICENSE = "CC-BY-4.0"


def _doc(path: Path, *, source: str | None = None, license_name: str = LICENSE) -> DocumentInput:
    return DocumentInput(
        path=path,
        source=source or path.name,
        license=license_name,
        title=path.stem,
    )


def _write_docx(path: Path) -> None:
    document_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
      <w:body>
        <w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr>
          <w:r><w:t>Chapter One</w:t></w:r></w:p>
        <w:p><w:r><w:t>DOCX paragraph with Arabic النص العربي.</w:t></w:r></w:p>
        <w:p><w:r><w:t>Second paragraph.</w:t></w:r></w:p>
      </w:body>
    </w:document>"""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", document_xml)


def _write_pdf(path: Path, text: str) -> None:
    """Create a tiny valid one-page PDF with a standard Type1 font."""
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 12 Tf 72 720 Td ({escaped}) Tj ET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n"
        + stream + b"\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(b"xref\n0 6\n0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n"
        + str(xref_offset).encode("ascii")
        + b"\n%%EOF\n"
    )
    path.write_bytes(output)


def test_markdown_ingestion_keeps_chapter_and_source_metadata(tmp_path: Path):
    source = tmp_path / "networking.md"
    source.write_text(
        "# Networking\n\nTCP provides reliable delivery.\n\n"
        "## Addressing\n\nIP addresses identify network interfaces.\n",
        encoding="utf-8",
    )
    output = tmp_path / "raw.jsonl"

    report = ingest_documents([_doc(source)], output, chunk_size=128, overlap=16)

    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert report.documents == 1
    assert report.chunks == len(records)
    assert report.characters > 0
    assert report.fingerprint
    assert {record["file_type"] for record in records} == {"md"}
    assert {record["source"] for record in records} == {"networking.md"}
    assert {record["license"] for record in records} == {LICENSE}
    assert {record["title"] for record in records} == {"networking"}
    assert any(record["chapter"] == "Networking" for record in records)
    assert any(record["chapter"] == "Addressing" for record in records)
    assert all(record["group_id"] == records[0]["document_id"] for record in records)
    assert all(record["page"] is None for record in records)


def test_txt_ingestion_detects_arabic_chapter_and_splits_long_content(tmp_path: Path):
    source = tmp_path / "arabic.txt"
    source.write_text(
        "الفصل ١: مقدمة\n\n" + ("هذه فقرة عربية تتحدث عن الشبكات والحاسوب. " * 30),
        encoding="utf-8",
    )
    output = tmp_path / "raw.jsonl"

    report = ingest_documents([_doc(source)], output, chunk_size=128, overlap=24)

    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert report.chunks > 1
    assert all(record["chapter"].startswith("الفصل") for record in records)
    assert all(record["language"] == "ar" for record in records)
    assert [record["chunk_index"] for record in records] == list(range(len(records)))


def test_docx_ingestion_extracts_paragraphs_and_heading_style(tmp_path: Path):
    source = tmp_path / "systems.docx"
    _write_docx(source)
    output = tmp_path / "raw.jsonl"

    report = ingest_documents([_doc(source)], output)

    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert report.documents == 1
    assert any(record["chapter"] == "Chapter One" for record in records)
    assert any("النص العربي" in record["text"] for record in records)
    assert all(record["file_type"] == "docx" for record in records)
    assert all(record["page"] == 1 for record in records)


def test_pdf_ingestion_preserves_one_based_page_numbers(tmp_path: Path):
    source = tmp_path / "networks.pdf"
    _write_pdf(source, "PDF text extraction for AYFAM")
    output = tmp_path / "raw.jsonl"

    report = ingest_documents([_doc(source)], output)

    records = [
        json.loads(line)
        for line in output.read_text(encoding="utf-8").splitlines()
    ]
    assert report.pages == 1
    assert report.empty_pages == 0
    assert len(records) == 1
    assert records[0]["page"] == 1
    assert records[0]["file_type"] == "pdf"
    assert "PDF text extraction" in records[0]["text"]


def test_preparation_preserves_document_metadata_and_group_identity(tmp_path: Path):
    source = tmp_path / "chapter.md"
    source.write_text("# Chapter A\n\nA small technical passage about operating systems.", encoding="utf-8")
    raw = tmp_path / "raw.jsonl"
    prepared = tmp_path / "prepared.jsonl"
    ingest_documents([_doc(source)], raw)
    prepare_corpus(
        raw,
        prepared,
        train_ratio=1.0,
        validation_ratio=0.0,
        test_ratio=0.0,
    )

    record = next(iter_records(prepared))
    report = validate_prepared_corpus(prepared, require_held_out=False)
    assert record.title == "chapter"
    assert record.filename == "chapter.md"
    assert record.file_type == "md"
    assert record.chapter == "Chapter A"
    assert record.document_id
    assert record.group_id == record.document_id
    assert report.total_records == 1


def test_ingestion_stages_text_before_license_review_and_checks_extension(tmp_path: Path):
    source = tmp_path / "book.txt"
    source.write_text("Some content.", encoding="utf-8")

    report = ingest_documents(
        [_doc(source, license_name="")],
        tmp_path / "raw.jsonl",
    )
    assert report.chunks == 1
    payload = json.loads((tmp_path / "raw.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert payload["license"] == ""

    unsupported = tmp_path / "book.rtf"
    unsupported.write_text("Some content.", encoding="utf-8")
    with pytest.raises(DocumentIngestionError, match="unsupported"):
        ingest_documents([_doc(unsupported)], tmp_path / "unsupported.jsonl")


def test_failed_ingestion_does_not_overwrite_existing_output(tmp_path: Path):
    source = tmp_path / "empty.md"
    source.write_text(" \n\n   \n", encoding="utf-8")
    output = tmp_path / "existing.jsonl"
    output.write_text('{"existing": true}\n', encoding="utf-8")

    with pytest.raises(DocumentIngestionError, match="no usable text"):
        ingest_documents([_doc(source)], output)

    assert output.read_text(encoding="utf-8") == '{"existing": true}\n'


def test_ingestion_rejects_duplicate_files_and_invalid_chunk_options(tmp_path: Path):
    source = tmp_path / "book.md"
    source.write_text("A valid paragraph for ingestion.", encoding="utf-8")
    output = tmp_path / "raw.jsonl"

    with pytest.raises(DocumentIngestionError, match="selected more than once"):
        ingest_documents([_doc(source), _doc(source)], output)
    with pytest.raises(ValueError, match="overlap"):
        ingest_documents([_doc(source)], output, chunk_size=64, overlap=64)


def test_document_level_splits_keep_whole_books_together(tmp_path: Path):
    documents = []
    for index, title in enumerate(("networks", "systems", "programming")):
        path = tmp_path / f"{title}.md"
        path.write_text(
            f"# {title.title()}\n\n"
            + (f"Independent technical material {index} about {title}. " * 8),
            encoding="utf-8",
        )
        documents.append(_doc(path))

    output = tmp_path / "held-out.jsonl"
    report = ingest_documents(documents, output, require_held_out=True)

    records = list(iter_records(output))
    splits_by_document = {}
    for record in records:
        previous = splits_by_document.setdefault(record.document_id, record.split)
        assert previous == record.split

    assert set(report.records_by_split) == {"train", "validation", "test"}
    assert set(splits_by_document.values()) == {"train", "validation", "test"}
    assert sum(report.records_by_split.values()) == report.chunks


def test_held_out_splits_require_three_independent_documents(tmp_path: Path):
    documents = []
    for title in ("book-a", "book-b"):
        path = tmp_path / f"{title}.txt"
        path.write_text(f"Distinct text belonging to {title}.", encoding="utf-8")
        documents.append(_doc(path))

    output = tmp_path / "not-created.jsonl"
    with pytest.raises(DocumentIngestionError, match="at least three independent documents"):
        ingest_documents(documents, output, require_held_out=True)
    assert not output.exists()
