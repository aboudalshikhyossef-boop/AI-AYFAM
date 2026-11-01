"""Regression tests for the corpus review and approval workflow."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from model_factory.corpus_review import (
    get_document_chunk,
    inspect_raw_corpus,
    prepare_reviewed_corpus,
)
from model_factory.data import iter_records


def _write_raw(path: Path, document_count: int = 4) -> list[str]:
    ids = []
    rows = []
    for index in range(document_count):
        document_id = f"document-{index}"
        ids.append(document_id)
        for chunk_index in range(2):
            rows.append({
                "id": f"{document_id}-chunk-{chunk_index}",
                "text": (
                    f"Unique technical content for document {index}, chunk {chunk_index}. "
                    "This passage contains enough words to be useful as training data."
                ),
                "source": f"source-{index}.txt",
                "license": "CC-BY-4.0",
                "document_id": document_id,
                "group_id": document_id,
                "title": f"Book {index}",
                "filename": f"book-{index}.txt",
                "file_type": "txt",
                "chapter": "Introduction",
                "page": chunk_index + 1,
                "chunk_index": chunk_index,
                "language": "en",
            })
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    return ids


def test_inspection_reports_document_quality_and_duplicates(tmp_path: Path):
    source = tmp_path / "raw.jsonl"
    ids = _write_raw(source, 3)
    rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines()]
    rows.extend([
        {**rows[0], "id": "duplicate-copy"},
        {**rows[1], "id": "tiny-chunk", "text": "tiny"},
        {**rows[2], "id": "malformed-chunk", "text": "This deliberately long text is used to test replacement characters in a realistic paragraph: \ufffd and additional context to keep it above the short-chunk threshold."},
        {**rows[2], "id": "unnormalized-chunk", "text": "This deliberately long paragraph contains extra   spaces between words, so normalization must detect the irregular spacing without classifying the sample as a tiny chunk."},
    ])
    source.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )

    report = inspect_raw_corpus(source)
    documents = {item["document_id"]: item for item in report["documents"]}

    assert report["chunks"] == 10
    assert report["duplicate_chunks"] == 1
    assert report["tiny_chunks"] == 1
    assert report["malformed_chunks"] == 1
    assert report["unnormalized_chunks"] == 1
    assert len(report["fingerprint"]) == 64
    assert documents[ids[0]]["chunks"] == 4
    assert documents[ids[0]]["pages_with_text"] == 2


def test_preview_returns_text_and_location_for_one_chunk(tmp_path: Path):
    source = tmp_path / "raw.jsonl"
    ids = _write_raw(source, 3)

    preview = get_document_chunk(source, ids[1], 1)

    assert preview["id"] == f"{ids[1]}-chunk-1"
    assert preview["page"] == 2
    assert preview["chapter"] == "Introduction"
    assert "document 1, chunk 1" in preview["text"]


def test_review_applies_exclusions_and_metadata_then_splits_by_document(tmp_path: Path):
    source = tmp_path / "raw.jsonl"
    ids = _write_raw(source, 4)
    output = tmp_path / "prepared.jsonl"

    report = prepare_reviewed_corpus(
        source,
        output,
        excluded_documents={ids[3]},
        excluded_chunks={(ids[0], f"{ids[0]}-chunk-0")},
        metadata_overrides={
            ids[1]: {
                "title": "Reviewed networking book",
                "source": "publisher archive",
                "license": "CC-BY-4.0",
            }
        },
        train_ratio=0.80,
        validation_ratio=0.10,
        test_ratio=0.10,
        seed=17,
    )

    records = list(iter_records(output))
    document_splits = {}
    for record in records:
        previous = document_splits.setdefault(record.document_id, record.split)
        assert previous == record.split

    assert ids[3] not in document_splits
    assert sum(record.document_id == ids[0] for record in records) == 1
    reviewed = [record for record in records if record.document_id == ids[1]]
    assert reviewed
    assert {record.title for record in reviewed} == {"Reviewed networking book"}
    assert {record.source for record in reviewed} == {"publisher archive"}
    assert set(document_splits.values()) == {"train", "validation", "test"}
    assert report["excluded_documents"] == 1
    assert report["excluded_chunks"] == 1
    assert Path(report["manifest_path"]).is_file()

    manifest = json.loads(Path(report["manifest_path"]).read_text(encoding="utf-8"))
    assert manifest["corpus_fingerprint"] == report["fingerprint"]
    assert manifest["split_ratios"] == {
        "train": 0.80,
        "validation": 0.10,
        "test": 0.10,
    }


def test_sequential_fallback_requires_enough_chunks_per_remaining_book(tmp_path: Path):
    source = tmp_path / "raw.jsonl"
    ids = _write_raw(source, 3)

    with pytest.raises(ValueError, match="at least five reviewed chunks"):
        prepare_reviewed_corpus(
            source,
            tmp_path / "prepared.jsonl",
            excluded_documents={ids[2]},
        )


def test_inspection_reports_metadata_conflicts_for_review(tmp_path: Path):
    source = tmp_path / "conflicting.jsonl"
    ids = _write_raw(source, 3)
    rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines()]
    rows[1]["license"] = "MIT"
    source.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )

    report = inspect_raw_corpus(source)
    document = next(row for row in report["documents"] if row["document_id"] == ids[0])

    assert document["metadata_conflicts"] == 1


def test_review_rejects_one_document_spanning_multiple_group_ids(tmp_path: Path):
    source = tmp_path / "inconsistent-groups.jsonl"
    _write_raw(source, 3)
    rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines()]
    rows[1]["group_id"] = "different-group"
    source.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="more than one group_id"):
        prepare_reviewed_corpus(source, tmp_path / "prepared.jsonl")


def test_single_book_uses_contiguous_chunk_splits_and_boundary_guards(tmp_path: Path):
    source = tmp_path / "single-book.jsonl"
    document_id = "one-large-book"
    rows = []
    for index in range(20):
        rows.append({
            "id": f"chunk-{index}",
            "text": (
                f"Unique long passage number {index} with independent detailed facts "
                "for testing contiguous data partitions and preventing overlap leakage."
            ),
            "source": "publisher archive",
            "license": "Written permission from the rights holder",
            "document_id": document_id,
            "group_id": document_id,
            "title": "One large book",
            "filename": "one-large-book.pdf",
            "file_type": "pdf",
            "page": index + 1,
            "chapter": f"Chapter {index // 5 + 1}",
            "chunk_index": index,
            "language": "en",
        })
    source.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )

    output = tmp_path / "single-book-prepared.jsonl"
    report = prepare_reviewed_corpus(source, output)
    records = list(iter_records(output))
    document_splits = {record.split for record in records}
    group_splits = {}
    for record in records:
        previous = group_splits.setdefault(record.group_id, record.split)
        assert previous == record.split

    assert report["split_strategy"] == "sequential_chunks"
    assert report["overlap_guard_chunks_removed"] == 2
    assert document_splits == {"train", "validation", "test"}
    assert len(records) == 18
    assert len({record.document_id for record in records}) == 1


def test_raw_corpus_can_be_reviewed_before_license_is_provided(tmp_path: Path):
    source = tmp_path / "staged-without-license.jsonl"
    document_ids = _write_raw(source, 3)
    rows = [json.loads(line) for line in source.read_text(encoding="utf-8").splitlines()]
    for row in rows:
        row["license"] = ""
    source.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )

    report = inspect_raw_corpus(source)
    assert report["chunks"] == 6

    with pytest.raises(ValueError, match="explicit training license"):
        prepare_reviewed_corpus(source, tmp_path / "blocked.jsonl")

    overrides = {
        document_id: {
            "source": f"Publisher {index}",
            "license": "Written permission from the rights holder",
        }
        for index, document_id in enumerate(document_ids)
    }
    result = prepare_reviewed_corpus(
        source,
        tmp_path / "approved.jsonl",
        metadata_overrides=overrides,
    )
    assert result["records_by_split"]


def test_review_rejects_corrupt_jsonl(tmp_path: Path):
    source = tmp_path / "broken.jsonl"
    source.write_text(
        '{"text": "valid", "source": "book", "license": "CC0"}\n{broken}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="not valid UTF-8 JSON"):
        inspect_raw_corpus(source)
