"""Tests for safe, leakage-aware corpus preparation."""

import json
import os

import pytest

from model_factory.corpus_tools import (
    detect_language,
    find_sensitive_content,
    normalize_text,
    prepare_corpus,
    validate_prepared_corpus,
)
from model_factory.data import iter_records, validate_corpus


def _record(text, source, split=None, license_name="CC0-1.0", group_id=None):
    value = {
        "text": text,
        "source": source,
        "license": license_name,
    }
    if split is not None:
        value["split"] = split
    if group_id is not None:
        value["group_id"] = group_id
    return value


def _write(path, records):
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in records),
        encoding="utf-8",
    )


def test_normalization_and_language_detection_cover_arabic_english_and_mixed():
    assert normalize_text("  cafe\u0301 \r\n \tنص   \n\n\n") == "café\nنص"
    assert detect_language("هذا اختبار عربي") == "ar"
    assert detect_language("AI AYFAM security") == "en"
    assert detect_language("الأمن AI") == "mixed"
    assert detect_language("123 !!!") == "other"


def test_preparation_normalizes_deduplicates_and_reports_provenance(tmp_path):
    source = tmp_path / "raw.jsonl"
    output = tmp_path / "ready.jsonl"
    _write(source, [
        _record("cafe\u0301", "doc-1", "train"),
        _record("café", "doc-1", "train"),
        _record("معلومة تحقق", "doc-2", "validation", "MIT"),
        _record("Test record", "doc-3", "test", "CC0-1.0"),
    ])

    report = prepare_corpus(source, output, require_held_out=True)
    assert report.input_records == 4
    assert report.output_records == 3
    assert report.duplicates_removed == 1
    assert report.records_by_split == {"train": 1, "validation": 1, "test": 1}
    assert report.languages == {"ar": 1, "en": 2}
    assert report.sources == 3
    assert len(report.fingerprint) == 64
    records = list(iter_records(output))
    assert records[0].text == "café"
    assert validate_corpus(output).total_records == 3
    assert os.stat(output).st_mode & 0o077 == 0


def test_source_group_stays_in_one_deterministic_split(tmp_path):
    source = tmp_path / "raw.jsonl"
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    records = []
    for index in range(100):
        records.append(_record(
            f"unique text item {index}",
            source=f"origin-{index // 2}",
            group_id=f"document-{index // 2}",
        ))
    _write(source, records)

    report_a = prepare_corpus(source, first, seed=99, train_ratio=0.8, validation_ratio=0.1, test_ratio=0.1)
    report_b = prepare_corpus(source, second, seed=99, train_ratio=0.8, validation_ratio=0.1, test_ratio=0.1)
    rows_a = [json.loads(line) for line in first.read_text(encoding="utf-8").splitlines()]
    rows_b = [json.loads(line) for line in second.read_text(encoding="utf-8").splitlines()]
    assert report_a.fingerprint == report_b.fingerprint
    assert [row["split"] for row in rows_a] == [row["split"] for row in rows_b]
    group_splits = {}
    for row in rows_a:
        previous = group_splits.setdefault(row["group_id"], row["split"])
        assert previous == row["split"]
    assert report_a.records_by_split["train"] > 0
    assert report_a.records_by_split["validation"] > 0
    assert report_a.records_by_split["test"] > 0


def test_identical_text_across_splits_is_rejected(tmp_path):
    source = tmp_path / "leak.jsonl"
    output = tmp_path / "out.jsonl"
    _write(source, [
        _record("same exact answer", "doc-a", "train"),
        _record("same exact answer", "doc-b", "test"),
    ])
    with pytest.raises(ValueError, match="different split"):
        prepare_corpus(source, output)
    assert not output.exists()


def test_same_group_cannot_be_explicitly_assigned_to_two_splits(tmp_path):
    source = tmp_path / "group-leak.jsonl"
    output = tmp_path / "out.jsonl"
    _write(source, [
        _record("first record", "doc-a", "train", group_id="shared"),
        _record("second record", "doc-a", "validation", group_id="shared"),
    ])
    with pytest.raises(ValueError, match="cross data splits"):
        prepare_corpus(source, output)


def test_mixed_explicit_and_automatic_splits_are_rejected(tmp_path):
    source = tmp_path / "mixed.jsonl"
    output = tmp_path / "out.jsonl"
    _write(source, [
        _record("first item", "doc-a", "train"),
        _record("second item", "doc-b"),
    ])
    with pytest.raises(ValueError, match="all provide split"):
        prepare_corpus(source, output)


@pytest.mark.parametrize("license_name", ["", "unknown", "unspecified", "none", "n/a"])
def test_missing_or_placeholder_license_is_rejected(tmp_path, license_name):
    source = tmp_path / "unlicensed.jsonl"
    output = tmp_path / "out.jsonl"
    _write(source, [_record("some training text", "doc-a", "train", license_name)])
    with pytest.raises(ValueError, match="explicit permission"):
        prepare_corpus(source, output)


@pytest.mark.parametrize("secret", [
    "password=hunter2password",
    "api_key: abcdefghijklmnop",
    "ghp_123456789012345678901234",
    "-----BEGIN PRIVATE KEY-----",
    "AKIA1234567890ABCDEF",
])
def test_sensitive_credential_patterns_are_detected(secret):
    assert find_sensitive_content(secret)


def test_prepare_corpus_rejects_sensitive_material_before_writing(tmp_path):
    source = tmp_path / "secret.jsonl"
    output = tmp_path / "out.jsonl"
    _write(source, [_record("api_key=supersecretvalue", "doc-a", "train")])
    with pytest.raises(ValueError, match="sensitive credential"):
        prepare_corpus(source, output)
    assert not output.exists()


def test_require_held_out_checks_both_validation_and_test(tmp_path):
    source = tmp_path / "train-only.jsonl"
    output = tmp_path / "out.jsonl"
    _write(source, [_record("one training sample", "doc-a", "train")])
    with pytest.raises(ValueError, match="validation and test"):
        prepare_corpus(source, output, require_held_out=True)
    assert not output.exists()


def test_prepare_corpus_rejects_input_output_alias_and_symlink(tmp_path):
    source = tmp_path / "input.jsonl"
    _write(source, [_record("valid item", "doc-a", "train")])
    with pytest.raises(ValueError, match="different"):
        prepare_corpus(source, source)
    link = tmp_path / "input-link.jsonl"
    link.symlink_to(source)
    with pytest.raises(OSError, match="symlinks"):
        prepare_corpus(link, tmp_path / "out.jsonl")



def test_prepared_corpus_passes_strict_training_audit(tmp_path):
    source = tmp_path / "raw.jsonl"
    output = tmp_path / "prepared.jsonl"
    _write(source, [
        _record("نص تدريب عربي", "doc-train", "train"),
        _record("English validation text", "doc-validation", "validation"),
        _record("نص اختبار مستقل", "doc-test", "test"),
    ])
    prepare_corpus(source, output)
    report = validate_prepared_corpus(output)
    assert report.total_records == 3
    assert report.records_by_split == {"test": 1, "train": 1, "validation": 1}


def test_training_audit_rejects_unprepared_rows_without_group_metadata(tmp_path):
    path = tmp_path / "missing-metadata.jsonl"
    _write(path, [_record("valid text", "doc-a", "train")])
    with pytest.raises(ValueError, match="group_id is required"):
        validate_prepared_corpus(path, require_held_out=False)


def test_training_audit_rejects_group_split_leakage(tmp_path):
    path = tmp_path / "leaking-groups.jsonl"
    rows = [
        _record("train passage", "doc-a", "train", group_id="same-document"),
        _record("validation passage", "doc-a", "validation", group_id="same-document"),
    ]
    for row, language in zip(rows, ("en", "en")):
        row["language"] = language
    _write(path, rows)
    with pytest.raises(ValueError, match="group_id crosses"):
        validate_prepared_corpus(path, require_held_out=False)


def test_training_audit_rejects_duplicate_text_inside_one_split(tmp_path):
    path = tmp_path / "duplicate.jsonl"
    rows = [
        _record("duplicate text", "doc-a", "train", group_id="doc-a"),
        _record("duplicate text", "doc-b", "train", group_id="doc-b"),
    ]
    for row in rows:
        row["language"] = "en"
    _write(path, rows)
    with pytest.raises(ValueError, match="duplicate text remains"):
        validate_prepared_corpus(path, require_held_out=False)


def test_normalization_preserves_arabic_join_controls():
    text = "می\u200cخواهم"
    assert normalize_text(text) == text
