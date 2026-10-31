"""Integrity and split tests for the committed AYFAM seed corpus."""

from collections import Counter
from pathlib import Path

from model_factory.corpus_tools import prepare_corpus, validate_prepared_corpus
from model_factory.data import iter_records


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SEED_CORPUS = REPOSITORY_ROOT / "data" / "seed_corpus" / "v0.1" / "ayfam-seed-v0.1.jsonl"


def test_seed_corpus_has_documented_size_languages_and_splits():
    records = list(iter_records(SEED_CORPUS))
    assert len(records) == 60
    assert Counter(record.split for record in records) == {
        "train": 54,
        "validation": 3,
        "test": 3,
    }
    assert Counter(record.language for record in records) == {"ar": 42, "en": 18}
    assert all(record.source.startswith("project-authored:AI-AYFAM-seed-v0.1:") for record in records)
    assert all(record.license == "MIT" for record in records)
    assert len({record.group_id for record in records}) == 60


def test_seed_corpus_prepares_and_passes_strict_audit(tmp_path: Path):
    prepared = tmp_path / "prepared.jsonl"
    report = prepare_corpus(SEED_CORPUS, prepared, require_held_out=True)
    audit = validate_prepared_corpus(prepared, require_held_out=True)

    assert report.output_records == 60
    assert report.records_by_split == {"train": 54, "validation": 3, "test": 3}
    assert audit.total_records == 60
    assert audit.fingerprint == report.fingerprint
