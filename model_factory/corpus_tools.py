"""Safe corpus cleaning, provenance checks, deduplication and leakage-safe splits."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import unicodedata

from model_factory.data import CorpusReport, MAX_RECORD_BYTES, fingerprint_file, iter_records

_ALLOWED_SPLITS = {"train", "validation", "test"}
_REJECTED_LICENSES = {"", "unknown", "unspecified", "none", "n/a", "na", "no-license"}
_SECRET_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("openai-style-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("credential-assignment", re.compile(
        r"""(?i)\b(?:password|passwd|api[_ -]?key|access[_ -]?token)\s*[:=]\s*['"]?(?!your_|example|placeholder|<)[A-Za-z0-9/+_.-]{8,}"""
    )),
)


@dataclass(frozen=True)
class CorpusPreparationReport:
    input_records: int
    output_records: int
    duplicates_removed: int
    records_by_split: dict[str, int]
    languages: dict[str, int]
    licenses: dict[str, int]
    sources: int
    fingerprint: str
    output_path: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def normalize_text(text: str) -> str:
    if not isinstance(text, str):
        raise TypeError("corpus text must be a string")
    normalized = unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n"))
    cleaned = "".join(
        char for char in normalized
        if char in "\n\t\u200c\u200d" or unicodedata.category(char) not in {"Cc", "Cf", "Cs"}
    )
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"[ \t]+\n", "\n", cleaned)
    cleaned = re.sub(r"\n[ \t]+", "\n", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def detect_language(text: str) -> str:
    arabic = 0
    latin = 0
    for char in text:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        if "ARABIC" in name:
            arabic += 1
        elif "LATIN" in name:
            latin += 1
    if arabic and latin:
        return "mixed"
    if arabic:
        return "ar"
    if latin:
        return "en"
    return "other"


def find_sensitive_content(text: str) -> list[str]:
    """Return names of high-confidence credential patterns; never echo matched values."""
    return [name for name, pattern in _SECRET_PATTERNS if pattern.search(text)]


def _stable_split(group_key: str, seed: int, train_ratio: float, validation_ratio: float) -> str:
    digest = hashlib.sha256(f"{seed}\0{group_key}".encode("utf-8")).digest()
    fraction = int.from_bytes(digest[:8], "big") / float(1 << 64)
    if fraction < train_ratio:
        return "train"
    if fraction < train_ratio + validation_ratio:
        return "validation"
    return "test"


def prepare_corpus(
    input_path: str | Path,
    output_path: str | Path,
    *,
    seed: int = 42,
    train_ratio: float = 0.90,
    validation_ratio: float = 0.05,
    test_ratio: float = 0.05,
    require_held_out: bool = False,
) -> CorpusPreparationReport:
    """Normalize and deduplicate JSONL using SQLite indexes and an atomic output file.

    If source rows have no split, assign a stable split by group_id (or source).
    Rows sharing one group are always kept in the same split. If explicit splits
    are present, all rows must specify one and groups may not cross splits.
    """
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    ratios = (train_ratio, validation_ratio, test_ratio)
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float))
        or not math.isfinite(float(value)) or value < 0
        for value in ratios
    ):
        raise ValueError("split ratios must be finite non-negative numbers")
    if not math.isclose(sum(ratios), 1.0, rel_tol=0.0, abs_tol=1e-8):
        raise ValueError("train, validation and test ratios must sum to 1.0")
    if train_ratio <= 0:
        raise ValueError("train_ratio must be greater than zero")
    if not isinstance(require_held_out, bool):
        raise ValueError("require_held_out must be a boolean")

    source = Path(input_path).expanduser()
    destination = Path(output_path).expanduser()
    if source.is_symlink() or destination.is_symlink():
        raise OSError("corpus input and output paths must not be symlinks")
    if source.resolve() == destination.resolve():
        raise ValueError("input and output corpus paths must be different")
    destination.parent.mkdir(parents=True, exist_ok=True)

    db_fd, db_name = tempfile.mkstemp(prefix=".ayfam-corpus-index-", suffix=".sqlite", dir=destination.parent)
    os.close(db_fd)
    output_fd, output_name = tempfile.mkstemp(prefix=".ayfam-corpus-", dir=destination.parent, text=True)
    os.close(output_fd)
    connection = sqlite3.connect(db_name)
    input_count = 0
    output_count = 0
    duplicates = 0
    split_counts = Counter()
    language_counts = Counter()
    license_counts = Counter()
    source_count = 0
    split_mode: bool | None = None
    failed = True

    try:
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA synchronous=OFF")
        connection.execute(
            "CREATE TABLE groups_seen (group_key TEXT PRIMARY KEY, split TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE text_seen (digest TEXT PRIMARY KEY, split TEXT NOT NULL, line_number INTEGER NOT NULL)"
        )
        connection.execute("CREATE TABLE sources_seen (source TEXT PRIMARY KEY)")
        with source.open("rb") as input_stream, open(output_name, "w", encoding="utf-8", newline="\n") as output_stream:
            line_number = 0
            while True:
                raw_bytes = input_stream.readline(MAX_RECORD_BYTES + 1)
                if not raw_bytes:
                    break
                line_number += 1
                if len(raw_bytes) > MAX_RECORD_BYTES:
                    raise ValueError(f"line {line_number} exceeds {MAX_RECORD_BYTES} bytes")
                if not raw_bytes.strip():
                    continue
                input_count += 1
                try:
                    payload = json.loads(raw_bytes.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError(f"line {line_number} is not valid UTF-8 JSON") from exc
                if not isinstance(payload, dict):
                    raise ValueError(f"line {line_number} must contain a JSON object")

                text = normalize_text(payload.get("text", ""))
                source_name = payload.get("source")
                license_name = payload.get("license")
                if not text:
                    raise ValueError(f"line {line_number}: text is empty after normalization")
                if not isinstance(source_name, str) or not source_name.strip():
                    raise ValueError(f"line {line_number}: source provenance is required")
                if not isinstance(license_name, str):
                    raise ValueError(f"line {line_number}: license must be a string")
                source_name = source_name.strip()
                license_name = license_name.strip()
                if license_name.casefold() in _REJECTED_LICENSES:
                    raise ValueError(f"line {line_number}: license value is not an explicit permission")
                sensitive = find_sensitive_content(text)
                if sensitive:
                    raise ValueError(
                        f"line {line_number}: sensitive credential pattern detected ({', '.join(sensitive)}); remove secrets before preparing a corpus"
                    )

                group_key = payload.get("group_id", source_name)
                if not isinstance(group_key, str) or not group_key.strip():
                    raise ValueError(f"line {line_number}: group_id must be a non-empty string")
                group_key = group_key.strip()

                has_split = "split" in payload
                if split_mode is None:
                    split_mode = has_split
                elif split_mode != has_split:
                    raise ValueError("corpus rows must either all provide split or all omit it")
                if has_split:
                    split = payload["split"]
                    if not isinstance(split, str) or split not in _ALLOWED_SPLITS:
                        raise ValueError(f"line {line_number}: split must be train, validation, or test")
                else:
                    split = _stable_split(group_key, seed, float(train_ratio), float(validation_ratio))

                existing_group = connection.execute(
                    "SELECT split FROM groups_seen WHERE group_key=?", (group_key,)
                ).fetchone()
                if existing_group and existing_group[0] != split:
                    raise ValueError(
                        f"line {line_number}: group {group_key!r} would cross data splits"
                    )
                if not existing_group:
                    connection.execute(
                        "INSERT INTO groups_seen(group_key, split) VALUES (?, ?)",
                        (group_key, split),
                    )

                digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
                existing_text = connection.execute(
                    "SELECT split, line_number FROM text_seen WHERE digest=?", (digest,)
                ).fetchone()
                if existing_text:
                    if existing_text[0] != split:
                        raise ValueError(
                            f"line {line_number}: duplicate text also occurs in a different split (line {existing_text[1]})"
                        )
                    duplicates += 1
                    continue
                connection.execute(
                    "INSERT INTO text_seen(digest, split, line_number) VALUES (?, ?, ?)",
                    (digest, split, line_number),
                )

                record_id = payload.get("id", f"line-{line_number}")
                if not isinstance(record_id, str):
                    raise ValueError(f"line {line_number}: id must be a string")
                language = detect_language(text)
                record = {
                    "id": record_id,
                    "text": text,
                    "source": source_name,
                    "license": license_name,
                    "group_id": group_key,
                    "split": split,
                    "language": language,
                }
                serialized = json.dumps(record, ensure_ascii=False) + "\n"
                if len(serialized.encode("utf-8")) > MAX_RECORD_BYTES:
                    raise ValueError(f"line {line_number}: prepared record exceeds {MAX_RECORD_BYTES} bytes")
                output_stream.write(serialized)
                output_count += 1
                split_counts[split] += 1
                language_counts[language] += 1
                license_counts[license_name] += 1
                connection.execute("INSERT OR IGNORE INTO sources_seen(source) VALUES (?)", (source_name,))
            output_stream.flush()
            os.fsync(output_stream.fileno())

        connection.commit()
        source_count = connection.execute("SELECT COUNT(*) FROM sources_seen").fetchone()[0]
        if split_counts["train"] == 0:
            raise ValueError("prepared corpus has no training records; add more independent source groups or provide explicit splits")
        if require_held_out and (split_counts["validation"] == 0 or split_counts["test"] == 0):
            raise ValueError("prepared corpus must contain non-empty validation and test splits")
        os.chmod(output_name, 0o600)
        os.replace(output_name, destination)
        failed = False
    finally:
        connection.close()
        for temporary in (db_name, output_name):
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    if failed:
        raise RuntimeError("corpus preparation did not complete")
    return CorpusPreparationReport(
        input_records=input_count,
        output_records=output_count,
        duplicates_removed=duplicates,
        records_by_split={split: split_counts[split] for split in ("train", "validation", "test")},
        languages=dict(sorted(language_counts.items())),
        licenses=dict(sorted(license_counts.items())),
        sources=source_count,
        fingerprint=fingerprint_file(destination),
        output_path=str(destination),
    )



def validate_prepared_corpus(
    path: str | Path,
    *,
    require_held_out: bool = True,
) -> CorpusReport:
    """Verify a prepared corpus before tokenizer learning or model training.

    Uses a temporary SQLite index so duplicate and source-group checks do not
    require keeping every text/hash in Python memory.
    """
    if not isinstance(require_held_out, bool):
        raise ValueError("require_held_out must be a boolean")
    source = Path(path).expanduser()
    if source.is_symlink():
        raise OSError("corpus path must not be a symlink")
    db_fd, db_name = tempfile.mkstemp(prefix=".ayfam-validate-", suffix=".sqlite")
    os.close(db_fd)
    connection = sqlite3.connect(db_name)
    counts = Counter()
    total = 0
    try:
        connection.execute(
            "CREATE TABLE groups_seen (group_key TEXT PRIMARY KEY, split TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE text_seen (digest TEXT PRIMARY KEY, split TEXT NOT NULL, line_number INTEGER NOT NULL)"
        )
        for record in iter_records(source):
            total += 1
            if not record.group_id.strip():
                raise ValueError(
                    f"record {record.record_id or total}: group_id is required; run prepare-corpus first"
                )
            if record.license.casefold() in _REJECTED_LICENSES:
                raise ValueError(
                    f"record {record.record_id or total}: explicit license or owner permission is required"
                )
            normalized = normalize_text(record.text)
            if normalized != record.text:
                raise ValueError(
                    f"record {record.record_id or total}: text is not normalized; run prepare-corpus first"
                )
            sensitive = find_sensitive_content(normalized)
            if sensitive:
                raise ValueError(
                    f"record {record.record_id or total}: sensitive credential pattern detected ({', '.join(sensitive)})"
                )
            if record.language not in {"ar", "en", "mixed", "other"} or record.language != detect_language(normalized):
                raise ValueError(
                    f"record {record.record_id or total}: language metadata is missing or invalid"
                )

            previous_group = connection.execute(
                "SELECT split FROM groups_seen WHERE group_key=?",
                (record.group_id,),
            ).fetchone()
            if previous_group and previous_group[0] != record.split:
                raise ValueError(
                    f"record {record.record_id or total}: group_id crosses data splits"
                )
            if not previous_group:
                connection.execute(
                    "INSERT INTO groups_seen(group_key, split) VALUES (?, ?)",
                    (record.group_id, record.split),
                )

            digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            previous_text = connection.execute(
                "SELECT split, line_number FROM text_seen WHERE digest=?",
                (digest,),
            ).fetchone()
            if previous_text:
                if previous_text[0] != record.split:
                    raise ValueError(
                        f"record {record.record_id or total}: duplicate text crosses data splits"
                    )
                raise ValueError(
                    f"record {record.record_id or total}: duplicate text remains after corpus preparation"
                )
            connection.execute(
                "INSERT INTO text_seen(digest, split, line_number) VALUES (?, ?, ?)",
                (digest, record.split, total),
            )
            counts[record.split] += 1
        connection.commit()
    finally:
        connection.close()
        try:
            os.unlink(db_name)
        except FileNotFoundError:
            pass

    if counts["train"] == 0:
        raise ValueError("prepared corpus has no training records")
    if require_held_out and (counts["validation"] == 0 or counts["test"] == 0):
        raise ValueError("prepared corpus must contain non-empty validation and test splits")
    return CorpusReport(
        path=str(source),
        fingerprint=fingerprint_file(source),
        records_by_split={split: counts[split] for split in ("test", "train", "validation")},
        total_records=total,
    )
