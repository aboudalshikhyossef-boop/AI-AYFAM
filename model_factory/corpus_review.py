"""Streaming quality review and approval for local training corpora."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import tempfile
import unicodedata
from typing import Iterable, Mapping

from model_factory.corpus_tools import detect_language, normalize_text, prepare_corpus
from model_factory.data import MAX_RECORD_BYTES, fingerprint_file

MIN_RECOMMENDED_CHUNK_CHARS = 80
_ALLOWED_METADATA = {"title", "source", "license"}
_REJECTED_LICENSES = {"", "unknown", "unspecified", "none", "n/a", "na", "no-license"}


def _document_id(payload: dict[str, object]) -> str:
    value = payload.get("document_id") or payload.get("group_id") or payload.get("source")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("every corpus record must contain document_id, group_id, or source")
    return value.strip()


def _record_id(payload: dict[str, object], line_number: int) -> str:
    value = payload.get("id", f"line-{line_number}")
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"line {line_number}: id must be a non-empty string")
    return value


def _iter_raw_records(path: Path):
    if path.is_symlink():
        raise OSError("corpus path must not be a symlink")
    with path.open("rb") as stream:
        line_number = 0
        while True:
            raw = stream.readline(MAX_RECORD_BYTES + 1)
            if not raw:
                break
            line_number += 1
            if len(raw) > MAX_RECORD_BYTES:
                raise ValueError(f"line {line_number} exceeds {MAX_RECORD_BYTES} bytes")
            if not raw.strip():
                continue
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"line {line_number} is not valid UTF-8 JSON") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"line {line_number} must contain a JSON object")
            text = payload.get("text")
            if not isinstance(text, str) or not text.strip():
                raise ValueError(f"line {line_number}: text must be a non-empty string")
            source = payload.get("source")
            license_name = payload.get("license", "")
            if not isinstance(source, str) or not source.strip():
                raise ValueError(f"line {line_number}: source provenance is required")
            if not isinstance(license_name, str):
                raise ValueError(f"line {line_number}: license must be a string")
            _document_id(payload)
            yield line_number, payload


def _is_malformed_text(text: str) -> bool:
    suspicious = sum(
        1 for char in text
        if char == "\ufffd"
        or (unicodedata.category(char) in {"Cc", "Cs"} and char not in "\n\t")
    )
    return suspicious > 0 and suspicious / max(1, len(text)) >= 0.001


def inspect_raw_corpus(
    path: str | Path,
    *,
    minimum_chunk_chars: int = MIN_RECOMMENDED_CHUNK_CHARS,
) -> dict[str, object]:
    """Inspect raw JSONL in one bounded-memory pass; use SQLite for duplicate detection."""
    if (
        isinstance(minimum_chunk_chars, bool)
        or not isinstance(minimum_chunk_chars, int)
        or minimum_chunk_chars < 1
    ):
        raise ValueError("minimum_chunk_chars must be a positive integer")
    source = Path(path).expanduser()
    descriptor, database_path = tempfile.mkstemp(prefix=".ayfam-review-", suffix=".sqlite")
    os.close(descriptor)
    connection = sqlite3.connect(database_path)
    connection.execute("CREATE TABLE seen_text (digest TEXT PRIMARY KEY)")
    documents: dict[str, dict[str, object]] = {}
    independent_groups: set[str] = set()
    totals = Counter()
    try:
        for line_number, payload in _iter_raw_records(source):
            document_id = _document_id(payload)
            group_id = payload.get("group_id") or document_id
            if not isinstance(group_id, str) or not group_id.strip():
                raise ValueError(f"line {line_number}: group_id must be a non-empty string")
            group_id = group_id.strip()
            independent_groups.add(group_id)
            text = payload["text"]
            assert isinstance(text, str)
            title = payload.get("title") or Path(
                str(payload.get("filename") or document_id)
            ).stem
            filename = payload.get("filename") or str(title)
            file_type = payload.get("file_type") or Path(str(filename)).suffix.lstrip(".")
            source_name = str(payload["source"]).strip()
            license_name = str(payload.get("license", "")).strip()
            if not all(isinstance(item, str) for item in (title, filename, file_type)):
                raise ValueError(f"line {line_number}: document metadata must be strings")

            entry = documents.setdefault(document_id, {
                "document_id": document_id,
                "group_id": group_id,
                "title": str(title),
                "filename": str(filename),
                "file_type": str(file_type),
                "source": source_name,
                "license": license_name,
                "chunks": 0,
                "characters": 0,
                "pages": set(),
                "languages": Counter(),
                "duplicate_chunks": 0,
                "tiny_chunks": 0,
                "malformed_chunks": 0,
                "unnormalized_chunks": 0,
                "metadata_conflicts": 0,
            })
            if (
                entry["source"] != source_name
                or entry["license"] != license_name
                or entry["title"] != str(title)
                or entry["group_id"] != group_id
            ):
                entry["metadata_conflicts"] = int(entry["metadata_conflicts"]) + 1

            page = payload.get("page")
            if page is not None:
                if isinstance(page, bool) or not isinstance(page, int) or page < 1:
                    raise ValueError(f"line {line_number}: page must be a positive integer or null")
                entry["pages"].add(page)

            language = payload.get("language")
            if not isinstance(language, str) or language not in {"ar", "en", "mixed", "other"}:
                language = detect_language(text)
            entry["languages"][language] += 1
            entry["chunks"] = int(entry["chunks"]) + 1
            entry["characters"] = int(entry["characters"]) + len(text)
            totals["chunks"] += 1
            totals["characters"] += len(text)

            normalized = normalize_text(text)
            if len(text) < minimum_chunk_chars:
                entry["tiny_chunks"] = int(entry["tiny_chunks"]) + 1
                totals["tiny_chunks"] += 1
            if _is_malformed_text(text):
                entry["malformed_chunks"] = int(entry["malformed_chunks"]) + 1
                totals["malformed_chunks"] += 1
            if normalized != text:
                entry["unnormalized_chunks"] = int(entry["unnormalized_chunks"]) + 1
                totals["unnormalized_chunks"] += 1

            digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            if connection.execute("SELECT 1 FROM seen_text WHERE digest=?", (digest,)).fetchone():
                entry["duplicate_chunks"] = int(entry["duplicate_chunks"]) + 1
                totals["duplicate_chunks"] += 1
            else:
                connection.execute("INSERT INTO seen_text(digest) VALUES (?)", (digest,))
        connection.commit()
    finally:
        connection.close()
        try:
            os.unlink(database_path)
        except FileNotFoundError:
            pass

    result_documents = []
    for _document_id_key, entry in sorted(
        documents.items(), key=lambda item: (str(item[1]["title"]).casefold(), item[0])
    ):
        pages = entry.pop("pages")
        languages = entry.pop("languages")
        entry["pages_with_text"] = len(pages)
        entry["languages"] = dict(sorted(languages.items()))
        result_documents.append(dict(entry))

    return {
        "raw_path": str(source),
        "fingerprint": fingerprint_file(source),
        "independent_groups": len(independent_groups),
        "documents": result_documents,
        **{key: int(totals[key]) for key in (
            "chunks", "characters", "duplicate_chunks", "tiny_chunks",
            "malformed_chunks", "unnormalized_chunks"
        )},
    }


def get_document_chunk(path: str | Path, document_id: str, chunk_offset: int) -> dict[str, object]:
    """Return one chunk preview by streaming the JSONL file."""
    if isinstance(chunk_offset, bool) or not isinstance(chunk_offset, int) or chunk_offset < 0:
        raise ValueError("chunk_offset must be a non-negative integer")
    source = Path(path).expanduser()
    selected = 0
    for line_number, payload in _iter_raw_records(source):
        if _document_id(payload) != document_id:
            continue
        if selected == chunk_offset:
            text = payload["text"]
            assert isinstance(text, str)
            return {
                "id": _record_id(payload, line_number),
                "chunk_index": payload.get("chunk_index", selected),
                "page": payload.get("page"),
                "chapter": payload.get("chapter", ""),
                "language": payload.get("language") or detect_language(text),
                "text": text,
                "characters": len(text),
                "tiny": len(text) < MIN_RECOMMENDED_CHUNK_CHARS,
                "malformed": _is_malformed_text(text),
                "unnormalized": normalize_text(text) != text,
            }
        selected += 1
    raise IndexError("chunk index is outside the selected document")


def _allocate_splits(group_count: int, ratios: tuple[float, float, float]) -> tuple[int, int, int]:
    quotas = [group_count * ratio for ratio in ratios]
    counts = [max(1, math.floor(quota)) for quota in quotas]
    while sum(counts) > group_count:
        reducible = [index for index, count in enumerate(counts) if count > 1]
        selected = max(reducible, key=lambda index: counts[index] - quotas[index])
        counts[selected] -= 1
    while sum(counts) < group_count:
        selected = max(range(3), key=lambda index: quotas[index] - counts[index])
        counts[selected] += 1
    return counts[0], counts[1], counts[2]


def prepare_reviewed_corpus(
    raw_path: str | Path,
    output_path: str | Path,
    *,
    excluded_documents: Iterable[str] = (),
    excluded_chunks: Iterable[tuple[str, str]] = (),
    metadata_overrides: Mapping[str, Mapping[str, str]] | None = None,
    train_ratio: float = 0.90,
    validation_ratio: float = 0.05,
    test_ratio: float = 0.05,
    full_corpus_training: bool = False,
    seed: int = 42,
) -> dict[str, object]:
    """Apply review choices, optionally using every approved chunk for optimizer training."""
    if not isinstance(full_corpus_training, bool):
        raise ValueError("full_corpus_training must be a boolean")
    if full_corpus_training:
        train_ratio, validation_ratio, test_ratio = 1.0, 0.0, 0.0
    else:
        ratios = (train_ratio, validation_ratio, test_ratio)
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(float(value)) or value <= 0
            for value in ratios
        ):
            raise ValueError("train, validation and test ratios must be positive finite numbers")
        if not math.isclose(sum(ratios), 1.0, rel_tol=0.0, abs_tol=1e-8):
            raise ValueError("train, validation and test ratios must sum to 1.0")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")

    source = Path(raw_path).expanduser()
    destination = Path(output_path).expanduser()
    if source.is_symlink() or destination.is_symlink():
        raise OSError("corpus input and output paths must not be symlinks")
    if source.resolve() == destination.resolve():
        raise ValueError("input and output corpus paths must be different")

    excluded_document_ids = {str(value) for value in excluded_documents}
    excluded_chunk_ids = {(str(doc_id), str(record_id)) for doc_id, record_id in excluded_chunks}
    overrides: dict[str, dict[str, str]] = {}
    for document_id, fields in (metadata_overrides or {}).items():
        if not isinstance(document_id, str) or not isinstance(fields, Mapping):
            raise ValueError("metadata overrides must map document IDs to metadata fields")
        unknown = set(fields) - _ALLOWED_METADATA
        if unknown:
            raise ValueError(f"unsupported metadata fields: {', '.join(sorted(unknown))}")
        cleaned = {}
        for name, value in fields.items():
            limit = 200 if name == "license" else 500
            if not isinstance(value, str) or len(value) > limit:
                raise ValueError(f"invalid {name} metadata for document {document_id}")
            cleaned[name] = value.strip()
        overrides[document_id] = cleaned

    groups: set[str] = set()
    document_groups: dict[str, str] = {}
    document_counts: Counter[str] = Counter()
    for line_number, payload in _iter_raw_records(source):
        document_id = _document_id(payload)
        record_id = _record_id(payload, line_number)
        if document_id in excluded_document_ids or (document_id, record_id) in excluded_chunk_ids:
            continue
        group_id = payload.get("group_id") or document_id
        if not isinstance(group_id, str) or not group_id.strip():
            raise ValueError(f"line {line_number}: group_id must be a non-empty string")
        group_id = group_id.strip()
        previous_group = document_groups.setdefault(document_id, group_id)
        if previous_group != group_id:
            raise ValueError(
                f"document {document_id!r} uses more than one group_id; "
                "all chunks from one document must share a single split group"
            )
        groups.add(group_id)
        document_counts[document_id] += 1

    # Prefer strict book-level isolation for evaluation mode. Full-corpus mode
    # deliberately assigns every approved record to Train and reports in-sample
    # metrics later; it does not pretend those metrics are held-out evaluation.
    split_strategy = "full_corpus" if full_corpus_training else "document"
    document_split_ranges: dict[str, tuple[int, int]] = {}
    group_splits: dict[str, str] = {}
    if full_corpus_training:
        group_splits = {group_id: "train" for group_id in groups}
    elif len(groups) >= 3:
        ranked_groups = sorted(
            groups,
            key=lambda value: hashlib.sha256(f"{seed}\0{value}".encode("utf-8")).digest(),
        )
        train_count, validation_count, test_count = _allocate_splits(len(ranked_groups), ratios)
        for index, group_id in enumerate(ranked_groups):
            if index < train_count:
                split = "train"
            elif index < train_count + validation_count:
                split = "validation"
            else:
                split = "test"
            group_splits[group_id] = split
    else:
        split_strategy = "sequential_chunks"
        if not document_counts or any(count < 5 for count in document_counts.values()):
            raise ValueError(
                "fewer than three independent books are available. To split data inside each book, "
                "keep at least five reviewed chunks per book so overlapping boundary chunks can be omitted."
            )
        for document_id, count in document_counts.items():
            validation_count = max(2, int(math.floor(count * validation_ratio)))
            test_count = max(2, int(math.floor(count * test_ratio)))
            train_count = count - validation_count - test_count
            if train_count < 1:
                raise ValueError(
                    f"document {document_id!r} needs at least five chunks for sequential splits"
                )
            document_split_ranges[document_id] = (
                train_count,
                train_count + validation_count,
            )

    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, stage_name = tempfile.mkstemp(prefix=".ayfam-reviewed-", suffix=".jsonl", dir=destination.parent)
    stage_path = Path(stage_name)
    records_written = 0
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            sequential_positions: Counter[str] = Counter()
            for line_number, payload in _iter_raw_records(source):
                document_id = _document_id(payload)
                record_id = _record_id(payload, line_number)
                if document_id in excluded_document_ids or (document_id, record_id) in excluded_chunk_ids:
                    continue
                group_id = payload.get("group_id") or document_id
                assert isinstance(group_id, str)
                group_id = group_id.strip()
                if document_groups.get(document_id) != group_id:
                    raise ValueError(
                        f"line {line_number}: document group identity changed during corpus preparation"
                    )

                record = dict(payload)
                for field, value in overrides.get(document_id, {}).items():
                    record[field] = value
                source_name = str(record.get("source", "")).strip()
                license_name = str(record.get("license", "")).strip()
                if not source_name:
                    raise ValueError(f"source cannot be empty for document {document_id}")
                if license_name.casefold() in _REJECTED_LICENSES:
                    raise ValueError(
                        f"an explicit training license or owner permission is required for document {document_id}"
                    )

                if split_strategy in {"document", "full_corpus"}:
                    split = group_splits[group_id]
                    output_group = group_id
                else:
                    position = sequential_positions[document_id]
                    sequential_positions[document_id] += 1
                    train_end, validation_end = document_split_ranges[document_id]
                    if position in {train_end, validation_end}:
                        continue
                    if position < train_end:
                        split = "train"
                    elif position < validation_end:
                        split = "validation"
                    else:
                        split = "test"
                    output_group = f"{document_id}::{split}"

                record["source"] = source_name
                record["license"] = license_name
                record["group_id"] = output_group
                record["split"] = split
                serialized = json.dumps(record, ensure_ascii=False) + "\n"
                if len(serialized.encode("utf-8")) > MAX_RECORD_BYTES:
                    raise ValueError(f"line {line_number}: reviewed record exceeds {MAX_RECORD_BYTES} bytes")
                output.write(serialized)
                records_written += 1
            output.flush()
            os.fsync(output.fileno())
        if not records_written:
            raise ValueError("no chunks remain after review exclusions")
        report = prepare_corpus(
            stage_path,
            destination,
            seed=seed,
            train_ratio=train_ratio,
            validation_ratio=validation_ratio,
            test_ratio=test_ratio,
            require_held_out=not full_corpus_training,
        )
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
        stage_path.unlink(missing_ok=True)

    result = report.to_dict()
    result.update({
        "reviewed_records": records_written,
        "excluded_documents": len(excluded_document_ids),
        "excluded_chunks": len(excluded_chunk_ids),
        "train_ratio": train_ratio,
        "validation_ratio": validation_ratio,
        "test_ratio": test_ratio,
        "full_corpus_training": full_corpus_training,
        "split_strategy": split_strategy,
        "overlap_guard_chunks_removed": 2 * len(document_split_ranges),
    })

    manifest = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_corpus": str(source),
        "source_fingerprint": fingerprint_file(source),
        "prepared_corpus": str(destination),
        "corpus_fingerprint": report.fingerprint,
        "documents": sorted(groups),
        "licenses": result.get("licenses", {}),
        "sources": result.get("sources", 0),
        "records_by_split": report.records_by_split,
        "split_ratios": {
            "train": train_ratio,
            "validation": validation_ratio,
            "test": test_ratio,
        },
        "full_corpus_training": full_corpus_training,
        "seed": seed,
        "split_strategy": split_strategy,
        "excluded_documents": sorted(excluded_document_ids),
        "excluded_chunks": len(excluded_chunk_ids),
    }
    manifest_path = destination.with_suffix(".manifest.json")
    fd, temporary = tempfile.mkstemp(prefix=".ayfam-manifest-", dir=manifest_path.parent, text=True)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, manifest_path)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    result["manifest_path"] = str(manifest_path)
    return result
