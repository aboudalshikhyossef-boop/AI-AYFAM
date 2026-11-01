"""Streaming, provenance-aware JSONL corpus reader and byte-token block builder."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import random
from typing import Iterator, Literal

from model_factory.tokenizer import ByteBPETokenizer, ByteTokenizer

CorpusSplit = Literal["train", "validation", "test"]
_ALLOWED_SPLITS = {"train", "validation", "test"}
MAX_RECORD_BYTES = 1_000_000


@dataclass(frozen=True)
class CorpusRecord:
    text: str
    source: str
    license: str
    split: CorpusSplit
    record_id: str = ""
    group_id: str = ""
    language: str = ""
    document_id: str = ""
    title: str = ""
    filename: str = ""
    file_type: str = ""
    chapter: str = ""
    page: int | None = None
    chunk_index: int | None = None


@dataclass(frozen=True)
class CorpusReport:
    path: str
    fingerprint: str
    records_by_split: dict[str, int]
    total_records: int


def _parse_record(raw: str, line_number: int) -> CorpusRecord:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON on line {line_number}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"line {line_number} must contain a JSON object")
    text = payload.get("text")
    source = payload.get("source")
    license_name = payload.get("license")
    split = payload.get("split")
    record_id = payload.get("id", "")
    if not isinstance(text, str) or not text.strip():
        raise ValueError(f"line {line_number}: text must be a non-empty string")
    if not isinstance(source, str) or not source.strip():
        raise ValueError(f"line {line_number}: source provenance is required")
    if not isinstance(license_name, str) or not license_name.strip():
        raise ValueError(f"line {line_number}: license information is required")
    if not isinstance(split, str) or split not in _ALLOWED_SPLITS:
        raise ValueError(f"line {line_number}: split must be train, validation, or test")
    if not isinstance(record_id, str):
        raise ValueError(f"line {line_number}: id must be a string when provided")
    group_id = payload.get("group_id", "")
    language = payload.get("language", "")
    metadata_fields = ("document_id", "title", "filename", "file_type", "chapter")
    metadata = {name: payload.get(name, "") for name in metadata_fields}
    if not isinstance(group_id, str) or not isinstance(language, str):
        raise ValueError(f"line {line_number}: group_id and language must be strings when provided")
    for name, value in metadata.items():
        if not isinstance(value, str):
            raise ValueError(f"line {line_number}: {name} must be a string when provided")
    page = payload.get("page")
    chunk_index = payload.get("chunk_index")
    if page is not None and (
        isinstance(page, bool) or not isinstance(page, int) or page < 1
    ):
        raise ValueError(f"line {line_number}: page must be a positive integer or null")
    if chunk_index is not None and (
        isinstance(chunk_index, bool) or not isinstance(chunk_index, int) or chunk_index < 0
    ):
        raise ValueError(f"line {line_number}: chunk_index must be a non-negative integer or null")
    return CorpusRecord(
        text=text,
        source=source.strip(),
        license=license_name.strip(),
        split=split,
        record_id=record_id,
        group_id=group_id,
        language=language,
        document_id=metadata["document_id"],
        title=metadata["title"],
        filename=metadata["filename"],
        file_type=metadata["file_type"],
        chapter=metadata["chapter"],
        page=page,
        chunk_index=chunk_index,
    )


def iter_records(path: str | Path, split: CorpusSplit | None = None) -> Iterator[CorpusRecord]:
    source = Path(path).expanduser()
    if source.is_symlink():
        raise OSError("corpus path must not be a symlink")
    if split is not None and split not in _ALLOWED_SPLITS:
        raise ValueError(f"unsupported corpus split: {split}")
    with source.open("rb") as stream:
        line_number = 0
        while True:
            # Bound the read itself, not just the subsequent length check: a corrupt
            # multi-gigabyte line must not be materialized in RAM before rejection.
            raw_bytes = stream.readline(MAX_RECORD_BYTES + 1)
            if not raw_bytes:
                break
            line_number += 1
            if len(raw_bytes) > MAX_RECORD_BYTES:
                raise ValueError(f"line {line_number} exceeds {MAX_RECORD_BYTES} bytes")
            if not raw_bytes.strip():
                continue
            try:
                raw = raw_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"line {line_number} is not valid UTF-8") from exc
            record = _parse_record(raw, line_number)
            if split is None or record.split == split:
                yield record


def fingerprint_file(path: str | Path) -> str:
    source = Path(path).expanduser()
    if source.is_symlink():
        raise OSError("corpus path must not be a symlink")
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_corpus(path: str | Path) -> CorpusReport:
    counts = {split: 0 for split in sorted(_ALLOWED_SPLITS)}
    for record in iter_records(path):
        # One streaming pass validates and counts without loading the corpus into RAM.
        counts[record.split] += 1
    total = sum(counts.values())
    if counts["train"] == 0:
        raise ValueError("corpus must contain at least one record with split='train'")
    return CorpusReport(
        path=str(Path(path).expanduser()),
        fingerprint=fingerprint_file(path),
        records_by_split=counts,
        total_records=total,
    )


def iter_token_blocks(
    path: str | Path,
    tokenizer: ByteTokenizer | ByteBPETokenizer,
    *,
    split: CorpusSplit,
    block_size: int,
) -> Iterator[tuple[list[int], list[int]]]:
    if isinstance(block_size, bool) or not isinstance(block_size, int) or block_size <= 0:
        raise ValueError("block_size must be a positive integer")
    for record in iter_records(path, split=split):
        tokens = tokenizer.encode(record.text, add_bos=True, add_eos=True)
        for offset in range(0, len(tokens) - 1, block_size):
            window = tokens[offset : offset + block_size + 1]
            if len(window) < 2:
                continue
            input_ids = window[:-1]
            target_ids = window[1:]
            missing = block_size - len(input_ids)
            if missing:
                input_ids = input_ids + [tokenizer.PAD] * missing
                target_ids = target_ids + [tokenizer.PAD] * missing
            yield input_ids, target_ids


def _buffered_shuffle(items, *, buffer_size: int, seed: int):
    """Shuffle a stream with a fixed memory bound rather than loading the corpus."""
    rng = random.Random(seed)
    buffer = []
    for item in items:
        if len(buffer) < buffer_size:
            buffer.append(item)
            continue
        selected = rng.randrange(len(buffer))
        yield buffer[selected]
        buffer[selected] = item
    while buffer:
        yield buffer.pop(rng.randrange(len(buffer)))


def iter_batches(
    path: str | Path,
    tokenizer: ByteTokenizer | ByteBPETokenizer,
    *,
    split: CorpusSplit,
    block_size: int,
    batch_size: int,
    shuffle: bool = False,
    seed: int = 42,
    shuffle_buffer_size: int = 256,
):
    """Yield bounded-memory PyTorch batches; shuffle uses a fixed-size buffer."""
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size <= 0:
        raise ValueError("batch_size must be a positive integer")
    if not isinstance(shuffle, bool):
        raise ValueError("shuffle must be a boolean")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    if isinstance(shuffle_buffer_size, bool) or not isinstance(shuffle_buffer_size, int) or shuffle_buffer_size <= 0:
        raise ValueError("shuffle_buffer_size must be a positive integer")
    try:
        import torch
    except ImportError as exc:
        raise RuntimeError(
            "PyTorch is optional. Install requirements-training.txt to use neural training."
        ) from exc
    blocks = iter_token_blocks(path, tokenizer, split=split, block_size=block_size)
    if shuffle:
        blocks = _buffered_shuffle(blocks, buffer_size=shuffle_buffer_size, seed=seed)
    pending_inputs: list[list[int]] = []
    pending_targets: list[list[int]] = []
    for input_ids, target_ids in blocks:
        pending_inputs.append(input_ids)
        pending_targets.append(target_ids)
        if len(pending_inputs) == batch_size:
            yield torch.tensor(pending_inputs, dtype=torch.long), torch.tensor(
                pending_targets, dtype=torch.long
            )
            pending_inputs.clear()
            pending_targets.clear()
    if pending_inputs:
        yield torch.tensor(pending_inputs, dtype=torch.long), torch.tensor(
            pending_targets, dtype=torch.long
        )
