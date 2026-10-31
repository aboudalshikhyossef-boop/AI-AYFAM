"""Deterministic byte tokenizers for AI AYFAM.

ByteTokenizer is kept stable for checkpoints created in the first model milestone.
ByteBPETokenizer learns all merges from the project's own training corpus.
No external vocabulary or pretrained tokenizer assets are loaded.
"""

from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Iterable


class ByteTokenizer:
    PAD = 256
    BOS = 257
    EOS = 258
    UNK = 259
    VOCAB_SIZE = 260
    SCHEMA_VERSION = 1

    @property
    def vocab_size(self) -> int:
        return self.VOCAB_SIZE

    def encode(self, text: str, *, add_bos: bool = False, add_eos: bool = False) -> list[int]:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        tokens = list(text.encode("utf-8"))
        if add_bos:
            tokens.insert(0, self.BOS)
        if add_eos:
            tokens.append(self.EOS)
        return tokens

    def decode(self, token_ids: Iterable[int], *, skip_special_tokens: bool = True) -> str:
        raw = bytearray()
        special = {self.PAD, self.BOS, self.EOS, self.UNK}
        names = {self.PAD: "pad", self.BOS: "bos", self.EOS: "eos", self.UNK: "unk"}
        for token_id in token_ids:
            if isinstance(token_id, bool) or not isinstance(token_id, int):
                raise TypeError("token IDs must be integers")
            if 0 <= token_id <= 255:
                raw.append(token_id)
            elif token_id in special and skip_special_tokens:
                continue
            elif token_id in special:
                raw.extend(f"<{names[token_id]}>".encode("ascii"))
            else:
                raise ValueError(f"token ID out of range: {token_id}")
        return raw.decode("utf-8", errors="replace")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "type": "utf8-byte",
            "vocab_size": self.VOCAB_SIZE,
            "special_tokens": {
                "pad": self.PAD,
                "bos": self.BOS,
                "eos": self.EOS,
                "unk": self.UNK,
            },
        }

    @classmethod
    def from_dict(cls, values: dict[str, object]) -> "ByteTokenizer":
        if values != cls().to_dict():
            raise ValueError("unsupported or incompatible tokenizer configuration")
        return cls()

    def save(self, path: str | Path) -> None:
        _atomic_json_save(path, self.to_dict(), prefix=".tokenizer-")

    @classmethod
    def load(cls, path: str | Path) -> "ByteTokenizer":
        payload = _load_json_object(path)
        return cls.from_dict(payload)


def _atomic_json_save(path: str | Path, payload: dict[str, object], *, prefix: str) -> None:
    destination = Path(path).expanduser()
    if destination.is_symlink():
        raise OSError("tokenizer destination must not be a symlink")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=prefix, dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _load_json_object(path: str | Path) -> dict[str, object]:
    source = Path(path).expanduser()
    if source.is_symlink():
        raise OSError("tokenizer source must not be a symlink")
    with source.open("r", encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, dict):
        raise ValueError("tokenizer configuration must be a JSON object")
    return payload


def _apply_merge(sequence: tuple[int, ...], left: int, right: int, merged: int) -> tuple[int, ...]:
    result: list[int] = []
    index = 0
    while index < len(sequence):
        if index + 1 < len(sequence) and sequence[index] == left and sequence[index + 1] == right:
            result.append(merged)
            index += 2
        else:
            result.append(sequence[index])
            index += 1
    return tuple(result)


class ByteBPETokenizer:
    """Trainable UTF-8 byte-level BPE tokenizer with stable, versioned IDs.

    IDs 0..255 represent raw bytes; 256..259 are special tokens; learned
    merge IDs start at 260. Whitespace is preserved and used as a boundary
    so merges are learned within word/whitespace pieces, not across pieces.
    """

    PAD = 256
    BOS = 257
    EOS = 258
    UNK = 259
    BASE_VOCAB_SIZE = 260
    SCHEMA_VERSION = 1
    _PIECE_PATTERN = re.compile(r"\s+|[^\s]+", flags=re.UNICODE)
    MAX_PIECE_BYTES = 256

    def __init__(self, merges: Iterable[tuple[int, int]] = ()):
        self.merges = [(int(left), int(right)) for left, right in merges]
        # Keep byte arrays index-aligned with public token IDs 0..259.
        self._token_bytes: list[bytes] = [bytes([value]) for value in range(256)] + [b""] * 4
        for index, (left, right) in enumerate(self.merges):
            expected_id = self.BASE_VOCAB_SIZE + index
            if (
                left < 0 or right < 0
                or 256 <= left < self.BASE_VOCAB_SIZE
                or 256 <= right < self.BASE_VOCAB_SIZE
                or left >= expected_id or right >= expected_id
            ):
                raise ValueError("BPE merges may only reference byte or previously merged tokens")
            self._token_bytes.append(self._token_bytes[left] + self._token_bytes[right])
        if len(set(self.merges)) != len(self.merges):
            raise ValueError("duplicate BPE merge rules are not allowed")

    @property
    def vocab_size(self) -> int:
        return self.BASE_VOCAB_SIZE + len(self.merges)

    @classmethod
    def train_from_iterator(
        cls,
        texts: Iterable[str],
        *,
        vocab_size: int = 1_024,
        min_frequency: int = 2,
        max_unique_pieces: int = 100_000,
    ) -> "ByteBPETokenizer":
        for name, value in (
            ("vocab_size", vocab_size),
            ("min_frequency", min_frequency),
            ("max_unique_pieces", max_unique_pieces),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if vocab_size < cls.BASE_VOCAB_SIZE:
            raise ValueError("vocab_size must be at least 260")
        if max_unique_pieces < 1:
            raise ValueError("max_unique_pieces must be positive")

        sequences: Counter[tuple[int, ...]] = Counter()
        for text in texts:
            if not isinstance(text, str):
                raise TypeError("training texts must be strings")
            for match in cls._PIECE_PATTERN.finditer(text):
                raw_piece = match.group(0).encode("utf-8")
                for offset in range(0, len(raw_piece), cls.MAX_PIECE_BYTES):
                    piece = tuple(raw_piece[offset : offset + cls.MAX_PIECE_BYTES])
                    if piece in sequences or len(sequences) < max_unique_pieces:
                        sequences[piece] += 1
        if not sequences:
            raise ValueError("cannot train BPE tokenizer from an empty text iterator")

        learned: list[tuple[int, int]] = []
        next_id = cls.BASE_VOCAB_SIZE
        while next_id < vocab_size:
            pair_counts: Counter[tuple[int, int]] = Counter()
            for sequence, frequency in sequences.items():
                for pair in zip(sequence, sequence[1:]):
                    pair_counts[pair] += frequency
            if not pair_counts:
                break
            best_pair, frequency = min(
                pair_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )
            if frequency < min_frequency:
                break

            learned.append(best_pair)
            merged_id = next_id
            updated: Counter[tuple[int, ...]] = Counter()
            for sequence, count in sequences.items():
                updated[_apply_merge(sequence, best_pair[0], best_pair[1], merged_id)] += count
            sequences = updated
            next_id += 1
        return cls(learned)

    def encode(
        self,
        text: str,
        *,
        add_bos: bool = False,
        add_eos: bool = False,
    ) -> list[int]:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        result: list[int] = []
        for match in self._PIECE_PATTERN.finditer(text):
            raw_piece = match.group(0).encode("utf-8")
            for offset in range(0, len(raw_piece), self.MAX_PIECE_BYTES):
                sequence = tuple(raw_piece[offset : offset + self.MAX_PIECE_BYTES])
                for merge_index, (left, right) in enumerate(self.merges):
                    sequence = _apply_merge(
                        sequence, left, right, self.BASE_VOCAB_SIZE + merge_index
                    )
                result.extend(sequence)
        if add_bos:
            result.insert(0, self.BOS)
        if add_eos:
            result.append(self.EOS)
        return result

    def decode(self, token_ids: Iterable[int], *, skip_special_tokens: bool = True) -> str:
        raw = bytearray()
        names = {self.PAD: "pad", self.BOS: "bos", self.EOS: "eos", self.UNK: "unk"}
        for token_id in token_ids:
            if isinstance(token_id, bool) or not isinstance(token_id, int):
                raise TypeError("token IDs must be integers")
            if 0 <= token_id < 256:
                raw.append(token_id)
            elif token_id in names and skip_special_tokens:
                continue
            elif token_id in names:
                raw.extend(f"<{names[token_id]}>".encode("ascii"))
            elif 260 <= token_id < self.vocab_size:
                raw.extend(self._token_bytes[token_id])
            else:
                raise ValueError(f"token ID out of range: {token_id}")
        return raw.decode("utf-8", errors="replace")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "type": "utf8-byte-bpe",
            "base_vocab_size": self.BASE_VOCAB_SIZE,
            "vocab_size": self.vocab_size,
            "special_tokens": {
                "pad": self.PAD,
                "bos": self.BOS,
                "eos": self.EOS,
                "unk": self.UNK,
            },
            "merges": [[left, right] for left, right in self.merges],
        }

    @classmethod
    def from_dict(cls, values: dict[str, object]) -> "ByteBPETokenizer":
        if not isinstance(values, dict):
            raise TypeError("tokenizer configuration must be a JSON object")
        if (
            values.get("schema_version") != cls.SCHEMA_VERSION
            or values.get("type") != "utf8-byte-bpe"
            or values.get("base_vocab_size") != cls.BASE_VOCAB_SIZE
            or values.get("special_tokens") != {
                "pad": cls.PAD, "bos": cls.BOS, "eos": cls.EOS, "unk": cls.UNK
            }
        ):
            raise ValueError("unsupported or incompatible BPE tokenizer configuration")
        raw_merges = values.get("merges")
        if not isinstance(raw_merges, list):
            raise ValueError("BPE merges must be a list")
        merges: list[tuple[int, int]] = []
        for pair in raw_merges:
            if (
                not isinstance(pair, list)
                or len(pair) != 2
                or any(isinstance(value, bool) or not isinstance(value, int) for value in pair)
            ):
                raise ValueError("each BPE merge must be a pair of integer token IDs")
            merges.append((pair[0], pair[1]))
        tokenizer = cls(merges)
        if values.get("vocab_size") != tokenizer.vocab_size:
            raise ValueError("BPE vocabulary size does not match its merge table")
        return tokenizer

    def save(self, path: str | Path) -> None:
        _atomic_json_save(path, self.to_dict(), prefix=".bpe-tokenizer-")

    @classmethod
    def load(cls, path: str | Path) -> "ByteBPETokenizer":
        return cls.from_dict(_load_json_object(path))



def load_tokenizer(path: str | Path) -> ByteTokenizer | ByteBPETokenizer:
    """Load a supported, versioned tokenizer configuration by its declared type."""
    payload = _load_json_object(path)
    tokenizer_type = payload.get("type")
    if tokenizer_type == "utf8-byte":
        return ByteTokenizer.from_dict(payload)
    if tokenizer_type == "utf8-byte-bpe":
        return ByteBPETokenizer.from_dict(payload)
    raise ValueError(f"unsupported tokenizer type: {tokenizer_type!r}")
