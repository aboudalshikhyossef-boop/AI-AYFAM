"""Deterministic UTF-8 byte tokenizer owned by AI AYFAM.

This first tokenizer intentionally has no external vocabulary or pretrained assets.
A learned BPE tokenizer can replace it later behind the same encode/decode contract.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Iterable


class ByteTokenizer:
    PAD = 256
    BOS = 257
    EOS = 258
    UNK = 259
    VOCAB_SIZE = 260
    SCHEMA_VERSION = 1

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
            "special_tokens": {"pad": self.PAD, "bos": self.BOS, "eos": self.EOS, "unk": self.UNK},
        }

    @classmethod
    def from_dict(cls, values: dict[str, object]) -> "ByteTokenizer":
        if values != cls().to_dict():
            raise ValueError("unsupported or incompatible tokenizer configuration")
        return cls()

    def save(self, path: str | Path) -> None:
        destination = Path(path).expanduser()
        if destination.is_symlink():
            raise OSError("tokenizer destination must not be a symlink")
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix=".tokenizer-", dir=destination.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(self.to_dict(), stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, destination)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)

    @classmethod
    def load(cls, path: str | Path) -> "ByteTokenizer":
        source = Path(path).expanduser()
        if source.is_symlink():
            raise OSError("tokenizer source must not be a symlink")
        with source.open("r", encoding="utf-8") as stream:
            payload = json.load(stream)
        if not isinstance(payload, dict):
            raise ValueError("tokenizer configuration must be a JSON object")
        return cls.from_dict(payload)
