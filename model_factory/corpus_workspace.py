"""Private local workspace helpers for user-supplied training corpora."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile


def default_corpus_root() -> Path:
    """Return AYFAM's per-user corpus workspace without creating it."""
    return Path.home() / ".local" / "share" / "ayfam" / "training" / "corpora"


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def import_raw_corpus(
    source_path: str | Path,
    *,
    workspace: str | Path | None = None,
) -> Path:
    """Copy a selected JSONL source into a private, content-addressed workspace.

    The original file is never modified. The imported copy is created atomically
    with owner-only permissions. Its digest in the filename prevents different
    datasets with the same original filename from overwriting one another.
    """
    source = Path(source_path).expanduser()
    if source.is_symlink():
        raise OSError("corpus source must not be a symbolic link")
    try:
        source_stat = source.stat()
    except OSError as exc:
        raise OSError(f"cannot access corpus source: {exc}") from exc
    if not stat.S_ISREG(source_stat.st_mode):
        raise ValueError("corpus source must be a regular file")
    if source.suffix.casefold() != ".jsonl":
        raise ValueError("raw corpus must use the .jsonl file extension")

    destination_dir = (
        Path(workspace).expanduser()
        if workspace is not None
        else default_corpus_root() / "raw"
    )
    if destination_dir.is_symlink():
        raise OSError("corpus workspace must not be a symbolic link")
    destination_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not destination_dir.is_dir():
        raise NotADirectoryError("corpus workspace is not a directory")

    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "-", source.stem).strip(".-_")
    safe_stem = (safe_stem or "corpus")[:48]
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".ayfam-import-",
            suffix=".jsonl",
            dir=destination_dir,
        )
        temporary_path = Path(temporary_name)
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "wb") as destination, source.open("rb") as origin:
            os.fchmod(destination.fileno(), 0o600)
            while True:
                chunk = origin.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                destination.write(chunk)
            destination.flush()
            os.fsync(destination.fileno())

        if temporary_path.stat().st_size == 0:
            raise ValueError("corpus source is empty")

        digest_hex = digest.hexdigest()
        destination_path = destination_dir / f"{safe_stem}-{digest_hex[:12]}.jsonl"
        if destination_path.exists():
            if destination_path.is_symlink() or _file_sha256(destination_path) != digest_hex:
                raise FileExistsError("a different corpus already uses the import destination")
            temporary_path.unlink()
            temporary_path = None
            return destination_path

        os.replace(temporary_path, destination_path)
        temporary_path = None
        try:
            destination_path.chmod(0o600)
        except OSError:
            destination_path.unlink(missing_ok=True)
            raise
        return destination_path
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
