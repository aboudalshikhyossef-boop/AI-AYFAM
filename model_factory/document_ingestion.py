"""Local document ingestion for AI AYFAM training corpora.

This module extracts text from user-selected PDF, TXT, DOCX and Markdown
files. It writes provenance-aware JSONL records only; it never starts training
and never contacts an external service.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Iterable, Iterator
import zipfile

from defusedxml import ElementTree as SafeET

from model_factory.corpus_tools import detect_language, normalize_text
from model_factory.data import MAX_RECORD_BYTES


SUPPORTED_DOCUMENT_EXTENSIONS = {".pdf", ".txt", ".docx", ".md", ".markdown"}
MAX_DOCUMENT_BYTES = 150 * 1024 * 1024
MAX_PDF_PAGES = 4_000
MAX_DOCX_UNCOMPRESSED_BYTES = 250 * 1024 * 1024
MAX_DOCX_XML_BYTES = 32 * 1024 * 1024
MAX_DOCX_COMPRESSION_RATIO = 200
MAX_CHUNKS_PER_DOCUMENT = 15_000
MAX_TEXT_BLOCK_CHARS = 64_000
DEFAULT_CHUNK_SIZE = 1_200
DEFAULT_CHUNK_OVERLAP = 150
_REJECTED_LICENSES = {"", "unknown", "unspecified", "none", "n/a", "na", "no-license"}
_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
_TEXT_HEADING_RE = re.compile(
    r"^\s*(?:chapter\s+\d+\b|section\s+\d+\b|الفصل\s+[\d٠-٩]+\b|الباب\s+[\d٠-٩]+\b).*$",
    re.IGNORECASE,
)
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


class DocumentIngestionError(ValueError):
    """Raised when a source document cannot safely be converted to training text."""


@dataclass(frozen=True)
class DocumentInput:
    """One selected document and the provenance/permission supplied by its owner."""

    path: str | Path
    source: str
    license: str
    title: str | None = None


@dataclass(frozen=True)
class DocumentIngestionReport:
    documents: int
    pages: int
    empty_pages: int
    chunks: int
    characters: int
    languages: dict[str, int]
    records_by_split: dict[str, int]
    fingerprint: str
    output_path: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class _TextBlock:
    text: str
    chapter: str = ""
    page: int | None = None


def _validated_document(item: DocumentInput) -> tuple[Path, str, str, str, str]:
    if not isinstance(item, DocumentInput):
        raise TypeError("documents must contain DocumentInput objects")
    path = Path(item.path).expanduser()
    if path.is_symlink():
        raise DocumentIngestionError(f"symbolic links are not accepted as document inputs: {path.name}")
    try:
        info = path.stat()
    except OSError as exc:
        raise DocumentIngestionError(f"cannot access document {path.name}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise DocumentIngestionError(f"document is not a regular file: {path.name}")
    if info.st_size <= 0:
        raise DocumentIngestionError(f"document is empty: {path.name}")
    if info.st_size > MAX_DOCUMENT_BYTES:
        raise DocumentIngestionError(
            f"{path.name} exceeds the {MAX_DOCUMENT_BYTES // (1024 * 1024)} MB per-document limit"
        )

    extension = path.suffix.casefold()
    if extension not in SUPPORTED_DOCUMENT_EXTENSIONS:
        supported = ", ".join(sorted(SUPPORTED_DOCUMENT_EXTENSIONS))
        raise DocumentIngestionError(f"unsupported document type {extension!r}; supported: {supported}")

    source = item.source.strip() if isinstance(item.source, str) else ""
    license_name = item.license.strip() if isinstance(item.license, str) else ""
    title = item.title.strip() if isinstance(item.title, str) and item.title.strip() else path.stem
    if not source:
        raise DocumentIngestionError(f"source provenance is required for {path.name}")
    if license_name.casefold() in _REJECTED_LICENSES:
        raise DocumentIngestionError(f"an explicit training license or owner permission is required for {path.name}")
    if len(source) > 500 or len(license_name) > 200 or len(title) > 500:
        raise DocumentIngestionError(f"document metadata is too long for {path.name}")
    return path, source, license_name, title, extension


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _iter_plain_text_blocks(path: Path, *, markdown: bool) -> Iterator[_TextBlock]:
    chapter = ""
    paragraph: list[str] = []
    paragraph_chars = 0
    try:
        with path.open("rb") as stream:
            first_line = True
            while True:
                raw_line = stream.readline(MAX_RECORD_BYTES + 1)
                if not raw_line:
                    break
                if len(raw_line) > MAX_RECORD_BYTES:
                    raise DocumentIngestionError(
                        f"{path.name} contains a text line longer than {MAX_RECORD_BYTES} bytes; split it into shorter lines before importing"
                    )
                encoding = "utf-8-sig" if first_line else "utf-8"
                first_line = False
                line = raw_line.rstrip(b"\r\n").decode(encoding, errors="strict")
                heading = _HEADING_RE.match(line) if markdown else None
                if heading:
                    if paragraph:
                        text = "\n".join(paragraph).strip()
                        if text:
                            yield _TextBlock(text=text, chapter=chapter)
                        paragraph.clear()
                        paragraph_chars = 0
                    chapter = heading.group(2).strip()
                    if chapter:
                        yield _TextBlock(text=chapter, chapter=chapter)
                    continue

                if not markdown and _TEXT_HEADING_RE.match(line):
                    if paragraph:
                        text = "\n".join(paragraph).strip()
                        if text:
                            yield _TextBlock(text=text, chapter=chapter)
                        paragraph.clear()
                        paragraph_chars = 0
                    chapter = line.strip()
                    yield _TextBlock(text=chapter, chapter=chapter)
                    continue

                if not line.strip():
                    if paragraph:
                        text = "\n".join(paragraph).strip()
                        if text:
                            yield _TextBlock(text=text, chapter=chapter)
                        paragraph.clear()
                        paragraph_chars = 0
                    continue
                paragraph.append(line)
                paragraph_chars += len(line) + 1
                if paragraph_chars >= MAX_TEXT_BLOCK_CHARS:
                    text = "\n".join(paragraph).strip()
                    if text:
                        yield _TextBlock(text=text, chapter=chapter)
                    paragraph.clear()
                    paragraph_chars = 0

            if paragraph:
                text = "\n".join(paragraph).strip()
                if text:
                    yield _TextBlock(text=text, chapter=chapter)
    except UnicodeDecodeError as exc:
        raise DocumentIngestionError(
            f"{path.name} is not valid UTF-8 text; convert it to UTF-8 before importing"
        ) from exc
    except OSError as exc:
        raise DocumentIngestionError(f"cannot read {path.name}: {exc}") from exc


def _iter_pdf_blocks(path: Path) -> Iterator[_TextBlock]:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise DocumentIngestionError(
            "PDF support requires the pinned pypdf dependency from requirements.txt"
        ) from exc

    try:
        reader = PdfReader(str(path), strict=False)
        if reader.is_encrypted:
            try:
                decrypted = reader.decrypt("")
            except Exception as exc:
                raise DocumentIngestionError(
                    f"{path.name} is password-protected and cannot be opened without a password"
                ) from exc
            if not decrypted:
                raise DocumentIngestionError(
                    f"{path.name} is password-protected and cannot be opened without a password"
                )
        page_count = len(reader.pages)
        if page_count > MAX_PDF_PAGES:
            raise DocumentIngestionError(
                f"{path.name} contains {page_count} pages; the limit is {MAX_PDF_PAGES}"
            )
        for index, page in enumerate(reader.pages, start=1):
            try:
                text = page.extract_text() or ""
            except Exception as exc:
                raise DocumentIngestionError(
                    f"could not extract text from page {index} of {path.name}: {exc}"
                ) from exc
            yield _TextBlock(text=text, page=index)
    except DocumentIngestionError:
        raise
    except Exception as exc:
        raise DocumentIngestionError(f"cannot parse PDF {path.name}: {exc}") from exc


def _iter_docx_blocks(path: Path) -> Iterator[_TextBlock]:
    """Read DOCX paragraphs in document order without resolving external links."""
    try:
        with zipfile.ZipFile(path, "r") as archive:
            entries = archive.infolist()
            total_uncompressed = sum(entry.file_size for entry in entries)
            if total_uncompressed > MAX_DOCX_UNCOMPRESSED_BYTES:
                raise DocumentIngestionError(
                    f"{path.name} expands beyond the safe DOCX size limit"
                )
            try:
                document_info = archive.getinfo("word/document.xml")
            except KeyError as exc:
                raise DocumentIngestionError(f"{path.name} is not a valid DOCX document") from exc
            if document_info.file_size > MAX_DOCX_XML_BYTES:
                raise DocumentIngestionError(
                    f"{path.name} contains an oversized document.xml part"
                )
            compressed_size = max(1, document_info.compress_size)
            if document_info.file_size / compressed_size > MAX_DOCX_COMPRESSION_RATIO:
                raise DocumentIngestionError(
                    f"{path.name} has an unsafe DOCX compression ratio"
                )

            chapter = ""
            page_number = 1
            with archive.open(document_info, "r") as document_xml:
                try:
                    for _event, paragraph in SafeET.iterparse(document_xml, events=("end",)):
                        if paragraph.tag != f"{_W}p":
                            continue

                        pieces: list[str] = []
                        page_break = False
                        for node in paragraph.iter():
                            if node.tag == f"{_W}t" and node.text:
                                pieces.append(node.text)
                            elif node.tag == f"{_W}tab":
                                pieces.append("\t")
                            elif node.tag == f"{_W}br":
                                pieces.append("\n")
                                if node.attrib.get(f"{_W}type") == "page":
                                    page_break = True
                            elif node.tag == f"{_W}lastRenderedPageBreak":
                                page_break = True

                        paragraph_text = "".join(pieces).strip()
                        properties = paragraph.find(f"{_W}pPr")
                        style = properties.find(f"{_W}pStyle") if properties is not None else None
                        style_id = style.attrib.get(f"{_W}val", "") if style is not None else ""
                        if paragraph_text and style_id.casefold().startswith("heading"):
                            chapter = paragraph_text[:500]

                        if paragraph_text:
                            yield _TextBlock(
                                text=paragraph_text,
                                chapter=chapter,
                                page=page_number,
                            )
                        if page_break:
                            page_number += 1
                        paragraph.clear()
                except Exception as exc:
                    raise DocumentIngestionError(
                        f"cannot safely parse DOCX XML in {path.name}: {exc}"
                    ) from exc
    except DocumentIngestionError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise DocumentIngestionError(f"cannot open DOCX {path.name}: {exc}") from exc


def _iter_blocks(path: Path, extension: str) -> Iterator[_TextBlock]:
    if extension == ".pdf":
        yield from _iter_pdf_blocks(path)
    elif extension == ".docx":
        yield from _iter_docx_blocks(path)
    elif extension in {".md", ".markdown"}:
        yield from _iter_plain_text_blocks(path, markdown=True)
    else:
        yield from _iter_plain_text_blocks(path, markdown=False)


def _split_text(text: str, chunk_size: int, overlap: int) -> Iterator[str]:
    start = 0
    length = len(text)
    while start < length:
        end = min(start + chunk_size, length)
        if end < length:
            minimum_cut = start + max(1, chunk_size // 2)
            candidates = (
                text.rfind("\n\n", minimum_cut, end),
                text.rfind("\n", minimum_cut, end),
                text.rfind(". ", minimum_cut, end),
                text.rfind(" ", minimum_cut, end),
            )
            cut = max(candidates)
            if cut >= minimum_cut:
                end = cut + (2 if text.startswith("\n\n", cut) else 1)
        piece = text[start:end].strip()
        if piece:
            yield piece
        if end >= length:
            break
        next_start = max(start + 1, end - overlap)
        start = next_start


def _iter_document_chunks(
    blocks: Iterable[_TextBlock],
    *,
    chunk_size: int,
    overlap: int,
) -> Iterator[tuple[str, str, int | None, int]]:
    pending = ""
    pending_chapter = ""
    pending_page: int | None = None
    chunk_index = 0

    def emit(text: str, chapter: str, page: int | None) -> Iterator[tuple[str, str, int | None, int]]:
        nonlocal chunk_index
        for piece in _split_text(text, chunk_size, overlap):
            normalized = normalize_text(piece)
            if normalized:
                yield normalized, chapter, page, chunk_index
                chunk_index += 1

    for block in blocks:
        block_text = normalize_text(block.text)
        if not block_text:
            continue
        boundary_changed = pending and (
            block.chapter != pending_chapter or block.page != pending_page
        )
        if boundary_changed:
            yield from emit(pending, pending_chapter, pending_page)
            pending = ""

        if not pending:
            pending_chapter = block.chapter
            pending_page = block.page
            pending = block_text
            continue

        separator = "\n\n"
        if len(pending) + len(separator) + len(block_text) <= chunk_size:
            pending = f"{pending}{separator}{block_text}"
            continue

        yield from emit(pending, pending_chapter, pending_page)
        tail = pending[-overlap:] if overlap else ""
        pending = f"{tail}{separator}{block_text}".strip()
        pending_chapter = block.chapter
        pending_page = block.page
        if len(pending) >= chunk_size:
            pieces = iter(_split_text(pending, chunk_size, overlap))
            previous = next(pieces, "")
            for piece in pieces:
                normalized = normalize_text(previous)
                if normalized:
                    yield normalized, pending_chapter, pending_page, chunk_index
                    chunk_index += 1
                previous = piece
            pending = previous

    if pending:
        yield from emit(pending, pending_chapter, pending_page)


def ingest_documents(
    documents: Iterable[DocumentInput],
    output_path: str | Path,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap: int = DEFAULT_CHUNK_OVERLAP,
    require_held_out: bool = False,
) -> DocumentIngestionReport:
    """Convert selected documents into a private, atomic, provenance-aware JSONL file.

    Original source files are never modified. A failed conversion leaves any
    previously existing destination untouched.
    """
    if not isinstance(require_held_out, bool):
        raise ValueError("require_held_out must be a boolean")
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or not 64 <= chunk_size <= 50_000:
        raise ValueError("chunk_size must be an integer between 64 and 50000")
    if isinstance(overlap, bool) or not isinstance(overlap, int) or overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must be a non-negative integer smaller than chunk_size")

    items = list(documents)
    if not items:
        raise DocumentIngestionError("select at least one document")
    validated = [_validated_document(item) for item in items]
    resolved_paths = [path.resolve() for path, *_ in validated]
    if len(set(resolved_paths)) != len(resolved_paths):
        raise DocumentIngestionError("the same document was selected more than once")

    document_ids_by_path = {
        path.resolve(): _file_sha256(path)[:24]
        for path, *_metadata in validated
    }
    document_splits: dict[str, str] = {}
    if require_held_out:
        unique_document_ids = set(document_ids_by_path.values())
        if len(unique_document_ids) < 3:
            raise DocumentIngestionError(
                "at least three independent documents are required to create train, validation, "
                "and test splits without dividing a book across them"
            )
        ranked_ids = sorted(
            unique_document_ids,
            key=lambda document_id: hashlib.sha256(
                f"ayfam-document-split-v1\\0{document_id}".encode("utf-8")
            ).digest(),
        )
        validation_count = max(1, int(round(len(ranked_ids) * 0.05)))
        test_count = max(1, int(round(len(ranked_ids) * 0.05)))
        train_count = len(ranked_ids) - validation_count - test_count
        if train_count < 1:
            raise DocumentIngestionError(
                "not enough independent documents to keep training and held-out splits separate"
            )
        for index, document_id in enumerate(ranked_ids):
            if index < train_count:
                document_splits[document_id] = "train"
            elif index < train_count + validation_count:
                document_splits[document_id] = "validation"
            else:
                document_splits[document_id] = "test"

    destination = Path(output_path).expanduser()
    if destination.suffix.casefold() != ".jsonl":
        raise DocumentIngestionError("document ingestion output must use the .jsonl extension")
    if destination.is_symlink():
        raise DocumentIngestionError("the corpus output path must not be a symbolic link")
    if destination.resolve() in resolved_paths:
        raise DocumentIngestionError("the corpus output path must differ from every source document")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".ayfam-document-ingestion-",
        suffix=".jsonl",
        dir=destination.parent,
        text=True,
    )
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    documents_count = 0
    pages_count = 0
    empty_pages = 0
    chunks_count = 0
    characters_count = 0
    languages: Counter[str] = Counter()
    split_counts: Counter[str] = Counter()

    try:
        os.chmod(temporary_path, 0o600)
        with temporary_path.open("w", encoding="utf-8", newline="\n") as output:
            for path, source, license_name, title, extension in validated:
                document_id = document_ids_by_path[path.resolve()]
                document_chunks = 0
                blocks = _iter_blocks(path, extension)
                page_numbers: set[int] = set()
                text_pages: set[int] = set()

                def tracked_blocks() -> Iterator[_TextBlock]:
                    for block in blocks:
                        if block.page is not None:
                            page_numbers.add(block.page)
                            if block.text.strip():
                                text_pages.add(block.page)
                        yield block

                for text, chapter, page, chunk_index in _iter_document_chunks(
                    tracked_blocks(),
                    chunk_size=chunk_size,
                    overlap=overlap,
                ):
                    record = {
                        "id": f"{document_id}-{chunk_index:06d}",
                        "text": text,
                        "source": source,
                        "license": license_name,
                        "group_id": document_id,
                        "document_id": document_id,
                        "title": title,
                        "filename": path.name,
                        "file_type": extension.lstrip("."),
                        "chapter": chapter,
                        "page": page,
                        "chunk_index": chunk_index,
                        "language": detect_language(text),
                    }
                    document_split = document_splits.get(document_id)
                    if document_split:
                        record["split"] = document_split
                        split_counts[document_split] += 1
                    serialized = json.dumps(record, ensure_ascii=False) + "\n"
                    if len(serialized.encode("utf-8")) > MAX_RECORD_BYTES:
                        raise DocumentIngestionError(
                            f"a generated text chunk from {path.name} exceeds the safe record size"
                        )
                    output.write(serialized)
                    chunks_count += 1
                    document_chunks += 1
                    characters_count += len(text)
                    languages[record["language"]] += 1
                pages_count += len(page_numbers)
                empty_pages += len(page_numbers - text_pages)
                if document_chunks == 0:
                    raise DocumentIngestionError(
                        f"no usable text could be extracted from {path.name}; scanned-image PDFs need OCR, which is not enabled for PDFs"
                    )
                if document_chunks > MAX_CHUNKS_PER_DOCUMENT:
                    raise DocumentIngestionError(
                        f"{path.name} exceeds the {MAX_CHUNKS_PER_DOCUMENT} chunk per-document limit"
                    )
                documents_count += 1
            output.flush()
            os.fsync(output.fileno())

        os.replace(temporary_path, destination)
    finally:
        temporary_path.unlink(missing_ok=True)

    fingerprint = _file_sha256(destination)
    return DocumentIngestionReport(
        documents=documents_count,
        pages=pages_count,
        empty_pages=empty_pages,
        chunks=chunks_count,
        characters=characters_count,
        languages=dict(sorted(languages.items())),
        records_by_split={
            split: split_counts[split]
            for split in ("train", "validation", "test")
            if split_counts[split]
        },
        fingerprint=fingerprint,
        output_path=str(destination),
    )
