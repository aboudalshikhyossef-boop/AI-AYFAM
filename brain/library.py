"""
AI AYFAM — Personal Library (Document Ingestion)
تُحمِّل ملفاً (PDF/TXT/Markdown) وتفهرسه بحثاً نصياً كاملاً محلياً — بدون
أي اتصال خارجي. هذا ليس "فهماً" بمعنى نموذج لغوي، بل استخراج نص + تقسيم
لمقاطع + فهرسة FTS5 (BM25) — بحث دقيق وسريع مع ذكر المصدر بدقة.
"""

import os
import re

from brain import tech_extractor

MAX_FILE_SIZE = 150 * 1024 * 1024   # 150MB — حد معقول لملف مرجعي واحد
MAX_PAGES = 4000                     # حماية من ملفات PDF ضخمة بشكل مَرضي
CHUNK_SIZE = 1200                    # أحرف تقريباً لكل مقطع
CHUNK_OVERLAP = 150                  # تداخل بين المقاطع حتى لا تُقطَع فكرة في المنتصف
MAX_CHUNKS = 15000                   # حماية إضافية من ملفات نصية ضخمة بشكل غير معتاد

SUPPORTED_EXTENSIONS = {".pdf", ".txt", ".md", ".markdown"}


class IngestError(Exception):
    pass


def _extract_pdf(path: str):
    """يُرجع قائمة (page_number, text) — صفحة واحدة في كل عنصر."""
    try:
        from pypdf import PdfReader
    except ImportError:
        raise IngestError(
            "مكتبة قراءة PDF غير مثبتة. ثبّتها بـ: pip3 install pypdf"
        )
    try:
        reader = PdfReader(path)
    except Exception as e:
        raise IngestError(f"تعذّرت قراءة ملف PDF (قد يكون تالفاً أو محمياً بكلمة مرور): {e}")

    if getattr(reader, "is_encrypted", False):
        try:
            reader.decrypt("")  # يحاول فتحه بدون كلمة مرور فقط
        except Exception:
            raise IngestError("ملف PDF محمي بكلمة مرور — لا يمكن استيعابه حالياً.")

    pages = []
    n = min(len(reader.pages), MAX_PAGES)
    for i in range(n):
        try:
            text = reader.pages[i].extract_text() or ""
        except Exception:
            text = ""
        if text.strip():
            pages.append((i + 1, text))
    return pages


def _extract_text_file(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    return [(None, content)]


def _chunk_text(pages: list):
    """يقسّم نص كل صفحة إلى مقاطع بحجم معقول مع تداخل بسيط، محافظاً على
    حدود الفقرات قدر الإمكان بدل التقطيع الحرفي الجاف."""
    chunks = []  # (page_hint, content)
    for page_num, text in pages:
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        if not text:
            continue
        start = 0
        n = len(text)
        while start < n:
            end = min(start + CHUNK_SIZE, n)
            # حاول قطع عند نهاية فقرة/جملة قريبة بدل منتصف كلمة
            if end < n:
                cut = text.rfind("\n\n", start, end)
                if cut == -1 or cut <= start + 200:
                    cut = text.rfind(". ", start, end)
                if cut != -1 and cut > start + 200:
                    end = cut + 1
            chunk = text[start:end].strip()
            if chunk:
                page_hint = f"صفحة {page_num}" if page_num else None
                chunks.append((page_hint, chunk))
                if len(chunks) >= MAX_CHUNKS:
                    return chunks
            if end >= n:
                break
            # تقدّم مضمون دائماً (start يزيد بمقدار حرف واحد على الأقل)
            # لتفادي أي احتمال لحلقة لا نهائية على نصوص غريبة الشكل.
            start = max(start + 1, end - CHUNK_OVERLAP)
    return chunks


def ingest_file(path: str, kb, title: str = None) -> dict:
    """يستوعب ملفاً في المكتبة الشخصية. يُرجع ملخصاً واضحاً يمكن عرضه مباشرة
    للمستخدم (شفافية: ماذا فعلت بالضبط)."""
    if not path or not isinstance(path, str) or "\x00" in path:
        raise IngestError(f"مسار غير صالح: '{path}'")
    # نقبل مساراً مطلقاً (/home/user/book.pdf) أو نسبياً (book.pdf,
    # ../book.pdf) أو يبدأ بـ ~ — كلها تُحوَّل هنا لمسار مطلق آمن ومُطبَّع
    # (os.path.abspath يُزيل أي ".." تلقائياً بطريقة صحيحة)، فلا داعي
    # لإجبار المستخدم على كتابة المسار الكامل يدوياً.
    path = os.path.abspath(os.path.expanduser(path.strip()))

    if not os.path.isfile(path):
        raise IngestError(f"الملف غير موجود: {path}")

    size = os.path.getsize(path)
    if size == 0:
        raise IngestError("الملف فارغ.")
    if size > MAX_FILE_SIZE:
        raise IngestError(
            f"الملف كبير جداً ({size / (1024*1024):.1f}MB). الحد الأقصى "
            f"{MAX_FILE_SIZE / (1024*1024):.0f}MB لكل ملف مرجعي."
        )

    ext = os.path.splitext(path)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise IngestError(
            f"صيغة غير مدعومة حالياً: {ext}\n"
            f"المدعوم الآن: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )

    if ext == ".pdf":
        pages = _extract_pdf(path)
    else:
        pages = _extract_text_file(path)

    if not pages or not any(t.strip() for _, t in pages):
        raise IngestError(
            "لم أستطع استخراج أي نص من الملف. قد يكون PDF ممسوحاً ضوئياً "
            "(صوراً فقط بدون طبقة نص) — هذا غير مدعوم حالياً."
        )

    chunks = _chunk_text(pages)
    if not chunks:
        raise IngestError("لم يُنتج تقسيم الملف أي مقاطع قابلة للفهرسة.")

    doc_title = title or os.path.splitext(os.path.basename(path))[0]
    total_chars = sum(len(c) for _, c in chunks)

    doc_id = kb.add_library_document(doc_title, path, ext.lstrip("."))
    tools_found = 0
    commands_found = 0
    for idx, (page_hint, content) in enumerate(chunks):
        chunk_id = kb.add_library_chunk(doc_id, idx, content, page_hint)
        for rec in tech_extractor.extract_from_chunk(content):
            kb.add_tool_mention(
                doc_id, chunk_id, rec["tool"], rec["category"],
                rec.get("command"), rec.get("context"), page_hint
            )
            tools_found += 1
            if rec.get("command"):
                commands_found += 1
    kb.finalize_library_document(doc_id, total_chars, len(chunks))

    # ─── تشخيص ذاتي لجودة الاستيعاب — شفافية بدل نجاح صامت مضلِّل ───────
    diagnostics = []
    sample_text = " ".join(c for _, c in chunks[:5])
    if sample_text:
        letters = sum(1 for ch in sample_text if ch.isalpha())
        if letters < len(sample_text) * 0.35:
            diagnostics.append(
                "⚠️ جودة استخراج النص تبدو ضعيفة (نسبة حروف منخفضة). هذا شائع مع "
                "PDF ممسوح ضوئياً بخط غير قياسي، أو ترميز غير مدعوم جيداً — النتائج "
                "أدناه قد تكون غير دقيقة بسبب هذا، وليس عيباً في محرك الاستخراج نفسه."
            )
    doc_tools = kb.get_doc_tool_stats(doc_id)
    if not doc_tools:
        diagnostics.append(
            "ℹ️ لم أكتشف أي أداة أو أمر معروف في هذا الملف رغم فهرسته بنجاح — "
            "إما أنه نظري بحت بدون أمثلة أوامر، أو يستخدم أدوات خارج قاموسي "
            "الحالي (يمكنك إخباري باسمها لأوسّع القاموس)."
        )

    return {
        "doc_id": doc_id,
        "title": doc_title,
        "file_type": ext.lstrip("."),
        "pages": len(pages) if ext == ".pdf" else None,
        "chunks": len(chunks),
        "tools_detected": doc_tools,
        "commands_extracted": commands_found,
        "diagnostics": diagnostics,
        "total_chars": total_chars,
        "preview": chunks[0][1][:220].strip() + ("…" if len(chunks[0][1]) > 220 else ""),
    }
