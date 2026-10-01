"""
AI AYFAM — محرك الذكاء المحلي (Relevance Engine) — v4
=======================================================
هذا الملف هو قلب التحسين المطلوب: "أذكى بكثير، بدون مفتاح API ولا نموذج
تُحمِّله". الطريقة الوحيدة الصادقة لتحقيق ذلك محلياً وبدون إنترنت هي
إحصاء رياضي حقيقي على نص مكتبتك نفسها — لا نموذج مُدرَّب مسبقاً، لا
أوزان مُحمَّلة من أي مكان. كل شيء هنا يُحسَب من الصفر من كتبك وقت
البناء، ويعمل بعدها بلا اتصال إطلاقاً.

ثلاث تقنيات كلاسيكية (أقدم من الشبكات العصبية بعقود، وما زالت تُستخدَم
في محركات بحث حقيقية اليوم كطبقة أولى قبل أي LLM):

1. **TF-IDF + تشابه جيبي (cosine similarity)** — بدل "تحتوي الكلمة أم لا"
   (FTS5)، نُرتِّب المقاطع بحسب مدى تركّز كلمات سؤالك فيها إحصائياً نسبة
   لبقية المكتبة. نفس فكرة "OR بين الكلمات" لكن مع وزن حقيقي بدل تساوٍ.
2. **TextRank (PageRank على الجمل)** — لاستخلاص أهم N جملة *موجودة فعلاً*
   في نص، بدل توليد ملخص جديد. هذا استخلاص، وليس كتابة.
3. **خريطة تكرار مشترك (co-occurrence graph)** — أي مصطلحين يتكرر ظهورهما
   معاً كأهم مصطلحات لنفس الكتب، عبر كل مكتبتك، يُربَطان بوزن يتراكم.

⚠️ الحدّ الصادق: هذا كله يعتمد على تطابق/تجاور مفردات فعلي في النص —
وليس فهم معنى أو استنتاج مرادفات. مقطع يتحدّث عن "تصعيد الصلاحيات" لن
يُطابَق تلقائياً مع سؤال عن "privilege escalation" ما لم يُذكر المصطلح
الإنجليزي أيضاً في مكان قريب بالنص. هذا تحسين إحصائي حقيقي وكبير عن
المطابقة الحرفية القديمة، لكنه ليس فهماً بشرياً — ولا يدّعي أنه كذلك.
"""

import re
import json
import pickle
import itertools
from pathlib import Path

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

INTEL_DIR = Path.home() / ".ayfam" / "intelligence"
VECTORIZER_PATH = INTEL_DIR / "tfidf_vectorizer.pkl"
MATRIX_PATH = INTEL_DIR / "tfidf_matrix.npz"
CHUNK_IDS_PATH = INTEL_DIR / "chunk_ids.json"
META_PATH = INTEL_DIR / "meta.json"

MIN_CHUNKS_TO_BUILD = 5
_SENTENCE_SPLIT_RE = re.compile(r'(?<=[.!?؟۔])\s+')

# قائمة أدوات نحوية بحتة (عربي + إنجليزي) — وليست مصطلحات مجال. هذا يختلف
# عمداً عن الاعتماد على max_df وحده لإقصاء الكلمات الشائعة: مكتبة أمن
# سيبراني مكوّنة من 200 كتاب ستذكر كلمات مثل "vulnerability" أو "exploit"
# أو "ثغرة" في أغلب الكتب لأنها *موضوع المكتبة نفسه*، لا لأنها حشو نحوي —
# فلو استخدمنا max_df منخفضاً كبديل عن قاموس كلمات توقف، سيُقصي المحرك
# بالضبط أهم المصطلحات التي يريد المستخدم البحث عنها والربط بينها.
_STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "if", "then", "else", "for", "to", "of",
    "in", "on", "at", "by", "with", "from", "as", "is", "are", "was", "were", "be",
    "been", "being", "this", "that", "these", "those", "it", "its", "he", "she",
    "they", "we", "you", "i", "not", "no", "yes", "can", "could", "will", "would",
    "should", "may", "might", "must", "do", "does", "did", "have", "has", "had",
    "also", "than", "so", "such", "which", "who", "what", "when", "where", "why",
    "how", "all", "any", "each", "more", "most", "other", "some", "only", "own",
    "same", "just", "about", "into", "over", "after", "before", "there", "here",
    "من", "في", "على", "إلى", "عن", "مع", "هذا", "هذه", "ذلك", "تلك", "الذي",
    "التي", "الذين", "أن", "إن", "كان", "كانت", "يكون", "لا", "لم", "لن", "قد",
    "هو", "هي", "هم", "نحن", "أو", "و", "ثم", "بل", "لكن", "كل", "بعض", "أي",
    "ما", "لماذا", "كيف", "متى", "أين", "عليه", "عليها", "منه", "منها", "به",
    "بها", "له", "لها", "كما", "حيث", "بين", "بعد", "قبل", "عند", "دون",
}


class IndexNotBuiltError(Exception):
    pass


def is_index_built() -> bool:
    return VECTORIZER_PATH.exists() and MATRIX_PATH.exists() and CHUNK_IDS_PATH.exists()


def get_index_meta() -> dict:
    if META_PATH.exists():
        try:
            return json.loads(META_PATH.read_text())
        except Exception:
            return {}
    return {}


def is_index_current(kb) -> bool:
    """Return whether the saved index covers the current library contents."""
    if not is_index_built():
        return False
    try:
        indexed_ids = json.loads(CHUNK_IDS_PATH.read_text())
        current_ids = kb.get_library_chunk_ids()
        indexed_count = int(get_index_meta().get("chunks_indexed", -1))
        return indexed_ids == current_ids and indexed_count == len(current_ids)
    except (AttributeError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return False


def _load_index():
    if not is_index_built():
        raise IndexNotBuiltError(
            "لم يُبنَ فهرس الذكاء بعد — شغّل أمر 'إعادة بناء فهرس الذكاء' "
            "بعد إضافة كتبك أولاً."
        )
    with open(VECTORIZER_PATH, "rb") as f:
        vectorizer = pickle.load(f)
    matrix = sparse.load_npz(MATRIX_PATH)
    chunk_ids = json.loads(CHUNK_IDS_PATH.read_text())
    return vectorizer, matrix, chunk_ids


# ─────────────────────────────────────────────────────────────────────────
#  1) بناء الفهرس (TF-IDF عبر كل مقاطع المكتبة)
# ─────────────────────────────────────────────────────────────────────────

def build_index(kb, max_features: int = 80000) -> dict:
    """
    يبني فهرس TF-IDF فوق كل مقاطع المكتبة دفعة واحدة. عملية ثقيلة على
    مكتبة كبيرة (مئات الكتب) — لهذا هي خطوة صريحة منفصلة يُطلَق عليها
    بعد إضافة دفعة كتب، وليست تلقائية بعد كل كتاب فردي (حتى لا يتباطأ
    استيعاب كل كتاب بإعادة بناء الفهرس الكامل في كل مرة).

    ملاحظة تصميم مهمة: لا نعتمد على max_df منخفض لإقصاء الكلمات الشائعة
    (كما تفعل بعض الأدوات). مكتبة أمن سيبراني من 200 كتاب ستذكر "exploit"
    أو "vulnerability" أو "ثغرة" في أغلب الكتب — لأنها *موضوع المكتبة
    نفسه*، لا حشواً نحوياً. max_df منخفض كان سيُقصي بالضبط أهم المصطلحات
    التي تريد البحث عنها والربط بينها. لذا: قائمة stop_words يدوية صغيرة
    (أدوات ربط عربية/إنجليزية فقط) تتولى هذه المهمة، وmax_df=0.95 يبقى
    فقط لإقصاء الحالات شبه الحاضرة في كل مقطع دون استثناء.
    """
    rows = kb.get_all_library_chunks()
    if len(rows) < MIN_CHUNKS_TO_BUILD:
        return {"success": False, "error": f"مقاطع قليلة جداً في المكتبة ({len(rows)}) — أضف كتباً أولاً"}

    texts = [r["content"] for r in rows]
    chunk_ids = [r["id"] for r in rows]

    vectorizer = TfidfVectorizer(
        max_features=max_features,
        ngram_range=(1, 3),
        min_df=2,
        max_df=0.95,
        stop_words=sorted(_STOPWORDS),
        sublinear_tf=True,
        token_pattern=r"(?u)\b[\w\u0600-\u06FF]{2,}\b",
    )
    try:
        matrix = vectorizer.fit_transform(texts)
    except ValueError as e:
        return {"success": False, "error": f"تعذّر بناء الفهرس: {e}"}

    INTEL_DIR.mkdir(parents=True, exist_ok=True)
    with open(VECTORIZER_PATH, "wb") as f:
        pickle.dump(vectorizer, f)
    sparse.save_npz(MATRIX_PATH, matrix)
    CHUNK_IDS_PATH.write_text(json.dumps(chunk_ids))
    meta = {"chunks_indexed": len(chunk_ids), "vocabulary_size": len(vectorizer.vocabulary_)}
    META_PATH.write_text(json.dumps(meta))

    return {"success": True, **meta}


# ─────────────────────────────────────────────────────────────────────────
#  2) بحث مرجَّح بالصلة الإحصائية (عبر كل المكتبة دفعة واحدة)
# ─────────────────────────────────────────────────────────────────────────

def search(query: str, kb, top_k: int = 8) -> list:
    """
    بخلاف FTS5 (تطابق حرفي، OR بين الكلمات، لا ترتيب حقيقي بالصلة)، هذا
    يُرتِّب كل مقاطع المكتبة دفعة واحدة بحسب مدى تركّز كلمات سؤالك فعلياً
    في كل مقطع نسبة لبقية المكتبة — يُفضِّل مقطعاً يذكر كل كلمات سؤالك
    معاً على آخر يذكر كلمة واحدة فقط مصادفة، وهذا هو "البحث الصحيح
    والمُنسَّق" الذي غاب سابقاً.
    """
    if not query or not query.strip():
        return []
    try:
        vectorizer, matrix, chunk_ids = _load_index()
    except IndexNotBuiltError as e:
        return [{"error": str(e)}]
    if not is_index_current(kb):
        return [{"error": "الفهرس قديم أو لا يطابق المكتبة الحالية — أعد بناء فهرس الذكاء."}]

    q_vec = vectorizer.transform([query])
    if q_vec.nnz == 0:
        return []

    sims = cosine_similarity(q_vec, matrix).flatten()
    top_idx = np.argsort(-sims)[:top_k]
    results = []
    for i in top_idx:
        if sims[i] <= 0.001:
            continue
        chunk = kb.get_library_chunk_by_id(int(chunk_ids[i]))
        if chunk:
            chunk["relevance"] = round(float(sims[i]), 4)
            results.append(chunk)
    return results


def related_chunks(chunk_id: int, kb, top_k: int = 5) -> list:
    """أقرب مقاطع أخرى (من أي كتاب في مكتبتك) لمقطع معيّن — هذا هو
    "الربط بين الكتب" فعلياً: فقرات في كتب مختلفة تناقش موضوعاً مشابهاً
    إحصائياً، حتى لو لم تُستخدَم نفس الصياغة بالضبط."""
    try:
        vectorizer, matrix, chunk_ids = _load_index()
    except IndexNotBuiltError as e:
        return [{"error": str(e)}]
    if not is_index_current(kb):
        return [{"error": "الفهرس قديم أو لا يطابق المكتبة الحالية — أعد بناء فهرس الذكاء."}]
    if chunk_id not in chunk_ids:
        return []
    idx = chunk_ids.index(chunk_id)
    sims = cosine_similarity(matrix[idx], matrix).flatten()
    sims[idx] = -1.0
    top_idx = np.argsort(-sims)[:top_k]
    results = []
    for i in top_idx:
        if sims[i] <= 0.001:
            continue
        chunk = kb.get_library_chunk_by_id(int(chunk_ids[i]))
        if chunk:
            chunk["relevance"] = round(float(sims[i]), 4)
            results.append(chunk)
    return results


# ─────────────────────────────────────────────────────────────────────────
#  3) TextRank — استخلاص أهم N جملة موجودة فعلاً في نص
# ─────────────────────────────────────────────────────────────────────────

def extractive_summary(text: str, n_sentences: int = 5) -> list:
    """
    خوارزمية TextRank الكلاسيكية (Mihalcea & Tarau, 2004): تشابه TF-IDF
    بين كل زوج جمل → مصفوفة انتقال → PageRank بالتكرار (power iteration)
    → أهم N جملة بحسب مركزيتها في شبكة الجمل، مُعادة بترتيبها الأصلي
    للقراءة الطبيعية. هذه جمل *موجودة فعلاً* في النص — استخلاص، وليس
    كتابة ملخص جديد بأسلوب حر (ما يفعله LLM).
    """
    sentences = [s.strip() for s in _SENTENCE_SPLIT_RE.split(text or "") if len(s.strip()) > 15]
    if not sentences:
        return []
    if len(sentences) <= n_sentences:
        return sentences

    try:
        vec = TfidfVectorizer(max_df=0.95, min_df=1, stop_words=sorted(_STOPWORDS),
                               token_pattern=r"(?u)\b[\w\u0600-\u06FF]{2,}\b")
        sent_matrix = vec.fit_transform(sentences)
    except ValueError:
        return sentences[:n_sentences]

    sim = cosine_similarity(sent_matrix)
    np.fill_diagonal(sim, 0.0)
    row_sums = sim.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1.0
    transition = sim / row_sums

    n = len(sentences)
    scores = np.full(n, 1.0 / n)
    damping = 0.85
    for _ in range(40):
        scores = (1 - damping) / n + damping * transition.T.dot(scores)

    top_idx = sorted(np.argsort(-scores)[:n_sentences])
    return [sentences[i] for i in top_idx]


# ─────────────────────────────────────────────────────────────────────────
#  4) خريطة المفاهيم — ربط عبر كل الكتب بحسب تكرار الظهور معاً
# ─────────────────────────────────────────────────────────────────────────

def build_concept_graph(kb, top_terms_per_doc: int = 30, graph_top_terms: int = 15) -> dict:
    """
    لكل كتاب: أهم المصطلحات (كلمة أو عبارة قصيرة) بحسب TF-IDF عبر كامل
    المكتبة (نفس فهرس البحث، لأوزان قابلة للمقارنة بين الكتب). ثم أي
    مصطلحين يتكرران معاً ضمن أهم مصطلحات نفس الكتاب يُربَطان، ويتراكم
    الوزن كل كتاب جديد يجمعهما. **هذا تكرار إحصائي مشترك، وليس فهم علاقة
    معنى حقيقية** — لكنه ربط حقيقي وقابل للتحقق (تقدر ترى بالضبط أي كتب
    ساهمت في أي رابط).
    """
    try:
        vectorizer, matrix, chunk_ids = _load_index()
    except IndexNotBuiltError as e:
        return {"success": False, "error": str(e)}

    docs = kb.list_library_documents()
    if not docs:
        return {"success": False, "error": "لا كتب في المكتبة"}

    kb.clear_concept_data()
    terms_array = np.array(vectorizer.get_feature_names_out())
    chunk_id_to_row = {cid: i for i, cid in enumerate(chunk_ids)}

    terms_count = 0
    edges_count = 0
    docs_covered = 0

    for doc in docs:
        doc_chunk_ids = kb.get_chunk_ids_for_doc(doc["id"])
        rows = [chunk_id_to_row[c] for c in doc_chunk_ids if c in chunk_id_to_row]
        if not rows:
            continue
        doc_vec = np.asarray(matrix[rows].sum(axis=0)).flatten()
        if doc_vec.sum() <= 0:
            continue
        docs_covered += 1

        top_idx = np.argsort(-doc_vec)[:top_terms_per_doc]
        top_idx = [i for i in top_idx if doc_vec[i] > 0]
        top_terms = [(str(terms_array[i]), float(doc_vec[i])) for i in top_idx]

        for term, weight in top_terms:
            kb.add_concept_index_entry(term, doc["id"], weight)
            terms_count += 1

        graph_terms = sorted(t for t, _ in top_terms[:graph_top_terms])
        for a, b in itertools.combinations(graph_terms, 2):
            kb.add_concept_edge(a, b, 1.0)
            edges_count += 1

    kb.commit()
    return {
        "success": True, "terms_indexed": terms_count,
        "edges_created": edges_count, "documents": docs_covered,
    }


# ─────────────────────────────────────────────────────────────────────────
#  5) ترتيب عام صغير الحجم (يُستخدَم لإعادة ترتيب نتائج بحث الويب)
# ─────────────────────────────────────────────────────────────────────────

def rank_texts(query: str, candidates: list) -> list:
    """
    يُرتِّب قائمة نصوص قصيرة (مثال: نتائج بحث ويب من مصادر متعددة) بحسب
    صلتها الإحصائية الفعلية بالاستعلام، بدل ترتيبها حسب مصدرها فقط. فهرس
    صغير مؤقت يُبنى فوراً من هذه القائمة نفسها (لا علاقة له بفهرس المكتبة
    الكبير) — مناسب لعشرات العناصر، وليس آلاف.
    """
    if not candidates:
        return []
    texts = [c if isinstance(c, str) else str(c) for c in candidates]
    try:
        vec = TfidfVectorizer(stop_words=sorted(_STOPWORDS), token_pattern=r"(?u)\b[\w\u0600-\u06FF]{2,}\b")
        matrix = vec.fit_transform(texts + [query])
    except ValueError:
        return list(range(len(candidates)))
    sims = cosine_similarity(matrix[-1], matrix[:-1]).flatten()
    return list(np.argsort(-sims))
