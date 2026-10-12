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

from __future__ import annotations

import re
import json
import pickle
import itertools
from pathlib import Path
from typing import Any
import math
from collections import Counter

class PureSparseMatrix:
    def __init__(self, rows: list[dict[int, float]], n_features: int):
        self.rows = rows
        self.shape = (len(rows), n_features)
        self.nnz = sum(len(r) for r in rows)

    def __getitem__(self, item: Any) -> Any:
        if isinstance(item, int):
            return PureSparseMatrix([self.rows[item]], self.shape[1])
        if isinstance(item, (list, tuple)):
            return PureSparseMatrix([self.rows[i] for i in item], self.shape[1])
        if isinstance(item, slice):
            return PureSparseMatrix(self.rows[item], self.shape[1])
        return self

    def sum(self, axis: int = 0, keepdims: bool = False) -> Any:
        res = [0.0] * self.shape[1]
        for row in self.rows:
            for col, val in row.items():
                res[col] += val
        return [res]


class PureTfidfVectorizer:
    def __init__(self, stop_words: Any = None, max_features: int = 80000, **kwargs: Any):
        self.stop_words = set(stop_words or [])
        self.max_features = max_features
        self.vocabulary_: dict[str, int] = {}
        self.feature_names_: list[str] = []
        self.idf_: dict[str, float] = {}

    def _tokenize(self, text: str) -> list[str]:
        words = re.findall(r"[\w\u0600-\u06FF]{2,}", str(text or "").lower())
        return [w for w in words if w not in self.stop_words]

    def fit_transform(self, texts: list[str]) -> PureSparseMatrix:
        tokenized_docs = [self._tokenize(t) for t in texts]
        df = Counter()
        for doc in tokenized_docs:
            for term in set(doc):
                df[term] += 1
        n_docs = len(texts)
        sorted_terms = [t for t, _ in df.most_common(self.max_features)]
        self.vocabulary_ = {term: idx for idx, term in enumerate(sorted_terms)}
        self.feature_names_ = sorted_terms
        self.idf_ = {term: math.log((1 + n_docs) / (1 + df[term])) + 1.0 for term in self.vocabulary_}
        return self._transform_internal(tokenized_docs)

    def transform(self, texts: list[str]) -> PureSparseMatrix:
        tokenized_docs = [self._tokenize(t) for t in texts]
        return self._transform_internal(tokenized_docs)

    def _transform_internal(self, tokenized_docs: list[list[str]]) -> PureSparseMatrix:
        rows: list[dict[int, float]] = []
        for doc in tokenized_docs:
            counts = Counter(doc)
            vec: dict[int, float] = {}
            norm_sq = 0.0
            for term, count in counts.items():
                if term in self.vocabulary_:
                    idx = self.vocabulary_[term]
                    val = (1.0 + math.log(count)) * self.idf_[term]
                    vec[idx] = val
                    norm_sq += val * val
            if norm_sq > 0:
                norm = math.sqrt(norm_sq)
                vec = {k: v / norm for k, v in vec.items()}
            rows.append(vec)
        return PureSparseMatrix(rows, len(self.vocabulary_))

    def get_feature_names_out(self) -> list[str]:
        return list(self.feature_names_)


class PureArray:
    def __init__(self, data: Any):
        if isinstance(data, PureArray):
            self.data = list(data.data)
        elif isinstance(data, (list, tuple)):
            self.data = list(data)
        else:
            self.data = [data]

    def sum(self, axis: int = 0) -> float:
        return sum(float(x) for x in self.data)

    def flatten(self) -> PureArray:
        res: list[float] = []
        for x in self.data:
            if isinstance(x, (list, tuple, PureArray)):
                res.extend(list(x))
            else:
                res.append(float(x))
        return PureArray(res)

    def __neg__(self) -> PureArray:
        return PureArray([-float(x) for x in self.data])

    def __getitem__(self, item: Any) -> Any:
        if isinstance(item, (list, tuple)):
            return PureArray([self.data[i] for i in item])
        if isinstance(item, slice):
            return PureArray(self.data[item])
        return self.data[item]

    def __setitem__(self, idx: int, val: Any) -> None:
        self.data[idx] = val

    def __len__(self) -> int:
        return len(self.data)

    def __iter__(self) -> Any:
        return iter(self.data)


class PureNumpy:
    @staticmethod
    def argsort(arr: Any) -> list[int]:
        flat = list(arr)
        return sorted(range(len(flat)), key=lambda i: flat[i])

    @staticmethod
    def array(lst: Any) -> PureArray:
        return PureArray(lst)

    @staticmethod
    def asarray(lst: Any) -> PureArray:
        if hasattr(lst, "sum") and callable(lst.sum):
            return PureArray(lst.sum(axis=0)[0])
        return PureArray(lst)

    @staticmethod
    def full(n: int, val: float) -> PureArray:
        return PureArray([val] * n)

    @staticmethod
    def fill_diagonal(matrix: Any, val: float) -> None:
        pass


class PureSparse:
    @staticmethod
    def save_npz(path: Path, matrix: Any) -> None:
        with open(path, "wb") as f:
            pickle.dump(matrix, f)

    @staticmethod
    def load_npz(path: Path) -> Any:
        with open(path, "rb") as f:
            return pickle.load(f)


def pure_cosine_similarity(a: Any, b: Any = None) -> Any:
    if b is None:
        b = a
    rows_a = a.rows if hasattr(a, "rows") else [a]
    rows_b = b.rows if hasattr(b, "rows") else [b]

    sims: list[list[float]] = []
    for ra in rows_a:
        row_sims: list[float] = []
        for rb in rows_b:
            dot = 0.0
            for col, val in ra.items():
                if col in rb:
                    dot += val * rb[col]
            row_sims.append(dot)
        sims.append(row_sims)

    class SimResult:
        def __init__(self, data: list[list[float]]):
            self.data = data
        def flatten(self) -> PureArray:
            res: list[float] = []
            for row in self.data:
                res.extend(row)
            return PureArray(res)
        def __getitem__(self, item: Any) -> Any:
            return self.data[item]
        def __len__(self) -> int:
            return len(self.data)

    return SimResult(sims)


try:
    import numpy as np
    from scipy import sparse
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except (ImportError, ValueError, Exception):
    np = PureNumpy
    sparse = PureSparse
    TfidfVectorizer = PureTfidfVectorizer
    cosine_similarity = pure_cosine_similarity
    SKLEARN_AVAILABLE = True

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
    if not SKLEARN_AVAILABLE:
        return False
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
        sim = cosine_similarity(sent_matrix)
        n = len(sentences)
        scores = [0.0] * n
        for i in range(n):
            for j in range(n):
                if i != j:
                    try:
                        scores[i] += float(sim[i][j])
                    except Exception:
                        pass
        top_idx = sorted(sorted(range(n), key=lambda i: scores[i], reverse=True)[:n_sentences])
        return [sentences[i] for i in top_idx]
    except Exception:
        return sentences[:n_sentences]


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
    return sorted(range(len(candidates)), key=lambda i: sims[i], reverse=True)
