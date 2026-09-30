import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from brain.knowledge_base import KnowledgeBase
from brain import relevance_engine as re_engine

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

TMPDB = tempfile.mktemp(suffix=".db")
kb = KnowledgeBase(db_path=TMPDB)

# ── بيانات اصطناعية واقعية: 4 "كتب" بمواضيع مميّزة، بعضها يتشارك مفاهيم ──
BOOK_NMAP = [
    "Nmap is the standard tool for network reconnaissance and port scanning.",
    "A typical scan uses nmap -sV -p- target.com to enumerate all open ports and service versions.",
    "Stealth scanning with nmap -sS avoids completing the TCP handshake to reduce detection.",
    "Firewall evasion techniques in nmap include fragmenting packets and using decoy source addresses.",
    "Port scanning is often the first reconnaissance step before any further penetration testing.",
]
BOOK_SQLI = [
    "SQL injection occurs when user input is concatenated directly into a database query.",
    "A classic SQL injection payload is ' OR '1'='1 to bypass a login form authentication check.",
    "Blind SQL injection relies on true/false responses rather than visible query output.",
    "Parameterized queries and prepared statements are the standard defense against SQL injection.",
    "Web application firewalls can mitigate but not fully prevent SQL injection attacks.",
]
BOOK_PRIVESC = [
    "Privilege escalation on Linux often exploits misconfigured SUID binaries.",
    "Finding SUID binaries is a routine reconnaissance step during privilege escalation, similar to port scanning in network reconnaissance.",
    "A world-writable file combined with a SUID binary can create a privilege escalation chain.",
    "Kernel exploits are another common vector for privilege escalation on outdated systems.",
    "After privilege escalation, an attacker typically establishes persistence mechanisms.",
]
BOOK_MIXED = [
    "This chapter covers penetration testing methodology from reconnaissance to privilege escalation.",
    "Nmap port scanning identifies attack surface before attempting SQL injection on discovered web services.",
    "Successful SQL injection can sometimes lead directly to remote code execution and privilege escalation.",
    "A professional penetration test report links reconnaissance findings to exploitation and escalation steps.",
]

def ingest_book(title, sentences):
    doc_id = kb.add_library_document(title, f"/tmp/{title}.txt", "txt")
    for i, s in enumerate(sentences):
        kb.add_library_chunk(doc_id, i, s)
    kb.finalize_library_document(doc_id, sum(len(s) for s in sentences), len(sentences))
    return doc_id

doc_nmap = ingest_book("Nmap_Network_Recon", BOOK_NMAP)
doc_sqli = ingest_book("SQL_Injection_Handbook", BOOK_SQLI)
doc_privesc = ingest_book("Linux_Privilege_Escalation", BOOK_PRIVESC)
doc_mixed = ingest_book("Pentest_Methodology", BOOK_MIXED)

print(f"\n[Setup] Ingested 4 synthetic books, {len(BOOK_NMAP)+len(BOOK_SQLI)+len(BOOK_PRIVESC)+len(BOOK_MIXED)} chunks total")

# ── 1) index not built yet → graceful errors, not crashes ──────────────
print("\n[1] Graceful behavior before index is built")
check("is_index_built() is False initially", re_engine.is_index_built() is False)
res = re_engine.search("nmap port scanning", kb)
check("search() returns clear error before build", len(res) == 1 and "error" in res[0])
rel = re_engine.related_chunks(1, kb)
check("related_chunks() returns clear error before build", len(rel) == 1 and "error" in rel[0])
graph_res = re_engine.build_concept_graph(kb)
check("build_concept_graph() returns clear error before build", graph_res["success"] is False)

# ── 2) build_index ───────────────────────────────────────────────────────
print("\n[2] build_index()")
# Redirect intelligence dir to a temp location so we don't touch the real ~/.ayfam
import tempfile as _tf
tmp_intel = _tf.mkdtemp(prefix="ayfam_intel_")
re_engine.INTEL_DIR = __import__("pathlib").Path(tmp_intel)
re_engine.VECTORIZER_PATH = re_engine.INTEL_DIR / "tfidf_vectorizer.pkl"
re_engine.MATRIX_PATH = re_engine.INTEL_DIR / "tfidf_matrix.npz"
re_engine.CHUNK_IDS_PATH = re_engine.INTEL_DIR / "chunk_ids.json"
re_engine.META_PATH = re_engine.INTEL_DIR / "meta.json"

build_res = re_engine.build_index(kb)
check("build succeeds", build_res.get("success") is True)
check("chunks_indexed matches total chunks", build_res.get("chunks_indexed") == 19)
check("vocabulary_size > 0", build_res.get("vocabulary_size", 0) > 0)
check("is_index_built() now True", re_engine.is_index_built() is True)

# ── 3) search() ranks by real relevance, not just source order ─────────
print("\n[3] search() — statistical relevance ranking")
nmap_results = re_engine.search("nmap port scanning reconnaissance", kb, top_k=5)
check("no error", not (nmap_results and "error" in nmap_results[0]))
check("returns results", len(nmap_results) > 0)
top_titles = [r["title"] for r in nmap_results[:2]]
check("top result comes from the Nmap book or the mixed methodology book",
      any("Nmap" in t or "Pentest" in t for t in top_titles))
check("results carry a relevance score", all("relevance" in r for r in nmap_results))
check("relevance scores are sorted descending", nmap_results == sorted(nmap_results, key=lambda r: -r["relevance"]))

sqli_results = re_engine.search("SQL injection login bypass authentication", kb, top_k=5)
check("SQLi query surfaces the SQLi book", any(r["doc_id"] == doc_sqli for r in sqli_results))

nonsense = re_engine.search("xyzxyzxyz nonexistent gibberish term qqq", kb)
check("nonsense query returns empty, not garbage matches", len(nonsense) == 0)

# ── 4) related_chunks() — cross-book linking ────────────────────────────
print("\n[4] related_chunks() — cross-book conceptual linking")
# Chunk 2 of the privesc book explicitly parallels port-scanning reconnaissance language
privesc_chunks = kb.get_chunk_ids_for_doc(doc_privesc)
target_chunk = privesc_chunks[1]  # "...similar to port scanning in network reconnaissance."
related = re_engine.related_chunks(target_chunk, kb, top_k=5)
check("no error", not (related and "error" in related[0]))
check("finds related chunks from OTHER books (cross-book linking)",
      any(r["doc_id"] != doc_privesc for r in related))
check("does not return the chunk itself", all(r["id"] != target_chunk for r in related))

# ── 5) extractive_summary() — TextRank ──────────────────────────────────
print("\n[5] extractive_summary() — TextRank")
long_text = " ".join(BOOK_NMAP + BOOK_SQLI + BOOK_PRIVESC)
summary = re_engine.extractive_summary(long_text, n_sentences=4)
check("returns requested number of sentences", len(summary) == 4)
check("every returned sentence exists verbatim in the source text",
      all(s in long_text for s in summary))
short_text = "One sentence only here."
short_summary = re_engine.extractive_summary(short_text, n_sentences=5)
check("short text returns all available sentences without crashing", len(short_summary) <= 1)
empty_summary = re_engine.extractive_summary("", n_sentences=3)
check("empty text returns empty list, no crash", empty_summary == [])

# ── 6) build_concept_graph() — cross-book concept linking ──────────────
print("\n[6] build_concept_graph()")
graph_res2 = re_engine.build_concept_graph(kb, top_terms_per_doc=15, graph_top_terms=10)
check("build succeeds", graph_res2.get("success") is True)
check("covers all 4 documents", graph_res2.get("documents") == 4)
check("creates some edges", graph_res2.get("edges_created", 0) > 0)

matches = kb.get_concept_matches("scanning")
check("concept index finds 'scanning' term across books", len(matches) > 0)

# ── 7) rank_texts() — lightweight reranking for web search results ─────
print("\n[7] rank_texts()")
candidates = [
    "Weather forecast for tomorrow in Paris",
    "Nmap network port scanning tutorial for beginners",
    "Best pizza recipes for a family dinner",
]
order = re_engine.rank_texts("nmap port scan tutorial", candidates)
check("nmap-related candidate ranked first", order[0] == 1)

print(f"\n{'='*50}\nTOTAL: {passed} passed, {failed} failed\n{'='*50}")

os.remove(TMPDB)
import shutil
shutil.rmtree(tmp_intel, ignore_errors=True)
sys.exit(1 if failed else 0)
