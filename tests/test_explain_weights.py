from unittest.mock import patch

import pytest

from brain.knowledge_base import KnowledgeBase
from brain.nlp import NLPEngine
from brain.weight_policy import DEFAULT_WEIGHTS, WeightPolicy


QUERY = "kernel namespace isolation"
SOURCE_ONE = """Kernel namespace isolation separates process and mount views.
1. Create a namespace for the process.
2. Attach the process to the namespace.
Example: A container can have a separate process namespace.
The local reference also documents namespace membership, process visibility, mount isolation, lifecycle handling, and the effect of namespace boundaries on resource access.
"""
SOURCE_TWO = """Kernel namespace isolation can restrict visible resources.
1. Configure the required namespace.
2. Verify the process view after configuration.
For example, a container may use a private mount namespace.
The local reference also documents process membership, resource views, mount isolation, lifecycle handling, and namespace boundary behavior.
"""


@pytest.fixture
def explanation_engine(tmp_path):
    kb = KnowledgeBase(db_path=str(tmp_path / "phase-a.db"))
    for title, content in (("Kernel guide A", SOURCE_ONE), ("Kernel guide B", SOURCE_TWO)):
        doc_id = kb.add_library_document(title, f"fixture:{title}", "txt")
        kb.add_library_chunk(doc_id, 0, content, page_hint="fixture-page")
        kb.finalize_library_document(doc_id, len(content), 1)
    return NLPEngine(kb), kb


def render_with_weights(engine, kb, weights):
    with patch.object(
        WeightPolicy,
        "active",
        return_value={"id": 1, "name": "property-test", "weights": dict(weights)},
    ):
        return engine.explain(QUERY)


@pytest.mark.parametrize(
    ("weight", "below", "above"),
    [
        ("question_alignment", 0.49, 0.51),
        ("evidence_first", 0.49, 0.51),
        ("structured_response", 0.49, 0.51),
        ("source_attribution", 0.49, 0.51),
        ("stepwise_reasoning", 0.54, 0.56),
        ("examples", 0.54, 0.56),
        ("limitations", 0.49, 0.51),
        ("retrieval_score_display", 0.49, 0.51),
        ("brevity", 0.94, 0.96),
    ],
)
def test_every_live_policy_weight_changes_the_real_explain_path(
    explanation_engine, weight, below, above
):
    engine, kb = explanation_engine
    base = dict(DEFAULT_WEIGHTS)
    base[weight] = below
    changed = dict(base)
    changed[weight] = above

    before = render_with_weights(engine, kb, base)
    after = render_with_weights(engine, kb, changed)

    assert before != after, f"weight {weight!r} did not change NLPEngine.explain output"


def test_explain_passes_real_document_source_steps_and_examples(explanation_engine):
    engine, kb = explanation_engine
    weights = dict(DEFAULT_WEIGHTS)
    weights["examples"] = 0.56
    output = render_with_weights(engine, kb, weights)
    assert "Kernel guide" in output
    assert "fixture-page" in output
    assert "Create a namespace" in output
    assert "container can have a separate process namespace" in output
    assert "Steps stated in the source" in output
    assert "Examples stated in the source" in output


def test_no_result_explanation_never_emits_a_retrieval_number(tmp_path):
    kb = KnowledgeBase(db_path=str(tmp_path / "empty.db"))
    engine = NLPEngine(kb)
    output = engine.explain("rarely matching hypothetical phrase")
    assert "BM25" not in output
    assert "TF-IDF" not in output
    assert "درجة الثقة" not in output
    assert "0.000" not in output


def test_not_found_tool_note_is_not_composed_as_evidence(tmp_path):
    kb = KnowledgeBase(db_path=str(tmp_path / "tool-gap.db"))
    engine = NLPEngine(kb)
    output = engine.explain("nmap")
    assert "لم أجد شرحاً لهذه الأداة" in output
    assert "No explanation for this tool" in output
    assert "Retrieval support" not in output


def test_weight_cleaner_drops_legacy_dead_keys():
    cleaned = WeightPolicy._clean({
        **DEFAULT_WEIGHTS,
        "uncertainty_disclosure": 1.5,
        "verification": 1.5,
        "arbitrary_unregistered_key": 1.5,
    })
    assert set(cleaned) == set(DEFAULT_WEIGHTS)
    assert "verification" not in cleaned
    assert "uncertainty_disclosure" not in cleaned
