import json

from brain.knowledge_base import KnowledgeBase
from brain.learning_governance import LearningGovernance


def make_governance(tmp_path):
    kb = KnowledgeBase(tmp_path / "brain.db")
    return kb, LearningGovernance(kb)


def test_external_answer_is_persisted_and_quarantined(tmp_path):
    kb, gov = make_governance(tmp_path)
    interaction_id = gov.record_external_answer(
        provider="openai", model="gpt-test", prompt="How do I harden SSH?",
        context={"language": "en", "purpose": "assistant_response"},
        answer="Review the evidence and limitations before applying a safe SSH change.",
        source="openai:gpt-test",
    )
    row = kb._connect().execute(
        "SELECT provider, model, context, answer, source, evaluation FROM external_interactions WHERE id=?",
        (interaction_id,),
    ).fetchone()
    assert row["provider"] == "openai"
    assert row["source"] == "openai:gpt-test"
    assert json.loads(row["context"])["purpose"] == "assistant_response"
    assert json.loads(row["evaluation"])["review_required"] is True
    assert "style_features" in json.loads(row["evaluation"])
    assert gov.get_style_profile()["evidence"] > 0
    proposals = gov.list_proposals("proposed")
    assert len(proposals) == 1
    assert proposals[0]["kind"] == "knowledge"


def test_knowledge_cannot_apply_without_review_and_passing_test(tmp_path):
    kb, gov = make_governance(tmp_path)
    proposal_id = gov.create_knowledge_proposal(
        title="candidate", description="review me", content="fact",
        category="candidate", key="k1",
    )
    assert gov.apply(proposal_id) is False
    assert kb.lookup("candidate", "k1") is None
    assert gov.review(proposal_id, approved=True, note="Evidence checked") is True
    assert gov.record_test_result(proposal_id, passed=True, command="pytest tests/test_learning_governance.py") is True
    assert gov.apply(proposal_id) is True
    assert kb.lookup("candidate", "k1") == "fact"


def test_code_proposal_never_modifies_files_and_needs_review_and_test(tmp_path):
    kb, gov = make_governance(tmp_path)
    proposal_id = gov.create_code_proposal(
        title="safe patch", description="suggestion only", patch="diff --git ...",
        tests=["pytest -q"],
    )
    assert gov.review(proposal_id, approved=True, note="Human review required") is True
    assert gov.record_test_result(proposal_id, passed=True, command="pytest -q") is True
    assert gov.apply(proposal_id) is False
    assert gov.list_proposals()[0]["status"] == "ready_for_merge"


def test_local_search_rejects_unrelated_knowledge(tmp_path):
    kb, _ = make_governance(tmp_path)
    kb.add_knowledge("concept", "firewall", "A firewall filters network traffic.", source="reviewed_external:1")
    kb.add_knowledge("concept", "database", "A database stores structured records.", source="reviewed_external:2")
    assert kb.search_knowledge("ما هو firewall", limit=3)[0]["key"] == "firewall"
    assert kb.search_knowledge("ما هو quantum entanglement", limit=3) == []
