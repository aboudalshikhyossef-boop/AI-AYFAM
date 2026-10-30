from brain.knowledge_base import KnowledgeBase
from brain.weight_policy import DEFAULT_WEIGHTS, WeightPolicy


def test_weight_candidate_is_calculated_and_inactive_until_approval(tmp_path):
    kb = KnowledgeBase(tmp_path / "brain.db")
    policy = WeightPolicy(kb)
    baseline = policy.active()
    candidate_id = policy.propose_from_observation(
        {"evidence": 1.0, "caution": 0.9, "steps": 0.8, "structured": 0.7},
        interaction_id=42,
    )
    candidate = policy.list_profiles("proposed")[0]
    assert candidate["id"] == candidate_id
    assert candidate["parent_id"] == baseline["id"]
    assert candidate["weights"]["evidence_first"] > DEFAULT_WEIGHTS["evidence_first"]
    assert policy.active()["id"] == baseline["id"]


def test_weight_activation_requires_review_and_passing_test_and_supports_rollback(tmp_path):
    kb = KnowledgeBase(tmp_path / "brain.db")
    policy = WeightPolicy(kb)
    baseline_id = policy.active()["id"]
    candidate_id = policy.propose_from_observation({"evidence": 1.0})
    assert policy.activate(candidate_id) is False
    assert policy.review(candidate_id, approved=True, note="Compared with baseline") is True
    assert policy.record_test_result(candidate_id, passed=True, command="pytest -q") is True
    assert policy.activate(candidate_id) is True
    assert policy.active()["id"] == candidate_id
    assert policy.rollback(candidate_id) is True
    assert policy.active()["id"] == baseline_id
