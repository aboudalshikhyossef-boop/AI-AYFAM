from brain.composer import Evidence, compose


def test_policy_weights_change_composed_output():
    evidence = [Evidence("Firewall filters network traffic.", source="book-1", confidence=0.8)]
    base = {
        "question_alignment": 1.0, "evidence_first": 1.0, "structured_response": 1.0,
        "source_attribution": 1.0, "limitations": 1.0, "confidence_calibration": 1.0,
        "brevity": 0.0, "stepwise_reasoning": 0.0, "examples": 0.0,
    }
    detailed = compose(base, evidence, "explain", profile_name="test-v1")
    short = compose({**base, "brevity": 1.0, "source_attribution": 0.0}, evidence, "explain", profile_name="test-v2")
    assert detailed.text != short.text
    assert "لماذا هذا الرد؟" in detailed.text
    assert detailed.evidence_count == 1


def test_composer_is_deterministic_and_does_not_copy_provider_metadata():
    result_a = compose({"structured_response": 1.0}, [
        {"text": "Local fact", "source": "local", "confidence": 0.5}
    ], "new-topic")
    result_b = compose({"structured_response": 1.0}, [
        {"text": "Local fact", "source": "local", "confidence": 0.5}
    ], "new-topic")
    assert result_a.text == result_b.text
    assert "provider" not in result_a.text.lower()
