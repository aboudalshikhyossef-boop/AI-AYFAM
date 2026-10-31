from brain.composer import Evidence, compose


def test_policy_weights_change_composed_output():
    evidence = [Evidence(
        "Firewall filters network traffic.",
        source="book-1",
        retrieval_score=0.8,
        retrieval_method="TF-IDF",
    )]
    base = {
        "question_alignment": 1.0, "evidence_first": 1.0, "structured_response": 1.0,
        "source_attribution": 1.0, "limitations": 1.0, "retrieval_score_display": 1.0,
        "brevity": 0.0, "stepwise_reasoning": 0.0, "examples": 0.0,
    }
    detailed = compose(base, evidence, "explain", profile_name="test-v1")
    short = compose(
        {**base, "brevity": 1.0, "source_attribution": 0.0},
        evidence,
        "explain",
        profile_name="test-v2",
    )
    assert detailed.text != short.text
    assert "لماذا هذا الرد؟" not in detailed.text
    assert detailed.evidence_count == 1
    assert "TF-IDF" in detailed.text


def test_composer_never_shows_a_number_without_a_retrieval_signal():
    result = compose(
        {"retrieval_score_display": 1.0},
        [Evidence("A source passage with no numeric retrieval signal.", source="local")],
        "explain",
    )
    assert "درجة الثقة" not in result.text
    assert "Retrieval support" not in result.text
    assert "0.00" not in result.text


def test_composer_shows_only_the_provided_retrieval_score():
    result = compose(
        {"retrieval_score_display": 1.0},
        [Evidence(
            "A retrieved passage.",
            source="book title, page 3",
            retrieval_score=0.625,
            retrieval_method="BM25",
        )],
        "explain",
    )
    assert "BM25" in result.text
    assert "0.625" in result.text
    assert "درجة الثقة" not in result.text


def test_composer_is_deterministic():
    kwargs = {
        "plan_weights": {"structured_response": 1.0, "retrieval_score_display": 0.0},
        "evidence": [Evidence("Local fact", source="local")],
        "question_type": "new-topic",
    }
    result_a = compose(**kwargs)
    result_b = compose(**kwargs)
    assert result_a.text == result_b.text
