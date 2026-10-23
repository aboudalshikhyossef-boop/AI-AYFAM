"""
Unit tests for Task 10 — Incident Timeline, Anomaly EWMA, Explanation Templates, and Suppression Engine
"""

import os
import tempfile
import pytest
from engine.finding import Finding
from engine.rules_registry import create_finding
from engine.baseline import BaselineEngineV2
from engine.timeline import IncidentTimeline
from engine.anomaly import AnomalyEngine
from engine.explanation import ExplanationEngine

def test_baseline_v2_and_accept_as_expected():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "baseline.db")
        key_path = os.path.join(tmpdir, "baseline.key")

        b2 = BaselineEngineV2(db_path=db_path, key_path=key_path)
        b2.update_component("user", "jules", {"shell": "/bin/bash"})

        # Verify component added
        new_items = b2.get_new_components_since(0)
        assert len(new_items) == 1
        assert new_items[0]["key"] == "jules"

        # Accept component
        assert b2.accept_as_expected("user", "jules", user="admin") is True

        # New expected items count should drop to 0
        accepted_items = b2.get_new_components_since(0)
        assert len(accepted_items) == 0

def test_anomaly_ewma_and_next_step_prediction():
    data = [10.0, 12.0, 15.0, 11.0, 20.0]
    ewma = AnomalyEngine.calculate_ewma(data)
    assert ewma > 0

    pred = AnomalyEngine.predict_likely_next_step(["T1110.001"])
    assert pred["is_heuristic"] is True
    assert "Privilege Escalation" in pred["likely_next_tactic"]

def test_explanation_and_suppression():
    with tempfile.TemporaryDirectory() as tmpdir:
        supp_file = os.path.join(tmpdir, "suppressions.json")
        expl_engine = ExplanationEngine(suppression_file=supp_file)

        finding = create_finding("FIREWALL-001", stable_key="ufw")

        # Verify explanation structure
        exp_ar = expl_engine.explain(finding, lang="ar")
        assert "what" in exp_ar and "why_it_matters" in exp_ar and "confidence" in exp_ar

        # Verify suppression
        assert expl_engine.is_suppressed(finding) is False
        expl_engine.add_suppression(finding.rule_id, finding.fingerprint, expiry_days=10)
        assert expl_engine.is_suppressed(finding) is True
