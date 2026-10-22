"""
Unit tests for Task 2 — Unified Finding Model, Rules Registry, Fingerprinting, and Correlation.
"""

import pytest
from engine.finding import Finding
from engine.rules_registry import RULES_REGISTRY, get_rule, create_finding
from engine.correlation import CorrelationEngine
from core.intelligence import SecurityIntelligence


def test_finding_rule_id_and_fingerprint():
    f1 = create_finding("SSH-001", detail="Detail 1", stable_key="permitroot")
    f2 = create_finding("SSH-001", detail="Detail 2", stable_key="permitroot")

    assert f1.rule_id == "SSH-001"
    assert f1.category == "ssh"
    assert "ssh" in f1["tags"]
    # Same rule_id + stable_key must produce identical fingerprint regardless of detail
    assert f1.fingerprint == f2.fingerprint
    assert f1.id == f2.id


def test_rules_registry_lookup():
    rule = get_rule("FIREWALL-001")
    assert rule["rule_id"] == "FIREWALL-001"
    assert rule["category"] == "network"
    assert "T1562.004" in rule["attack_ids"]

    # Unknown rule falls back to GENERIC-001
    unknown = get_rule("UNKNOWN-999")
    assert unknown["rule_id"] == "GENERIC-001"


def test_correlation_by_rule_id():
    f_ssh = create_finding("SSH-001", detail="Root allowed", stable_key="ssh_root")
    f_brute = create_finding("LOG-SSH-BRUTE", detail="from 192.168.1.100", stable_key="brute_192")

    engine = CorrelationEngine()
    chains = engine.analyze([f_ssh, f_brute])

    assert len(chains) >= 1
    assert any("SSH" in c["title"] for c in chains)
    assert any("brute_force" in c["tags"] for c in chains)


def test_compare_scans_uses_fingerprint():
    intel = SecurityIntelligence()
    f1 = create_finding("FIREWALL-001", stable_key="ufw")
    f2 = create_finding("SSH-001", stable_key="ssh")

    scan1 = {"findings": [f1, f2], "risk": {"score": 100, "level": "high"}}
    scan2 = {"findings": [f1], "risk": {"score": 40, "level": "low"}}

    cmp_res = intel.compare_scans({"result": scan1}, scan2)
    assert cmp_res is not None
    assert cmp_res["trend"] == "improved"
    assert len(cmp_res["resolved"]) == 1
    assert cmp_res["resolved"][0].rule_id == "SSH-001"
