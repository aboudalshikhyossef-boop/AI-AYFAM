"""
Unit tests for AutoReactor critical infrastructure hardening (engine/autoreactor.py)
"""

import pytest
from engine.autoreactor import AutoReactor
from engine.finding import Finding

def test_autoreactor_excludes_loopback_and_gateway():
    critical_ips = {"192.168.1.1", "1.1.1.1", "127.0.0.1"}

    # Loopback IP
    assert AutoReactor.is_protected_ip("127.0.0.1", critical_ips) is True
    # Gateway IP
    assert AutoReactor.is_protected_ip("192.168.1.1", critical_ips) is True
    # DNS IP
    assert AutoReactor.is_protected_ip("1.1.1.1", critical_ips) is True
    # Multicast IP
    assert AutoReactor.is_protected_ip("224.0.0.1", critical_ips) is True
    # Attacker IP
    assert AutoReactor.is_protected_ip("185.220.101.5", critical_ips) is False

def test_autoreactor_rule_synthesis_safety():
    findings = [
        Finding(
            severity="high",
            title="هجوم قوة غاشمة من 192.168.1.1 و 185.199.108.7",
            detail="محاولات من 127.0.0.1 ومن البوابة 192.168.1.1 والعنوان المهاجم 185.199.108.7",
            tags=["brute_force"]
        )
    ]

    # Mocking critical IPs so test is deterministic
    original_get_ips = AutoReactor.get_critical_infrastructure_ips
    AutoReactor.get_critical_infrastructure_ips = staticmethod(lambda: {"192.168.1.1", "1.1.1.1", "127.0.0.1"})

    try:
        rules = AutoReactor.synthesize_rules(findings)
        cmds = [r["cmd"] for r in rules]

        # Ensure attacker IP is blocked
        assert any("185.199.108.7" in c for c in cmds)
        # Ensure Gateway (192.168.1.1) and Loopback (127.0.0.1) are NOT blocked
        assert not any("192.168.1.1" in c for c in cmds)
        assert not any("127.0.0.1" in c for c in cmds)
    finally:
        AutoReactor.get_critical_infrastructure_ips = original_get_ips
