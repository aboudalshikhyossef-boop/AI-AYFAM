"""
Unit tests for Task 5 — Kernel Security Inspection Engine
"""

import pytest
from engine.kernelcheck import KernelChecker

def test_kernel_tainted_decoding():
    checker = KernelChecker()
    # Test clean kernel
    clean_findings = checker.check_tainted(taint_val=0)
    assert len(clean_findings) == 0

    # Test tainted kernel (e.g., bit 0 for proprietary, bit 13 for unsigned)
    tainted_val = (1 << 0) | (1 << 13)
    tainted_findings = checker.check_tainted(taint_val=tainted_val)
    assert len(tainted_findings) == 1
    assert "Proprietary module" in tainted_findings[0]["detail"]
    assert "Unsigned module" in tainted_findings[0]["detail"]

def test_hidden_modules_detection():
    checker = KernelChecker()
    proc_mods = "ext4 12345 0 - Live 0x0000000000000000\nssh 54321 0 - Live 0x0000000000000000\n"
    sys_mods = ["ext4", "ssh", "rootkit_hidden_mod"]

    findings = checker.check_hidden_modules(proc_modules=proc_mods, sys_modules=sys_mods)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SYS-WRITE-001"
    assert "rootkit_hidden_mod" in findings[0]["title"]

def test_sysctl_hardening_audit():
    checker = KernelChecker()
    # Execute sysctl check against engine
    findings = checker.check_sysctl_hardening()
    assert isinstance(findings, list)
    for f in findings:
        assert f.get("rule_id").startswith("KERN-SYSCTL-")
        assert "sudo sysctl -w" in f.get("fix")
