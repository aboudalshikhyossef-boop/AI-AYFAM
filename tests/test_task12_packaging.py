"""
Unit tests for Task 12 — Packaging, CI Workflow, and Installation Integrity
"""

import os
import pytest

def test_github_ci_workflow_exists():
    ci_path = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "ci.yml")
    assert os.path.exists(ci_path)
    with open(ci_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "python-version" in content
        assert "pytest" in content
        assert "ruff" in content

def test_security_policy_exists():
    sec_path = os.path.join(os.path.dirname(__file__), "..", "SECURITY.md")
    assert os.path.exists(sec_path)

def test_debian_control_structure():
    control_path = os.path.join(os.path.dirname(__file__), "..", "packaging", "deb", "DEBIAN", "control")
    assert os.path.exists(control_path)
    with open(control_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "Package: ai-ayfam" in content
        assert "Depends: python3" in content

def test_uninstall_and_setup_scripts_exist():
    root_dir = os.path.join(os.path.dirname(__file__), "..")
    setup_path = os.path.join(root_dir, "setup.sh")
    uninstall_path = os.path.join(root_dir, "uninstall.sh")

    assert os.path.exists(setup_path)
    assert os.path.exists(uninstall_path)

def test_debian_build_script_exists():
    build_path = os.path.join(
        os.path.dirname(__file__), "..", "packaging", "build-deb.sh"
    )
    assert os.path.exists(build_path)
    assert os.access(build_path, os.X_OK)
