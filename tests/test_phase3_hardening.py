"""Regression tests for phase-three hardening safeguards."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from brain import relevance_engine
from tools import fix
from utils import validators


def test_critical_paths_and_current_process_are_rejected():
    ok, message = validators.validate_safe_path("/etc/passwd")
    assert not ok
    assert "محم" in message
    ok, message = validators.validate_safe_path("/etc")
    assert not ok
    ok, message = validators.validate_pid(str(os.getpid()))
    assert not ok
    assert "AI AYFAM" in message


def test_pickle_artifacts_must_be_owned_and_private(tmp_path):
    artifact = tmp_path / "index.pkl"
    artifact.write_bytes(b"not a pickle")
    artifact.chmod(stat.S_IRUSR | stat.S_IWUSR)
    with patch.object(relevance_engine, "VECTORIZER_PATH", artifact), \
         patch.object(relevance_engine, "MATRIX_PATH", artifact):
        assert relevance_engine._trusted_artifact(artifact)
        # The current user owns a private regular file, so it is eligible for
        # loading; unpickling itself remains behind the existing index checks.
        artifact.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)
        assert not relevance_engine._trusted_artifact(artifact)


def test_firewall_fix_does_not_open_ssh_automatically():
    results = []

    def run(args, **kwargs):
        results.append(args)
        return SimpleNamespace(ok=True, stdout="", stderr="")

    with patch("tools.fix.safe_exec.run", side_effect=run):
        result = fix.fix_enable_firewall()
    assert result["success"]
    assert not any(args[:2] == ["ufw", "allow"] for args in results)


def test_dns_fix_does_not_write_resolv_conf_when_resolved_is_absent():
    with patch("tools.fix.safe_exec.run", return_value=SimpleNamespace(ok=False, stdout="", stderr="")) as run, \
         patch("tools.fix.safe_exec.write_file_privileged") as write:
        result = fix.fix_change_dns()
    assert not result["success"]
    write.assert_not_called()


def test_ssh_password_fix_requires_authorized_keys():
    with patch("tools.fix.os.path.isfile", return_value=False), \
         patch("tools.fix._backup_file", return_value="/tmp/backup"), \
         patch("tools.fix.safe_exec.run") as run:
        result = fix.fix_disable_ssh_password_auth()
    assert not result["success"]
    assert "authorized_keys" in result["error"]
    run.assert_not_called()


def test_close_event_no_longer_contains_forced_thread_termination():
    code = Path(__file__).resolve().parents[1].joinpath("ui/gui_app.py").read_text(encoding="utf-8")
    assert "self.worker.terminate()" not in code
    assert "requestInterruption" in code
