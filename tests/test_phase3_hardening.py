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


def test_validate_safe_path_symlink_and_unprotected_paths(tmp_path):
    # 1. Symlink pointing to a protected file (/etc/passwd)
    symlink_file = tmp_path / "symlink_passwd"
    try:
        os.symlink("/etc/passwd", symlink_file)
    except OSError:
        pass
    else:
        ok, msg = validators.validate_safe_path(str(symlink_file))
        assert not ok
        assert "محم" in msg

    # 2. Symlink pointing to a protected directory (/etc)
    symlink_dir = tmp_path / "symlink_etc"
    try:
        os.symlink("/etc", symlink_dir)
    except OSError:
        pass
    else:
        ok, msg = validators.validate_safe_path(str(symlink_dir))
        assert not ok
        assert "محم" in msg

    # Symlink pointing to a file inside a protected directory (/etc/issue)
    symlink_issue = tmp_path / "symlink_issue"
    try:
        os.symlink("/etc/issue", symlink_issue)
    except OSError:
        pass
    else:
        ok, msg = validators.validate_safe_path(str(symlink_issue))
        assert not ok
        assert "محم" in msg

    # Virtual path through symlinked directory pointing inside /etc
    if symlink_dir.exists():
        file_under_symdir = symlink_dir / "some_file"
        ok, msg = validators.validate_safe_path(str(file_under_symdir))
        assert not ok
        assert "محم" in msg

    # 3. Normal temporary file
    normal_file = tmp_path / "normal.txt"
    normal_file.write_text("safe content", encoding="utf-8")
    ok, val = validators.validate_safe_path(str(normal_file))
    assert ok
    assert val == str(normal_file)

    # 4. Non-existent path in normal directory
    non_existent = tmp_path / "does_not_exist.txt"
    ok, val = validators.validate_safe_path(str(non_existent))
    assert ok
    assert val == str(non_existent)


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
