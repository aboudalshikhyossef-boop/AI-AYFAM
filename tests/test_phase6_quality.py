"""Coverage for high-risk API and process-execution contracts."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import api_server
from utils import safe_exec


def test_run_scan_normalizes_profile_and_isolates_failed_checks():
    good = {"findings": [{"severity": "high", "title": "Open service", "detail": "x"}]}
    with patch.object(api_server.network, "check_firewall", return_value=good), \
         patch.object(api_server.network, "scan_ports", side_effect=RuntimeError("scanner failed")), \
         patch.object(api_server.network, "check_data_leaks", return_value={"findings": []}), \
         patch.object(api_server.system, "check_ssh_config", return_value={"findings": []}), \
         patch.object(api_server.system, "check_suid_files", return_value={"findings": []}), \
         patch.object(api_server.system, "check_world_writable", return_value={"findings": []}), \
         patch.object(api_server.system, "analyze_logs", return_value={"findings": []}):
        result = api_server.run_scan("invalid-profile", "127.0.0.1")
    assert result["ok"] is True
    assert result["profile"] == "full"
    assert result["counts"]["high"] == 1
    assert any(f["title"].startswith("تعذر تشغيل فحص ports") for f in result["findings"])


def test_safe_exec_rejects_string_commands_and_missing_binaries():
    with pytest.raises(TypeError):
        safe_exec.run("echo unsafe")
    result = safe_exec.run(["definitely-not-a-real-ayfam-binary"], check_binary=True)
    assert not result.ok
    assert "غير موجودة" in result.stderr


def test_safe_exec_translates_timeout_without_leaking_exception():
    with patch("utils.safe_exec.shutil.which", return_value="/bin/fake"), \
         patch("utils.safe_exec.subprocess.run", side_effect=safe_exec.subprocess.TimeoutExpired("fake", 1)):
        result = safe_exec.run(["fake"], check_binary=True)
    assert not result.ok
    assert result.stderr == "timeout"


def test_safe_exec_never_uses_shell_for_argv_commands():
    captured = {}

    def fake_run(args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")

    with patch("utils.safe_exec.shutil.which", return_value="/bin/echo"), \
         patch("utils.safe_exec.subprocess.run", side_effect=fake_run):
        result = safe_exec.run(["echo", "safe; not shell"], check_binary=True)
    assert result.ok
    assert captured["shell"] is False


def test_ui_exposes_keyboard_access_and_uses_timezone_aware_utc():
    root = Path(__file__).resolve().parents[1]
    ui_code = (root / "ui/gui_app.py").read_text(encoding="utf-8")
    web_code = (root / "tools/web.py").read_text(encoding="utf-8")
    github_code = (root / "tools/github_tool.py").read_text(encoding="utf-8")
    assert "Ctrl+Shift+F" in ui_code
    assert "setAccessibleName" in ui_code
    assert "datetime.utcnow()" not in web_code
    assert "datetime.utcnow()" not in github_code
