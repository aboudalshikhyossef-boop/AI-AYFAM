"""Unit tests for Phase 11 coverage expansion."""

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

# 1. Test tools/fix.py
from tools.fix import apply_fix, list_available_fixes


def test_fix_apply_and_list():
    fixes = list_available_fixes()
    assert "enable_firewall" in fixes
    assert "disable_root_ssh" in fixes

    # Test unknown fix
    res = apply_fix("unknown_fix_action")
    assert not res["success"]

    # Test enable_firewall fix with mock safe_exec
    with patch("utils.safe_exec.run") as mock_run:
        mock_run.return_value = MagicMock(ok=True, stdout="Firewall enabled", stderr="", code=0)
        res = apply_fix("enable_firewall")
        assert res["success"]


# 2. Test tools/usb_control.py
from tools.usb_control import authorize_device, deauthorize_device, eject_storage_device, fix_flash_issues


def test_usb_control_operations():
    with patch("tools.usb_control._find_sysfs_path", return_value="/sys/bus/usb/devices/1-1"), \
         patch("utils.safe_exec.write_file_privileged") as mock_write, \
         patch("tools.usb_control._removable_transport", return_value=(True, {"parent": "/dev/sdb"})), \
         patch("tools.usb_control._lsblk_query", return_value=(True, [])), \
         patch("utils.safe_exec.run") as mock_run:
        mock_write.return_value = MagicMock(ok=True, stderr="")
        mock_run.return_value = MagicMock(ok=True, stdout="ok", stderr="", code=0)

        res = authorize_device("001", "002")
        assert res["success"]

        res = deauthorize_device("001", "002")
        assert res["success"]

        res = eject_storage_device("/dev/sdb1")
        assert res["success"]


def test_fix_flash_issues():
    findings = [{
        "target_path": "/media/usb/autorun.inf",
        "severity": "critical",
        "title": "Malicious autorun"
    }]
    with patch("os.path.realpath", side_effect=lambda p: p), \
         patch("os.path.islink", return_value=False), \
         patch("os.remove") as mock_remove:
        actions = fix_flash_issues("/media/usb", findings)
        assert len(actions) == 1
        assert actions[0]["ok"]


# 3. Test utils/safe_exec.py
from utils.safe_exec import run, validate_sudo_password


def test_safe_exec_run_and_sudo():
    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        res = run(["echo", "hello"])
        assert res.ok
        assert res.stdout == "ok"

    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = MagicMock(returncode=0, stdout="", stderr="")
        res = validate_sudo_password("correct_pass")
        assert res.ok


# 4. Test ui/intro_splash.py
def test_intro_splash_smoke():
    try:
        from PyQt6.QtWidgets import QApplication
        from ui.intro_splash import AyfamIntroSplash, SystemOverviewDialog
    except (ImportError, OSError) as exc:
        pytest.skip(f"Qt runtime unavailable: {exc}")

    app = QApplication.instance() or QApplication([])
    splash = AyfamIntroSplash(auto_close=False)
    assert splash.isVisible() or splash.height() > 0
    splash.close()

    overview = SystemOverviewDialog()
    assert overview.windowTitle() != ""
    overview.close()
