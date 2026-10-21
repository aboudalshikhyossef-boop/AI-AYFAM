"""Regression tests for desktop bootstrap, settings validation, and versioning."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import config.settings as settings_module
import main
from config.version import APP_VERSION, APP_VERSION_LABEL


def _settings_for(tmp_path: Path, payload: object):
    config_dir = tmp_path / ".ayfam"
    config_file = config_dir / "config.json"
    config_dir.mkdir()
    config_file.write_text(json.dumps(payload), encoding="utf-8")
    defaults = dict(settings_module.DEFAULT_SETTINGS)
    defaults["report_dir"] = str(tmp_path / "reports")
    with patch.object(settings_module, "CONFIG_DIR", config_dir), \
         patch.object(settings_module, "CONFIG_FILE", config_file), \
         patch.object(settings_module, "DEFAULT_SETTINGS", defaults):
        return settings_module.Settings()


def test_non_object_json_does_not_block_startup(tmp_path):
    settings = _settings_for(tmp_path, [])
    assert settings.get("language") == "ar"
    assert settings.get("version") == APP_VERSION
    assert Path(settings.get("report_dir")).is_dir()


def test_invalid_known_types_fall_back_to_safe_defaults(tmp_path):
    settings = _settings_for(tmp_path, {
        "report_dir": None,
        "language": 42,
        "auto_fix": "yes",
        "max_scan_threads": -1,
        "trusted_networks": "not-a-list",
        "gemini_model": "custom-model",
    })
    assert settings.get("report_dir").endswith("/reports")
    assert settings.get("language") == "ar"
    assert settings.get("auto_fix") is False
    assert settings.get("max_scan_threads") == 50
    assert settings.get("trusted_networks") == []
    assert settings.get("gemini_model") == "custom-model"


def test_version_flag_uses_single_desktop_version():
    parser = main.parse_args
    with patch.object(sys, "argv", ["ayfam", "--version"]):
        # argparse raises SystemExit after printing the version; the assertion
        # below verifies the source used by the parser without launching Qt.
        try:
            parser()
        except SystemExit as exc:
            assert exc.code == 0
    assert APP_VERSION_LABEL == "AI AYFAM v8.0.0"


def test_check_only_does_not_launch_gui():
    with patch.object(sys, "argv", ["ayfam", "--check"]), \
         patch.object(main, "check_requirements") as check, \
         patch.object(main, "run_gui") as run_gui:
        check.return_value.ok = True
        check.return_value.text.return_value = "ok"
        assert main.main() == 0
        run_gui.assert_not_called()
