import json
from pathlib import Path
from unittest.mock import patch

from engine.hardening import HardeningEngine
from engine.planner import RemediationPlanner
from config import settings as settings_module


def test_remediation_plan_never_contains_eval_or_execution_call():
    script = RemediationPlanner.generate_bash_script([
        {"title": "untrusted", "fix": "echo safe; touch /tmp/pwned"}
    ])
    assert "eval" not in script
    assert "execute \"" not in script
    assert "REVIEW ONLY" in script


def test_hardening_rejects_group_writable_account_file():
    class Reader:
        def stat(self, _path):
            return type("Stat", (), {"st_mode": 0o100664})()

    findings = HardeningEngine(Reader()).check_file_permissions()
    assert any("passwd" in finding["title"] or "group" in finding["title"] for finding in findings)


def test_settings_save_is_atomic_and_private(tmp_path):
    config_dir = tmp_path / ".ayfam"
    config_file = config_dir / "config.json"
    with patch.object(settings_module, "CONFIG_DIR", config_dir), patch.object(settings_module, "CONFIG_FILE", config_file):
        settings = settings_module.Settings()
        settings.set("language", "en")
        assert json.loads(config_file.read_text())["language"] == "en"
        assert config_file.stat().st_mode & 0o777 == 0o600
        assert not list(config_dir.glob(".config.*"))
