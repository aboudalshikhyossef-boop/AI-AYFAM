"""Release and installation safety regression tests."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from config import settings as settings_module


def test_secret_prefers_keyring_and_is_not_written_to_config(tmp_path):
    values = {}
    fake_keyring = SimpleNamespace(
        get_password=lambda service, name: values.get((service, name)),
        set_password=lambda service, name, value: values.__setitem__((service, name), value),
    )
    config_dir = tmp_path / ".ayfam"
    config_file = config_dir / "config.json"
    with patch.object(settings_module, "CONFIG_DIR", config_dir), \
         patch.object(settings_module, "CONFIG_FILE", config_file), \
         patch.object(settings_module, "keyring", fake_keyring):
        settings = settings_module.Settings()
        settings.set("github_token", "gh-secret-value")
        saved = json.loads(config_file.read_text(encoding="utf-8"))
        assert saved["github_token"] == ""
        assert values[("ai-ayfam", "github_token")] == "gh-secret-value"
        loaded = settings_module.Settings()
        assert loaded.get("github_token") == "gh-secret-value"


def test_ci_and_single_supported_installer_exist():
    root = Path(__file__).resolve().parents[1]
    assert (root / ".github/workflows/ci.yml").is_file()
    assert (root / "setup.sh").is_file()
    legacy = [
        "install_v5.sh", "install_v7_abouda.sh", "upgrade_v6_arsenal.sh",
        "upgrade_phase2.sh", "upgrade_phase3.sh", "upgrade_phase4_gui.sh",
        "fix_phase2.sh", "fix_pyqt6.sh", "fix_sklearn.sh", "fix_yara.sh", "fix_gui_abort.sh",
    ]
    assert not any((root / name).exists() for name in legacy)


def test_ci_checks_desktop_and_frontend_paths():
    ci = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "pytest -q" in ci
    assert "ruff check" in ci
    assert "pyflakes" in ci
    assert "permissions:" in ci
