"""Regression test verifying Debian control package version matches APP_VERSION."""

from pathlib import Path
from config.version import APP_VERSION


def test_debian_control_version_matches_app_version():
    root_dir = Path(__file__).resolve().parents[1]
    control_path = root_dir / "packaging" / "deb" / "DEBIAN" / "control"
    assert control_path.is_file(), f"Control file missing at {control_path}"

    version_in_control = None
    with open(control_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("Version:"):
                version_in_control = line.split(":", 1)[1].strip()
                break

    assert version_in_control is not None, "Version field not found in DEBIAN/control"
    assert version_in_control == APP_VERSION, (
        f"DEBIAN/control version '{version_in_control}' does not match "
        f"APP_VERSION '{APP_VERSION}'"
    )
