"""Regression test verifying Debian control package version matches APP_VERSION."""

import shutil
import subprocess
from pathlib import Path

import pytest

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


def test_debian_package_build_and_dpkg_version(tmp_path):
    root_dir = Path(__file__).resolve().parents[1]
    build_script = root_dir / "packaging" / "build-deb.sh"
    if not build_script.is_file() or not shutil.which("dpkg-deb"):
        pytest.skip("build-deb.sh or dpkg-deb not available")

    out_deb = tmp_path / "ai-ayfam-test.deb"
    subprocess.run(
        [str(build_script), str(out_deb)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out_deb.is_file()

    dpkg_res = subprocess.run(
        ["dpkg-deb", "-f", str(out_deb), "Version"],
        capture_output=True,
        text=True,
        check=True,
    )
    built_version = dpkg_res.stdout.strip()
    assert built_version == APP_VERSION
