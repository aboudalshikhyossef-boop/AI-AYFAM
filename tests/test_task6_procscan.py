"""
Unit tests for Task 6 — Process & Network Inspection by Path and Package
"""

import os
import tempfile
import pytest
from engine.procscan import ProcessNetworkScanner, PackageIndex

def test_package_index_lookup():
    with tempfile.TemporaryDirectory() as tmpdir:
        list_file = os.path.join(tmpdir, "python3.list")
        with open(list_file, "w") as f:
            f.write("/usr/bin/python3.12\n/usr/bin/python3\n")

        pkg_index = PackageIndex(dpkg_info_dir=tmpdir)
        assert pkg_index.get_owning_package("/usr/bin/python3") == "python3"
        assert pkg_index.get_owning_package("/tmp/python3") is None

def test_reverse_shell_and_deleted_memfd_heuristics():
    with tempfile.TemporaryDirectory() as proc_dir:
        # Create fake /proc/1234
        pid_dir = os.path.join(proc_dir, "1234")
        os.makedirs(os.path.join(pid_dir, "fd"), exist_ok=True)

        # Fake symlink exe -> /tmp/python3 (deleted)
        exe_link = os.path.join(pid_dir, "exe")
        os.symlink("/tmp/python3 (deleted)", exe_link)

        # Fake cmdline
        with open(os.path.join(pid_dir, "cmdline"), "wb") as f:
            f.write(b"python3\x00-c\x00import socket\x00")

        # Fake status
        with open(os.path.join(pid_dir, "status"), "w") as f:
            f.write("Name:\tpython3\nPPid:\t100\nUid:\t1000\t1000\n")

        # Fake fd 0, 1, 2 pointing to same socket
        for fd in ("0", "1", "2"):
            os.symlink("socket:[99999]", os.path.join(pid_dir, "fd", fd))

        scanner = ProcessNetworkScanner(proc_dir=proc_dir)
        findings = scanner.scan_all_processes()

        assert len(findings) >= 2
        titles = [f["title"] for f in findings]
        assert any("ملف محذوف" in t or "deleted" in t for t in titles)
        assert any("Reverse Shell" in t for t in titles)
