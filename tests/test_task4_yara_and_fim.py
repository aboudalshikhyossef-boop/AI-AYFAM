"""
Unit tests for Task 4 — Real YARA Scanner and File Integrity Monitor (FIM)
"""

import os
import tempfile
import pytest
from engine.yarascan import YaraScanner
from engine.fim import FileIntegrityMonitor

def test_yara_scanner_webshell_and_benign_python_script():
    scanner = YaraScanner()

    with tempfile.TemporaryDirectory() as tmpdir:
        # Benign python socket script (should NOT produce critical false positives)
        benign_path = os.path.join(tmpdir, "benign_server.py")
        with open(benign_path, "w") as f:
            f.write("import socket\ns = socket.socket()\ns.bind(('127.0.0.1', 8080))\nprint('Server started')\n")

        # Webshell script matching YARA rules
        webshell_path = os.path.join(tmpdir, "shell.php")
        with open(webshell_path, "w") as f:
            f.write("<?php system($_POST['cmd']); ?>")

        benign_findings = scanner.scan_file(benign_path)
        assert len(benign_findings) == 0, "Benign python socket script should not be flagged as critical"

        webshell_findings = scanner.scan_file(webshell_path)
        assert len(webshell_findings) >= 1
        assert any("مطابقة YARA" in f["title"] or "YARA Match" in f.get("title_en", "") for f in webshell_findings)

def test_fim_baseline_and_integrity_verification():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "fim.db")
        key_path = os.path.join(tmpdir, "fim.key")

        # Target test file
        test_file = os.path.join(tmpdir, "important_config.conf")
        with open(test_file, "w") as f:
            f.write("setting=original_value\n")

        fim = FileIntegrityMonitor(db_path=db_path, key_path=key_path)
        count = fim.build_baseline(paths=[test_file])
        assert count == 1

        # First verification must pass cleanly
        findings = fim.verify_baseline()
        assert len(findings) == 0

        # Modify file content
        with open(test_file, "w") as f:
            f.write("setting=tampered_value\n")

        # Verification must now catch the tampering
        tamper_findings = fim.verify_baseline()
        assert len(tamper_findings) == 1
        assert "تغيير غير مصرح به" in tamper_findings[0]["title"] or "Unauthorized" in tamper_findings[0].get("title_en", "")
