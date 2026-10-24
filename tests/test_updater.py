"""
Unit tests for Signed Updates and Anti-Rollback Manager (engine/updater.py)
"""

import os
import json
import tempfile
import pytest
from unittest.mock import patch, MagicMock
from engine.updater import UpdateManager
from tools.dev.sign_bundle import generate_keypair
from cryptography.hazmat.primitives import serialization

def test_update_manager_anti_rollback():
    with tempfile.TemporaryDirectory() as tmpdir:
        vfile = os.path.join(tmpdir, "version.json")
        mgr = UpdateManager(version_file=vfile, pub_key_hex="00" * 32)

        mgr._save_installed_meta({"version": "2.0.0", "sequence_number": 10})

        # Lower sequence number rejected
        assert mgr.check_anti_rollback(9, "1.9.0") is False
        # Equal sequence number rejected
        assert mgr.check_anti_rollback(10, "2.0.0") is False
        # Higher sequence number allowed
        assert mgr.check_anti_rollback(11, "2.1.0") is True

def test_update_manager_signature_and_verification():
    priv_key, pub_key = generate_keypair()

    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pub_hex = pub_bytes.hex()

    with tempfile.TemporaryDirectory() as tmpdir:
        vfile = os.path.join(tmpdir, "version.json")
        mgr = UpdateManager(version_file=vfile, pub_key_hex=pub_hex)

        data = b"AYFAM update bundle data"
        sig = priv_key.sign(data)

        # Valid signature
        assert mgr.verify_signature(data, sig) is True
        # Tampered data
        assert mgr.verify_signature(data + b"tampered", sig) is False

def test_download_and_verify_update_anti_rollback_triggered():
    priv_key, pub_key = generate_keypair()
    pub_hex = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()

    with tempfile.TemporaryDirectory() as tmpdir:
        vfile = os.path.join(tmpdir, "version.json")
        mgr = UpdateManager(version_file=vfile, pub_key_hex=pub_hex)
        mgr._save_installed_meta({"version": "2.0.0", "sequence_number": 20})

        # Mocking metadata response with old sequence_number = 15
        meta_response = MagicMock()
        meta_response.read.return_value = json.dumps({
            "version": "1.5.0",
            "sequence_number": 15
        }).encode("utf-8")
        meta_response.__enter__.return_value = meta_response

        with patch("urllib.request.urlopen", return_value=meta_response):
            success, msg, meta = mgr.download_and_verify_update(
                "http://example.com/tar",
                "http://example.com/sig",
                "http://example.com/meta",
                tmpdir
            )
            assert success is False
            assert "Anti-Rollback" in msg
