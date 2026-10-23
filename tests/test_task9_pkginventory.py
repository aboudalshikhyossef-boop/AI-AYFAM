"""
Unit tests for Task 9 — Package Inventory, Version Comparison, and Rules Bundle Signature
"""

import os
import tempfile
import pytest
from engine.pkginventory import PackageInventoryEngine
from tools.dev.sign_bundle import generate_keypair, sign_rules_bundle
from cryptography.hazmat.primitives import serialization

def test_version_comparison_via_dpkg():
    engine = PackageInventoryEngine()
    # 1.0 < 2.0
    assert engine.compare_versions("1.0", "2.0") == -1
    # 2.0 == 2.0
    assert engine.compare_versions("2.0", "2.0") == 0
    # 2.1 > 2.0
    assert engine.compare_versions("2.1", "2.0") == 1

def test_signed_rules_bundle_signature_verification():
    priv_key, pub_key = generate_keypair()

    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pub_hex = pub_bytes.hex()

    with tempfile.TemporaryDirectory() as tmpdir:
        bundle_dir = os.path.join(tmpdir, "rules")
        os.makedirs(bundle_dir, exist_ok=True)
        with open(os.path.join(bundle_dir, "test.yar"), "w") as f:
            f.write("rule Test { condition: true }")

        output_tar = os.path.join(tmpdir, "rules.tar.gz")
        sig_file = output_tar + ".sig"

        # Sign bundle
        assert sign_rules_bundle(bundle_dir, priv_pem, output_tar) is True

        # Verify valid signature
        assert PackageInventoryEngine.verify_rules_bundle_signature(output_tar, sig_file, pub_hex) is True

        # Tamper with archive
        with open(output_tar, "ab") as f:
            f.write(b"tamper_bytes")

        # Signature verification must fail on tampered archive
        assert PackageInventoryEngine.verify_rules_bundle_signature(output_tar, sig_file, pub_hex) is False
