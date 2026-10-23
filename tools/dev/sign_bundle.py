"""
AI AYFAM — Development Signed Rule Bundle Generator
أداة لتوقيع حزم القواعد (YARA & YAML) باستخدام مفتاح Ed25519
"""

import os
import sys
import json
import tarfile
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def generate_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def sign_rules_bundle(bundle_dir: str, private_key_pem: bytes, output_tar: str) -> bool:
    if not os.path.exists(bundle_dir):
        return False

    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    # Pack rules into tar.gz
    with tarfile.open(output_tar, "w:gz") as tar:
        tar.add(bundle_dir, arcname="rules")

    # Read tar content and sign
    with open(output_tar, "rb") as f:
        data = f.read()

    signature = private_key.sign(data)

    sig_file = output_tar + ".sig"
    with open(sig_file, "wb") as f:
        f.write(signature)

    return True

if __name__ == "__main__":
    print("Bundle signing tool initialized.")
