"""
AI AYFAM — Signed Update Downloader & Anti-Rollback Manager
تنزيل التحديثات الموقعة والتحقق بـ Ed25519 ومنع الرجوع لإصدارات قديمة (Anti-Rollback)
"""

import os
import json
import urllib.request
import urllib.parse
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from engine.pkginventory import EMBEDDED_PUBLIC_KEY_HEX

VERSION_FILE = os.path.expanduser("~/.ayfam/installed_version.json")

class UpdateError(Exception):
    """استثناء يمثل خطأ في عملية التحديث."""
    pass

class UpdateManager:
    """إدارة تنزيل والتثبيت والتحقق من التحديثات مع حماية ضد التراجعات الزمانية (Anti-Rollback)."""

    def __init__(self, version_file: str = VERSION_FILE, pub_key_hex: str = EMBEDDED_PUBLIC_KEY_HEX):
        self.version_file = version_file
        self.pub_key_hex = pub_key_hex
        os.makedirs(os.path.dirname(self.version_file), exist_ok=True)
        self.current_meta = self._load_installed_meta()

    def _load_installed_meta(self) -> Dict[str, Any]:
        if os.path.exists(self.version_file):
            try:
                with open(self.version_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"version": "1.0.0", "sequence_number": 1}

    def _save_installed_meta(self, meta: Dict[str, Any]):
        with open(self.version_file, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        self.current_meta = meta

    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """التحقق من توقيع المفتاح العام Ed25519."""
        try:
            pub_bytes = bytes.fromhex(self.pub_key_hex)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            public_key.verify(signature, data)
            return True
        except Exception:
            return False

    def check_anti_rollback(self, new_sequence_number: int, new_version: str) -> bool:
        """
        التحقق من عدم الرجوع لإصدار قديم.
        الشرط: الرقم التسلسلي الجديد يجب أن يكون أكبر من الرقم التسلسلي الحالي.
        """
        current_seq = self.current_meta.get("sequence_number", 0)
        if new_sequence_number <= current_seq:
            return False
        return True

    def download_and_verify_update(
        self,
        update_tar_url: str,
        signature_url: str,
        meta_url: str,
        dest_dir: str
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        تنزيل التحديث، التحقق من توقيع Ed25519، ومنع الرجوع لإصدارات قديمة (Anti-Rollback).
        """
        os.makedirs(dest_dir, exist_ok=True)
        tar_path = os.path.join(dest_dir, "update.tar.gz")
        sig_path = os.path.join(dest_dir, "update.tar.gz.sig")

        try:
            # 1. Download Metadata
            req_meta = urllib.request.Request(meta_url, headers={"User-Agent": "AI-AYFAM-Updater"})
            with urllib.request.urlopen(req_meta, timeout=15) as resp:
                meta_data = json.loads(resp.read().decode("utf-8"))

            new_seq = meta_data.get("sequence_number", 0)
            new_version = meta_data.get("version", "0.0.0")

            # 2. Anti-Rollback Check
            if not self.check_anti_rollback(new_seq, new_version):
                err = f"محاولة خفض الإصدار مرفوضة (Anti-Rollback Protection): الإصدار الحالي seq={self.current_meta.get('sequence_number')}، المطلوب seq={new_seq}"
                return False, err, meta_data

            # 3. Download Package & Signature
            urllib.request.urlretrieve(update_tar_url, tar_path)
            urllib.request.urlretrieve(signature_url, sig_path)

            with open(tar_path, "rb") as f:
                tar_bytes = f.read()

            with open(sig_path, "rb") as f:
                sig_bytes = f.read()

            # 4. Ed25519 Signature Verification
            if not self.verify_signature(tar_bytes, sig_bytes):
                return False, "التوقيع الرقمي للتحديث غير صالح بـ Ed25519!", meta_data

            # 5. Apply Update Metadata State
            self._save_installed_meta(meta_data)
            return True, f"تم التنزيل والتحقق بنجاح للإصدار {new_version} (seq={new_seq})", meta_data

        except Exception as exc:
            return False, f"فشل التحديث: {exc}", {}
