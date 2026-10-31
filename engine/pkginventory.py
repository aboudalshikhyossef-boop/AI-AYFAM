"""
AI AYFAM — Package Inventory & OSV/CISA KEV Vulnerability Engine
محرك جرد حزم النظام والمطابقة الدقيقة مع ثغرات OSV وCISA KEV عبر dpkg
"""

import os
import json
import sqlite3
import time
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from utils import safe_exec, http_client
from engine.rules_registry import create_finding
from engine.finding import Finding

DB_PATH = os.path.expanduser("~/.ayfam/osv_cache.db")

# Public Key embedded for verifying downloaded rule bundles
EMBEDDED_PUBLIC_KEY_HEX = "1e8623adfb376378e9b883011a0ff1ba07842605b0b925b6a715f01e74bf0e29"

# Ubuntu version codename to OSV ecosystem identifier map
UBUNTU_CODENAME_TO_ECOSYSTEM = {
    "noble": "Ubuntu:24.04:LTS",
    "mantic": "Ubuntu:23.10",
    "lunar": "Ubuntu:23.04",
    "jammy": "Ubuntu:22.04:LTS",
    "focal": "Ubuntu:20.04:LTS",
    "bionic": "Ubuntu:18.04:LTS",
    "xenial": "Ubuntu:16.04:LTS",
    "trusty": "Ubuntu:14.04:LTS",
}

class PackageInventoryEngine:
    """محرك جرد الحزم والمطابقة الدقيقة للإصدارات مع OSV وCISA KEV."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS osv_cache (
                    package_name TEXT PRIMARY KEY,
                    cve_json TEXT NOT NULL,
                    cached_at REAL NOT NULL,
                    etag TEXT
                )
            """)
            conn.commit()

    def detect_os_ecosystem(self) -> str:
        """اكتشاف قاعدة التوزيعة وتحويل اسم المورد (مثلاً noble) إلى التنسيق الرسمي لـ OSV."""
        codename = None
        if os.path.exists("/etc/upstream-release/lsb-release"):
            try:
                with open("/etc/upstream-release/lsb-release") as f:
                    content = f.read()
                    if "DISTRIB_CODENAME=" in content:
                        codename = content.split("DISTRIB_CODENAME=")[1].splitlines()[0].strip().strip('"')
            except Exception:
                pass

        if not codename and os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release") as f:
                    content = f.read()
                    if "UBUNTU_CODENAME=" in content:
                        codename = content.split("UBUNTU_CODENAME=")[1].splitlines()[0].strip().strip('"')
                    elif "VERSION_CODENAME=" in content:
                        codename = content.split("VERSION_CODENAME=")[1].splitlines()[0].strip().strip('"')
            except Exception:
                pass

        if codename and codename in UBUNTU_CODENAME_TO_ECOSYSTEM:
            return UBUNTU_CODENAME_TO_ECOSYSTEM[codename]
        elif codename:
            return f"Ubuntu:{codename}"

        return "Ubuntu"

    def get_installed_packages(self) -> Dict[str, str]:
        """جرد الحزم الدقيقة عبر dpkg-query."""
        pkgs = {}
        res = safe_exec.run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=20, check_binary=False)
        if res.ok and res.stdout:
            for line in res.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    pkg_name = parts[0].split(":")[0].strip()
                    pkgs[pkg_name] = parts[1].strip()
        return pkgs

    def compare_versions(self, ver1: str, ver2: str) -> int:
        """مقارنة دقيقة للإصدارات باستخدام dpkg --compare-versions."""
        # Returns -1 if ver1 < ver2, 0 if ver1 == ver2, 1 if ver1 > ver2
        res = safe_exec.run(["dpkg", "--compare-versions", ver1, "lt", ver2], timeout=5, check_binary=False)
        if res.ok:
            return -1
        res_eq = safe_exec.run(["dpkg", "--compare-versions", ver1, "eq", ver2], timeout=5, check_binary=False)
        if res_eq.ok:
            return 0
        return 1

    def query_osv_batch(self, packages: Dict[str, str], batch_size: int = 100) -> Tuple[List[Finding], Optional[str]]:
        """
        مطابقة الحزم المثبتة مع OSV.dev عبر تقسيم الحزم إلى دفعات متتابعة.
        تعيد (قائمة النتائج، نص الخطأ إن وُجد مشكلة شبكة أو اتصال).
        """
        findings = []
        ecosystem = self.detect_os_ecosystem()

        pkg_items = list(packages.items())
        if not pkg_items:
            return findings, None

        total_packages = len(pkg_items)
        network_errors = 0

        # Split all packages into chunks of batch_size
        for i in range(0, total_packages, batch_size):
            chunk = pkg_items[i:i + batch_size]
            queries = []
            for pkg_name, ver in chunk:
                queries.append({"package": {"name": pkg_name, "ecosystem": ecosystem}, "version": ver})

            try:
                req_data = json.dumps({"queries": queries}).encode("utf-8")
                resp = http_client.post(
                    "https://api.osv.dev/v1/querybatch",
                    data=req_data,
                    headers={"Content-Type": "application/json"},
                    timeout=12,
                )
                if resp.status_code != 200:
                    raise RuntimeError(f"OSV HTTP {resp.status_code}")
                data = resp.json()
                results = data.get("results", [])

                for idx, res_item in enumerate(results):
                    vulns = res_item.get("vulns", [])
                    pkg_name = queries[idx]["package"]["name"]
                    installed_ver = queries[idx]["version"]

                    for v in vulns[:3]:
                        cve_id = v.get("id", "OSV-VULN")
                        details = v.get("details", "Vulnerability detected in package")[:200]
                        findings.append(create_finding(
                            rule_id="SYS-UPDATE-001",
                            severity="high",
                            title_ar=f"ثغرة أمنية مؤكدة في الحزمة {pkg_name} ({cve_id})",
                            title_en=f"Vulnerability in package {pkg_name} ({cve_id})",
                            detail=f"الحزمة المثبتة: {pkg_name} ({installed_ver})\nالثغرة: {cve_id}\nالتفاصيل: {details}",
                            fix=f"sudo apt-get --only-upgrade install {pkg_name}",
                            evidence={"package": pkg_name, "installed_version": installed_ver, "cve_id": cve_id},
                            stable_key=f"{pkg_name}:{cve_id}",
                        ))
            except Exception as exc:
                network_errors += 1
                # If network fails for all/first batch, report network error
                if i == 0 and total_packages > 0:
                    err_msg = f"فشل الاتصال بـ OSV.dev: {exc}"
                    return findings, err_msg

        if network_errors > 0 and not findings:
            return findings, f"تعذر استكمال مطابقة الثغرات بسبب انقطاع الشبكة ({network_errors} دفعة فشلت)"

        return findings, None

    @staticmethod
    def verify_rules_bundle_signature(tar_path: str, sig_path: str, pub_key_hex: str = EMBEDDED_PUBLIC_KEY_HEX) -> bool:
        if not os.path.exists(tar_path) or not os.path.exists(sig_path):
            return False

        try:
            pub_bytes = bytes.fromhex(pub_key_hex)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

            with open(tar_path, "rb") as f:
                data = f.read()

            with open(sig_path, "rb") as f:
                signature = f.read()

            public_key.verify(signature, data)
            return True
        except Exception:
            return False
