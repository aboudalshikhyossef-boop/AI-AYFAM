"""
AI AYFAM — Real YARA Scanner Engine
محرك فحص YARA الحقيقي — فحص آمن للملفات مع حماية من الحجم والمهلة والروابط الرمزية
"""

import os
import hashlib
import yara
import logging
from typing import List, Dict, Any, Optional
from engine.rules_registry import create_finding
from engine.finding import Finding

DEFAULT_RULES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "resources", "yara", "rules.yar"))
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit per file

DEFAULT_SCAN_TARGETS = [
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/usr/local/bin",
    os.path.expanduser("~/.config/autostart"),
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
]

class YaraScanner:
    """محرك YARA التجميعي والفاحص الآمن للملفات."""

    def __init__(self, rules_path: str = DEFAULT_RULES_PATH, extra_rules_dir: Optional[str] = None):
        self.compiled_rules = None
        self._load_rules(rules_path, extra_rules_dir)

    def _load_rules(self, rules_path: str, extra_rules_dir: Optional[str]):
        filepaths = {}
        if os.path.isfile(rules_path):
            filepaths["default_rules"] = rules_path

        if extra_rules_dir and os.path.isdir(extra_rules_dir):
            for fname in os.listdir(extra_rules_dir):
                if fname.endswith(".yar") or fname.endswith(".yara"):
                    full_p = os.path.join(extra_rules_dir, fname)
                    if os.path.isfile(full_p):
                        filepaths[f"user_{fname}"] = full_p

        if filepaths:
            try:
                self.compiled_rules = yara.compile(filepaths=filepaths)
            except Exception as e:
                logging.error(f"Failed to compile YARA rules: {e}")

    def scan_file(self, filepath: str, timeout: int = 5) -> List[Finding]:
        findings = []
        if not self.compiled_rules:
            return findings

        try:
            # Avoid symlinks and non-regular files
            st = os.lstat(filepath)
            if os.path.islink(filepath) or not (st.st_mode & 0o100000):  # S_IFREG check
                return findings

            if st.st_size > MAX_FILE_SIZE or st.st_size == 0:
                return findings

            matches = self.compiled_rules.match(filepath, timeout=timeout)
            if matches:
                with open(filepath, "rb") as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()

                for m in matches:
                    rule_name = m.rule
                    meta = m.meta or {}
                    rule_id_meta = meta.get("rule_id", "NET-SUSP-PROC")
                    sev = meta.get("severity", "HIGH").lower()
                    desc = meta.get("description", f"YARA match: {rule_name}")

                    matched_strings = []
                    if hasattr(m, "strings"):
                        for sm in m.strings[:3]:
                            ident = getattr(sm, "identifier", "match")
                            instances = getattr(sm, "instances", [])
                            for inst in instances[:1]:
                                m_data = getattr(inst, "matched_data", b"")
                                s_data = m_data[:60].decode("utf-8", "ignore")
                                matched_strings.append(f"{ident}: {s_data}")

                    finding = create_finding(
                        rule_id=rule_id_meta,
                        severity=sev,
                        title_ar=f"مطابقة YARA خبيثة ({rule_name}): {os.path.basename(filepath)}",
                        title_en=f"YARA Match ({rule_name}): {os.path.basename(filepath)}",
                        detail=f"الوصف: {desc}\nالمسار: {filepath}\nSHA256: {file_hash}\nالمطابقات: {', '.join(matched_strings)}",
                        fix=f"احذف الملف أو افحصه: rm -f -- '{filepath}'",
                        evidence={"path": filepath, "sha256": file_hash, "rule": rule_name, "matched_strings": matched_strings},
                        stable_key=filepath,
                    )
                    findings.append(finding)
        except (PermissionError, OSError) as e:
            logging.debug(f"Yara scan file access issue on {filepath}: {e}")
        except Exception as e:
            logging.debug(f"Yara scan error on {filepath}: {e}")

        return findings

    def scan_directory(self, target_dir: str, timeout: int = 5) -> List[Finding]:
        findings = []
        if not os.path.exists(target_dir) or not os.path.isdir(target_dir):
            return findings

        try:
            for root, dirs, files in os.walk(target_dir, followlinks=False):
                # Skip pseudo filesystems
                if any(root.startswith(p) for p in ("/proc", "/sys", "/dev", "/run/user")):
                    dirs[:] = []
                    continue

                for fname in files:
                    fpath = os.path.join(root, fname)
                    findings.extend(self.scan_file(fpath, timeout=timeout))
        except (PermissionError, OSError) as e:
            logging.debug(f"Directory scan access issue on {target_dir}: {e}")
        except Exception as e:
            logging.debug(f"Directory scan error on {target_dir}: {e}")

        return findings

    def scan_system_targets(self, targets: Optional[List[str]] = None) -> List[Finding]:
        findings = []
        scan_list = targets or DEFAULT_SCAN_TARGETS
        for target in scan_list:
            if os.path.isfile(target):
                findings.extend(self.scan_file(target))
            elif os.path.isdir(target):
                findings.extend(self.scan_directory(target))
        return findings
