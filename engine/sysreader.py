"""
AI AYFAM v5 — System Reader Abstraction
طبقة تجريد قراءة النظام — تتيح الفحص الحقيقي للنظام أو المحاكاة المعزولة (FakeSystem)
للاختبارات بدون الحاجة لصلاحيات Root.
"""

import os
import glob
import re
from typing import Optional, List, Dict, Any, Tuple
from utils import safe_exec

class SystemReader:
    """قارئ النظام الفعلي — يعتمد على safe_exec فقط."""
    def read_text(self, path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            return ""

    def read_text_limited(self, path: str, max_bytes: int) -> Optional[str]:
        """Read a UTF-8 text file only when its byte size is within the limit.

        Returns None when the file is too large or cannot be read.
        """
        try:
            with open(path, "rb") as stream:
                data = stream.read(max_bytes + 1)
            if len(data) > max_bytes or b"\x00" in data:
                return None
            return data.decode("utf-8", errors="replace")
        except (OSError, ValueError):
            return None

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def is_file(self, path: str) -> bool:
        return os.path.isfile(path)

    def is_dir(self, path: str) -> bool:
        return os.path.isdir(path)

    def listdir(self, path: str) -> List[str]:
        try:
            return os.listdir(path)
        except Exception:
            return []

    def glob(self, pattern: str) -> List[str]:
        return glob.glob(pattern)

    def stat(self, path: str) -> Optional[os.stat_result]:
        try:
            return os.stat(path)
        except Exception:
            return None

    def sysctl(self, key: str) -> str:
        path = os.path.join("/proc/sys", key.replace(".", "/"))
        val = self.read_text(path).strip()
        if val:
            return val
        # fallback to command
        res = safe_exec.run(["sysctl", "-n", key], check_binary=False)
        return res.stdout.strip() if res.ok else ""

    def run_cmd(self, args: List[str], timeout: int = 15) -> Tuple[bool, str, str]:
        r = safe_exec.run(args, timeout=timeout, check_binary=False)
        return r.ok, r.stdout, r.stderr


class FakeSystem(SystemReader):
    """نظام وهمي للاختبارات والمحاكاة التامة في الذاكرة."""
    def __init__(self, files: Optional[Dict[str, str]] = None, sysctls: Optional[Dict[str, str]] = None):
        self.files = files or {}
        self.sysctls = sysctls or {}
        self.cmd_responses: Dict[str, Tuple[bool, str, str]] = {}

    def read_text(self, path: str) -> str:
        return self.files.get(path, "")

    def read_text_limited(self, path: str, max_bytes: int) -> Optional[str]:
        value = self.files.get(path)
        if value is None:
            return None
        encoded = value.encode("utf-8", errors="replace")
        if len(encoded) > max_bytes or b"\x00" in encoded:
            return None
        return value

    def stat(self, path: str):
        value = self.files.get(path)
        if value is None:
            return None
        class FakeStat:
            st_size = len(value.encode("utf-8", errors="replace"))
            st_mode = 0o100600
        return FakeStat()

    def exists(self, path: str):
        return path in self.files or any(f.startswith(path.rstrip("/") + "/") for f in self.files)

    def is_file(self, path: str) -> bool:
        return path in self.files

    def is_dir(self, path: str) -> bool:
        p = path.rstrip("/") + "/"
        return any(f.startswith(p) for f in self.files)

    def listdir(self, path: str) -> List[str]:
        p = path.rstrip("/") + "/"
        res = set()
        for f in self.files:
            if f.startswith(p):
                sub = f[len(p):].split("/")[0]
                if sub:
                    res.add(sub)
        return sorted(list(res))

    def glob(self, pattern: str) -> List[str]:
        regex = re.compile("^" + pattern.replace("*", ".*") + "$")
        return [f for f in self.files if regex.match(f)]

    def sysctl(self, key: str) -> str:
        return self.sysctls.get(key, "")

    def set_cmd_response(self, cmd_prefix: str, ok: bool, stdout: str, stderr: str = ""):
        self.cmd_responses[cmd_prefix] = (ok, stdout, stderr)

    def run_cmd(self, args: List[str], timeout: int = 15) -> Tuple[bool, str, str]:
        cmd_str = " ".join(args)
        for prefix, resp in self.cmd_responses.items():
            if cmd_str.startswith(prefix):
                return resp
        return False, "", "command not found in mock"
