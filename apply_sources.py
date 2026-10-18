#!/usr/bin/env python3
"""Expand .ayfam_parts/*.b64 into real source files. Run from repo root once."""
import base64, zlib
from pathlib import Path
ROOT = Path(__file__).resolve().parent
PARTS = ROOT / ".ayfam_parts"
for b64_name, target in [
    ("system.b64", "tools/system.py"),
    ("web.b64", "tools/web.py"),
    ("agent.b64", "core/agent.py"),
]:
    src = PARTS / b64_name
    if not src.exists():
        print("missing", src)
        continue
    data = zlib.decompress(base64.b64decode(src.read_text(encoding="ascii").strip()))
    out = ROOT / target
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    print("OK", target, len(data))
print("Done.")
