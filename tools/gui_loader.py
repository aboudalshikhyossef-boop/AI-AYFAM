"""Loader for ui/gui_app.py — decompresses chunks and writes full GUI source."""
import zlib, base64
from pathlib import Path

parts = []
for i in range(9):
    mod = __import__(f"tools._gui_p{i}", fromlist=[f"P{i}"])
    parts.append(getattr(mod, f"P{i}"))

from tools import _gui_remaining as rem
for i in range(9, 21):
    parts.append(getattr(rem, f"P{i}"))

_src = zlib.decompress(base64.b64decode("".join(parts)))
_target = Path(__file__).resolve().parent.parent / "ui" / "gui_app.py"
_target.parent.mkdir(parents=True, exist_ok=True)
_target.write_bytes(_src)
print(f"[gui_loader] wrote {_target} ({len(_src)} bytes)")
