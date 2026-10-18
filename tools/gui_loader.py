"""Loader for ui/gui_app.py — decompresses and writes the full GUI source."""
import zlib, base64
from pathlib import Path

from tools._gui_payload_p0 import P0
from tools._gui_payload_p1 import P1
from tools._gui_payload_p2 import P2
from tools._gui_payload_p3 import P3
from tools._gui_payload_p4 import P4
from tools._gui_payload_p5 import P5

_src = zlib.decompress(base64.b64decode(P0 + P1 + P2 + P3 + P4 + P5))
_target = Path(__file__).resolve().parent.parent / "ui" / "gui_app.py"
_target.parent.mkdir(parents=True, exist_ok=True)
_target.write_bytes(_src)
print(f"[gui_loader] wrote {_target} ({len(_src)} bytes)")
