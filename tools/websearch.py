"""بحث الإنترنت الدقيق: Google CSE + ويكيبيديا + بدائل."""
import zlib, base64
from tools._websearch_payload_p0 import P0
from tools._websearch_payload_p1 import P1
_src = zlib.decompress(base64.b64decode(P0 + P1))
exec(compile(_src, "tools/websearch.py", "exec"), globals())
