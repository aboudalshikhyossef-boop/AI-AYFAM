"""يلخّص فشل pytest في annotation مرئي في صفحة التشغيل (آخر الاختبارات + أسباب الفشل/الانهيار)."""
import re
import sys

log_path, code = sys.argv[1], sys.argv[2]
lines = open(log_path, encoding="utf-8", errors="replace").read().splitlines()
interesting = [ln for ln in lines if re.search(r"FAILED|ERROR|Fatal|Segmentation|Abort|Traceback|Error:|assert ", ln)]
tail = lines[-25:]
text = f"pytest exit code {code}\n-- key lines --\n" + "\n".join(interesting[-25:]) + "\n-- last lines --\n" + "\n".join(tail)
text = text[-3800:]
text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
print(f"::error title=pytest failed::{text}")
