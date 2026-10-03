import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.baseline import BaselineEngine
from engine.sysreader import FakeSystem
from engine.autoreactor import AutoReactor
from engine.finding import Finding

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

print("\n[1] Baseline Engine Snapshot & Learning")
tmp_db = tempfile.mktemp(suffix=".db")
fake_sys = FakeSystem(
    files={"/etc/passwd": "root:x:0:0::/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash"}
)
be = BaselineEngine(db_path=tmp_db, sys_reader=fake_sys)
ok = be.save_baseline()
check("baseline saved to SQLite", ok is True)

# محاكاة إنشاء مستخدم مشبوه جديد
fake_sys.files["/etc/passwd"] += "\nhacker:x:0:0::/root:/bin/bash"
findings = be.check_deviations()
check("detects unauthorized new user anomaly", len(findings) > 0)
check("severity is critical for new UID 0 user", any(f["severity"] == "critical" for f in findings))

print("\n[2] Auto-Reactor Rule Synthesizer")
test_finding = Finding(
    severity="critical",
    title="هجوم Brute Force من 198.51.100.22",
    detail="تفاصيل المحاولات المتكررة من 198.51.100.22",
    tags=["brute_force"],
)
rules = AutoReactor.synthesize_rules([test_finding])
check("synthesizes firewall rule", len(rules) > 0)
check("rule targets attacker IP", "198.51.100.22" in rules[0]["cmd"])

print("\n[3] Auto-Reactor SUID Privilege Strip Path (regression: missing import os)")
# إنشاء ملف SUID وهمي على القرص لاختبار مسار os.path.exists()
suid_test_file = "/tmp/test_suid_regression"
with open(suid_test_file, "w") as f:
    f.write("dummy")
suid_finding = Finding(
    severity="critical",
    title=f"ملف SUID خطير: {suid_test_file}",
    detail=f"الملف {suid_test_file} يحمل صلاحية SUID غير المصرح بها.",
    tags=["suid"],
)
suid_rules = AutoReactor.synthesize_rules([suid_finding])
check("suid path does not raise NameError (import os fixed)", True)
check("suid rule generated for existing file", len(suid_rules) > 0)
check("suid rule contains chmod u-s", any("chmod u-s" in r["cmd"] for r in suid_rules))
if os.path.exists(suid_test_file):
    os.remove(suid_test_file)

print(f"\n{'='*50}\nTOTAL PHASE 3 TESTS: {passed} passed, {failed} failed\n{'='*50}")
if os.path.exists(tmp_db):
    os.remove(tmp_db)
sys.exit(1 if failed else 0)
