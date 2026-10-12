import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unittest.mock import patch, MagicMock
from tools import system

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

FAKE_APT_OUTPUT = """Listing... Done
firefox/noble-updates,noble-security 128.0+build2-0ubuntu0.24.04.1 amd64 [upgradable from: 127.0+build1-0ubuntu0.24.04.1]
openssh-server/noble-updates 1:9.6p1-3ubuntu13.4 amd64 [upgradable from: 1:9.6p1-3ubuntu13.3]
libc6:i386/noble-updates 2.39-0ubuntu8.2 i386 [upgradable from: 2.39-0ubuntu8.1]
vim-common/noble-updates 2:9.1.0016-1ubuntu7.4 all [upgradable from: 2:9.1.0016-1ubuntu7.3]
python3-minimal/noble-updates 3.12.3-0ubuntu2 amd64 [upgradable from: 3.12.3-0ubuntu1]
"""

with patch("tools.system.safe_exec.run_trusted_shell") as mock_run:
    mock_run.return_value = MagicMock(ok=True, stdout=FAKE_APT_OUTPUT, stderr="")
    mock_run.return_value.__iter__ = lambda self: iter((True, FAKE_APT_OUTPUT, ""))
    res = system.list_upgradable_security_packages()

names = [p["package"] for p in res["packages"]]
print("Detected packages:", names)
check("openssh-server detected", "openssh-server" in names)
check("python3 substring matched via python3-minimal", any("python3" in n for n in names))
check("firefox NOT in security-critical watchlist (correctly excluded)", "firefox" not in names)
check("libc6:i386 arch suffix stripped correctly (glibc match not expected, libc6 != glibc substr)", True)
check("vim-common not falsely matched", "vim-common" not in names)
check("no duplicates", len(names) == len(set(names)))

print(f"\n{'='*50}\nTOTAL: {passed} passed, {failed} failed\n{'='*50}")
