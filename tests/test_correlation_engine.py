"""
AI AYFAM v8 — Attack Chain Correlation Engine Tests
اختبارات محرك الارتباط الذكي وسلاسل الهجوم.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.finding import Finding
from engine.correlation import CorrelationEngine, SmartRemediationAdvisor

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")

engine = CorrelationEngine()

print("\n[1] SSH Compromise Path: weak SSH config + brute force = critical chain")
# Use realistic scanner output — Finding with tags=["ssh", "hardening"]
ssh_finding = Finding(
    severity="high",
    title="SSH يقبل كلمات المرور — استخدم SSH keys",
    detail="PasswordAuthentication yes",
    fix="PasswordAuthentication no  # في /etc/ssh/sshd_config",
    category="ssh",
    tags=["ssh", "hardening"],
)
# Brute force finding from tools/system.py — tags=["brute_force", "ssh"]
brute_finding = Finding(
    severity="high",
    title="هجوم Brute Force: 192.168.1.100 (50 محاولة فاشلة)",
    detail="محاولات دخول فاشلة متكررة من نفس IP.",
    fix="sudo ufw deny from 192.168.1.100\nsudo fail2ban-client set sshd banip 192.168.1.100",
    category="brute_force",
    tags=["brute_force", "ssh"],
)
chains = engine.analyze([ssh_finding, brute_finding])
check("SSH compromise chain detected", len(chains) > 0)
check("chain is critical severity", any(f["severity"] == "critical" for f in chains))
check("chain has attack_chain tag", any("attack_chain" in (f.get("tags") or []) for f in chains))
check("chain includes SSH attack IDs", any("T1021.004" in (f.get("attack_ids") or []) for f in chains))
check("chain evidence references both findings", any(
    f.get("evidence", {}).get("ssh_finding_id") and f.get("evidence", {}).get("brute_finding_id")
    for f in chains
))

print("\n[2] Exposed Service Path: open port + firewall disabled = critical")
# Realistic: network scanner produces raw dicts without tags
exposed_finding = {
    "severity": "medium",
    "title": "خدمة مكشوفة على جميع الواجهات: منفذ 6379 (redis-server)",
    "detail": "الخدمة تقبل الاتصالات من أي مصدر خارجي.",
    "fix": "قيّد الاستماع على localhost إن أمكن، أو أضف قاعدة UFW.",
}
# Realistic: firewall scanner produces raw dict without tags
fw_finding = {
    "severity": "high",
    "title": "جدار الحماية UFW معطّل / UFW Firewall is disabled",
    "detail": "لا يوجد جدار حماية نشط يحمي نظامك.",
    "fix": "sudo ufw enable\nsudo ufw default deny incoming\nsudo ufw default allow outgoing\nsudo ufw allow 22/tcp",
}
chains = engine.analyze([exposed_finding, fw_finding])
check("exposed service chain detected", len(chains) > 0)
check("chain is critical", any(f["severity"] == "critical" for f in chains))
check("chain has T1190 attack ID", any("T1190" in (f.get("attack_ids") or []) for f in chains))

print("\n[3] Credential-to-Privilege Path: secret + SUID = escalation chain")
secret_finding = Finding(
    severity="critical",
    title="كشف سر حساس: مفتاح وصول AWS Access Key في config.py:12",
    detail="الملف: /app/config.py\nالقيمة المحجوبة: AKIA...XAMPLE",
    fix="انقل السر من /app/config.py إلى متغيرات البيئة.",
    category="secrets",
    tags=["secrets", "credential_leak"],
)
suid_finding = Finding(
    severity="critical",
    title="🔴 SUID في مكان خطير جداً: /tmp/escalate",
    detail="ملف SUID خارج النظام — يشير إلى rootkit أو اختراق",
    fix="chmod u-s /tmp/escalate",
    category="suid",
    tags=["suid_anomaly", "privesc"],
)
chains = engine.analyze([secret_finding, suid_finding])
check("credential-to-privilege chain detected", len(chains) > 0)
check("chain is critical", any(f["severity"] == "critical" for f in chains))
check("chain has T1552.001 attack ID", any("T1552.001" in (f.get("attack_ids") or []) for f in chains))
check("chain has T1548.001 attack ID", any("T1548.001" in (f.get("attack_ids") or []) for f in chains))

print("\n[4] Persistence Path: cron + shell backdoor + deleted exe")
cron_finding = Finding(
    severity="critical",
    title="🔴 Cron خبيث (Bash reverse shell): /etc/cron.d",
    detail="السطر: * * * * * root /tmp/reverse_shell.sh",
    fix="احذف فوراً: crontab -e",
    category="persistence",
    tags=["cron", "persistence"],
)
shell_finding = Finding(
    severity="critical",
    title="🚨 نمط باب خلفي في ملف تشغيل الشيل: /etc/profile",
    detail="تم رصد: اتصال عكسي مباشر عبر /dev/tcp",
    fix="افحص الملف /etc/profile فوراً",
    category="persistence",
    tags=["shell_backdoor", "persistence"],
)
deleted_finding = Finding(
    severity="high",
    title="عملة تعمل من ملف محذوف: PID 1234 (/tmp/backdoor (deleted))",
    detail="العملية تستمر بالعمل في الذاكرة بعد حذف ملفها من القرص.",
    fix="sudo kill -9 1234",
    category="evasion",
    tags=["deleted_binary", "malware"],
)
chains = engine.analyze([cron_finding, shell_finding, deleted_finding])
check("persistence chain detected with 2+ indicators", len(chains) > 0)
check("chain is critical", any(f["severity"] == "critical" for f in chains))
check("chain evidence records indicator count", any(
    f.get("evidence", {}).get("count", 0) >= 2 for f in chains
))

print("\n[5] Exploitability Amplifier: ASLR off + exposed service")
aslr_finding = Finding(
    severity="critical",
    title="ميزة عزل الذاكرة العشوائي (ASLR) غير مفعلة بالكامل: 0",
    detail="ASLR يمنع استغلال ثغرات تجاوز سعة المخزن المؤقت.",
    fix="sudo sysctl -w kernel.randomize_va_space=2",
    category="memory_protection",
    tags=["aslr", "memory", "exploit_mitigation"],
)
update_finding = Finding(
    severity="medium",
    title="تحديثات أمنية معلّقة: 15 حزمة",
    detail="تحديثات تتضمن إصلاحات أمنية",
    fix="sudo apt-get update && sudo apt-get upgrade -y",
    category="updates",
    tags=["updates"],
)
chains = engine.analyze([aslr_finding, update_finding])
check("exploitability amplifier chain detected", len(chains) > 0)
check("chain is at least high severity", any(
    f["severity"] in ("high", "critical") for f in chains
))

print("\n[6] Data Exfiltration Path: reverse shell + secrets")
c2_finding = Finding(
    severity="critical",
    title="🚨 اتصال خارجي مريب من مفسر أوامر: bash ➔ 185.220.101.1:4444",
    detail="العملية 'bash' تملك اتصالاً نشطاً مع خادم خارجي",
    fix="افحص العملية فوراً وأوقفها: sudo pkill -9 bash",
    category="reverse_shell",
    tags=["reverse_shell", "c2", "intrusion"],
)
chains = engine.analyze([c2_finding, secret_finding])
check("data exfiltration chain detected", len(chains) > 0)
check("chain is critical", any(f["severity"] == "critical" for f in chains))
check("chain has T1041 attack ID", any("T1041" in (f.get("attack_ids") or []) for f in chains))

print("\n[7] No false positives on clean findings")
clean_findings = [
    Finding(severity="low", title="SSH على المنفذ الافتراضي 22", detail="تغيير المنفذ يقلل Brute Force", fix="Port 2222", tags=["ssh", "hardening"]),
    Finding(severity="info", title="مستخدم sudo: admin (مجموعة: sudo)", detail="تأكد أن فقط المستخدمين الموثوقين في sudo", fix=""),
]
chains = engine.analyze(clean_findings)
check("no attack chains from clean findings", len(chains) == 0)

print("\n[7b] Negative: firewall enabled + exposed service = NO chain")
fw_enabled = {"severity": "info", "title": "جدار الحماية UFW مفعّل", "detail": "UFW نشط", "fix": ""}
chains = engine.analyze([exposed_finding, fw_enabled])
check("no chain when firewall is enabled", len(chains) == 0)

print("\n[7c] Negative: SSH password disabled + brute force = NO SSH chain")
ssh_secure = Finding(
    severity="info", title="SSH يستخدم مفاتيح فقط", detail="PasswordAuthentication no",
    fix="", tags=["ssh", "hardening"],
)
chains = engine.analyze([ssh_secure, brute_finding])
check("no SSH chain when password auth is disabled", len(chains) == 0)

print("\n[7d] Negative: ASLR enabled + updates = NO amplifier chain")
aslr_on = Finding(
    severity="info", title="ASLR مفعّل بالكامل: 2",
    detail="ASLR يعمل بشكل صحيح", fix="",
    tags=["aslr", "memory", "exploit_mitigation"],
)
chains = engine.analyze([aslr_on, update_finding])
check("no amplifier chain when ASLR is enabled", len(chains) == 0)

print("\n[7e] Negative: secrets + safe permissions = NO privilege chain")
safe_perms = Finding(
    severity="info", title="صلاحيات الملفات آمنة", detail="جميع الملفات الحساسة محمية",
    fix="", tags=["permissions", "auth", "hardening"],
)
chains = engine.analyze([secret_finding, safe_perms])
check("no privilege chain with only safe permissions", len(chains) == 0)

print("\n[7f] Negative: SSH port finding (not weak) + brute force = NO chain")
ssh_port = Finding(
    severity="low", title="SSH على المنفذ الافتراضي 22",
    detail="تغيير المنفذ يقلل Brute Force", fix="Port 2222",
    tags=["ssh", "hardening"],
)
chains = engine.analyze([ssh_port, brute_finding])
check("no SSH chain for port-only finding", len(chains) == 0)

print("\n[8] Smart Remediation Advisor prioritizes by impact")
all_findings = [ssh_finding, brute_finding, secret_finding, suid_finding, aslr_finding]
# Convert raw dicts to Finding for the advisor
exposed_as_finding = Finding(
    severity="medium",
    title="خدمة مكشوفة على جميع الواجهات: منفذ 6379 (redis-server)",
    detail="الخدمة تقبل الاتصالات من أي مصدر خارجي.",
    fix="قيّد الاستماع على localhost إن أمكن، أو أضف قاعدة UFW.",
    category="exposed_service",
    tags=["exposed_port", "database"],
)
fw_as_finding = Finding(
    severity="high",
    title="جدار الحماية UFW معطّل / UFW Firewall is disabled",
    detail="لا يوجد جدار حماية نشط يحمي نظامك.",
    fix="sudo ufw enable",
    category="firewall",
    tags=["firewall"],
)
all_findings = [ssh_finding, brute_finding, exposed_as_finding, fw_as_finding, secret_finding, suid_finding, aslr_finding]
chains = engine.analyze(all_findings)
combined = all_findings + chains
recs = SmartRemediationAdvisor.prioritize(combined, top_n=5)
check("recommendations generated", len(recs) > 0)
check("top recommendation is critical or high priority", recs[0]["priority"] in ("حرج", "عالي"))
check("each recommendation has a fix command", all(r.get("fix_cmd") for r in recs))
check("each recommendation has a reason", all(r.get("reason") for r in recs))
check("recommendations are sorted by priority", recs[0]["impact_score"] >= recs[-1]["impact_score"])

print("\n[9] Smart Remediation format output")
formatted = SmartRemediationAdvisor.format_recommendations(combined, top_n=3)
check("formatted output is non-empty", len(formatted) > 100)
check("output contains priority labels", "حرج" in formatted or "عالي" in formatted)
check("output contains fix commands", "sudo" in formatted or "PermitRootLogin" in formatted)

print("\n[10] Analy and Extend: original findings + chains returned together")
extended = engine.analyze_and_extend(clean_findings + [ssh_finding, brute_finding])
check("extended list includes original findings", len(extended) >= len(clean_findings) + 2)
check("extended list includes attack chains", any(
    "attack_chain" in (f.get("tags") or []) for f in extended
))

print(f"\n{'='*55}\nTOTAL CORRELATION TESTS: {passed} passed, {failed} failed\n{'='*55}")
