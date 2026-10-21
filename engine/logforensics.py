"""
AI AYFAM v5 — Advanced Log Forensics Engine
تحليل جنائي متقدم للسجلات — كشف الهجمات الموزعة، Password Spraying،
والمؤشر الحرج لنجاح الاختراق: دخول ناجح بعد إخفاقات متكررة.
"""

import re
from collections import defaultdict
from typing import List, Optional
from engine.finding import Finding
from engine.sysreader import SystemReader

class LogForensicsEngine:
    def __init__(self, sys_reader: Optional[SystemReader] = None):
        self.sys = sys_reader or SystemReader()

    def analyze_auth_logs(self) -> List[Finding]:
        findings = []
        # الملف المدوَّر أقدم، لذلك يُقرأ أولاً حتى يبقى التسلسل زمنياً.
        log_files = ["/var/log/auth.log.1", "/var/log/auth.log"]
        content = ""
        for lf in log_files:
            if self.sys.is_file(lf):
                content += self.sys.read_text(lf) + "\n"

        if not content.strip():
            ok, out, _ = self.sys.run_cmd(["journalctl", "-u", "ssh", "-n", "3000", "--no-pager"])
            if ok:
                content = out

        if not content.strip():
            return findings

        failed_by_ip = defaultdict(int)
        failed_by_user = defaultdict(set)
        successful_logins = set()
        ip_timeline = defaultdict(list)

        ip = r"((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]{2,})"
        fail_pattern = re.compile(rf"Failed password for (?:invalid user )?(\S+) from {ip}")
        succ_pattern = re.compile(rf"Accepted (?:password|publickey) for (\S+) from {ip}")

        for line in content.splitlines():
            # Bolt Optimization: Fast string pre-filter before running regex patterns
            # avoids executing costly regex evaluation on millions of non-matching log lines
            if "Failed password" in line:
                m_fail = fail_pattern.search(line)
                if m_fail:
                    user, address = m_fail.group(1), m_fail.group(2)
                    failed_by_ip[address] += 1
                    failed_by_user[user].add(address)
                    ip_timeline[address].append(('fail', user))
            elif "Accepted" in line:
                m_succ = succ_pattern.search(line)
                if m_succ:
                    user, address = m_succ.group(1), m_succ.group(2)
                    successful_logins.add(address)
                    ip_timeline[address].append(('success', user))

        for address, events in ip_timeline.items():
            fails_before_success = 0
            for ev_type, user in events:
                if ev_type == 'fail':
                    fails_before_success += 1
                elif ev_type == 'success' and fails_before_success >= 4:
                    findings.append(Finding(
                        severity="critical",
                        title=f"مؤشر اختراق: دخول SSH ناجح بعد {fails_before_success} محاولات فاشلة من {address}",
                        detail=f"نجاح بعد إخفاقات متكررة لحساب '{user}'. راجع الحساب والجلسات فوراً.",
                        fix=f"sudo ufw insert 1 deny from {address}\n# غيّر كلمة مرور الحساب '{user}' وراجع جلساته",
                        category="intrusion",
                        tags=["brute_force_success", "compromise_indicator", "ssh"],
                        attack_ids=["T1110.001", "T1078"],
                        effort="low",
                    ))
                    break

        ip_targeted_users = defaultdict(set)
        for address, events in ip_timeline.items():
            for ev_type, user in events:
                if ev_type == 'fail':
                    ip_targeted_users[address].add(user)

        for address, users in ip_targeted_users.items():
            if len(users) >= 5 and failed_by_ip[address] >= 10:
                findings.append(Finding(
                    severity="high",
                    title=f"هجوم Password Spraying نشط من العنوان: {address}",
                    detail=f"قام العنوان بتجربة كلمات مرور على {len(users)} حساباً مختلفاً ({', '.join(list(users)[:4])}...).",
                    fix=f"sudo ufw deny from {address}",
                    category="brute_force",
                    tags=["password_spraying", "ssh"],
                    attack_ids=["T1110.003"],
                ))

        return findings
