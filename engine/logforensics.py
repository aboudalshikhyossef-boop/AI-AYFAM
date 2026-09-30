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
        log_files = ["/var/log/auth.log", "/var/log/auth.log.1"]
        content = ""
        for lf in log_files:
            if self.sys.is_file(lf):
                content += self.sys.read_text(lf) + "\n"

        if not content.strip():
            # إذا تعذر قراءة الملفات مباشرة، جرب سحبها عبر journalctl
            ok, out, _ = self.sys.run_cmd(["journalctl", "-u", "ssh", "-n", "3000", "--no-pager"])
            if ok:
                content = out

        if not content.strip():
            return findings

        # 1. تتبع المحاولات الفاشلة لكل IP ولكل مستخدم
        failed_by_ip = defaultdict(int)
        failed_by_user = defaultdict(set) # user -> set of IPs
        successful_logins = set()          # IPs that succeeded
        ip_timeline = defaultdict(list)    # ip -> list of ('fail'/'success', user)

        fail_pattern = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
        succ_pattern = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)")

        for line in content.splitlines():
            m_fail = fail_pattern.search(line)
            if m_fail:
                user, ip = m_fail.group(1), m_fail.group(2)
                failed_by_ip[ip] += 1
                failed_by_user[user].add(ip)
                ip_timeline[ip].append(('fail', user))

            m_succ = succ_pattern.search(line)
            if m_succ:
                user, ip = m_succ.group(1), m_succ.group(2)
                successful_logins.add(ip)
                ip_timeline[ip].append(('success', user))

        # 2. مؤشر الاختراق الحرج: نجاح تسجيل الدخول بعد إخفاقات متعددة من نفس الـ IP
        for ip, events in ip_timeline.items():
            fails_before_success = 0
            for ev_type, user in events:
                if ev_type == 'fail':
                    fails_before_success += 1
                elif ev_type == 'success' and fails_before_success >= 4:
                    findings.append(Finding(
                        severity="critical",
                        title=f"🚨 مؤشر اختراق مؤكد: دخول SSH ناجح بعد {fails_before_success} محاولات فاشلة من {ip}",
                        detail=f"المهاجم استمر في التخمين حتى نجح في الدخول بحساب '{user}'. هذا نمط اختراق مؤكد يتطلب تدخلاً فورياً!",
                        fix=f"sudo ufw insert 1 deny from {ip}\n# غيّر كلمة مرور الحساب '{user}' فوراً وافصل جلساته: sudo pkill -u {user}",
                        category="intrusion",
                        tags=["brute_force_success", "compromise_indicator", "ssh"],
                        attack_ids=["T1110.001", "T1078"],
                        effort="low",
                    ))
                    break

        # 3. كشف هجمات Password Spraying (عنوان IP واحد يجرب عدداً كبيراً من المستخدمين المختلفين)
        ip_targeted_users = defaultdict(set)
        for ip, events in ip_timeline.items():
            for ev_type, user in events:
                if ev_type == 'fail':
                    ip_targeted_users[ip].add(user)

        for ip, users in ip_targeted_users.items():
            if len(users) >= 5 and failed_by_ip[ip] >= 10:
                findings.append(Finding(
                    severity="high",
                    title=f"هجوم Password Spraying نشط من العنوان: {ip}",
                    detail=f"قام الـ IP بتجربة كلمات مرور على {len(users)} حساباً مختلفاً ({', '.join(list(users)[:4])}...).",
                    fix=f"sudo ufw deny from {ip}",
                    category="brute_force",
                    tags=["password_spraying", "ssh"],
                    attack_ids=["T1110.003"],
                ))

        return findings
