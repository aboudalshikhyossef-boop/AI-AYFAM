"""
AI AYFAM — Advanced Time-Windowed Log Forensics Engine
محرك التحليل الزمني الجنائي المتقدم — فحص السجلات عبر النوافذ الزمنية، الكواشف المركبة، وتفويض system.py
"""

import time
from typing import List, Dict, Any, Optional
from engine.logsource import LogSourceReader, sanitize_log_text
from engine.rules_registry import create_finding
from engine.finding import Finding

class LogForensicsEngine:
    """محرك الفحص والتحليل الزمني الجنائي للسجلات."""

    def __init__(self, reader: Optional[LogSourceReader] = None):
        self.reader = reader or LogSourceReader()

    def analyze_auth_logs(self, window_minutes: int = 1440) -> List[Finding]:
        return self.analyze_all_logs(window_minutes=window_minutes)

    def analyze_all_logs(self, window_minutes: int = 1440) -> List[Finding]:
        findings = []
        now = time.time()
        window_start = now - (window_minutes * 60)

        # Read events
        events = []
        if hasattr(self.reader, "read_journal_json"):
            events = self.reader.read_journal_json(since=f"-{window_minutes}m")
        if not events and hasattr(self.reader, "read_file_logs"):
            events = self.reader.read_file_logs(limit=3000)
        if not events and hasattr(self.reader, "files"):
            for path, content in self.reader.files.items():
                if "auth" in path:
                    for line in content.splitlines():
                        msg = line.strip()
                        if msg:
                            from engine.logsource import parse_ip_address
                            events.append({
                                "timestamp": now,
                                "service": "auth",
                                "message": msg,
                                "raw": msg,
                                "ip": parse_ip_address(msg),
                                "source": path,
                            })

        if not events:
            findings.append(create_finding(
                "LOG-SSH-BRUTE",
                severity="medium",
                title_ar="تعذّر قراءة سجلات المصادقة أو أن السجلات فارغة",
                detail="لم يُعثر على سجلات جديدة ضمن النافذة الزمنية المحددة.",
                fix="sudo usermod -aG adm,systemd-journal $USER",
                stable_key="no_log_access",
            ))
            return findings

        # Filter events by window
        recent_events = [e for e in events if e["timestamp"] >= window_start]
        if not recent_events:
            recent_events = events  # Fallback if timestamps vary

        # Detector 1: SSH Brute Force & Password Spraying
        ssh_failed_ips: Dict[str, int] = {}
        ssh_success_root = 0
        sudo_failures = 0
        user_changes = []

        for ev in recent_events:
            msg = ev["message"]
            ip = ev["ip"]

            if "Failed password" in msg or "authentication failure" in msg:
                if ip:
                    ssh_failed_ips[ip] = ssh_failed_ips.get(ip, 0) + 1

            if "Accepted" in msg and "for root" in msg:
                ssh_success_root += 1

            if "sudo:" in msg and ("authentication failure" in msg or "incorrect password" in msg):
                sudo_failures += 1

            if "new user:" in msg or "useradd" in msg or "usermod" in msg:
                user_changes.append(msg)

        # Emit findings based on time-windowed aggregates
        for ip, count in ssh_failed_ips.items():
            if count >= 4:
                sev = "critical" if count >= 20 or ssh_success_root > 0 else "high"
                findings.append(create_finding(
                    "LOG-SSH-BRUTE",
                    severity=sev,
                    title_ar=f"هجوم تخمين كلمة المرور SSH مؤكد من {ip} ({count} محاولة)",
                    title_en=f"Confirmed SSH brute force attempt from {ip} ({count} attempts)",
                    detail=f"رُصدت {count} محاولة دخول فاشلة من العنوان {ip} خلال النافذة الزمنية.",
                    fix=f"sudo ufw deny from {ip}\nsudo fail2ban-client set sshd banip {ip}",
                    evidence={"ip": ip, "count": count},
                    stable_key=f"brute:{ip}",
                ))

        if ssh_success_root > 0:
            findings.append(create_finding(
                "SSH-ROOT-001",
                severity="critical",
                title_ar=f"دخول root ناجح عبر SSH خلال النافذة الزمنية ({ssh_success_root} مرة)",
                title_en=f"Successful root login via SSH in window ({ssh_success_root} times)",
                detail="رُصد تسجيل دخول كـ root عبر SSH. يُوصى بتعطيل دخول root المباشر.",
                fix="PermitRootLogin no\nsudo systemctl restart ssh",
                stable_key="root_ssh_login_window",
            ))

        if sudo_failures >= 3:
            findings.append(create_finding(
                "LOG-SUDO-FAIL",
                severity="medium",
                title_ar=f"إخفاقات متكررة في كلمة مرور sudo ({sudo_failures} محاولة)",
                title_en=f"Repeated sudo password failures ({sudo_failures} attempts)",
                detail="رُصدت محاولات رفع صلاحيات فاشلة باستخدام sudo.",
                fix="sudo journalctl -u sudo -n 30",
                stable_key="sudo_failures_window",
            ))

        for change in user_changes[:3]:
            findings.append(create_finding(
                "SYS-USER-SHELL",
                severity="medium",
                title_ar="تغيير أو إضافة مستخدم جديد في سجلات النظام",
                title_en="User account modification or creation detected in logs",
                detail=f"السطر: {change}",
                fix="تأكد من إنشاء الحساب بنفسك وإلا قم بحذفه فوراً.",
                stable_key=f"user_change:{change[:30]}",
            ))

        if not findings:
            findings.append(create_finding(
                "LOG-SSH-BRUTE",
                severity="info",
                title_ar="لا توجد أنشطة مشبوهة في السجلات المقروءة",
                title_en="No suspicious activity detected in read logs",
                detail=f"تم تحليل {len(recent_events)} سجل بنجاح.",
                fix="أعد الفحص دورياً.",
                stable_key="clean_logs_v2",
            ))

        return findings
