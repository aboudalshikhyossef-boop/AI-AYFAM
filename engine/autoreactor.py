"""
AI AYFAM v6 — Auto-Reactor & Rule Synthesizer
محرك الاستجابة التلقائية وتوليد القواعد — يحلل الهجمات المرصودة ويولد قواعد حماية
فورية لـ UFW و iptables و auditd لتصليب النظام ديناميكياً مع استثناء أجهزة البنية التحتية.
"""

import os
import re
import ipaddress
from typing import List, Dict, Any, Set
from utils import safe_exec
from engine.finding import Finding

class AutoReactor:
    @staticmethod
    def get_critical_infrastructure_ips() -> Set[str]:
        """استخراج العناوين الحساسة للشبكة (البوابة الافتراضية، خوادم DNS، الواجهات المحلية)."""
        critical_ips: Set[str] = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}

        # 1. Get default gateway IPs
        res_gw = safe_exec.run(["ip", "route", "show", "default"], check_binary=False)
        if res_gw.ok and res_gw.stdout:
            # e.g., "default via 192.168.1.1 dev eth0 ..."
            matches = re.findall(r"via\s+((?:\d{1,3}\.){3}\d{1,3})", res_gw.stdout)
            critical_ips.update(matches)

        # 2. Get DNS servers from /etc/resolv.conf
        if os.path.exists("/etc/resolv.conf"):
            try:
                with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2 and re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", parts[1]):
                                critical_ips.add(parts[1])
            except Exception:
                pass

        # 3. Get local interface IPs
        res_addr = safe_exec.run(["ip", "-4", "addr", "show"], check_binary=False)
        if res_addr.ok and res_addr.stdout:
            matches = re.findall(r"inet\s+((?:\d{1,3}\.){3}\d{1,3})", res_addr.stdout)
            critical_ips.update(matches)

        return critical_ips

    @classmethod
    def is_protected_ip(cls, ip_str: str, critical_ips: Set[str]) -> bool:
        """التحقق مما إذا كان العنوان يمثل جهاز بنية تحتية أو عنواناً خاصاً يحظر استهدافه."""
        if ip_str in critical_ips:
            return True

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
                return True
        except ValueError:
            return True

        return False

    @classmethod
    def synthesize_rules(cls, findings: List[Finding]) -> List[Dict[str, str]]:
        """توليد قواعد حماية جاهزة للتطبيق التلقائي بناءً على التهديدات المرصودة مع حماية البنية التحتية."""
        rules = []
        critical_ips = cls.get_critical_infrastructure_ips()

        for f in findings:
            tags = f.get("tags", [])
            title = f.get("title", "")
            detail = f.get("detail", "")

            # 1. هجمات القوة الغاشمة والتخمين -> قواعد حظر فورية
            if "brute_force" in tags or "brute_force_success" in tags or "password_spraying" in tags:
                ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", title + " " + detail)
                for ip in set(ips):
                    if not cls.is_protected_ip(ip, critical_ips):
                        rules.append({
                            "type": "FIREWALL_BLOCK",
                            "desc": f"حظر IP المهاجم {ip} في جدار الحماية",
                            "cmd": f"sudo ufw insert 1 deny from {ip}",
                        })

            # 2. خدمات غير محمية مكشوفة -> قواعد تقييد
            if "exposed_port" in tags or "exposed_service" in tags:
                ports = re.findall(r"منفذ\s+(\d+)", title)
                for port in ports:
                    rules.append({
                        "type": "PORT_RESTRICTION",
                        "desc": f"إغلاق المنفذ المكشوف {port} عن الخارج",
                        "cmd": f"sudo ufw deny {port}/tcp",
                    })

            # 3. ملفات امتيازات خطيرة -> إزالة SUID
            if "suid" in tags or "suid_anomaly" in tags:
                paths = re.findall(r"(/[\w\.-]+(?:/[\w\.-]+)+)", title + " " + detail)
                for p in paths:
                    if os.path.exists(p):
                        rules.append({
                            "type": "PRIVILEGE_STRIP",
                            "desc": f"إزالة صلاحية SUID من الملف {p}",
                            "cmd": f"sudo chmod u-s {p}",
                        })

        return rules
