"""
AI AYFAM v5 — Deep Network Intelligence
ذكاء شبكي عميق — كشف العمليات المشبوهة المتصلة بالخارج، ربط المنافذ المستمعة
بالعمليات، وفحص سلامة التوجيه وتسمم الـ ARP Spoofing.
"""

import re
from typing import List, Optional
from engine.finding import Finding
from engine.sysreader import SystemReader

class NetworkIntelligence:
    def __init__(self, sys_reader: Optional[SystemReader] = None):
        self.sys = sys_reader or SystemReader()

    def audit_all(self) -> List[Finding]:
        findings = []
        findings.extend(self.check_arp_spoofing())
        findings.extend(self.check_promiscuous_interfaces())
        findings.extend(self.check_suspicious_outbound_processes())
        findings.extend(self.check_wildcard_listeners())
        return findings

    def check_arp_spoofing(self) -> List[Finding]:
        """كشف تكرار عنوان MAC لبوابة الشبكة أو وجود هجوم ARP Poisoning."""
        findings = []
        arp_content = self.sys.read_text("/proc/net/arp")
        if not arp_content:
            return findings

        mac_to_ips = {}
        for line in arp_content.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ip, mac = parts[0], parts[3].lower()
                if mac not in ("00:00:00:00:00:00", "00-00-00-00-00-00"):
                    mac_to_ips.setdefault(mac, []).append(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                findings.append(Finding(
                    severity="critical",
                    title=f"🚨 رصد احتمال هجوم ARP Spoofing / تضارب MAC: {mac}",
                    detail=f"نفس عنوان العتاد MAC مرتبط بعدة عناوين IP: {', '.join(ips)}. قد يشير هذا إلى اعتراض نشط للبيانات (MITM).",
                    fix="تحقق من أجهزة الشبكة وفعّل ARP Inspection أو ثبّت عناوين ARP للبوابة: sudo arp -s <gateway_ip> <gateway_mac>",
                    category="network_mitm",
                    tags=["arp_spoof", "mitm", "network"],
                    attack_ids=["T1557.002"],
                ))
        return findings

    def check_promiscuous_interfaces(self) -> List[Finding]:
        """فحص ما إذا كانت إحدى واجهات الشبكة في وضع التجسس والالتقاط (Promiscuous)."""
        findings = []
        ok, out, _ = self.sys.run_cmd(["ip", "link"])
        if ok:
            for line in out.splitlines():
                if "PROMISC" in line:
                    m = re.search(r"^\d+: ([^:]+):", line)
                    iface = m.group(1) if m else "interface"
                    findings.append(Finding(
                        severity="high",
                        title=f"واجهة الشبكة {iface} في وضع التجسس (PROMISC)",
                        detail="الواجهة في وضع الالتقاط العام للحزم، مما يشير إلى وجود برنامج Sniffer يلتقط بيانات الشبكة.",
                        fix=f"sudo ip link set {iface} promisc off",
                        category="network_sniffing",
                        tags=["promisc", "sniffing"],
                        attack_ids=["T1040"],
                    ))
        return findings

    def check_suspicious_outbound_processes(self) -> List[Finding]:
        """كشف مفسرات الأوامر أو الأدوات التي تفتح اتصالات خارجية مباشرة (Reverse Shells)."""
        findings = []
        ok, out, _ = self.sys.run_cmd(["ss", "-tunap"])
        if not ok:
            return findings

        # مفسرات وأدوات يجب ألا تكون متصلة بالخارج كجلسة شيل
        suspicious_procs = ["bash", "sh", "python", "python3", "perl", "ruby", "nc", "netcat", "ncat"]
        for line in out.splitlines():
            if "ESTAB" in line:
                for sp in suspicious_procs:
                    if f'"{sp}"' in line or f"/{sp}" in line:
                        parts = line.split()
                        remote = parts[4] if len(parts) > 4 else "unknown"
                        # استبعاد الاتصالات المحلية
                        if not any(remote.startswith(x) for x in ("127.", "::1", "10.", "192.168.")):
                            findings.append(Finding(
                                severity="critical",
                                title=f"🚨 اتصال خارجي مريب من مفسر أوامر: {sp} ➔ {remote}",
                                detail=f"العملية '{sp}' تملك اتصالاً نشطاً مع خادم خارجي: {line[:120]}",
                                fix=f"افحص العملية فوراً وأوقفها: sudo pkill -9 {sp}",
                                category="reverse_shell",
                                tags=["reverse_shell", "c2", "intrusion"],
                                attack_ids=["T1059.004", "T1071"],
                            ))
                            break
        return findings

    def check_wildcard_listeners(self) -> List[Finding]:
        """كشف الخدمات الخطيرة المستمعة على جميع الواجهات (0.0.0.0)."""
        findings = []
        ok, out, _ = self.sys.run_cmd(["ss", "-tulpn"])
        if not ok:
            return findings

        risky_ports = {
            2375: "Docker Socket (بدون تشفير)",
            6379: "Redis Database",
            27017: "MongoDB Database",
            9200: "Elasticsearch",
        }

        for line in out.splitlines():
            if "LISTEN" in line and ("0.0.0.0:" in line or "*:" in line or ":::" in line):
                for port, name in risky_ports.items():
                    if f":{port}" in line:
                        findings.append(Finding(
                            severity="critical",
                            title=f"خدمة حساسة مكشوفة خارجياً: {name} (منفذ {port})",
                            detail=f"الخدمة تقبل الاتصال من أي شبكة خارجية: {line[:100]}",
                            fix=f"قيّد استماع الخدمة على 127.0.0.1 أو اغلق المنفذ: sudo ufw deny {port}",
                            category="exposed_service",
                            tags=["exposed_port", "database"],
                            attack_ids=["T1190"],
                        ))
        return findings
