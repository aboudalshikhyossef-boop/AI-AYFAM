"""
AI AYFAM - Smart Network Scanner
فحص شبكي ذكي — يميّز بين الاتصالات الموثوقة وغير الموثوقة
"""

import subprocess
import socket
import json
import re
import ipaddress
from datetime import datetime
from typing import Optional

from utils import safe_exec, validators
from tools import port_catalog
from engine.rules_registry import create_finding


def _run(cmd, timeout=30):
    """⚠️ لأوامر shell ثابتة (بدون أي جزء متغيّر من مستخدم/USB/شبكة) فقط.
    أي قيمة متغيّرة (target, ip, ...) يجب أن تمر عبر safe_exec.run() بقائمة
    وسائط — راجع scan_ports() أدناه كمثال."""
    res = safe_exec.run_trusted_shell(cmd, timeout=timeout)
    return res.stdout, res.stderr


# ─────────────────────────────────────────────────────────────────────────────
#  TRUST ENGINE — القلب الذكي للتمييز بين الموثوق وغير الموثوق
# ─────────────────────────────────────────────────────────────────────────────

TRUSTED_PROCESSES = {
    # متصفحات / Browsers
    "firefox", "firefox-bin", "firefox-esr",
    "chromium", "chromium-browser", "google-chrome", "brave", "brave-browser",
    "opera", "vivaldi", "epiphany", "midori",
    # نظام / System
    "systemd", "systemd-resolve", "systemd-network", "NetworkManager",
    "avahi-daemon", "cups", "dbus-daemon", "polkitd",
    "sshd", "rsyslog", "cron", "snapd", "packagekitd",
    "apt", "apt-get", "dpkg", "snap",
    # شبكة / Network tools (legitimate)
    "nm-applet", "dhclient", "dhcpcd", "wpa_supplicant",
    "ntpd", "chronyd", "resolved",
    # أدوات / Dev tools (trusted)
    "python3", "node", "npm", "curl", "wget",
    "git", "ssh", "scp",
    # ترفيه / Media
    "spotify", "vlc", "rhythmbox", "totem",
    "thunderbird", "evolution", "geary",
    "slack", "telegram-desktop", "discord",
    # Replit / Dev env
    "node", "tsx", "ts-node",
}

TRUSTED_PORTS_OUTBOUND = {
    80,    # HTTP
    443,   # HTTPS
    53,    # DNS
    123,   # NTP
    143,   # IMAP
    993,   # IMAPS
    587,   # SMTP submission
    465,   # SMTPS
    22,    # SSH (outbound)
    5353,  # mDNS
    67, 68,  # DHCP
    8080, 8443,  # Alt HTTP/HTTPS
    1194,  # OpenVPN
    51820, # WireGuard
}

SUSPICIOUS_PORTS = {
    4444, 4445, 1337, 31337, 12345, 9001, 9002,
    6666, 6667, 6668, 1080, 3128, 8888,
    2323, 5555, 5554,  # ADB exposed
    23,    # Telnet
    135, 139, 445,  # Windows SMB (suspicious on Linux)
    1433, 3306, 5432,  # DB ports exposed externally
    5900, 5901,  # VNC externally
    3389,  # RDP externally
    6379,  # Redis exposed
    27017, 27018,  # MongoDB exposed
    9200, 9300,  # Elasticsearch exposed
}

def _is_local_ip(ip: str) -> bool:
    """Return whether an endpoint is loopback, private, link-local, or unspecified."""
    candidate = (ip or "").strip().strip("[]").split("%", 1)[0]
    if not candidate or candidate == "*":
        return False
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
    )


def _extract_process_name(process_str: str) -> str:
    """Extract clean process name from ss/netstat output like users:(("firefox",pid=123))"""
    m = re.search(r'"([^"]+)"', process_str)
    if m:
        name = m.group(1).split("/")[-1]
        return name.lower()
    return process_str.split()[0].lower() if process_str.split() else ""


def _classify_connection(proto, local, remote, state, process_str) -> dict:
    """
    Smart connection classifier.
    Returns: { trust: trusted|suspicious|critical, reason: str, risk: low|medium|high|critical }
    """
    proc_name = _extract_process_name(process_str)
    remote_clean = remote.strip() if remote else ""

    # Wildcard peers are listeners, not proof of a trusted/local service.
    if not remote_clean or remote_clean in ("*:*", "0.0.0.0:*", ":::*", "[::]:*"):
        return {"trust": "unknown", "risk": "info", "reason": "مقبس استماع؛ يجب تقييم عنوان الربط في فحص الخدمات"}

    proc_name = proc_name.lower()

    # Extract remote IP and port
    remote_ip = ""
    remote_port = 0
    if remote_clean:
        parts = remote_clean.rsplit(":", 1)
        if len(parts) == 2:
            remote_ip = parts[0].strip("[]")
            try:
                remote_port = int(parts[1])
            except ValueError:
                pass

    # Local connections are always safe
    if _is_local_ip(remote_ip):
        return {"trust": "trusted", "risk": "low", "reason": "اتصال محلي / Local connection"}

    # Known trusted process connecting outbound on standard ports
    if proc_name in TRUSTED_PROCESSES:
        if remote_port in TRUSTED_PORTS_OUTBOUND or remote_port == 0:
            return {
                "trust": "trusted",
                "risk": "low",
                "reason": f"برنامج موثوق ({proc_name}) على منفذ قياسي ({remote_port})"
            }
        # A familiar process name is not sufficient to trust an unusual port.
        if remote_port not in SUSPICIOUS_PORTS:
            return {
                "trust": "unknown",
                "risk": "medium",
                "reason": f"عملية معروفة الاسم ({proc_name}) تستخدم منفذاً غير معتاد ({remote_port})؛ يلزم التحقق"
            }

    # Suspicious port — regardless of process
    if remote_port in SUSPICIOUS_PORTS:
        return {
            "trust": "suspicious",
            "risk": "critical",
            "reason": f"منفذ خطير معروف {remote_port} ({proc_name or 'unknown process'})"
        }

    # Unknown process connecting to external host
    if proc_name and proc_name not in TRUSTED_PROCESSES:
        if remote_port not in TRUSTED_PORTS_OUTBOUND:
            return {
                "trust": "suspicious",
                "risk": "high",
                "reason": f"عملية غير معروفة ({proc_name}) تتصل خارجياً على منفذ {remote_port}"
            }
        # Unknown process on standard port (HTTPS/HTTP) — medium
        return {
            "trust": "unknown",
            "risk": "medium",
            "reason": f"عملية غير مُصنَّفة ({proc_name}) — منفذ {remote_port}"
        }

    # External connection, standard port, no process name
    if remote_port in TRUSTED_PORTS_OUTBOUND:
        return {
            "trust": "trusted",
            "risk": "low",
            "reason": f"اتصال خارجي على منفذ قياسي {remote_port}"
        }

    return {
        "trust": "unknown",
        "risk": "medium",
        "reason": f"اتصال خارجي غير مُصنَّف — منفذ {remote_port}"
    }


# ─────────────────────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_network_interfaces():
    interfaces = []
    out, _ = _run("ip -j addr show 2>/dev/null")
    try:
        data = json.loads(out)
        for iface in data:
            name = iface.get("ifname", "")
            state = iface.get("operstate", "UNKNOWN")
            addrs = [f"{a.get('local','')}/{a.get('prefixlen','')}" for a in iface.get("addr_info", [])]
            interfaces.append({"name": name, "state": state, "addresses": addrs})
    except Exception:
        out2, _ = _run("ip addr show 2>/dev/null")
        for line in out2.split("\n"):
            m = re.match(r"\d+: (\S+):.*state (\S+)", line)
            if m:
                interfaces.append({"name": m.group(1), "state": m.group(2), "addresses": []})
            m2 = re.search(r"inet6? (\S+)", line)
            if m2 and interfaces:
                interfaces[-1]["addresses"].append(m2.group(1))
    return interfaces


def get_active_connections():
    """Get connections with smart trust classification."""
    connections = []
    out, _ = _run("ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null")

    for line in out.split("\n")[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            proto = parts[0]
            local  = parts[4] if len(parts) > 4 else ""
            remote = parts[5] if len(parts) > 5 else ""
            state  = parts[1] if proto.startswith("tcp") else "stateless"
            process = " ".join(parts[6:]) if len(parts) > 6 else ""

            classification = _classify_connection(proto, local, remote, state, process)
            proc_name = _extract_process_name(process)

            connections.append({
                "proto": proto,
                "local": local,
                "remote": remote,
                "state": state,
                "process": proc_name or process[:30],
                "trust": classification["trust"],
                "risk": classification["risk"],
                "reason": classification["reason"],
            })
        except Exception:
            continue
    return connections


def check_data_leaks():
    """Check for real data leaks — only flag genuinely suspicious connections."""
    findings = []
    connections = get_active_connections()

    for conn in connections:
        if conn["trust"] == "suspicious" or conn["risk"] in ("critical", "high"):
            sev = "critical" if conn["risk"] == "critical" else "high"
            findings.append(create_finding(
                "NET-PORT-001",
                severity=sev,
                title_ar=f"اتصال مشبوه حقيقي: {conn['remote']} — {conn['process']}",
                detail=f"السبب: {conn['reason']}\nالبروتوكول: {conn['proto']} | الحالة: {conn['state']}",
                fix=f"اقطع الاتصال: sudo ss -K dst {conn['remote'].split(':')[0]}\nأو أوقف العملية: sudo pkill -9 {conn['process']}",
                evidence={"remote": conn["remote"], "process": conn["process"]},
                stable_key=f"{conn['remote']}:{conn['process']}",
            ))
        elif conn["trust"] == "unknown" and conn["risk"] == "medium":
            findings.append(create_finding(
                "NET-PORT-001",
                severity="medium",
                title_ar=f"اتصال يحتاج مراجعة: {conn['remote']} ({conn['process']})",
                detail=conn["reason"],
                fix=f"تحقق من العملية: sudo lsof -i -p $(pgrep {conn['process']})",
                evidence={"remote": conn["remote"], "process": conn["process"]},
                stable_key=f"{conn['remote']}:{conn['process']}",
            ))

    # Check for services listening on all interfaces
    out, _ = _run("ss -tlnp 2>/dev/null")
    for line in out.split("\n")[1:]:
        if "0.0.0.0:" in line or ":::" in line:
            parts = line.split()
            if len(parts) > 3:
                addr = parts[3]
                if addr.startswith("0.0.0.0:") or addr.startswith("*:") or addr.startswith(":::"):
                    try:
                        port = int(addr.rsplit(":", 1)[-1])
                        process = parts[-1] if len(parts) > 4 else ""
                        proc = _extract_process_name(process)
                        # A wildcard bind is an exposure regardless of process name or port.
                        severity = "critical" if port in SUSPICIOUS_PORTS else "medium"
                        findings.append(create_finding(
                            "NET-PORT-001",
                            severity=severity,
                            title_ar=f"خدمة تستمع على جميع واجهات الشبكة: منفذ {port} ({proc or 'عملية غير معروفة'})",
                            detail="الخدمة مرتبطة بعنوان wildcard ويمكن الوصول إليها عبر واجهات الشبكة؛ اسم العملية أو شيوع المنفذ لا يثبتان أنها آمنة.",
                            fix="تحقق من ضرورة التعريض الخارجي، وقيّد عنوان الاستماع إلى localhost أو استخدم قواعد جدار حماية مناسبة.",
                            evidence={"port": port, "process": proc, "bind": addr},
                            stable_key=f"wildcard:{port}:{proc}",
                        ))
                    except Exception:
                        pass

    # DNS check — only flag truly unknown DNS servers
    dns_out, _ = _run("cat /etc/resolv.conf 2>/dev/null")
    known_dns = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
                 "208.67.222.222", "208.67.220.220", "127.0.0.53", "127.0.1.1", "::1"}
    for line in dns_out.split("\n"):
        if line.startswith("nameserver"):
            ip = line.split()[-1] if len(line.split()) > 1 else ""
            if ip and ip not in known_dns and not ip.startswith("192.168.") and not ip.startswith("10."):
                findings.append(create_finding(
                    "NET-PORT-001",
                    severity="medium",
                    title_ar=f"خادم DNS غير معروف: {ip}",
                    detail="خادم DNS قد يتسبب في تسريب استعلامات DNS أو إعادة توجيه.",
                    fix="غيّر DNS إلى 1.1.1.1 في /etc/resolv.conf أو Network Manager",
                    evidence={"ip": ip},
                    stable_key=ip,
                ))

    return {"connections": connections, "findings": findings}


def check_firewall():
    result = {"enabled": False, "policy": {}, "rules": [], "findings": []}
    out, _ = _run("sudo ufw status verbose 2>/dev/null || ufw status 2>/dev/null")
    if "Status: active" in out:
        result["enabled"] = True
        result["rules"] = [l for l in out.split("\n") if l.strip() and "Status" not in l]
    else:
        result["findings"].append(create_finding(
            "FIREWALL-001",
            severity="high",
            title_ar="جدار الحماية UFW معطَّل / UFW Firewall is disabled",
            detail="لا يوجد جدار حماية نشط يحمي نظامك.",
            fix="sudo ufw enable\nsudo ufw default deny incoming\nsudo ufw default allow outgoing\nsudo ufw allow 22/tcp",
            stable_key="ufw_disabled",
        ))
    return result


def ping_host(target: str, count: int = 4) -> dict:
    """اختبار اتصال آمن — نفس معيار التحقق المُطبَّق في scan_ports تماماً:
    الهدف يجب أن يكون IP أو hostname صالحاً، والتنفيذ بدون shell إطلاقاً."""
    result = {"target": target, "reachable": False, "output": "", "error": None}
    ok_target, target_or_err = validators.validate_scan_target(target)
    if not ok_target:
        result["error"] = target_or_err
        return result
    target = target_or_err

    try:
        count = max(1, min(int(count), 10))  # حماية من قيمة عدد حزم غير معقولة
    except (TypeError, ValueError):
        count = 4

    res = safe_exec.run(["ping", "-c", str(count), "-W", "2", target], timeout=count * 3 + 5)
    result["output"] = res.stdout or res.stderr
    result["reachable"] = res.ok and "0% packet loss" in res.stdout
    return result


def scan_ports(target: str, port_range: str = "1-1024") -> dict:
    result = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "open_ports": [],
        "tool_used": "-",
        "findings": [],
        "error": None,
    }

    # ── التحقق الإلزامي — نقطة العبور الوحيدة قبل أي تنفيذ ─────────────────
    ok_target, target_or_err = validators.validate_scan_target(target)
    if not ok_target:
        result["error"] = target_or_err
        result["findings"].append({
            "severity": "info", "title": f"🚫 رُفض الفحص: {target_or_err}",
            "detail": "تم رفض الهدف قبل الوصول لأي أمر نظام — حماية من حقن الأوامر.",
            "fix": "أدخل عنوان IP صالح (مثال: 192.168.1.1) أو اسم مضيف صالح فقط.",
        })
        return result
    target = target_or_err

    ok_range, range_or_err = validators.validate_port_range(port_range)
    if not ok_range:
        result["error"] = range_or_err
        result["findings"].append({
            "severity": "info", "title": f"🚫 رُفض الفحص: {range_or_err}",
            "detail": "", "fix": "استخدم نطاقاً مثل 1-1024",
        })
        return result
    port_range = range_or_err

    ports_found = []      # (port, proto, service_hint, banner)
    notes = []
    nmap_check = safe_exec.run(["nmap", "--version"], timeout=5, check_binary=True)
    if nmap_check.ok:
        result["tool_used"] = "nmap"
        # بدون shell إطلاقاً — كل وسيطة عنصر منفصل، لا يوجد أي احتمال لحقن
        nmap_res = safe_exec.run(["nmap", "-sV", "--open", f"-p{port_range}", target], timeout=180)
        for line in nmap_res.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "open" and "/" in parts[0]:
                try:
                    ports_found.append((int(parts[0].split("/")[0]), parts[0].split("/")[1], " ".join(parts[2:]), ""))
                except ValueError:
                    continue
    else:
        result["tool_used"] = "python-socket"
        import concurrent.futures
        start, end = map(int, port_range.split("-")) if "-" in port_range else (int(port_range), int(port_range))
        limit = 5000
        if end - start + 1 > limit:
            notes.append(f"النطاق {start}-{end} أكبر من حد الفاحص المدمج؛ فُحصت المنافذ {start}-{start + limit - 1} فقط. ثبّت nmap لفحص كامل: sudo apt install nmap")
            end = start + limit - 1
        local = _is_local_ip(target) or target in ("localhost",)
        timeout = 0.35 if local else 0.8

        def check(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    if sock.connect_ex((target, port)) != 0:
                        return None
                    return port, _grab_banner(sock, port)
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
            for hit in ex.map(check, range(start, end + 1)):
                if hit:
                    ports_found.append((hit[0], "tcp", "", hit[1]))

    bindings = _local_bindings() if (_is_local_ip(target) or target == "localhost") else {}
    for port, proto, hint, banner in sorted(ports_found):
        info = port_catalog.describe(port, hint.split()[0] if hint else "")
        service = info["service"] if info["known"] or not hint else hint
        risk = info["risk"]
        exposure = ""
        addrs = bindings.get(port)
        if addrs:
            if all(a.startswith("127.") or a in ("::1", "localhost") for a in addrs):
                risk, exposure = "info", "مربوط بالحلقة المحلية فقط (127.0.0.1) فلا يُرى من الشبكة."
            else:
                exposure = "يستمع على جميع الواجهات فيراه كل من في شبكتك."
        entry = {"port": f"{port}/{proto}", "state": "open", "service": service, "risk": risk, "banner": banner, "why": info["why"], "exposure": exposure}
        result["open_ports"].append(entry)
        detail = [f"الخدمة: {service}" + (f" | الشعار: {banner}" if banner else ""), info["why"]]
        if exposure:
            detail.append(exposure)
        result["findings"].append(create_finding(
            "NET-PORT-001",
            severity=risk,
            title_ar=f"منفذ مفتوح: {service} ({port}/{proto})",
            detail="\n".join(detail),
            fix=info["fix"] if risk != "info" else "لا إجراء: الخدمة محلية فقط.",
            evidence={"target": target, "port": port, "banner": banner or None, "bindings": sorted(addrs) if addrs else None},
            stable_key=f"{target}:{port}",
        ))
    for note in notes:
        result["findings"].append(create_finding(
            "NET-PORT-001",
            severity="info",
            title_ar="فحص جزئي: النطاق مقتطع",
            detail=note,
            fix="sudo apt install nmap",
            stable_key="partial_scan_note",
        ))
    if not ports_found:
        result["findings"].append(create_finding(
            "NET-PORT-001",
            severity="info",
            title_ar=f"لا منافذ مفتوحة في النطاق {port_range}",
            detail="لم يستجب أي منفذ في النطاق المفحوص. الجدار قد يُخفي المنافذ (filtered) بدل أن يُغلقها.",
            fix="لا إجراء. يمكن توسيع النطاق أو استخدام nmap للتأكد.",
            stable_key=f"no_ports:{port_range}",
        ))

    result["open_ports"].sort(key=lambda x: int(str(x["port"]).split("/")[0]))
    return result


_BANNER_PROBES = {80: b"HEAD / HTTP/1.0\r\n\r\n", 8080: b"HEAD / HTTP/1.0\r\n\r\n", 8000: b"HEAD / HTTP/1.0\r\n\r\n", 8888: b"HEAD / HTTP/1.0\r\n\r\n"}


def _grab_banner(sock, port) -> str:
    """شعار الخدمة (إن وُجد) بحدّ أقصى 80 حرفاً؛ لا يرسل شيئاً سوى HEAD للمنافذ الويب."""
    try:
        sock.settimeout(0.6)
        probe = _BANNER_PROBES.get(port)
        if probe:
            sock.sendall(probe)
        data = sock.recv(160)
    except Exception:
        return ""
    text = data.decode("latin-1", "ignore")
    for line in text.splitlines():
        line = "".join(ch for ch in line if 32 <= ord(ch) < 127).strip()
        if line.lower().startswith("server:"):
            return line[7:].strip()[:80]
        if line:
            first = line
            break
    else:
        return ""
    return first[:80]


def _local_bindings() -> dict:
    """منفذ ← العناوين التي يستمع عليها (من ss) لمعرفة هل الخدمة محلية فقط أم مكشوفة."""
    out = {}
    try:
        res = safe_exec.run(["ss", "-H", "-ltn"], timeout=5)
        for line in res.stdout.splitlines():
            cols = line.split()
            if len(cols) < 4:
                continue
            addr, _, port = cols[3].rpartition(":")
            if port.isdigit():
                out.setdefault(int(port), set()).add(addr.strip("[]") or "*")
    except Exception:
        return {}
    return out


def get_wifi_networks():
    out, _ = _run("nmcli -t -f SSID,BSSID,SIGNAL,SECURITY,IN-USE dev wifi list 2>/dev/null")
    networks = []
    for line in out.split("\n"):
        if not line.strip():
            continue
        parts = line.split(":")
        if len(parts) >= 4:
            ssid = parts[0]
            security = parts[-2] if len(parts) >= 3 else ""
            in_use = parts[-1] if parts else ""
            risk = "high" if security in ("--", "", "OPEN") else "low"
            networks.append({"ssid": ssid, "security": security, "in_use": in_use == "*", "risk": risk})
    return networks
