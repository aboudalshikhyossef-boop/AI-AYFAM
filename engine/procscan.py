"""
AI AYFAM — Deep Process & Network Scanner
محرك فحص العمليات والشبكة بمسار الملف والتثبت من الحزمة التابعة لها
"""

import os
import glob
import re
import hashlib
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from engine.rules_registry import create_finding
from engine.finding import Finding

SYSTEM_DIRS = (
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
    "/usr/lib/", "/lib/", "/lib64/", "/snap/", "/opt/",
)

SUSPICIOUS_PATHS = (
    "/tmp/", "/dev/shm/", "/var/tmp/", "/home/", "/run/shm/",
)

class PackageIndex:
    """فهرس الحزم المسبق البناء عبر قراءة /var/lib/dpkg/info/*.list مرة واحدة."""

    def __init__(self, dpkg_info_dir: str = "/var/lib/dpkg/info"):
        self.path_to_pkg: Dict[str, str] = {}
        self.hash_cache: Dict[Tuple[int, int, float], str] = {}
        self._build_index(dpkg_info_dir)

    def _build_index(self, dpkg_info_dir: str):
        if not os.path.exists(dpkg_info_dir):
            return

        try:
            for list_file in glob.glob(os.path.join(dpkg_info_dir, "*.list")):
                pkg_name = os.path.basename(list_file).removesuffix(".list").split(":")[0]
                try:
                    with open(list_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            p = line.strip()
                            if p and p.startswith("/"):
                                self.path_to_pkg[p] = pkg_name
                except Exception:
                    pass
        except Exception as e:
            logging.debug(f"Error building package index: {e}")

    def get_owning_package(self, path: str) -> Optional[str]:
        real_p = os.path.realpath(path)
        return self.path_to_pkg.get(real_p) or self.path_to_pkg.get(path)

    def get_file_sha256(self, path: str) -> Optional[str]:
        try:
            st = os.stat(path)
            cache_key = (st.st_dev, st.st_ino, st.st_mtime)
            if cache_key in self.hash_cache:
                return self.hash_cache[cache_key]

            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            digest = h.hexdigest()
            self.hash_cache[cache_key] = digest
            return digest
        except Exception:
            return None


class ProcessNetworkScanner:
    """محرك الفحص الشامل لجميع العمليات في /proc والربط بالمميزات الأمنية."""

    def __init__(self, proc_dir: str = "/proc", pkg_index: Optional[PackageIndex] = None):
        self.proc_dir = proc_dir
        self.pkg_index = pkg_index or PackageIndex()

    def _parse_net_sockets(self) -> Dict[str, Tuple[str, str, int]]:
        """قراءة /proc/net/{tcp,tcp6,udp,udp6} لربط inode بالـ ip والـ port."""
        inode_map: Dict[str, Tuple[str, str, int]] = {}
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            net_path = os.path.join(self.proc_dir, "net", proto)
            if not os.path.exists(net_path):
                continue
            try:
                with open(net_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()[1:]
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 10:
                            local_addr = parts[1]
                            state = parts[3]
                            inode = parts[9]

                            # Decode port
                            try:
                                port = int(local_addr.rsplit(":", 1)[1], 16)
                                ip_hex = local_addr.rsplit(":", 1)[0]
                                inode_map[inode] = (proto, ip_hex, port)
                            except Exception:
                                pass
            except Exception:
                pass
        return inode_map

    def scan_all_processes(self) -> List[Finding]:
        findings = []
        if not os.path.exists(self.proc_dir):
            return findings

        net_inodes = self._parse_net_sockets()

        try:
            entries = os.listdir(self.proc_dir)
        except Exception:
            return findings

        for entry in entries:
            if not entry.isdigit():
                continue

            pid = entry
            pid_dir = os.path.join(self.proc_dir, pid)

            try:
                # 1. Read exe realpath
                exe_link = os.path.join(pid_dir, "exe")
                exe_target = ""
                try:
                    exe_target = os.readlink(exe_link)
                except OSError:
                    continue

                # 2. Read cmdline
                cmdline = ""
                cmdline_path = os.path.join(pid_dir, "cmdline")
                if os.path.exists(cmdline_path):
                    try:
                        with open(cmdline_path, "rb") as f:
                            cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", "ignore").strip()
                    except Exception:
                        pass

                # 3. Read status (UID, EUID, Parent PID, CapEff)
                status_path = os.path.join(pid_dir, "status")
                uid, euid, ppid, capeff = 0, 0, 0, ""
                proc_name = ""
                if os.path.exists(status_path):
                    try:
                        with open(status_path, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                if line.startswith("Name:"):
                                    proc_name = line.split(":", 1)[1].strip()
                                elif line.startswith("PPid:"):
                                    ppid = int(line.split(":", 1)[1].strip())
                                elif line.startswith("Uid:"):
                                    u_parts = line.split(":", 1)[1].split()
                                    if len(u_parts) >= 2:
                                        uid, euid = int(u_parts[0]), int(u_parts[1])
                                elif line.startswith("CapEff:"):
                                    capeff = line.split(":", 1)[1].strip()
                    except Exception:
                        pass

                # Check 1: Execution from memfd or deleted binary
                if "memfd:" in exe_target or " (deleted)" in exe_target:
                    clean_exe = exe_target.replace(" (deleted)", "")
                    # Ignore benign deleted binaries due to system updates (e.g. in /usr/bin, /usr/lib, /snap)
                    is_system_update = " (deleted)" in exe_target and any(clean_exe.startswith(sd) for sd in SYSTEM_DIRS)
                    if not is_system_update:
                        findings.append(create_finding(
                            rule_id="NET-SUSP-PROC",
                            severity="critical" if "memfd:" in exe_target else "high",
                            title_ar=f"عملية تعمل من ملف محذوف أو الذاكرة المباشرة memfd (PID:{pid})",
                            title_en=f"Process executing from deleted binary or memfd (PID:{pid})",
                            detail=f"العملية {proc_name} (PID:{pid}) تنفذ من {exe_target}.\nCMD: {cmdline[:150]}",
                            fix=f"sudo kill -9 {pid}",
                            evidence={"pid": pid, "exe": exe_target, "cmdline": cmdline},
                            stable_key=f"{proc_name}:{clean_exe}",
                        ))

                # Check 2: Execution from temporary / suspicious directory
                real_exe = exe_target.replace(" (deleted)", "")
                if any(real_exe.startswith(sp) for sp in SUSPICIOUS_PATHS):
                    # Exclude legitimate user application paths like flatpak, snap, appimages, or virtualenvs
                    is_legit_app = any(sub in real_exe for sub in (
                        "/.local/share/flatpak/", "/.local/bin/", "/.venv/", "/venv/", "/.cargo/bin/",
                        "/.cdda/", "/.steam/", "/.appimage"
                    )) or real_exe.endswith(".AppImage")

                    pkg = self.pkg_index.get_owning_package(real_exe)
                    if not pkg and not is_legit_app:  # Not owned by official package nor legitimate user app dir
                        findings.append(create_finding(
                            rule_id="NET-SUSP-PROC",
                            severity="critical" if any(real_exe.startswith(p) for p in ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/")) else "medium",
                            title_ar=f"عملية غير موثوقة تعمل من مجلد مؤقت: {real_exe} (PID:{pid})",
                            title_en=f"Untrusted process running from temp dir: {real_exe} (PID:{pid})",
                            detail=f"العملية {proc_name} تنفذ من {real_exe} ولا تتبع لأي حزمة نظام رسمية.\nCMD: {cmdline[:150]}",
                            fix=f"sudo kill -9 {pid}",
                            evidence={"pid": pid, "exe": real_exe, "cmdline": cmdline},
                            stable_key=real_exe,
                        ))

                # Check 3: LD_PRELOAD in process environment
                environ_path = os.path.join(pid_dir, "environ")
                if os.path.exists(environ_path):
                    try:
                        with open(environ_path, "rb") as f:
                            env_bytes = f.read()
                            if b"LD_PRELOAD=" in env_bytes:
                                findings.append(create_finding(
                                    "NET-SUSP-PROC",
                                    severity="high",
                                    title_ar=f"حقن مكتبة ديناميكية LD_PRELOAD في العملية (PID:{pid})",
                                    title_en=f"LD_PRELOAD environment library injection in process (PID:{pid})",
                                    detail=f"العملية {proc_name} (PID:{pid}) تعمل بمتغير LD_PRELOAD لربط مكتبات خارجية.",
                                    fix=f"sudo kill -9 {pid}",
                                    evidence={"pid": pid, "proc": proc_name},
                                    stable_key=f"ld_preload:{pid}",
                                ))
                    except Exception:
                        pass

                # Check 4: Socket FD analysis and Reverse Shell heuristic (fd 0, 1, 2 attached to same socket)
                fd_dir = os.path.join(pid_dir, "fd")
                if os.path.exists(fd_dir):
                    try:
                        fd_links = {}
                        for fd_num in ("0", "1", "2"):
                            fd_p = os.path.join(fd_dir, fd_num)
                            if os.path.lexists(fd_p):
                                try:
                                    target_link = os.readlink(fd_p)
                                    if "socket:[" in target_link:
                                        fd_links[fd_num] = target_link
                                except OSError:
                                    pass

                        if len(fd_links) == 3 and fd_links["0"] == fd_links["1"] == fd_links["2"]:
                            findings.append(create_finding(
                                "NET-SUSP-PROC",
                                severity="critical",
                                title_ar=f"مؤشر هجوم شيل عكسي مؤكد Reverse Shell (PID:{pid})",
                                title_en=f"Confirmed Reverse Shell indicator (PID:{pid})",
                                detail=f"العملية {proc_name} (PID:{pid}) يربط فيها الإدخال والإخراج القياسي (fd 0,1,2) بنفس المقبس الشبكي.\nCMD: {cmdline[:150]}",
                                fix=f"sudo kill -9 {pid}",
                                evidence={"pid": pid, "cmdline": cmdline, "socket": fd_links["0"]},
                                stable_key=f"revshell:{cmdline[:30]}",
                            ))
                    except Exception:
                        pass

            except Exception as e:
                logging.debug(f"Error scanning proc pid {pid}: {e}")

        return findings
