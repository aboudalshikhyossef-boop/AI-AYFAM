"""
AI AYFAM v7 — Live Network & Kernel Telemetry Engine
محرك الرادار المباشر — قراءة المقابس اللحظية ومراقبة العمليات واستدعاءات النظام مباشرة من النواة
"""

import os
import re
from typing import List, Dict, Any
from utils import safe_exec

class LiveReconEngine:
    @staticmethod
    def get_live_connections() -> List[Dict[str, Any]]:
        conns = []
        res = safe_exec.run(["ss", "-tunap"], timeout=5, check_binary=False)
        if not res.ok or not res.stdout:
            return conns

        for line in res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                proto = parts[0]
                state = parts[1]
                local = parts[4]
                remote = parts[5]
                proc_info = " ".join(parts[6:]) if len(parts) > 6 else "—"

                pname = "—"
                pid = "—"
                m_proc = re.search(r'"([^"]+)"', proc_info)
                if m_proc:
                    pname = m_proc.group(1)
                m_pid = re.search(r'pid=(\d+)', proc_info)
                if m_pid:
                    pid = m_pid.group(1)

                is_foreign = not any(remote.startswith(x) for x in ("127.", "0.0.", "::", "*", "192.168.", "10."))
                
                conns.append({
                    "proto": proto,
                    "state": state,
                    "local": local,
                    "remote": remote,
                    "process": pname,
                    "pid": pid,
                    "is_foreign": is_foreign,
                })
        return conns

    @staticmethod
    def get_top_processes(limit: int = 15) -> List[Dict[str, str]]:
        procs = []
        res = safe_exec.run(["ps", "aux", "--sort=-%cpu"], timeout=5, check_binary=False)
        if not res.ok or not res.stdout:
            return procs

        for line in res.stdout.splitlines()[1:limit+1]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({
                    "user": parts[0],
                    "pid": parts[1],
                    "cpu": parts[2],
                    "mem": parts[3],
                    "command": parts[10][:70],
                })
        return procs
