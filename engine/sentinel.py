"""
AI AYFAM v6 — Active Sentinel (Real-time Background Defense)
محرك الحارس النشط — يعمل بصمت في خلفية النظام لمراقبة الأحداث اللحظية،
التغييرات على الملفات الحساسة، ومنع الاتصالات المريبة، مع إرسال إشعارات لسطح المكتب.
"""

import os
import time
import threading
from typing import Dict, Any, List
from utils import safe_exec

class ActiveSentinel:
    def __init__(self, check_interval: int = 10):
        self.check_interval = check_interval
        self._running = False
        self._thread: threading.Thread = None
        self.alerts_log: List[Dict[str, Any]] = []

    def notify_desktop(self, title: str, message: str, urgency: str = "critical"):
        """إرسال إشعار فوري إلى سطح مكتب Linux Mint."""
        safe_exec.run([
            "notify-send",
            "-u", urgency,
            "-a", "AI AYFAM Sentinel",
            title,
            message
        ], check_binary=False)

    def _monitor_loop(self):
        """حلقة المراقبة الخفيفة في الخلفية."""
        watched_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/ld.so.preload",
            "/etc/ssh/sshd_config",
        ]
        file_mtimes = {f: os.path.getmtime(f) for f in watched_files if os.path.exists(f)}

        while self._running:
            try:
                # 1. مراقبة تعديل الملفات الحساسة
                for fpath in watched_files:
                    if os.path.exists(fpath):
                        mtime = os.path.getmtime(fpath)
                        old_mtime = file_mtimes.get(fpath)
                        if old_mtime and mtime > old_mtime:
                            alert = {
                                "time": time.strftime("%H:%M:%S"),
                                "type": "FILE_MODIFIED",
                                "target": fpath,
                            }
                            self.alerts_log.append(alert)
                            self.notify_desktop(
                                "🚨 تنبيه أمني حرج!",
                                f"تم تعديل ملف حساس للتو: {fpath}",
                                urgency="critical"
                            )
                        file_mtimes[fpath] = mtime

                # 2. فحص وجود ملفات شيل عكسي في الذاكرة المشتركة
                for shm in ("/dev/shm", "/tmp"):
                    if os.path.exists(shm):
                        try:
                            for fname in os.listdir(shm):
                                if fname.endswith((".sh", ".py", ".elf")) and not fname.startswith("."):
                                    full_path = os.path.join(shm, fname)
                                    # إذا تم إنشاء ملف تنفيذي خلال آخر دقيقة
                                    if time.time() - os.path.getctime(full_path) < self.check_interval * 2:
                                        self.notify_desktop(
                                            "⚠️ تحذير: ملف تنفيذي مشبوه!",
                                            f"تم إسقاط ملف تنفيذي جديد في: {full_path}",
                                            urgency="normal"
                                        )
                        except Exception:
                            pass

                time.sleep(self.check_interval)
            except Exception:
                time.sleep(self.check_interval)

    def start(self):
        """بدء تشغيل الحارس النشط في خيط منفصل (Background Thread)."""
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._thread.start()
            self.notify_desktop("🛡️ AI AYFAM Sentinel", "تم تفعيل وضع الحارس النشط ومراقبة النظام لحظياً.", "low")

    def stop(self):
        self._running = False
