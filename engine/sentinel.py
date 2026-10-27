"""
AI AYFAM — Real-time Sentinel Monitor
الحارس اللحظي — مراقبة في الوقت الفعلي للتغيرات عبر inotify وتقليص استهلاك الموارد
"""

import os
import time
import threading
import logging
from typing import List, Dict, Any, Optional
from utils import safe_exec
from engine.events import EventStore, EventSource

try:
    import inotify_simple
    INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False

MONITORED_INOTIFY_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssh/sshd_config",
    "/etc/ld.so.preload",
    "/etc/cron.d",
    os.path.expanduser("~/.config/autostart"),
]

class InotifyEventSource(EventSource):
    """مصدر مراقبة التغيرات اللحظية على الملفات باستخدام inotify."""

    def __init__(self, watch_paths: Optional[List[str]] = None):
        self.watch_paths = watch_paths or MONITORED_INOTIFY_PATHS
        self.running = False
        self.inotify = None
        self.wd_map = {}

    def start(self):
        if not INOTIFY_AVAILABLE:
            logging.warning("inotify_simple module not available")
            return

        try:
            self.inotify = inotify_simple.INotify()
            flags = inotify_simple.flags.MODIFY | inotify_simple.flags.CREATE | inotify_simple.flags.DELETE
            for p in self.watch_paths:
                if os.path.exists(p):
                    try:
                        wd = self.inotify.add_watch(p, flags)
                        self.wd_map[wd] = p
                    except Exception:
                        pass
            self.running = True
        except Exception as e:
            logging.error(f"Failed to start inotify: {e}")

    def stop(self):
        self.running = False
        if self.inotify:
            try:
                self.inotify.close()
            except Exception:
                pass

    def yield_events(self):
        if not self.running or not self.inotify:
            return

        try:
            events = self.inotify.read(timeout=500)
            for ev in events:
                path = self.wd_map.get(ev.wd, "unknown")
                mask_str = "modified"
                if ev.mask & inotify_simple.flags.CREATE:
                    mask_str = "created"
                elif ev.mask & inotify_simple.flags.DELETE:
                    mask_str = "deleted"

                yield {
                    "source": "inotify",
                    "event_type": f"file_{mask_str}",
                    "subject": path,
                    "details": f"File event {mask_str} on {path}",
                    "severity": "critical" if any(p in path for p in ("/passwd", "/shadow", "/sudoers", "/ld.so.preload")) else "high",
                }
        except Exception:
            pass


class ActiveSentinel:
    """Class name alias for legacy imports compatibility."""
    def __init__(self, *args, **kwargs):
        self.engine = SentinelEngine()
        self.alerts_log = []

    def start(self):
        self.engine.start()

    def stop(self):
        self.engine.stop()

    def notify_desktop(self, title: str, message: str, urgency: str = "normal"):
        self.engine._notify(title, message)

class SentinelEngine:
    """محرك الحارس اللحظي لمعالجة وتنبيه الأحداث وإدارتها بدون خنق المعالج."""

    def __init__(self, store: Optional[EventStore] = None):
        self.store = store or EventStore()
        self.inotify_source = InotifyEventSource()
        self.running = False
        self.thread = None
        self.cooldown_map = {}

    def start(self):
        if self.thread is not None and self.thread.is_alive():
            return
        self.running = True
        self.inotify_source.start()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        self.inotify_source.stop()
        if self.thread is not None:
            if self.thread.is_alive() and self.thread != threading.current_thread():
                self.thread.join(timeout=2.0)
            self.thread = None

    def _notify(self, title: str, msg: str):
        safe_exec.run(["notify-send", "-u", "critical", "AI AYFAM Alert", f"{title}: {msg}"], check_binary=False)

    def _monitor_loop(self):
        while self.running:
            for ev in self.inotify_source.yield_events():
                if not self.running:
                    break
                # Dedup / cooldown 10s per subject
                subj = ev["subject"]
                now = time.time()
                if now - self.cooldown_map.get(subj, 0) < 10:
                    continue
                self.cooldown_map[subj] = now

                self.store.record_event(
                    source=ev["source"],
                    event_type=ev["event_type"],
                    subject=ev["subject"],
                    details=ev["details"],
                    severity=ev["severity"],
                )
                self._notify(ev["event_type"], ev["subject"])

            for _ in range(10):
                if not self.running:
                    break
                time.sleep(0.1)
