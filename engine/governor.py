"""
AI AYFAM v5 — Resource Governor
حاكم الموارد — يضمن تشغيل الأداة بأقل استهلاك للطاقة والذاكرة، والتكيف التلقائي
مع وضع البطارية على اللابتوب.
"""

import os
import time
from typing import Optional

class ResourceGovernor:
    def __init__(self, sys_reader=None):
        from engine.sysreader import SystemReader
        self.sys = sys_reader or SystemReader()
        self._is_battery = self._detect_battery()

    def _detect_battery(self) -> bool:
        # فحص إمداد الطاقة في Linux sysfs
        power_dir = "/sys/class/power_supply"
        if self.sys.is_dir(power_dir):
            for dev in self.sys.listdir(power_dir):
                type_path = f"{power_dir}/{dev}/type"
                status_path = f"{power_dir}/{dev}/status"
                if "Battery" in self.sys.read_text(type_path):
                    status = self.sys.read_text(status_path).strip().lower()
                    if status in ("discharging",):
                        return True
        return False

    @property
    def is_eco_mode(self) -> bool:
        return self._is_battery

    def get_max_workers(self, requested: int = 20) -> int:
        cpu_cores = os.cpu_count() or 2
        if self.is_eco_mode:
            # تقليل الخيوط إلى النصف في وضع البطارية لتوفير الطاقة
            return max(2, min(requested, cpu_cores))
        return max(4, min(requested, cpu_cores * 4))

    def throttle(self):
        """فواصل زمنية دقيقة عند الفحص الثقيل لتفادي تعليق الجهاز."""
        if self.is_eco_mode:
            time.sleep(0.015)
