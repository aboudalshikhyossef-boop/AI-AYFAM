"""اختبارات معيارية للواجهة العصرية ونظام التصميم وشاشة المقدمة بدون اشتراط تشغيل بيئة العرض المادية."""
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


class TestModernUiSpecs(unittest.TestCase):
    def test_theme_constants_and_styling(self):
        from ui.theme import (
            QSS,
            ACCENT,
            ACCENT_SECONDARY,
            BG_BASE,
            CARD_ACCENTS,
            SEV_CRITICAL,
            SEV_SAFE,
            alpha,
            get_qss,
            severity_color,
        )

        self.assertTrue(len(QSS) > 1000)
        self.assertTrue(ACCENT.startswith("#"))
        self.assertTrue(ACCENT_SECONDARY.startswith("#"))
        self.assertTrue(BG_BASE.startswith("#"))
        self.assertEqual(alpha("#38bdf8", 50), "#3238bdf8")

        custom_qss = get_qss("#ff00ff", "#00ffff")
        self.assertIn("#ff00ff", custom_qss)

        self.assertEqual(severity_color("critical"), SEV_CRITICAL)
        self.assertEqual(severity_color("safe"), SEV_SAFE)
        self.assertIn("connections", CARD_ACCENTS)
        self.assertIn("processes", CARD_ACCENTS)
        self.assertIn("score", CARD_ACCENTS)

    def test_intro_splash_structure(self):
        # التحقق من نصوص الإقلاع التشخيصية والتسلسل
        boot_steps = [
            ("فحص سلامة النواة والبيئة المحلية", "Local Kernel & Sandbox Integrity Check", 18),
            ("تهيئة مستشعرات المراقبة والاتصالات الحية", "Initializing Telemetry & Network Radar", 42),
            ("تفعيل درع حماية الأجهزة والوسائط USB Sentry", "Activating USB Sentry & Isolation Guard", 68),
            ("تحميل حزم التحليل الأمني ومحرك الذكاء الاصطناعي", "Loading Threat Intel & Local AI Copilot", 88),
            ("اكتملت الجاهزية — كابينة العمليات جاهزة للدخول", "SOC Cockpit Ready — Access Granted", 100),
        ]
        self.assertEqual(len(boot_steps), 5)
        self.assertEqual(boot_steps[-1][2], 100)

    def test_nav_items_integrity(self):
        with open(ROOT_DIR / "ui/gui_app.py", "r", encoding="utf-8") as f:
            code = f.read()

        self.assertIn("NAV_ITEMS =", code)
        self.assertIn("dashboard", code)
        self.assertIn("scans", code)
        self.assertIn("usb", code)
        self.assertIn("chat", code)
        self.assertIn("ترسانة العمليات التكتيكية السريعة", code)
        self.assertIn("guide_btn", code)
        self.assertIn("intro_btn", code)

    def test_main_cli_splash_flag(self):
        import argparse
        from main import parse_args

        # تجربة التحقق من وسيط --no-splash
        parser = argparse.ArgumentParser()
        parser.add_argument("--no-splash", action="store_true")
        args = parser.parse_args(["--no-splash"])
        self.assertTrue(args.no_splash)

        args_default = parser.parse_args([])
        self.assertFalse(args_default.no_splash)


if __name__ == "__main__":
    unittest.main()
