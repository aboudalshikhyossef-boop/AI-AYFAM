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
        # The dashboard intentionally avoids a duplicated tactical hub; the
        # primary action lives in the mission banner and tools remain in nav.
        self.assertNotIn("ترسانة العمليات التكتيكية السريعة", code)
        self.assertIn("مؤشرات الحالة الأمنية", code)
        self.assertIn("guide_btn", code)
        self.assertIn("intro_btn", code)

    def test_score_is_pending_until_a_scan_completes(self):
        with open(ROOT_DIR / "ui/gui_app.py", "r", encoding="utf-8") as f:
            code = f.read()
        self.assertIn("بانتظار الفحص الأول", code)
        self.assertIn("self.security_gauge.set_pending()", code)
        self.assertNotIn("96.0 - external_penalty", code)
        self.assertNotIn("ACTIVE & SECURED", code)

        with open(ROOT_DIR / "ui/widgets.py", "r", encoding="utf-8") as f:
            widgets_code = f.read()
        self.assertIn("def set_pending(self)", widgets_code)
        self.assertIn('"—" if self.pending', widgets_code)

    def test_desktop_paths_and_telemetry_are_safe(self):
        with open(ROOT_DIR / "ui/gui_app.py", "r", encoding="utf-8") as f:
            code = f.read()
        self.assertIn("class LiveTelemetryWorker(QThread)", code)
        self.assertIn("LiveReconEngine.get_live_connections()", code)
        self.assertIn("self.telemetry_worker.start()", code)
        self.assertNotIn("self.worker.terminate()", code)

    def test_known_tool_catalog_has_no_duplicate_dictionary_keys(self):
        import ast

        source = (ROOT_DIR / "brain/tech_extractor.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        assignment = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                          and any(getattr(target, "id", "") == "KNOWN_TOOLS" for target in node.targets))
        keys = [key.value for key in assignment.value.keys if isinstance(key, ast.Constant)]
        self.assertEqual(len(keys), len(set(keys)))

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
