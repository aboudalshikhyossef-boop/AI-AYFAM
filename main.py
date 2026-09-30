#!/usr/bin/env python3
"""
AI AYFAM v3 — وكيل الأمن السيبراني الذكي
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import Settings
from ui.terminal import TerminalUI


def main():
    parser = argparse.ArgumentParser(
        prog="ayfam",
        description="AI AYFAM v3 — وكيل الأمن السيبراني الذكي | Smart Cybersecurity Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
أمثلة / Examples:
  ayfam                              → وضع محادثة ذكي (موصى به)
  ayfam --scan network               → فحص الشبكة
  ayfam --scan ports --target 192.168.1.1
  ayfam --scan system
  ayfam --scan full
  ayfam --status                     → حالة الوكيل
  ayfam --update                     → تحديث معلومات التهديدات
  ayfam --set-github-token ghp_XXX
  ayfam --language en
        """
    )
    parser.add_argument("--set-github-token", metavar="TOKEN", help="حفظ رمز GitHub")
    parser.add_argument("--language", choices=["ar", "en"], help="تغيير اللغة")
    parser.add_argument("--scan", metavar="TARGET",
                        choices=["network", "ports", "system", "logs", "usb", "full"],
                        help="فحص: network | ports | system | logs | usb | full")
    parser.add_argument("--target", metavar="IP/URL", help="هدف الفحص")
    parser.add_argument("--report", action="store_true", help="إنشاء تقرير شامل")
    parser.add_argument("--fix",    action="store_true", help="تشغيل الإصلاح التلقائي")
    parser.add_argument("--update", action="store_true", help="تحديث معلومات التهديدات")
    parser.add_argument("--status", action="store_true", help="حالة الوكيل")
    parser.add_argument("--gui", action="store_true", help="تشغيل واجهة سطح المكتب الرسومية (GUI Cockpit)")
    parser.add_argument("--audit", action="store_true", help="فحص تحصين شامل بنمط CIS")
    parser.add_argument("--baseline-learn", action="store_true", help="التقاط وحفظ خط الأساس السلوكي للنظام")
    parser.add_argument("--baseline-check", action="store_true", help="كشف شذوذ النظام بالمقارنة بخط الأساس")
    parser.add_argument("--synthesize-rules", action="store_true", help="توليد قواعد جدار ناري وحماية تلقائية")
    parser.add_argument("--playbook", metavar="TOPIC", help="استخراج خطة عمل أمنية مهيكلة لأداة أو موضوع من الكتب")
    parser.add_argument("--lynis", action="store_true", help="تشغيل فحص Lynis القياسي المتقدم")
    parser.add_argument("--yara", metavar="PATH", nargs="?", const=".", help="فحص البرمجيات الخبيثة بمحرك YARA")
    parser.add_argument("--rootkits", action="store_true", help="كشف الجذور الخفية والـ Rootkits")
    parser.add_argument("--sentinel", action="store_true", help="تشغيل الحارس النشط في الخلفية")
    parser.add_argument("--hunt", action="store_true", help="صيد التهديدات والاستمرارية والأبواب الخلفية")
    parser.add_argument("--secrets", metavar="PATH", nargs="?", const=".", help="كشف الأسرار والمفاتيح الحساسة")
    parser.add_argument("--plan", action="store_true", help="توليد سكريبت معالجة Bash آمن")
    parser.add_argument("--html-report", action="store_true", help="تصدير تقرير HTML تفاعلي")
    parser.add_argument("--learn", metavar="FILE", help="تعلّم من ملف (PDF/TXT/MD) وفهرسته في المكتبة الشخصية")
    parser.add_argument("--teach", metavar="FACT", help="علّم الأداة حقيقة مباشرة تتذكرها لاحقاً")
    parser.add_argument("--learned", action="store_true", help="اعرض كل ما تعلمته الأداة حتى الآن")
    parser.add_argument("--no-color", action="store_true", help="بدون ألوان")
    parser.add_argument("--verbose",  action="store_true", help="وضع التصحيح المفصّل")
    args = parser.parse_args()

    settings = Settings()
    ui = TerminalUI(no_color=args.no_color)

    # ── Quick commands (no full agent load) ──────────────────────────────────
    if args.gui:
        from ui.gui_app import launch_gui
        launch_gui()
        return

    if args.set_github_token:
        token = args.set_github_token.strip()
        if not token or any(ord(c) < 0x21 for c in token) or len(token) < 20:
            print("❌ الرمز المُدخَل لا يبدو رمز GitHub صالحاً (تحقق من عدم وجود مسافات أو قصّه بالخطأ).")
            return
        settings.set("github_token", token)
        print(f"✅ تم حفظ رمز GitHub ({token[:8]}...)")
        return

    if args.language:
        settings.set("language", args.language)
        print(f"✅ تم تغيير اللغة إلى: {args.language}")
        return

    # ── Load full agent ───────────────────────────────────────────────────────
    from core.agent import AYFAMAgent
    agent = AYFAMAgent(settings=settings, ui=ui, verbose=args.verbose)

    try:
        if args.status:
            agent._agent_status()
        elif args.scan:
            agent.run_scan(args.scan, value=args.target)
        elif args.report:
            agent.generate_full_report()
        elif args.fix:
            agent.run_autofix()
        elif args.update:
            agent.update_intelligence()
        elif args.learn:
            agent._learn_from_file(args.learn)
        elif args.teach:
            agent._teach(args.teach)
        elif args.learned:
            agent._show_learned()
        else:
            # Default: interactive NLP chat mode
            agent.interactive_mode()

    except KeyboardInterrupt:
        print("\n\n  مع السلامة! / Goodbye!\n")
    except EOFError:
        print("\n\n  مع السلامة! / Goodbye!\n")
    except Exception as e:
        from brain.self_heal import SelfHealEngine
        healer = SelfHealEngine(ui=ui)
        err = healer._analyze_error(e)
        healer.display_error(err)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
