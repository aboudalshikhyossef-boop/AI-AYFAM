#!/usr/bin/env python3
"""
AI AYFAM v3 — وكيل الأمن السيبراني الذكي
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.preflight import check_requirements, feature_flags, is_root, root_error


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
    parser.add_argument("--check-deps", action="store_true", help="فحص مكتبات Python وأدوات النظام المطلوبة")
    args = parser.parse_args()

    if not is_root():
        print(f"❌ {root_error()}")
        return 1

    preflight = check_requirements(feature_flags(args))
    if args.check_deps:
        print(preflight.text())
        return 0 if preflight.ok else 2
    if not preflight.ok:
        print("❌ متطلبات أساسية ناقصة، لا يمكن تشغيل هذا الخيار بأمان.")
        print(preflight.text())
        return 2
    if preflight.missing_optional:
        print("⚠️ بعض الأدوات الاختيارية غير مثبتة؛ ستبقى الوظائف الأخرى متاحة:")
        print(preflight.text())

    from config.settings import Settings
    from ui.terminal import TerminalUI
    settings = Settings()
    ui = TerminalUI(no_color=args.no_color)

    # ── Quick commands (no full agent load) ──────────────────────────────────
    if args.gui:
        from ui.gui_app import launch_gui
        launch_gui()
        return 0

    if args.set_github_token:
        token = args.set_github_token.strip()
        if not token or any(ord(c) < 0x21 for c in token) or len(token) < 20:
            print("❌ الرمز المُدخَل لا يبدو رمز GitHub صالحاً (تحقق من عدم وجود مسافات أو قصّه بالخطأ).")
            return 1
        settings.set("github_token", token)
        print(f"✅ تم حفظ رمز GitHub ({token[:8]}...)")
        return 0

    if args.language:
        settings.set("language", args.language)
        print(f"✅ تم تغيير اللغة إلى: {args.language}")
        return 0

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
        elif args.audit:
            agent._run_deep_audit()
        elif args.baseline_learn:
            agent._run_baseline_learn_cli()
        elif args.baseline_check:
            agent._run_baseline_check_cli()
        elif args.synthesize_rules:
            agent._run_synthesize_rules_cli()
        elif args.playbook:
            agent._show_playbook_cli(args.playbook)
        elif args.lynis:
            agent._run_lynis_cli()
        elif args.yara is not None:
            agent._run_yara_cli(args.yara)
        elif args.rootkits:
            agent._run_rootkit_cli()
        elif args.sentinel:
            agent._run_sentinel_cli()
        elif args.hunt:
            agent._run_deep_audit()
        elif args.secrets is not None:
            agent._scan_secrets_cli(args.secrets)
        elif args.plan:
            agent._generate_remediation_plan()
        elif args.html_report:
            agent._export_html_report()
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
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
