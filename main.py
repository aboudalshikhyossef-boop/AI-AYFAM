#!/usr/bin/env python3
"""
AI AYFAM — Unified Cybersecurity Operations Center
Target: Linux Mint / Ubuntu Desktop (PyQt6 + Terminal CLI)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config.settings import Settings
from core.agent import AYFAMAgent
from ui.terminal import TerminalUI
from utils.preflight import check_requirements, is_root


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ayfam",
        description="AI AYFAM — Unified Cybersecurity Suite for Linux Mint",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--gui", action="store_true", help="Launch PyQt6 Desktop GUI Cockpit")
    mode_group.add_argument("--cli", action="store_true", help="Launch interactive Terminal UI")
    mode_group.add_argument("--scan", action="store_true", help="Execute immediate full security audit")
    mode_group.add_argument("--harden", action="store_true", help="Run automated Linux Mint hardening routine")
    mode_group.add_argument("--check", action="store_true", help="Run preflight diagnostic checks")

    parser.add_argument("--no-color", action="store_true", help="Disable colored output in terminal")
    parser.add_argument("--cve", type=str, metavar="QUERY", help="Search CVE / vulnerability intelligence")
    parser.add_argument("--version", action="version", version="AI AYFAM v5.2.0 (Linux Mint Edition)")
    return parser.parse_args()


def run_gui() -> int:
    try:
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
        from ui.gui_app import UnifiedCockpitWindow
    except ImportError as exc:
        print(f"[!] PyQt6 is not installed or GUI libraries are missing: {exc}", file=sys.stderr)
        print("[*] Falling back to Terminal UI...\n", file=sys.stderr)
        return run_cli()

    app = QApplication.instance()
    if not app:
        # High DPI scaling enabled by default in Qt6
        app = QApplication(sys.argv)
        app.setApplicationName("AI AYFAM")
        app.setDesktopFileName("ai-ayfam")

    window = UnifiedCockpitWindow()
    window.show()
    return app.exec()


def run_cli(no_color: bool = False) -> int:
    ui = TerminalUI(no_color=no_color)
    settings = Settings()
    agent = AYFAMAgent(settings=settings, ui=ui)

    if not is_root():
        ui.warning("تنبيه: الأداة تعمل بدون صلاحيات root. بعض الفحوصات العميقة (مثل فحص المنافذ وجدار الحماية) قد تكون محدودة.")

    agent.interactive_loop()
    return 0


def run_direct_scan(no_color: bool = False) -> int:
    ui = TerminalUI(no_color=no_color)
    settings = Settings()
    agent = AYFAMAgent(settings=settings, ui=ui)

    ui.info("بدء الفحص الأمني الشامل للنظام...")
    results = agent.run_full_audit()
    ui.print_table(
        headers=["الخطورة", "العنوان", "الفئة"],
        rows=[[f.get("severity", "info"), f.get("title", ""), f.get("category", "")] for f in results],
        title="نتائج الفحص الأمني"
    )
    ui.success(f"اكتمل الفحص: {len(results)} نتائج مسجلة.")
    return 0


def run_direct_hardening(no_color: bool = False) -> int:
    ui = TerminalUI(no_color=no_color)
    settings = Settings()
    agent = AYFAMAgent(settings=settings, ui=ui)

    if not is_root():
        ui.error("يتطلب تطبيق التحصين الأمني صلاحيات root.")
        return 1

    ui.info("بدء تطبيق إجراءات التحصين الأمني...")
    res = agent.run_hardening()
    ui.success(f"تم تنفيذ إجراءات التحصين بنجاح: {res}")
    return 0


def run_cve_search(query: str, no_color: bool = False) -> int:
    ui = TerminalUI(no_color=no_color)
    settings = Settings()
    agent = AYFAMAgent(settings=settings, ui=ui)

    ui.info(f"البحث في قواعد ثغرات CVE عن: {query}...")
    findings = agent.search_cve(query)
    if findings:
        for f in findings:
            ui.print_finding(
                severity=f.get("severity", "medium"),
                title=f.get("title", query),
                detail=f.get("detail", ""),
                fix=f.get("fix", "")
            )
    else:
        ui.warning(f"لم يتم العثور على نتائج لـ {query}")
    return 0


def main() -> int:
    args = parse_args()

    # Preflight check
    if args.check:
        results = check_requirements()
        print("AI AYFAM Preflight Diagnostics:")
        print(results.text())
        return 0 if results.ok else 1

    if args.scan:
        return run_direct_scan(no_color=args.no_color)

    if args.harden:
        return run_direct_hardening(no_color=args.no_color)

    if args.cve:
        return run_cve_search(args.cve, no_color=args.no_color)

    if args.cli:
        return run_cli(no_color=args.no_color)

    if args.gui:
        return run_gui()

    # Default launch logic:
    # If a display is available (Linux Mint desktop session), prefer GUI; otherwise CLI
    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if has_display:
        try:
            import PyQt6
            return run_gui()
        except ImportError:
            return run_cli(no_color=args.no_color)

    return run_cli(no_color=args.no_color)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Exiting AI AYFAM...", file=sys.stderr)
        sys.exit(0)
    except EOFError:
        print("\n[!] Input closed. Exiting AI AYFAM...", file=sys.stderr)
        sys.exit(0)
