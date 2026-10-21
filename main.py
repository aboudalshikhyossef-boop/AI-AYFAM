#!/usr/bin/env python3
"""
AI AYFAM — Unified Cybersecurity Operations Center
Target: Linux Mint / Ubuntu Desktop (PyQt6 desktop application only)
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from utils.preflight import check_requirements
from config.version import APP_VERSION_LABEL


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ayfam",
        description="AI AYFAM — تطبيق سطح مكتب للأمن السيبراني على Linux Mint",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--gui", action="store_true", help="تشغيل تطبيق سطح المكتب (الوضع الوحيد)")
    parser.add_argument("--check", action="store_true", help="فحص المتطلبات قبل تشغيل التطبيق")
    parser.add_argument("--no-splash", action="store_true", help="تخطي شاشة الترحيب والمقدمة والدخول المباشر")
    parser.add_argument("--version", action="version", version=f"{APP_VERSION_LABEL} (Linux Mint Desktop)")
    return parser.parse_args()


def prepare_gui_environment() -> None:
    sudo_user = os.environ.get("SUDO_USER")
    sudo_uid = os.environ.get("SUDO_UID")

    if sudo_user:
        user_home = Path(f"/home/{sudo_user}")
        try:
            import PyQt6  # noqa: F401
        except ImportError:
            candidates = [
                ROOT_DIR / ".venv/lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages",
                ROOT_DIR / "venv/lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages",
                user_home / ".local/lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages",
            ]
            user_py_dir = user_home / ".local/lib"
            if user_py_dir.exists():
                for p in user_py_dir.glob("python3.*/site-packages"):
                    candidates.append(p)
            for cand in candidates:
                if cand.exists() and str(cand) not in sys.path:
                    sys.path.insert(0, str(cand))
                    try:
                        import PyQt6  # noqa: F401
                        break
                    except ImportError:
                        pass
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            os.environ["DISPLAY"] = ":0"
        if not os.environ.get("XAUTHORITY"):
            xauth_candidates = [user_home / ".Xauthority"]
            if sudo_uid:
                xauth_candidates.append(Path(f"/run/user/{sudo_uid}/gdm/Xauthority"))
                run_user_dir = Path(f"/run/user/{sudo_uid}")
                if run_user_dir.exists():
                    xauth_candidates.extend(list(run_user_dir.glob(".Xauthority*")))
                    xauth_candidates.extend(list(run_user_dir.glob("xauth*")))
            for xauth in xauth_candidates:
                if xauth.exists():
                    os.environ["XAUTHORITY"] = str(xauth)
                    break
        if not os.environ.get("XDG_RUNTIME_DIR") and sudo_uid:
            os.environ["XDG_RUNTIME_DIR"] = f"/run/user/{sudo_uid}"


def run_gui(no_splash: bool = False) -> int:
    prepare_gui_environment()
    log_dir = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "ayfam"
    log_file = log_dir / "gui.log"

    def log_failure(exc: BaseException) -> None:
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            with log_file.open("a", encoding="utf-8") as stream:
                stream.write(f"\n--- GUI startup failure ---\n{traceback.format_exc()}\n")
        except OSError:
            pass

    try:
        from PyQt6.QtWidgets import QApplication
        from ui.gui_app import UnifiedCockpitWindow
        from ui.intro_splash import AyfamIntroSplash
    except ImportError as exc:
        print(f"[!] PyQt6 غير مثبت أو مكتبات الواجهة ناقصة: {exc}", file=sys.stderr)
        print("[*] ثبّت التطبيق عبر setup.sh أو: python3 -m pip install PyQt6", file=sys.stderr)
        print("[*] هذا الإصدار يعمل كتطبيق سطح مكتب فقط، بدون طرفية وبدون واجهة ويب.", file=sys.stderr)
        return 2

    try:
        app = QApplication.instance()
        if not app:
            app = QApplication(sys.argv)
            app.setApplicationName("AI AYFAM")
            app.setDesktopFileName("ai-ayfam")

        window = UnifiedCockpitWindow()

        if not no_splash:
            splash = AyfamIntroSplash(auto_close=True)
            splash.ready_to_launch.connect(window.show)
            splash.show()
        else:
            window.show()

        return app.exec()
    except Exception as exc:
        log_failure(exc)
        print(f"[!] فشل تشغيل الواجهة الرسومية. راجع: {log_file}", file=sys.stderr)
        return 1


def main() -> int:
    args = parse_args()
    if args.check:
        results = check_requirements()
        print("AI AYFAM Preflight Diagnostics:")
        print(results.text())
        if not results.ok:
            return 1
        return 0
    return run_gui(no_splash=args.no_splash)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Exiting AI AYFAM...", file=sys.stderr)
        sys.exit(0)
    except EOFError:
        print("\n[!] Input closed. Exiting AI AYFAM...", file=sys.stderr)
        sys.exit(0)
