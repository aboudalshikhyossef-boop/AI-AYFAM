import os
import sys
from types import SimpleNamespace
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from PyQt6.QtCore import QEventLoop, QTimer
    from PyQt6.QtWidgets import QApplication
    from ui.gui_app import GuiTerminalUI, UnifiedCockpitWindow, WorkerThread
except (ImportError, OSError) as exc:
    pytest.skip(f"Qt runtime is unavailable ({exc})", allow_module_level=True)


passed = failed = 0


def check(name, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS {name}")
    else:
        failed += 1
        print(f"  FAIL {name}")


app = QApplication.instance() or QApplication([])

print("\n[1] GUI prompt defaults are non-interactive")
ui = GuiTerminalUI(no_color=True)
check("ask returns its default without reading stdin", ui.ask("Port range", "1-1024") == "1-1024")
check("ask without a default returns an empty value", ui.ask("Website URL") == "")
check("confirm returns its default without reading stdin", ui.confirm("Save report?", True) is True)
check("confirm safely declines by default", ui.confirm("Open browser?") is False)
ui.print_table(["Port"], [[443]], title="Open ports")
check("table rows are available to the GUI event log", any("443" in msg for _, _, msg in ui.get_events()))

print("\n[2] GUI worker returns its task result")
loop = QEventLoop()
received = []
worker = WorkerThread(lambda: ["current result"])
worker.task_result.connect(lambda result: (received.append(result), loop.quit()))
QTimer.singleShot(3000, loop.quit)
worker.start()
loop.exec()
worker.wait()
check("worker emitted exactly one result", received == [["current result"]])

print("\n[3] GUI task results do not retain stale findings")
window = SimpleNamespace(agent=SimpleNamespace(_last_findings=[{"title": "stale"}]))
empty = UnifiedCockpitWindow._execute_gui_task(window, lambda: None)
check("empty task clears previous findings", empty == [])
current = [{"title": "current"}]


def set_current_findings():
    window.agent._last_findings = current


result = UnifiedCockpitWindow._execute_gui_task(window, set_current_findings)
check("task exposes only its current findings", result == current)
preserved = UnifiedCockpitWindow._execute_gui_task(window, lambda: None, True)
check("report tasks retain findings from the previous scan", preserved == current)

print("\n[4] Theme module loads correctly")
from ui.theme import QSS, ACCENT, SEV_CRITICAL, severity_color
check("QSS stylesheet is non-empty", len(QSS) > 500)
check("accent color defined", ACCENT.startswith("#"))
check("severity color mapping works", severity_color("critical") == SEV_CRITICAL)
check("unknown severity falls back to info", severity_color("unknown") != SEV_CRITICAL)

print("\n[5] Navigation structure")
from ui.gui_app import NAV_ITEMS
check("navigation has 9 items", len(NAV_ITEMS) == 9)
check("dashboard is first nav item", NAV_ITEMS[0][0] == "dashboard")
check("settings is last nav item", NAV_ITEMS[-1][0] == "settings")

print(f"\nTOTAL GUI TESTS: {passed} passed, {failed} failed")
