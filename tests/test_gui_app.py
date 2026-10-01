import os
import sys
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from PyQt6.QtCore import QEventLoop, QTimer
    from PyQt6.QtWidgets import QApplication
    from ui.gui_app import GuiTerminalUI, UnifiedCockpitWindow, WorkerThread
except (ImportError, OSError) as exc:
    print(f"SKIP GUI tests: Qt runtime is unavailable ({exc})")
    sys.exit(0)


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

print(f"\nTOTAL GUI TESTS: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)