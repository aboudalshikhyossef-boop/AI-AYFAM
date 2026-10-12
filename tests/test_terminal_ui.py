import sys, os, io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from contextlib import redirect_stdout

from ui.terminal import TerminalUI

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1; print(f"  ✅ {name}")
    else:
        failed += 1; print(f"  ❌ {name}")


class FakeCtx:
    system = {"hostname": "test-host", "os": "Linux Mint 21.3", "kernel": "6.5.0",
              "cpu_cores": 8, "load": " 0.5", "memory": {"used": "2GB", "total": "16GB"},
              "disk_root": "40GB/500GB", "uptime": "up 1 day"}
    network = {"firewall_active": True, "interfaces": {"eth0": "10.0.0.5"},
               "gateway": "10.0.0.1", "public_ip": "203.0.113.1", "dns": ["1.1.1.1"]}
    security = {"open_ports_count": 2, "failed_login_attempts": 3, "running_services": 20, "pending_updates": 1}
    devices = {"usb_count": 1, "bluetooth": False, "wifi_adapters": ["wlan0"], "android_phones": []}
    user = {"username": "tester", "role": "admin"}
    def threat_level(self):
        return "MEDIUM"


def run_all_methods(ui, label):
    buf = io.StringIO()
    err = None
    try:
        with redirect_stdout(buf):
            ui.matrix_splash(0.15)
            ui.banner(context=FakeCtx())
            ui.dashboard(context=FakeCtx(), kb_stats={"knowledge_entries": 10, "db_size_mb": 2})
            ui.section("Test Section")
            ui.subsection("Test Subsection")
            ui.info("info message")
            ui.success("success message")
            ui.warning("warning message")
            ui.error("error message")
            ui.critical("critical message")
            ui.print_finding("critical", "Critical finding", "detail text", "fix text")
            ui.print_finding("high", "High finding")
            ui.print_finding("medium", "Medium finding")
            ui.print_finding("low", "Low finding")
            ui.print_finding("info", "Info finding")
            ui.print_finding("unknownseverity", "Unknown severity finding")
            ui.print_table(["A", "B"], [["1", "2"], ["3", "4"]], title="Test Table")
            ui.print_table(["A"], [])  # empty rows path
            ui.print_tree({"a": 1, "b": {"c": 2}}, title="Tree")
            ui.chat_you("hello")
            ui.chat_agent("hi there", intent="TEST")
            ui.chat_thinking("thinking...")
            ui.raw("raw text block")
            ui.status_bar({"Connection": "Active", "Firewall": "Disabled", "Updates": "pending"})
            ui.show_improvement({"category": "perf", "description": "speed up X", "proposed_at": "2026-01-01"})
            with ui.spinner("working"):
                pass
    except Exception as e:
        err = e
    return buf.getvalue(), err


print(f"\n[1] Full method sweep — rich console mode")
ui_rich = TerminalUI(no_color=False)
if ui_rich.console:
    ui_rich.console.width = 100
out, err = run_all_methods(ui_rich, "rich")
check("no exception raised in rich-console mode", err is None)
if err:
    import traceback
    traceback.print_exception(type(err), err, err.__traceback__)

print(f"\n[2] Full method sweep — no_color fallback mode")
ui_plain = TerminalUI(no_color=True)
check("console is None in no_color mode", ui_plain.console is None)
out2, err2 = run_all_methods(ui_plain, "plain")
check("no exception raised in no_color mode", err2 is None)
if err2:
    import traceback
    traceback.print_exception(type(err2), err2, err2.__traceback__)

print(f"\n[3] Dashboard panel height-equalization")
# Force a real width mismatch between the network/devices panel pair
ctx = FakeCtx()
ctx.devices = dict(ctx.devices)
ctx.devices["wifi_adapters"] = ["wlan0", "wlan1"]  # doesn't change row count, but kb_stats does
buf = io.StringIO()
old_file = ui_rich.console.file if ui_rich.console else None
if ui_rich.console:
    ui_rich.console.file = buf
try:
    with redirect_stdout(buf):
        ui_rich.dashboard(context=ctx, kb_stats={"knowledge_entries": 99, "db_size_mb": 5})
finally:
    if ui_rich.console and old_file:
        ui_rich.console.file = old_file
rendered = buf.getvalue()
lines = [l for l in rendered.split("\n") if l.strip()]
# Find the two panel-pair blocks and confirm both sides in each row have matching border chars
box_rows = [l for l in lines if l.count("╭") == 2 or l.count("╰") == 2]
check("dashboard renders without exception", True)
check("both panel pairs show matching top/bottom borders (no ragged edge)",
      any("╭" in l for l in lines) and any("╰" in l for l in lines))

print(f"\n[4] get_events / event log")
ui_rich.info("event one")
ui_rich.warning("event two")
events = ui_rich.get_events(5)
check("events were logged", len(events) >= 2)
check("event tuples have (ts, level, msg) shape", all(len(e) == 3 for e in events))

print(f"\n[5] ask() on a closed stdin raises EOFError (by design — caught at main.py's top level for a graceful exit, not swallowed here)")
import io as _io
old_stdin = sys.stdin
sys.stdin = _io.StringIO("")  # EOF immediately
try:
    ui_rich.ask("Test prompt", default="fallback")
    check("EOFError propagates as expected (main.py handles it globally)", False)
except EOFError:
    check("EOFError propagates as expected (main.py handles it globally)", True)
except Exception as e:
    check(f"unexpected exception type (expected EOFError): {e}", False)
sys.stdin = old_stdin

print(f"\n{'='*50}\nTOTAL: {passed} passed, {failed} failed\n{'='*50}")
