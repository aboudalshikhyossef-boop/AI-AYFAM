"""Central policy for the low-resource desktop UI.

The default profile avoids continuous visual effects and reduces periodic polling.
Training integrations should call set_training_mode(True) on the main window to
pause optional background refreshes while compute-intensive work is running.
"""

LOW_RESOURCE_UI = True
TELEMETRY_REFRESH_MS = 15_000
EVENT_POLL_INTERVAL_MS = 3_000
