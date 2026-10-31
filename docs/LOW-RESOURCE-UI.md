# Low-resource desktop UI profile

AI AYFAM now starts with a static, low-resource desktop presentation.

- The animated live backdrop and frosted-glass controller are not installed.
- Sidebar navigation uses native checkable buttons instead of the animated navigation wheel.
- Activity pulses, animated page transitions, hover halos, flowing borders, button glow feedback, and UI sounds are disabled.
- The analog clock is replaced by a static brand label.
- The existing icon is reused as a subdued static watermark. It is a placeholder until the final brand mark is supplied.
- Passive network/process telemetry refreshes every 15 seconds; the event feed refreshes every 3 seconds.
- The main window exposes `set_training_mode(True/False)`. Training integrations should call it from the Qt GUI thread to pause/resume passive polling.

This change intentionally preserves user-triggered scans, navigation, search, reports, and form interaction. It does not claim a measured CPU/RAM reduction; measure on the target Linux Mint machine before and after.

The low-resource profile is the default. The intro splash is skipped in this profile to avoid its simulated boot timer.
