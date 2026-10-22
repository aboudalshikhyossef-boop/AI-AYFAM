# AI AYFAM - rules for coding agents
Project: defensive security desktop tool for Linux Mint (Python 3.10+, PyQt6). Arabic is the primary UI language, English secondary.

1. Never use shell=True with any value that comes from outside the program. All subprocess calls go through utils/safe_exec.py with argv lists. run_trusted_shell is for constant strings only.
2. Treat every string read from the system (log lines, file names, process names, USB descriptors, banners) as hostile. Sanitize before putting it in titles, HTML, bash scripts, notifications or SQL. SQL is parameterized only.
3. New checks return engine.finding.Finding with a stable rule_id, tags and attack_ids. Never match on Arabic title text.
4. Scanners are read-only. Anything that changes the system lives in tools/fix.py and needs explicit user confirmation.
5. Keep every user-facing string bilingual (ar/en). Never delete Arabic strings.
6. Every change ships with pytest tests. Use fixtures with sample proc/log data instead of touching the real system. Keep `pytest -q` green.
7. No new dependency without pinning it in requirements.txt and justifying it in the PR description.
8. No network access at import time. Network calls only in modules designed for it, with timeouts and error handling.
9. One topic per PR. The PR description must list what was NOT verified.
10. Honest naming: do not call a check YARA, CIS or ATT&CK-mapped unless it really is.