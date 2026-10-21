## 2026-03-31 - Safe Cron Reading Without Shell Globbing
**Vulnerability:** Shell globbing and string formatting (`cat {d}/*`) in `check_crontabs()` passed directory paths with wildcard globs into `run_trusted_shell()`. If a directory name contained special characters or a path injection occurred, shell command injection or unexpected expansion could happen.
**Learning:** Functions that wrap shell calls for convenience must never combine dynamic path assembly with `shell=True` or wildcard globs.
**Prevention:** Use Python's filesystem APIs (`os.listdir`, `os.path.join`, `os.path.isfile`) to resolve target files explicitly, and pass file paths as argument vectors to `safe_exec.run(["cat", filepath])`.
