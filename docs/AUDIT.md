# AI AYFAM — Read-Only Comprehensive Security & Code Audit Report
**Date:** October 2026
**Auditor:** Jules (AI Assistant)
**Scope:** Read-only audit of `ui/gui_app.py`, `core/agent.py`, `tools/fix.py`, `tools/usb.py`, `tools/usb_control.py`, `tools/web.py`, `tools/websearch.py`, `tools/github_tool.py`, `engine/netintel.py`, `engine/secretscan.py`, `engine/autoreactor.py`, `engine/planner.py`, `reports/*`, `config/settings.py`, `setup.sh`, and `ayfam-gui-launcher.sh`, along with codebase-wide inventory of `sudo` and `shell=True`.

---

## Executive Summary & Top 10 Riskiest Items

1. **Direct `shell=True` Execution in GUI (`ui/gui_app.py`)**: `subprocess.run(fix_cmd, shell=True, ...)` is called directly when applying custom fixes in the GUI. If a finding title or recommendation text contains adversarial characters (e.g., newlines, semicolons, shell backticks), arbitrary shell execution can occur.
2. **Sudo Password Storage in Plaintext Memory (`ui/gui_app.py`, `tools/usb_control.py`, `utils/safe_exec.py`)**: Sudo password is requested from the GUI, stored in object attributes (`self._sudo_password`), and passed down function call chains into `safe_exec.run(..., sudo_password=...)`.
3. **HTML / Script Injection in HTML Reports & Web Views (`reports/html_report.py`, `ui/gui_app.py`)**: Finding titles, paths, IP addresses, and command outputs read from untrusted system sources are formatted directly into HTML without html-escaping (`html.escape()`).
4. **Shell Script Escaping / Injection in Remediation Script Generator (`core/agent.py`, `tools/fix.py`)**: Remediation scripts wrap commands or findings in bash scripts with basic quote escaping only. Adversarial filenames or process names containing newlines break out of quotes and execute arbitrary bash commands.
5. **Widespread Silent Exception Suppression (`except Exception: pass`)**: Over 20 instances of `except Exception: pass` exist across `core/agent.py`, `tools/web.py`, `tools/usb.py`, `tools/github_tool.py`, and `config/settings.py`, hiding critical runtime failures and permission errors silently.
6. **Unbounded Log & Output Reads (`engine/netintel.py`, `engine/secretscan.py`, `tools/web.py`)**: Reading files or network streams without buffer caps or line limits allows adversarial or excessively large log files to consume system RAM and freeze the application.
7. **Missing Network & Subprocess Timeouts (`tools/web.py`, `tools/github_tool.py`)**: HTTP requests and external tool calls in several utility modules lack strict timeouts, leaving threads blocked indefinitely if remote endpoints hang.
8. **In-Memory Alert Persistence (`engine/autoreactor.py`, `engine/sentinel.py`)**: Security alerts and sentinel events are maintained solely in RAM, causing historical security event data to be lost across application restarts.
9. **Plaintext Settings & Secrets Storage (`config/settings.py`)**: Configuration settings, API keys (e.g., Gemini/GitHub keys), and local states are saved in unencrypted JSON files under `~/.config/ayfam/`.
10. **Insecure Desktop Launcher & Sudo Ambiguity (`ayfam-gui-launcher.sh`, `setup.sh`)**: Direct execution patterns in launcher scripts risk launching the entire PyQt6 GUI under root if user uses `sudo ayfam-gui`, violating GUI privilege isolation guidelines.

---

## Audit Findings Table

| File | Line | Severity | Issue | Recommended Fix |
| :--- | :--- | :--- | :--- | :--- |
| `ui/gui_app.py` | 2519 | Critical | `subprocess.run(fix_cmd, shell=True)` executes raw fix string from finding object in shell | Remove `shell=True`. Route all fixes through `tools/fix.py::apply_fix(fix_id)` with validated argv via privileged helper |
| `ui/gui_app.py` | 350, 480 | High | `self._sudo_password` stores user's root password in plain memory | Replace sudo password prompt with standard Polkit (`pkexec`) authenticated daemon/helper |
| `reports/html_report.py` | 85, 142 | High | Unescaped finding titles, details, and system paths embedded into HTML report template | Wrap all dynamically generated text with `html.escape()` before formatting into HTML templates |
| `ui/gui_app.py` | 1210 | Medium | Unescaped finding titles rendered inside QWebView / QTextBrowser HTML components | Use `html.escape()` for all finding properties before inserting into Qt rich text components |
| `core/agent.py` | 212 | Medium | `except Exception: pass` suppresses agent execution errors silently | Log exception details using `logger.warning` or `logger.exception` |
| `core/agent.py` | 1642 | Medium | `except Exception: pass` masks tool invocation failures | Log tool execution error and return structured error response |
| `tools/fix.py` | 38 | Medium | `_set_global_sshd_option` runs Python snippet inline via `safe_exec.run` without file lock | Ensure atomic update pattern (write temporary file, validate config with `sshd -t`, then replace) |
| `tools/usb.py` | 105, 128 | Low | Silent exception suppression when querying USB device attributes | Log device read errors to debug logs |
| `tools/usb_control.py` | 44, 401, 799 | Medium | Plaintext `sudo_password` passed as parameter and silent exception handling during unmount | Remove `sudo_password` argument; delegate privileged disk actions to Polkit helper |
| `tools/web.py` | 49, 445, 499, 530, 554, 585, 594, 645, 749, 774, 806 | Low | 11 instances of `except Exception: pass` hiding HTTP / network request errors | Replace bare passes with error logging and distinct network error handling |
| `tools/github_tool.py` | 78, 178, 242 | Low | Silent `except Exception: pass` on GitHub API network queries | Raise or log specific API exceptions with rate-limit warnings |
| `engine/netintel.py` | 65 | Medium | Unbounded read of network response payload into memory | Set `max_bytes` limit on `requests` / `urllib` stream reading |
| `engine/secretscan.py` | 112 | High | High-volume file scanning without file size caps or binary file skip check | Restrict scanning to text files < 5MB and check binary MIME / magic bytes |
| `engine/autoreactor.py` | 45 | Medium | Reactive alert history stored solely in memory (`self.alerts = []`) | Persist event alerts to SQLite database WAL |
| `engine/planner.py` | 88 | Low | Remediation plan bash script generation lacks newline sanitization for path variables | Sanitize path variables and replace string formatting with argv execution |
| `config/settings.py` | 99, 104, 223 | Low | Plaintext storage of API keys in `~/.config/ayfam/settings.json` and silent JSON read errors | Restrict file permissions (`0600`) on config directory and log settings parsing errors |
| `setup.sh` | 42 | Low | Uses `sudo` in installer without checking if current user is already root | Check `euid` before invoking `sudo` and handle polkit policy installation |
| `ayfam-gui-launcher.sh` | 12 | Medium | Launcher does not prevent execution under `sudo`, risking X11/Wayland environment corruption | Add `if [ "$EUID" -eq 0 ]; then echo "Do not run GUI as root"; exit 1; fi` check |

---

## Complete Codebase Inventory of `sudo` and `shell=True`

### 1. `shell=True` Usage
- **`ui/gui_app.py:2519`**: `subprocess.run(fix_cmd, shell=True, ...)` — **CRITICAL RISK** (Direct shell execution of custom fix strings).
- **`utils/safe_exec.py:121`**: `subprocess.run(cmd, shell=True, ...)` — Inside `run_trusted_shell()`. Restricted to hardcoded constant strings only.
- **`AGENTS.md:4`**: Documentation rule prohibiting `shell=True` with external data.
- **`tools/fix.py:7`**: Docstring noting `shell=True` avoidance.
- **`tools/usb_control.py:8`**: Docstring noting `shell=True` avoidance.
- **`brain/self_heal.py:202`**: Comment documenting split argument execution without `shell=True`.

### 2. `sudo` Usage
- **`utils/safe_exec.py`**:
  - `validate_sudo_password()`: Executes `["sudo", "-k", "-S", "-p", "", "-v"]`.
  - `run()`: Prefixes `args` with `["sudo", "-S", "-p", ""]` or `["sudo"]`.
  - `write_file_privileged()`: Executes `["sudo", "tee", ...]`.
  - `remove_path_privileged()`: Executes `["sudo", "rm", "-f", "--", ...]`.
- **`tools/fix.py`**:
  - `_backup_file()`: `safe_exec.run(["cp", "--", ...], sudo=True)`.
  - `_set_global_sshd_option()`: `safe_exec.run(["python3", "-c", ...], sudo=True)`.
  - `fix_enable_firewall()`: Calls `ufw enable`, `ufw default deny incoming`, `ufw default allow outgoing` via `sudo=True`.
  - `fix_disable_root_ssh()`: Restart `sshd` via `sudo=True`.
  - `fix_remove_suid()`: Calls `chmod u-s` via `sudo=True`.
  - `fix_ban_ip()`: Calls `ufw deny`, `iptables`, `fail2ban-client` via `sudo=True`.
  - `fix_update_system()`: Calls `apt-get update`, `apt-get upgrade` via `sudo=True`.
  - `fix_kill_process()`: Calls `kill -9` via `sudo=True`.
  - `fix_disable_ssh_password_auth()`: Calls `systemctl restart sshd` via `sudo=True`.
  - `fix_restrict_world_writable()`: Calls `chmod o-w` via `sudo=True`.
  - `fix_setup_fail2ban()`: Calls `apt-get install`, `systemctl enable` via `sudo=True`.
  - `fix_change_dns()`: Calls `resolvectl` via `sudo=True`.
- **`tools/system.py`**:
  - Hardcoded paths to `/usr/bin/sudo`.
  - Command strings checking sudoers: `sudo crontab -l`, `sudo kill -9`, `sudo strace -p`, `getent group sudo wheel admin`, `sudo userdel`, `sudo usermod`, `sudo apt-get update`.
  - Journald queries: `journalctl -u ssh -u sshd -t sudo --since -7d`.
- **`tools/usb_control.py`**:
  - Function parameters `sudo_password=None`.
  - privileged operations using `safe_exec.run(..., sudo=True)`.
- **`tools/usb.py`**:
  - Diagnostic messages advising user to run deeper scan with `sudo`.
- **`tools/port_catalog.py`**:
  - Tactic advice strings containing example `sudo ufw deny` and `sudo systemctl` commands.
- **`setup.sh`**:
  - Package installation commands using `sudo apt-get install`.

---

## Conclusion & Recommendations for Future Tasks
1. **Task 2 (Unified Finding Model)**: Eliminate Arabic substring matching in findings and ensure `Finding` objects contain stable `rule_id` and hashed `fingerprint`.
2. **Task 3 (Privileged Helper)**: Implement `pkexec` Polkit helper (`org.ayfam.helper.policy`) and Unix domain socket under `/run/ayfam/` to completely remove `sudo_password` memory handling and `shell=True` execution.
3. **Escaping**: Enforce `html.escape()` across all HTML report generators and QT view renders.
