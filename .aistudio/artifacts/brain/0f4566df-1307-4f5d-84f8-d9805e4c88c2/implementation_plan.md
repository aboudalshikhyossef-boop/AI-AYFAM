# AI AYFAM — Native Linux Mint Desktop Cybersecurity Suite (PyQt6)

Transform and harden **AI AYFAM** into an enterprise-grade, native Linux Mint desktop cybersecurity suite powered by PyQt6. Fixes Gemini CTI API integration with automated local offline fallback, resolves tool execution and threading crashes, and modernizes the user interface into a dark cyber terminal HUD with aligned iconography.

---

### User Review & Critical Decisions

> [!IMPORTANT]
> The following architectural and UX decisions were confirmed during initial clarification and guide this implementation:

- **Confirmed Decision 1 (Runtime & Target)**: Native Linux Mint Python 3.8+ / PyQt6 desktop application only, formatted and packaged cleanly for direct push to GitHub.
- **Confirmed Decision 2 (AI Intelligence Mode)**: Google Gemini API integration (`gemini-3.8-flash` via official SDK / REST) with automatic fallback to local rule-based / TF-IDF offline intelligence when the API key is absent or network is disconnected.
- **Confirmed Decision 3 (GUI Aesthetic)**: Dark cyber terminal HUD with real-time visual diagnostics, telemetry meters, unified SVG iconography, and responsive grid layouts.

---

### 1. Overview & Core Concept

- **What It Does**: AI AYFAM is a Linux Mint cybersecurity cockpit providing real-time port auditing, UFW firewall inspection, SUID privilege escalation detection, BadUSB forensics, secret leak detection, automated system hardening, and interactive AI threat intelligence.
- **Target Audience / Persona**: Linux Mint / Ubuntu administrators, penetration testers, security engineers, and privacy-conscious users seeking local or cloud-assisted security posture enforcement.
- **Key Value**: Direct hardware and OS inspection with root safety preflights, instant automated remediation scripts, and zero downtime even without an internet connection or external API credentials.

---

### 2. User Experience & Visual Design

#### Key User Flows
1. **Launch & Diagnostics Check**: Launch via `ayfam` or `./ayfam-gui-launcher.sh`. The app validates root permissions, Python dependencies, and available external binaries (Nmap, Lynis, YARA, USBGuard).
2. **Operations Cockpit (غرفة العمليات)**: Real-time gauge dials showing security posture score (0–100%), live memory/CPU meters, open socket counts, and an event ticker.
3. **Automated Audit & Remediation**: User triggers an audit; background `QThread` workers execute checks without freezing the UI. Vulnerabilities appear as cards with ATT&CK tags and one-click "Apply Fix" or global "Auto-Reactor" buttons.
4. **AI Security Assistant (المحادثة الأمنية)**: Interactive chat supporting Arabic and English. If `GEMINI_API_KEY` is present, it uses Gemini Flash CTI; if absent, it gracefully uses the offline concept engine.
5. **USB & Hardware Forensics (الأجهزة المتصلة)**: Displays connected USB peripherals with VID/PID, BadUSB risk scoring, and kernel authorization toggles.
6. **Incident Playbooks & Reports**: Step-by-step checklists for Ransomware containment, SSH brute-force defense, and exportable audit reports.

#### Visual Identity & Theme
- **Aesthetic Direction**: Military/Cyber SOC Terminal HUD — minimalist dark theme, high-contrast indicators, monospace telemetry, and clean Arabic typography (Cairo/System Sans).
- **Color Palette & Mood**:
  - Background Base: `#060911` (Deep Abyss)
  - Surface Panels: `#0d1322` (Cyber Surface)
  - Accent / Primary: `#10b981` (Terminal Emerald)
  - Diagnostic Cyan: `#06b6d4` (Telemetry Cyan)
  - Warning: `#f59e0b` (Caution Amber)
  - Critical / Threat: `#f43f5e` (Alert Crimson)
  - Text Primary: `#f8fafc`, Text Muted: `#64748b`
- **Iconography & Layout**:
  - Crisp, scalable SVG icons aligned with buttons and headers (no pixelation or misaligned text).
  - Clear section titles with category tags and status pills.
- **Interactive Feedback & Motion**:
  - Pulsing activity LEDs for background thread execution.
  - Smooth progress bars and copy-to-clipboard confirmation toasts.

---

### 3. Key Product Decisions & Trade-Offs

- **Decision 1: Multi-Threaded Worker Engine (`QThread`)**:
  - *Chosen Approach*: Decouple all OS scans, subprocess executions, and network requests into dedicated `QThread` workers emitting Qt signals (`pyqtSignal`).
  - *Why*: Eliminates GUI freezing ("Not Responding") and avoids X11/Wayland crash aborts during heavy scans.
  - *Alternatives Considered*: Running scans synchronously on the main thread was the primary cause of previous crashes.

- **Decision 2: Resilient Dual-Layer AI Engine**:
  - *Chosen Approach*: Check for `GEMINI_API_KEY` in environment or settings. If valid, connect to `gemini-3.8-flash` for threat enrichment and conversational advice; if absent or on timeout, transparently fall back to local rule-based / TF-IDF logic.
  - *Why*: Guarantees the application remains 100% functional offline while offering advanced generative intelligence when configured.
  - *Alternatives Considered*: Hard failure on missing API key prevented offline usage on Linux Mint.

- **Decision 3: Safe Subprocess Execution & Root Preflight**:
  - *Chosen Approach*: Validate command arguments, enforce strict timeouts, and wrap all shell executions in `safe_exec.py` with sanitized error reporting.
  - *Why*: Protects against command injection and prevents hanging threads on interactive prompts.

---

### 4. Technical Architecture & Data Strategy

#### System & Component Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                   AI AYFAM Linux Mint Desktop App                     │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
               ┌───────────────────┴───────────────────┐
               ▼                                       ▼
┌──────────────────────────────┐       ┌─────────────────────────────────┐
│     PyQt6 GUI Cockpit        │       │      CLI / Terminal Engine      │
│  - UnifiedCockpitWindow      │       │  - TerminalUI (Rich / ANSI)     │
│  - Dark Cyber HUD Theme      │       │  - Argparse command runner      │
│  - SVG Iconography System    │       │  - Scriptable batch mode        │
└──────────────┬───────────────┘       └────────────────┬────────────────┘
               │                                        │
               └───────────────────┬────────────────────┘
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      AYFAM Core Agent (core/agent.py)                  │
│   - Task Dispatcher & Event Logger                                     │
│   - Telemetry Collector & Risk Scoring Engine (engine/risk.py)         │
└───────┬───────────────────┬────────────────────┬─────────────────┬─────┘
        │                   │                    │                 │
        ▼                   ▼                    ▼                 ▼
┌──────────────┐    ┌──────────────┐     ┌──────────────┐   ┌────────────┐
│ Security     │    │ USB          │     │ AI Threat    │   │ Playbooks  │
│ Scanners     │    │ Forensics    │     │ Intelligence │   │ & Reports  │
│ - Ports      │    │ - USBGuard   │     │ - Gemini CTI │   │ - Incident │
│ - SSH & UFW  │    │ - BadUSB     │     │ - Offline ML │   │   SOPs     │
│ - SUID       │    │ - MassStore  │     │ - CVE/NVD    │   │ - HTML/JSON│
│ - Leaks/YARA │    │   Heuristics │     │ - ATT&CK Map │   │   Export   │
└──────────────┘    └──────────────┘     └──────────────┘   └────────────┘
```

#### Core Data Entities
- **`Finding`**: Standardized dictionary model containing `id`, `severity` (critical, high, medium, low, info), `title`, `detail`, `fix`, `category`, `attack_ids`, `fix_cmds`, and `risk_of_fix`.
- **`SystemTelemetry`**: Live system metrics (CPU load, RAM usage, storage mount points, listening sockets, kernel release).
- **`UsbDeviceRecord`**: Hardware descriptors (vendor_id, product_id, bus_device, classification, authorization status, risk level).
- **`ThreatContext`**: CVE records, CVSS scores, affected packages, and MITRE tactics.

#### Execution Phases & File Modifications
1. **Environment & Dependency Setup**:
   - Update `requirements.txt` with verified PyQt6, requests, google-genai, and python-dotenv versions.
   - Fix `setup.sh` and `ayfam-gui-launcher.sh` for Linux Mint 20/21/22 desktop integration.
2. **AI Engine Refactor (`engine/gemini_cti.py` & `brain/nlp.py`)**:
   - Implement `GeminiCTIEngine` with `gemini-3.8-flash` calling patterns and offline fallback handler.
   - Clean up API key loading from `.env` or system environment without crashing.
3. **Core Scanners & Safe Execution Fixes**:
   - Repair `tools/system.py`, `tools/network.py`, `tools/usb.py`, and `engine/hardening.py`.
   - Ensure commands run with proper non-blocking timeouts and sudo validation.
4. **PyQt6 GUI Overhaul (`ui/gui_app.py` & `ui/theme.py`)**:
   - Redesign window layout to dark cyber HUD with organized navigation tabs.
   - Fix icon sizing, SVG rendering, and layout overlap issues.
   - Connect all buttons to real asynchronous `WorkerThread` instances.
5. **Validation & Testing**:
   - Run unit test suite in `tests/` verifying scanner outputs, offline fallbacks, and GUI startup sanity.
