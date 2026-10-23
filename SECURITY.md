# AI AYFAM Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability within AI AYFAM, please do NOT create a public issue. Instead, report it directly to the maintainers following these steps:

1. **Email:** Send a detailed report to `security@ayfam.local` or contact the core maintainers privately.
2. **Report Details:**
   - Description of the flaw and potential security impact.
   - Proof of Concept (PoC) or reproduction steps.
   - Affected components, files, or versions.
3. **Response Time:** We aim to acknowledge receipt within 48 hours and provide a patch timeline within 7 business days.

## Security Guidelines for Contributions
- Subprocess execution must strictly go through `utils/safe_exec.py` without `shell=True`.
- Untrusted inputs (USB labels, log lines, process names, banners) must be sanitized before UI rendering or script generation.
- All privileged operations must run through the Polkit helper daemon (`engine/privileged/helper.py`).
