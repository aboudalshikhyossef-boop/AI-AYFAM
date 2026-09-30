"""
AI AYFAM v5 — Automated Remediation Planner
مولّد خطة المعالجة الذكي — يجمع الإصلاحات ويرتبها وينتج سكريبت Bash تنفيذي
آمن وقابل للمراجعة مع دعم النسخ الاحتياطي ووضع التجربة (Dry-run).
"""

from typing import List
from datetime import datetime
from engine.finding import Finding

class RemediationPlanner:
    @staticmethod
    def generate_bash_script(findings: List[Finding], filename: str = "ayfam-remediation.sh") -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        seen_cmds = set()
        unique_fixes = []

        for f in findings:
            fix = f.get("fix", "").strip()
            if not fix or fix.startswith("#"):
                continue
            lines = [l.strip() for l in fix.splitlines() if l.strip() and not l.strip().startswith("#")]
            for cmd in lines:
                if cmd not in seen_cmds:
                    seen_cmds.add(cmd)
                    unique_fixes.append((cmd, f.get("title", "")))

        script_lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            "#  AI AYFAM v5 — Auto-Generated Remediation Script",
            f"#  Generated at: {now}",
            "#  Run with: sudo bash ayfam-remediation.sh [--dry-run]",
            "# ==============================================================================",
            "",
            "set -euo pipefail",
            "",
            'DRY_RUN=false',
            'if [[ "${1:-}" == "--dry-run" ]]; then',
            '    DRY_RUN=true',
            '    echo "[*] وضع المحاكاة مفعل (Dry-Run) — لن يتم تطبيق أي تغيير فعلي."',
            'fi',
            "",
            'execute() {',
            '    local cmd="$1"',
            '    local title="$2"',
            '    echo -e "\\n[*] معالجة: $title"',
            '    echo "    الأمر: $cmd"',
            '    if [ "$DRY_RUN" = false ]; then',
            '        eval "$cmd"',
            '        echo "    ✓ تم التطبيق بنجاح."',
            '    fi',
            '}',
            "",
            '# إنشاء نقطة نسخ احتياطي لإعدادات النظام',
            'BACKUP_DIR="/var/backups/ayfam_$(date +%Y%m%d_%H%M%S)"',
            'if [ "$DRY_RUN" = false ]; then',
            '    mkdir -p "$BACKUP_DIR"',
            '    echo "[*] تم إنشاء مجلد النسخ الاحتياطي في: $BACKUP_DIR"',
            '    [ -f /etc/ssh/sshd_config ] && cp -a /etc/ssh/sshd_config "$BACKUP_DIR/" || true',
            '    [ -f /etc/sysctl.conf ] && cp -a /etc/sysctl.conf "$BACKUP_DIR/" || true',
            'fi',
            "",
        ]

        for cmd, title in unique_fixes:
            safe_title = title.replace('"', '\\"')
            safe_cmd = cmd.replace('"', '\\"')
            script_lines.append(f'execute "{safe_cmd}" "{safe_title}"')

        script_lines.append("")
        script_lines.append('echo -e "\\n[✓] اكتملت جميع خطوات المعالجة بنجاح!"')
        return "\n".join(script_lines)
