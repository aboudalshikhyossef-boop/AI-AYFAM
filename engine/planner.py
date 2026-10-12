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
            '    # آمن عمداً: لا يوجد تنفيذ ديناميكي ولا تنفيذ تلقائي لأوامر findings.',
            '    echo "    [REVIEW ONLY] راجع الأمر يدوياً ونفذه عبر إصلاح مسجل ومتحقق."',
            '}',
            "",
            '# هذه الخطة غير تنفيذية عمداً: لا تنشئ نسخاً ولا تغيّر النظام.',
            "",
        ]

        for cmd, title in unique_fixes:
            safe_title = title.replace('"', '\\"')
            safe_cmd = cmd.replace('"', '\\"')
            script_lines.append(f'# [REVIEW ONLY] {safe_title}')
            script_lines.append(f'# {safe_cmd}')

        script_lines.append("")
        script_lines.append('echo -e "\\n[INFO] اكتملت قائمة المراجعة؛ لم تُنفذ أي تغييرات."')
        return "\n".join(script_lines)
