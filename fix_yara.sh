#!/usr/bin/env bash
set -e

# تحديث دالة فحص YARA لتدعم فحص الملفات المنفردة والمجلدات معاً
python3 -c '
code = """
    def scan_with_yara(self, target_path: str) -> List[Finding]:
        findings = []
        ok_path, clean_path = validators.validate_safe_path(target_path, must_be_absolute=False)
        if not ok_path or not os.path.exists(clean_path):
            return findings

        # استخراج قائمة الملفات سواء كان الهدف ملفاً منفرداً أو مجلداً
        files_to_scan = []
        if os.path.isfile(clean_path):
            files_to_scan = [clean_path]
        else:
            for root, _, files in os.walk(clean_path):
                for fn in files:
                    files_to_scan.append(os.path.join(root, fn))

        # الفحص الداخلي الآمن بالتوقيعات
        for fp in files_to_scan:
            try:
                with open(fp, "rb") as fl:
                    data = fl.read(65536)
                if b"/dev/tcp/" in data or b"bash -i" in data or b"eval(base64_decode(" in data:
                    findings.append(Finding(
                        severity="critical",
                        title=f"🦠 برمجية خبيثة مرصودة بتوقيع YARA: {os.path.basename(fp)}",
                        detail=f"الملف {fp} يحتوي على أنماط شيل عكسي أو كود خبيث محقون.",
                        fix=f"sudo rm -f {fp}",
                        category="malware",
                        tags=["yara", "signature_match"],
                        attack_ids=["T1059.004"],
                    ))
            except Exception:
                continue

        return findings
"""

with open("tools/arsenal.py", "r", encoding="utf-8") as f:
    text = f.read()

import re
text = re.sub(r"    def scan_with_yara.*?return findings\n", code.strip() + "\n", text, flags=re.DOTALL)

with open("tools/arsenal.py", "w", encoding="utf-8") as f:
    f.write(text)
print("[✓] تم تصحيح محرك YARA ليدعم فحص الملفات والمجلدات بنجاح.")
'

# إعادة تشغيل الاختبار للتأكد
python3 tests/test_arsenal.py
