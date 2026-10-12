#!/usr/bin/env bash
#
# 🖥️ سكريبت إطلاق الواجهة الرسومية الآمن والذكي
# AI AYFAM GUI Smart Launcher
#

set -euo pipefail

# ── البحث عن مجلد المشروع ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── البحث عن Python من .venv أولاً ──
if [ -f "./.venv/bin/python3" ]; then
    PYTHON_BIN="./.venv/bin/python3"
elif [ -f "./venv/bin/python3" ]; then
    PYTHON_BIN="./venv/bin/python3"
else
    PYTHON_BIN="python3"
fi

# ── البيئة الافتراضية المطلوبة ──
export PYTHONUNBUFFERED=1
export PYTHONPATH="$SCRIPT_DIR:${PYTHONPATH}"

# ── لا تثبّت حزمًا أثناء التشغيل؛ اعرض خطأ واضحًا بدل تغيير البيئة ──
if ! "$PYTHON_BIN" -c "from PyQt6.QtWidgets import QApplication" 2>/dev/null; then
    echo "❌ PyQt6 غير متوفر في: $PYTHON_BIN" >&2
    echo "ثبّت المتطلبات مرة واحدة عبر setup.sh أو: $PYTHON_BIN -m pip install PyQt6" >&2
    exit 2
fi

# تعمل الواجهة بحساب المستخدم كي ترث DISPLAY/Wayland وDBus وXAuthority.
# العمليات التي تحتاج امتيازًا تستخدم طبقة safe_exec/pkexec عند الحاجة.
exec "$PYTHON_BIN" "$SCRIPT_DIR/main.py" --gui "$@"
