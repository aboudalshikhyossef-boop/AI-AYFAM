#!/usr/bin/env bash
#
# 🖥️ سكريبت إطلاق الواجهة الرسومية الآمن والذكي
# AI AYFAM GUI Smart Launcher
#

set -e

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
export QT_QPA_PLATFORM_PLUGIN_PATH=""
export PYTHONPATH="$SCRIPT_DIR:${PYTHONPATH}"

# ── محاولة إعادة تثبيت PyQt6 إذا كانت هناك مشكلة ──
if ! "$PYTHON_BIN" -c "from PyQt6.QtWidgets import QApplication" 2>/dev/null; then
    echo "⚠️  PyQt6 غير متوفر، جاري المحاولة لتثبيته..."
    "$PYTHON_BIN" -m pip install --quiet PyQt6 2>/dev/null || true
fi

# ── إذا كنت بدون root، جرّب sudo ──
if [ "$EUID" -ne 0 ]; then
    exec sudo env PYTHONPATH="$PYTHONPATH" \
                  PYTHONUNBUFFERED=1 \
                  "$PYTHON_BIN" "$SCRIPT_DIR/main.py" --gui "$@"
else
    exec "$PYTHON_BIN" "$SCRIPT_DIR/main.py" --gui "$@"
fi
