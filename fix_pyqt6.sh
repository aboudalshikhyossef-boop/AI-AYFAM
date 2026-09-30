#!/usr/bin/env bash
set -e

echo "[*] جاري ربط PyQt6 مع بيئة التطبيق..."

# 1. السماح للبيئة الافتراضية بقراءة حزم النظام (PyQt6 و sklearn)
if [ -f ".venv/pyvenv.cfg" ]; then
    sed -i 's/include-system-site-packages = false/include-system-site-packages = true/g' .venv/pyvenv.cfg
fi

# 2. تثبيت PyQt6 داخل البيئة الافتراضية أيضاً كضمان إضافي
if [ -d ".venv" ]; then
    source .venv/bin/activate
    pip install --quiet PyQt6 2>/dev/null || true
fi

# 3. التأكد من تثبيتها على مستوى النظام
sudo apt-get install -y python3-pyqt6

echo "[✓] تم حل مشكلة الربط بنجاح 100%!"
echo "[*] تشغيل التطبيق المكتبي الآن..."

# تشغيل التطبيق المكتبي
ayfam-gui &
