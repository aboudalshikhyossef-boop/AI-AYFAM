#!/usr/bin/env bash
set -e

echo "[*] جاري تثبيت scikit-learn والمكتبات الرياضية على النظام..."
sudo apt-get update -q
sudo apt-get install -y python3-sklearn python3-numpy python3-scipy python3-pypdf

# إذا كانت البيئة الافتراضية موجودة نثبت فيها أيضاً
if [ -d ".venv" ]; then
    source .venv/bin/activate
    pip install --quiet scikit-learn numpy scipy pypdf 2>/dev/null || true
fi

# ضبط سكريبت ayfam-gui وملف سطح المكتب لاستخدام بايثون الصحيح تلقائياً
APP_DIR="$(pwd)"
PY_BIN="python3"
if [ -f "$APP_DIR/.venv/bin/python3" ]; then
    PY_BIN="$APP_DIR/.venv/bin/python3"
fi

sudo tee /usr/local/bin/ayfam-gui > /dev/null << LEOF
#!/usr/bin/env bash
exec "$PY_BIN" "$APP_DIR/main.py" --gui "\$@"
LEOF
sudo chmod +x /usr/local/bin/ayfam-gui

# تحديث اختصار سطح المكتب
cat << DEOF > ~/.local/share/applications/ayfam.desktop
[Desktop Entry]
Version=1.0
Type=Application
Name=AI AYFAM Security Cockpit
GenericName=Cybersecurity EDR & Sentinel Console
Comment=Enterprise Local Cybersecurity Agent for Linux Mint
Exec=$PY_BIN $APP_DIR/main.py --gui
Icon=$APP_DIR/resources/icon.svg
Terminal=false
Categories=System;Security;Settings;
StartupNotify=true
DEOF
chmod +x ~/.local/share/applications/ayfam.desktop

echo "[✓] تم تثبيت المكتبة وضبط مسارات النظام بنجاح!"
echo "[*] جاري فتح التطبيق المكتبي الآن..."
ayfam-gui &
