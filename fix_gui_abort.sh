#!/usr/bin/env bash
#
# 🔧 تصحيح مشكلة اجهاض الواجهة الرسومية AI AYFAM
# Fix AI AYFAM GUI Abort Issue
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  🔧 AI AYFAM GUI Abort Fix — تصحيح مشكلة اجهاض الواجهة  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"

# ─────────────────────────────────────────────────────────────────────────
# 1️⃣ تحديث الحزم وتثبيت مكتبات X11 المفقودة
# ─────────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[1/5]${NC} تثبيت مكتبات X11 والنظام..."
sudo apt-get update -q
sudo apt-get install -y \
    python3-pyqt6 \
    python3-pyqt6.qtcore \
    python3-pyqt6.qtgui \
    python3-pyqt6.qtwidgets \
    python3-pyqt6.qtprintsupport \
    libgl1 \
    libxcb-cursor0 \
    libxkbcommon-x11-0 \
    libxcb-xinerama0 \
    libxcb-randr0 \
    libxcb-icccm4 \
    libxcb-image0 \
    libxcb-keysyms1 \
    libxcb-render-util0 \
    libxcb-shape0 \
    libxcb-sync1 \
    libxcb-util1 \
    libxcb-xfixes0 \
    libxcb-xinerama0 \
    libxcb-xkb1 \
    libxkb1 \
    libpng16-16 \
    libfontconfig1 \
    libharfbuzz0b \
    libfreetype6

echo -e "${GREEN}✓ مكتبات X11 مثبتة${NC}"

# ─────────────────────────────────────────────────────────────────────────
# 2️⃣ تكوين البيئة الافتراضية لاستخدام PyQt6 من النظام
# ─────────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[2/5]${NC} تكوين البيئة الافتراضية (.venv)..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f ".venv/pyvenv.cfg" ]; then
    sed -i 's/include-system-site-packages = false/include-system-site-packages = true/g' .venv/pyvenv.cfg
    echo -e "${GREEN}✓ تم تفعيل وصول البيئة الافتراضية لحزم النظام${NC}"
fi

# ─────────────────────────────────────────────────────────────────────────
# 3️⃣ تثبيت PyQt6 داخل البيئة الافتراضية أيضاً (كنسخة احتياطية)
# ────────���────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[3/5]${NC} تثبيت PyQt6 في البيئة الافتراضية..."

if [ -d ".venv" ]; then
    # استخدم bash -c لتشغيل source في bash بدلاً من sh
    bash -c "source .venv/bin/activate && pip install --quiet PyQt6 2>/dev/null || true"
    echo -e "${GREEN}✓ PyQt6 مثبت في .venv${NC}"
fi

# ─────────────────────────────────────────────────────────────────────────
# 4️⃣ إنشاء سكريبت إطلاق آمن للواجهة الرسومية
# ─────────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[4/5]${NC} إنشاء سكريبت إطلاق الواجهة الرسومية الآمن..."

APP_DIR="$SCRIPT_DIR"
APP_PYTHON="$APP_DIR/.venv/bin/python3"

# تحقق إذا كانت .venv موجودة، وإلا استخدم python3 الافتراضي
if [ ! -f "$APP_PYTHON" ]; then
    APP_PYTHON="python3"
fi

# إنشاء سكريبت اطلاق عالمي مع معالجة الأخطاء
sudo tee /usr/local/bin/ayfam-gui > /dev/null <<'LAUNCHER_EOF'
#!/usr/bin/env bash
# 
# 🖥️ AI AYFAM Desktop GUI Launcher
# سكريبت إطلاق آمن مع معالجة متقدمة للأخطاء
#

set -e

APP_DIR="$(cd "$(dirname "$(which "$0")")/.." && pwd 2>/dev/null)" || APP_DIR="/opt/ayfam"
if [ ! -f "$APP_DIR/main.py" ]; then
    # حاول العثور على المشروع من المسار الحالي
    if [ -f "./main.py" ]; then
        APP_DIR="."
    else
        echo "❌ Error: Could not locate AI-AYFAM installation directory"
        exit 1
    fi
fi

APP_PYTHON="$APP_DIR/.venv/bin/python3"
if [ ! -f "$APP_PYTHON" ]; then
    APP_PYTHON="python3"
fi

# ─── البيئة الافتراضية المطلوبة ───
export PYTHONUNBUFFERED=1
export QT_QPA_PLATFORM_PLUGIN_PATH="/usr/lib/x86_64-linux-gnu/qt6/plugins:$($APP_PYTHON -c 'import PyQt6.QtCore; print(PyQt6.QtCore.__path__[0])')/plugins"
export QT_DEBUG_PLUGINS=0  # تجنب رسائل التصحيح المزعجة
export PYTHONPATH="$APP_DIR:${PYTHONPATH}"

# حاول بناء قائمة مسارات التوزيعات المعروفة
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/lib:/usr/lib/x86_64-linux-gnu:/usr/local/lib"

# ─── إذا كنت تحت sudo أو بدون صلاحيات root، فجّر sudo ───
if [ "$EUID" -ne 0 ]; then
    # نحتاج إلى صلاحيات root لبعض الفحوصات
    exec sudo env QT_QPA_PLATFORM_PLUGIN_PATH="$QT_QPA_PLATFORM_PLUGIN_PATH" \
                  LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
                  PYTHONPATH="$PYTHONPATH" \
                  "$APP_PYTHON" "$APP_DIR/main.py" --gui "$@"
else
    exec "$APP_PYTHON" "$APP_DIR/main.py" --gui "$@"
fi
LAUNCHER_EOF

sudo chmod +x /usr/local/bin/ayfam-gui
echo -e "${GREEN}✓ سكريبت الإطلاق جاهز: /usr/local/bin/ayfam-gui${NC}"

# ─────────────────────────────────────────────────────────────────────────
# 5️⃣ تحديث اختصار سطح المكتب (.desktop)
# ─────────────────────────────────────────────────────────────────────────
echo -e "\n${YELLOW}[5/5]${NC} تحديث اختصار التطبيق في قائمة التطبيقات..."

DESKTOP_DIR="$HOME/.local/share/applications"
mkdir -p "$DESKTOP_DIR"

cat > "$DESKTOP_DIR/ayfam.desktop" <<'DESKTOP_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=AI AYFAM Security Cockpit
GenericName=Cybersecurity EDR & Sentinel Console
Comment=Enterprise Local Cybersecurity Agent for Linux Mint
Keywords=security;cybersecurity;firewall;network;scanning;
Exec=ayfam-gui %U
Icon=shield
Terminal=false
Categories=System;Security;Settings;
StartupNotify=true
MimeType=text/plain;
Actions=RunAsRoot;

[Desktop Action RunAsRoot]
Name=Run as Administrator
Exec=sudo ayfam-gui
DESKTOP_EOF

chmod +x "$DESKTOP_DIR/ayfam.desktop"
echo -e "${GREEN}✓ اختصار التطبيق مُحدّث${NC}"

# ─────────────────────────────────────────────────────────────────────────
# ✅ الخلاصة والتحقق
# ───────────────────────���─────────────────────────────────────────────────
echo -e "\n${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}[✓] تم تصحيح مشكلة الواجهة الرسومية بنجاح!${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}🔍 التحقق السريع:${NC}"

echo -n "  • PyQt6 Python binding: "
if $APP_PYTHON -c "from PyQt6.QtWidgets import QApplication" 2>/dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗ (اتصل بـ: pip install PyQt6)${NC}"
fi

echo -n "  • Qt Platform Plugins: "
if [ -d "/usr/lib/x86_64-linux-gnu/qt6/plugins" ] || [ -d "/usr/lib/qt6/plugins" ]; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗ (اتصل بـ: sudo apt install python3-pyqt6)${NC}"
fi

echo -n "  • X11 Display: "
if [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ]; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${YELLOW}⚠ (قد تحتاج إلى جلسة سطح مكتب متقدمة)${NC}"
fi

echo -e "\n${BLUE}🚀 الآن يمكنك تشغيل الواجهة بطريقتين:${NC}"
echo -e "  1️⃣  من سطر الأوامر:     ${YELLOW}ayfam-gui${NC}"
echo -e "  2️⃣  من قائمة التطبيقات: ابحث عن ${YELLOW}AI AYFAM Security Cockpit${NC}"
echo ""
echo -e "${GREEN}حظاً موفقاً! / Good luck! 🛡️${NC}\n"
