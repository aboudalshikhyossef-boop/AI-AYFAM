#!/bin/bash
# ====================================================
#  AI AYFAM v3 — سكريبت التثبيت — Linux Mint
# ====================================================

set -eo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'; BGREEN='\033[1;32m'

info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${BGREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

echo -e "${BGREEN}"
cat <<'BANNER'
  ╔══════════════════════════════════════════════════════════════╗
  ║  AI AYFAM v3  —  وكيل الأمن السيبراني الذكي                ║
  ║  Smart Cybersecurity Agent — Self-Learning · NLP-Powered    ║
  ╚══════════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Python ────────────────────────────────────────────────────────────────────
info "التحقق من Python 3.8+..."
if ! command -v python3 &>/dev/null; then
    warn "Python 3 غير مثبت — تثبيت..."
    sudo apt-get update -q && sudo apt-get install -y python3 python3-pip python3-venv
fi
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED="3.8"
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)"; then
    success "Python $PY_VER ✓"
else
    error "Python $PY_VER غير مدعوم — يلزم $REQUIRED+"
fi

# ── Python النظام — بدون venv أو بيئة افتراضية ───────────────────────────────
APP_PYTHON="/usr/bin/python3"
info "تثبيت مكتبات AI AYFAM في Python النظام مباشرة — بدون venv..."
PIP_SYSTEM_FLAG=""
if "$APP_PYTHON" -m pip help install 2>/dev/null | grep -q -- '--break-system-packages'; then
    PIP_SYSTEM_FLAG="--break-system-packages"
fi
PIP_LOG="$HOME/.cache/ayfam/setup-pip.log"
mkdir -p "$(dirname "$PIP_LOG")"
if ! sudo "$APP_PYTHON" -m pip install --ignore-installed $PIP_SYSTEM_FLAG --progress-bar on --disable-pip-version-check \
    --timeout 120 --retries 5 -r requirements.txt 2>&1 | tee "$PIP_LOG"; then
    error "فشل تثبيت مكتبات Python. راجع السجل: $PIP_LOG"
fi
success "مكتبات Python النظام جاهزة (بما فيها PyQt6 ومحركات التحليل)"

# ── System tools ──────────────────────────────────────────────────────────────
info "التحقق من أدوات الأمن..."
declare -A TOOLS=(
    ["nmap"]="nmap"
    ["lsusb"]="usbutils"
    ["adb"]="adb"
    ["ss"]="iproute2"
    ["netstat"]="net-tools"
    ["iw"]="iw"
    ["hciconfig"]="bluez-tools"
    ["curl"]="curl"
    ["ufw"]="ufw"
    ["pkexec"]="policykit-1"
)
INSTALL_PKGS=""
for bin in "${!TOOLS[@]}"; do
    if ! command -v "$bin" &>/dev/null; then
        warn "  $bin غير موجود"
        INSTALL_PKGS="$INSTALL_PKGS ${TOOLS[$bin]}"
    fi
done
if [ -n "$INSTALL_PKGS" ]; then
    info "تثبيت:$INSTALL_PKGS"
    sudo apt-get update
    sudo apt-get install -y $INSTALL_PKGS || warn "بعض الأدوات لم تُثبَّت"
fi
success "أدوات النظام جاهزة"

# ── Qt/X11 runtime للواجهة ────────────────────────────────────────────────────
info "التحقق من مكتبات Qt/X11 اللازمة للواجهة..."
QT_PACKAGES=(
    libgl1 libxcb-cursor0 libxkbcommon-x11-0 libxcb-xinerama0
    libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0
    libxcb-xkb1 libxcb-randr0 libxcb-shape0 libxcb-xfixes0 libxcb-sync1
    libxcb-shm0 libxcb-util1 libx11-xcb1
)
QT_MISSING=0
for pkg in "${QT_PACKAGES[@]}"; do
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed" || QT_MISSING=1
done
if [ "$QT_MISSING" -eq 1 ]; then
    sudo apt-get update -q
    sudo apt-get install -y "${QT_PACKAGES[@]}" || error "تعذر تثبيت مكتبات Qt/X11 المطلوبة للواجهة"
fi
success "مكتبات Qt/X11 جاهزة"

QT_XCB_PLUGIN="$($APP_PYTHON -c 'from pathlib import Path; from PyQt6.QtCore import QLibraryInfo; print(Path(QLibraryInfo.path(QLibraryInfo.LibraryPath.PluginsPath)) / "platforms/libqxcb.so")')"
[[ -f "$QT_XCB_PLUGIN" ]] || error "لم يتم العثور على إضافة Qt X11: $QT_XCB_PLUGIN"
QT_MISSING_LIBS="$(ldd "$QT_XCB_PLUGIN" 2>/dev/null | awk '/not found/{print $1}')"
if [[ -n "$QT_MISSING_LIBS" ]]; then
    error "إضافة Qt X11 موجودة لكن ينقصها ربط المكتبات التالية: $QT_MISSING_LIBS"
fi
success "اعتماديات إضافة Qt X11 (xcb) مكتملة"

# اختبر الاستيراد وبدء Qt؛ قد تعرض pip تحذيرات عن حزم خارج AI AYFAM ولا نوقف
# التثبيت بسببها، لأن هذه الحزم لا تدخل في تشغيل الأداة.
"$APP_PYTHON" -m pip check || warn "توجد تعارضات في حزم Python خارج متطلبات AI AYFAM؛ راجع سجل pip عند الحاجة"
if ! QT_QPA_PLATFORM=offscreen "$APP_PYTHON" - <<'PY'
import rich, requests, pypdf, sklearn, numpy, scipy
from PyQt6.QtWidgets import QApplication

app = QApplication([])
print("فحص استيراد مكتبات Python وبدء Qt: OK")
PY
then
    error "تعذر تحميل مكتبات Python أو بدء Qt. راجع سجل pip ومكتبات Qt/X11"
fi

# اجعل USB متطلباً صريحاً، لا تحذيراً اختيارياً بعد نجاح التثبيت.
"$APP_PYTHON" - <<'PY'
from utils.preflight import check_requirements
report = check_requirements({"gui", "usb"})
if not report.ok:
    print(report.text())
    raise SystemExit("متطلبات GUI وUSB الأساسية ناقصة")
print("فحص متطلبات GUI وUSB: OK")
PY

# ── fail2ban (اختياري) ───────────────────────────────────────────────────────
if ! command -v fail2ban-server &>/dev/null; then
    read -rp "  تثبيت fail2ban (موصى به للحماية)؟ [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && sudo apt-get install -y fail2ban && success "fail2ban مُثبَّت"
fi

# ── إعداد قاعدة المعرفة ───────────────────────────────────────────────────────
info "تهيئة قاعدة المعرفة SQLite..."
mkdir -p ~/ayfam-reports
sudo mkdir -p /root/ayfam-reports
sudo -H "$APP_PYTHON" -c "
from brain.knowledge_base import KnowledgeBase
kb = KnowledgeBase()
stats = kb.get_stats()
print(f'  قاعدة المعرفة: {stats[\"knowledge_entries\"]} سجل، {stats[\"db_size_mb\"]} MB')
" && success "قاعدة المعرفة جاهزة (~/.ayfam/brain.db)"

# ── Launcher ──────────────────────────────────────────────────────────────────
info "إنشاء أمر 'ayfam' عالمي..."
LAUNCHER="/usr/local/bin/ayfam"
sudo tee "$LAUNCHER" > /dev/null <<EOF
#!/bin/bash
exec "$APP_PYTHON" "$SCRIPT_DIR/main.py" "\$@"
EOF
sudo chmod +x "$LAUNCHER"
success "الأمر 'ayfam' جاهز"

# ── مشغّل الواجهة وأيقونة قائمة التطبيقات ────────────────────────────────────
info "إنشاء مشغّل الواجهة الرسومية وأيقونة قائمة التطبيقات..."
GUI_LAUNCHER="/usr/local/bin/ayfam-gui"
sudo tee "$GUI_LAUNCHER" > /dev/null <<EOF
#!/usr/bin/env bash
set -euo pipefail
APP_DIR="$SCRIPT_DIR"
LOG_DIR="\${XDG_STATE_HOME:-\$HOME/.local/state}/ayfam"
mkdir -p "\$LOG_DIR"
LOG_FILE="\$LOG_DIR/gui.log"
printf '[%s] Starting GUI as %s (DISPLAY=%s, WAYLAND_DISPLAY=%s)\\n' "\$(date '+%F %T')" "\$(id -un)" "\${DISPLAY:-unset}" "\${WAYLAND_DISPLAY:-unset}" >>"\$LOG_FILE"
exec /usr/bin/python3 "\$APP_DIR/main.py" --gui "\$@" >>"\$LOG_FILE" 2>&1
EOF
sudo chmod +x "$GUI_LAUNCHER"

DESKTOP_FILE="/usr/share/applications/ayfam.desktop"
sudo tee "$DESKTOP_FILE" > /dev/null <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=AI AYFAM Security Center
Name[ar]=مركز AI AYFAM الأمني
Comment=AI AYFAM cybersecurity control center
Comment[ar]=مركز التحكم الأمني AI AYFAM
Exec=$GUI_LAUNCHER
Icon=$SCRIPT_DIR/resources/icon.svg
Terminal=false
Categories=System;Security;
StartupNotify=true
EOF
sudo chmod 644 "$DESKTOP_FILE"
command -v update-desktop-database >/dev/null 2>&1 && sudo update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
DESKTOP_USER="${SUDO_USER:-$(id -un)}"
DESKTOP_HOME="$(getent passwd "$DESKTOP_USER" | cut -d: -f6)"
[[ -n "$DESKTOP_HOME" ]] || error "تعذر تحديد مجلد المستخدم $DESKTOP_USER لإنشاء أيقونة سطح المكتب"
DESKTOP_DIR="$DESKTOP_HOME/Desktop"
if command -v xdg-user-dir >/dev/null 2>&1; then
    XDG_DESKTOP_DIR="$(sudo -u "$DESKTOP_USER" xdg-user-dir DESKTOP 2>/dev/null || true)"
    [[ -z "$XDG_DESKTOP_DIR" ]] || DESKTOP_DIR="$XDG_DESKTOP_DIR"
fi
DESKTOP_GROUP="$(id -gn "$DESKTOP_USER")"
sudo install -d -o "$DESKTOP_USER" -g "$DESKTOP_GROUP" "$DESKTOP_DIR"
USER_DESKTOP_FILE="$DESKTOP_DIR/AI-AYFAM.desktop"
sudo install -m 755 -o "$DESKTOP_USER" -g "$DESKTOP_GROUP" "$DESKTOP_FILE" "$USER_DESKTOP_FILE"
if command -v gio >/dev/null 2>&1; then
    sudo -u "$DESKTOP_USER" gio set "$USER_DESKTOP_FILE" metadata::trusted true 2>/dev/null || true
fi
[[ -x "$USER_DESKTOP_FILE" ]] || error "تعذر إنشاء أيقونة سطح المكتب: $USER_DESKTOP_FILE"
success "أيقونة AI AYFAM أُضيفت إلى قائمة التطبيقات وسطح مكتب $DESKTOP_USER"
info "سجل تشغيل الواجهة: $DESKTOP_HOME/.local/state/ayfam/gui.log"

# ── تفعيل UFW ─────────────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
    UFW_STATUS=$(sudo ufw status 2>/dev/null | head -1)
    if echo "$UFW_STATUS" | grep -qi "inactive"; then
        read -rp "  تفعيل جدار الحماية UFW؟ [Y/n]: " ans
        if [[ ! "$ans" =~ ^[Nn]$ ]]; then
            sudo ufw --force enable 2>/dev/null && success "UFW مُفعَّل"
        fi
    else
        success "UFW: $UFW_STATUS"
    fi
fi

echo ""
echo -e "${BGREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗"
echo -e "║  ✅  AI AYFAM v3 جاهز! / Ready to launch!                   ║"
echo -e "╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}كيفية الاستخدام:${NC}"
echo "    sudo ayfam               → وضع محادثة ذكي (اكتب بالعربي أو الإنجليزي)"
echo "    sudo ayfam --check-deps  → فحص المتطلبات والأدوات الناقصة"
echo "    sudo ayfam --scan network → فحص الشبكة"
echo "    sudo ayfam --scan usb    → مركز تحكم USB"
echo "    sudo ayfam --scan full   → فحص شامل"
echo "    sudo ayfam --status      → حالة الوكيل وإحصائيات قاعدة المعرفة"
echo "    sudo ayfam --update      → تحديث معلومات التهديدات من الإنترنت"
echo "    ayfam-gui                → فتح الواجهة الرسومية / أيقونة قائمة التطبيقات"
echo "    sudo ayfam --configure-gemini → حفظ مفتاح Gemini بشكل مخفي"
echo "    sudo ayfam --gemini-threats   → CTI آخر 48 ساعة + مطابقة محلية"
echo ""
echo -e "  ${YELLOW}إعداد GitHub (اختياري — لرفع التقارير):${NC}"
echo "    1. https://github.com/settings/tokens"
echo "    2. أنشئ Token بصلاحيات: repo, read:user"
echo "    3. ayfam --set-github-token ghp_XXXXXXXX"
echo ""
echo -e "  ${CYAN}مثال على المحادثة الذكية:${NC}"
echo "    > افحص الشبكة"
echo "    > ما هو CVE-2024-1234"
echo "    > اشرح brute force"
echo "    > تحليل USB"
echo "    > ابحث عن ثغرات OpenSSL"
echo ""
