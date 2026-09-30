#!/bin/bash
# ====================================================
#  AI AYFAM v3 — سكريبت التثبيت — Linux Mint
# ====================================================

set -e

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

# ── Virtual env ───────────────────────────────────────────────────────────────
info "إنشاء بيئة Python افتراضية..."
python3 -m venv .venv 2>/dev/null || true
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
success "مكتبات Python جاهزة (rich, requests)"

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
    sudo apt-get update -q
    sudo apt-get install -y $INSTALL_PKGS 2>/dev/null || warn "بعض الأدوات لم تُثبَّت"
fi
success "أدوات النظام جاهزة"

# ── fail2ban (اختياري) ───────────────────────────────────────────────────────
if ! command -v fail2ban-server &>/dev/null; then
    read -rp "  تثبيت fail2ban (موصى به للحماية)؟ [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && sudo apt-get install -y fail2ban && success "fail2ban مُثبَّت"
fi

# ── إعداد قاعدة المعرفة ───────────────────────────────────────────────────────
info "تهيئة قاعدة المعرفة SQLite..."
mkdir -p ~/.ayfam ~/ayfam-reports
python3 -c "
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
source "$SCRIPT_DIR/.venv/bin/activate"
exec python3 "$SCRIPT_DIR/main.py" "\$@"
EOF
sudo chmod +x "$LAUNCHER"
success "الأمر 'ayfam' جاهز"

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
echo "    ayfam                    → وضع محادثة ذكي (اكتب بالعربي أو الإنجليزي)"
echo "    ayfam --scan network     → فحص الشبكة"
echo "    ayfam --scan usb         → مركز تحكم USB"
echo "    ayfam --scan full        → فحص شامل"
echo "    ayfam --status           → حالة الوكيل وإحصائيات قاعدة المعرفة"
echo "    ayfam --update           → تحديث معلومات التهديدات من الإنترنت"
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
