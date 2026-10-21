# 📦 دليل التثبيت الكامل — AI AYFAM
# Complete Installation Guide — AI AYFAM

## الطريقة 1: من GitHub (الأسرع) / Method 1: From GitHub (Fastest)

```bash
git clone https://github.com/YOUR-USERNAME/AI-AYFAM.git
cd AI-AYFAM
chmod +x setup.sh
./setup.sh
```

ينشئ `setup.sh` بيئة `.venv` خاصة بالتطبيق ويثبت المكتبات داخلها، ولا يستخدم
`pip --break-system-packages` أو يعبث بحزم Python الخاصة بالنظام.

إذا ظهر خطأ من نوع `Cannot uninstall pip ... RECORD file not found`، فهذا يعني
أن سكربتًا قديمًا توقف قبل تحديث المشغّل. اسحب آخر نسخة ثم أعد التثبيت؛ النسخة
الحالية لا تحدّث pip نفسه ولا تحاول إزالة حزم apt:

```bash
cd ~/AI-AYFAM
git pull --ff-only origin main
chmod +x setup.sh
./setup.sh
ayfam --check
```

## الطريقة 2: رفع المشروع على GitHub / Method 2: Push to GitHub

### الخطوات / Steps:

```bash
# 1. انتقل إلى مجلد المشروع / Go to project folder
cd AI-AYFAM

# 2. ابدأ Git / Initialize Git
git init

# 3. أضف كل الملفات / Add all files
git add .

# 4. أول commit
git commit -m "🛡️ Initial commit — AI AYFAM Cybersecurity Agent"

# 5. أنشئ مستودع GitHub جديد من الموقع / Create GitHub repo at:
#    https://github.com/new
#    الاسم المقترح: AI-AYFAM

# 6. اربط المشروع بـ GitHub / Link to GitHub
git remote add origin https://github.com/YOUR-USERNAME/AI-AYFAM.git

# 7. ارفع المشروع / Push project
git branch -M main
git push -u origin main
```

## بعد التثبيت / After Installation

```bash
# فحص المتطلبات دون تشغيل الواجهة / Check dependencies only
ayfam --check

# تشغيل تطبيق سطح المكتب / Run the desktop application
ayfam

# تشغيل دون شاشة المقدمة / Run without splash screen
ayfam --no-splash

# عرض الإصدار / Show version
ayfam --version
```

بعد تشغيل `setup.sh` تظهر أيقونة **AI AYFAM Security Center** في قائمة
التطبيقات. يمكن تشغيل الواجهة من الطرفية أيضًا:

```bash
ayfam-gui
```

تعمل الواجهة بحساب المستخدم داخل جلسة سطح المكتب الحالية، وتستخدم طبقة
التنفيذ الآمن لطلب الامتياز فقط عند الحاجة إلى عملية إدارية محددة.

## المتطلبات / Requirements

| المطلوب | الإصدار |
|---------|---------|
| Linux Mint / Ubuntu / Debian | 20+ |
| Python | 3.10+ |
| pip/venv | ضمن البيئة الافتراضية التي ينشئها المثبت |
| PyQt6 (للواجهة) | 6.5+ |
| nmap (لفحص المنافذ) | أي |
| adb (اختياري، للهواتف) | أي |

## الأدوات الموصى بها / Recommended Tools

```bash
sudo apt install nmap usbutils adb net-tools iproute2 lynis chkrootkit fail2ban
```

## الصلاحيات / Privileges

تعمل واجهة سطح المكتب بحساب المستخدم للحفاظ على DISPLAY/Wayland وDBus وXAuthority.
بعض الفحوصات أو عمليات التحصين قد تحتاج امتيازاً، وتتم معالجتها عبر طبقة التنفيذ
الآمن بدلاً من تشغيل التطبيق كاملاً بصلاحيات root.
