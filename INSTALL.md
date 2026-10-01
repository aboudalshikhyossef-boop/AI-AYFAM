# 📦 دليل التثبيت الكامل — AI AYFAM
# Complete Installation Guide — AI AYFAM

## الطريقة 1: من GitHub (الأسرع) / Method 1: From GitHub (Fastest)

```bash
git clone https://github.com/YOUR-USERNAME/AI-AYFAM.git
cd AI-AYFAM
chmod +x setup.sh
./setup.sh
```

يَستخدم `setup.sh` **Python النظام مباشرة** ولا ينشئ `venv` أو أي بيئة افتراضية.
تُثبت المكتبات على مستوى النظام عبر `sudo`، ويعمل الأمر `ayfam` على Python النظام
مع فحص root الحقيقي من النواة.

إذا ظهر خطأ من نوع `Cannot uninstall pip ... RECORD file not found`، فهذا يعني
أن سكربتًا قديمًا توقف قبل تحديث المشغّل. اسحب آخر نسخة ثم أعد التثبيت؛ النسخة
الحالية لا تحدّث pip نفسه ولا تحاول إزالة حزم apt:

```bash
cd ~/AI-AYFAM
git pull --ff-only origin main
chmod +x setup.sh
./setup.sh
sudo ayfam --check-deps
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
# فحص المتطلبات / Check dependencies
sudo ayfam --check-deps

# تشغيل الوكيل بصلاحيات root / Run the agent as root
sudo ayfam

# إضافة GitHub token (اختياري) / Add GitHub token (optional)
sudo ayfam --set-github-token ghp_XXXXXXXXXXXXXXXX

# أول فحص / First scan
sudo ayfam --scan full
```

## المتطلبات / Requirements

| المطلوب | الإصدار |
|---------|---------|
| Linux Mint / Ubuntu / Debian | 20+ |
| Python | 3.8+ |
| pip | أي إصدار |
| PyQt6 (للواجهة) | 6.5+ |
| nmap (لفحص المنافذ) | أي |
| adb (اختياري، للهواتف) | أي |

## الأدوات الموصى بها / Recommended Tools

```bash
sudo apt install nmap usbutils adb net-tools iproute2 lynis chkrootkit fail2ban
```

## الصلاحيات / Privileges

تعمل الأداة عمدًا **بمستخدم root فقط** لأن بعض فحوصات النظام والشبكة وعمليات
التحصين تحتاج قراءة ملفات محمية وتنفيذ أوامر إدارية. إذا كان المستخدم الحالي
غير root فسيتم إيقاف التشغيل برسالة واضحة بدل تنفيذ جزء ناقص من الفحص.
