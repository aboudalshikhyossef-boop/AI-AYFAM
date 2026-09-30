# 📦 دليل التثبيت الكامل — AI AYFAM
# Complete Installation Guide — AI AYFAM

## الطريقة 1: من GitHub (الأسرع) / Method 1: From GitHub (Fastest)

```bash
git clone https://github.com/YOUR-USERNAME/AI-AYFAM.git
cd AI-AYFAM
chmod +x setup.sh
./setup.sh
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
# تشغيل الوكيل / Run the agent
ayfam

# إضافة GitHub token (اختياري) / Add GitHub token (optional)
ayfam --set-github-token ghp_XXXXXXXXXXXXXXXX

# أول فحص / First scan
ayfam scan full
```

## المتطلبات / Requirements

| المطلوب | الإصدار |
|---------|---------|
| Linux Mint / Ubuntu / Debian | 20+ |
| Python | 3.8+ |
| pip | أي إصدار |
| nmap (اختياري) | أي |
| adb (اختياري، للهواتف) | أي |

## الأدوات الموصى بها / Recommended Tools

```bash
sudo apt install nmap usbutils adb net-tools iproute2 fail2ban
```
