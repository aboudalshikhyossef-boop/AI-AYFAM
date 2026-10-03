# 🛡️ AI AYFAM — وكيل الأمن السيبراني الذكي

**AI AYFAM** هو وكيل أمن سيبراني CLI (سطر أوامر) متخصص، يعمل على **Linux Mint** بدون الحاجة لأي خدمة ذكاء اصطناعي خارجية أو رسوم.

> **AI AYFAM** is a specialized CLI cybersecurity agent for **Linux Mint** — no external AI services, no subscriptions, no API fees.

---

## ✨ المزايا الرئيسية / Key Features

| الميزة | Feature |
|--------|---------|
| 🌐 فحص الشبكة والاتصالات | Network & connection scanning |
| 🔍 فحص المنافذ المفتوحة | Port scanning |
| 🔌 فحص USB والهواتف والفلاشات | USB, phone & flash drive scanning |
| 🖥️ فحص النظام والسجلات | System & log analysis |
| 🔐 فحص SSH وجدار الحماية | SSH config & firewall check |
| 🔒 كشف تسريب البيانات | Data leak detection |
| 🔧 إصلاح تلقائي للمشاكل | Auto-fix security issues |
| 📋 تقارير مفصّلة | Detailed security reports |
| 🐙 رفع التقارير على GitHub | Push reports to GitHub |
| 🔎 بحث CVE + OSV.dev + Exploit-DB محلي | CVE search (NVD, CISA, OSV.dev, local Exploit-DB) |
| 🧠 محرك ذكاء محلي (TF-IDF + خريطة مفاهيم) | Local intelligence engine (TF-IDF + concept graph) — v4، بدون LLM ولا مفتاح API |
| 📈 تتبّع تطوّر الوضع الأمني عبر الزمن | Security trend tracking over time |
| 🌍 دعم عربي/إنجليزي | Bilingual Arabic/English support |

---

## 📦 التثبيت / Installation

```bash
# 1. نسخ المشروع / Clone the project
git clone https://github.com/AYFAM-Security/AI-AYFAM.git
cd AI-AYFAM

# 2. تشغيل سكريبت التثبيت / Run setup
chmod +x setup.sh
./setup.sh

# 3. تشغيل الوكيل / Run the agent
ayfam
```

**المتطلبات / Requirements:**
- Linux Mint 20+ (أو أي Ubuntu/Debian)
- Python 3.8+
- اتصال إنترنت (لبحث CVE والتحديثات فقط)

> التثبيت يستخدم **Python النظام مباشرة** ولا ينشئ `.venv` أو بيئة افتراضية، بينما
> تتطلب وظائف الفحص الحساسة صلاحيات root عبر `sudo` أو نافذة التفويض.

---

## 🚀 الاستخدام / Usage

> **مهم / Important:** تعمل الأداة بصلاحيات root فقط. استخدم `sudo ayfam ...`.
> لفحص مكتبات Python وأدوات النظام قبل البدء استخدم `sudo ayfam --check-deps`.

### Gemini CTI — استخبارات تهديدات خاصة بالتصميم

التكامل اختياري ويعمل وفق مبدأ الخصوصية أولاً: يُرسل إلى Gemini مفتاح API
والسؤال العام عن التهديدات فقط. لا تُرسل قائمة الحزم أو الملفات أو عناوين الجهاز.
بعد عودة النتائج، تتم المطابقة مع الجهاز **محلياً بالكامل** وتُحفظ النتائج في
`~/.ayfam/gemini_cti.db` والتقارير في مجلد التقارير المحلي.

```bash
# إدخال المفتاح دون ظهوره في الشاشة أو سطر الأوامر
sudo ayfam --configure-gemini

# اكتشاف أفضل نموذج متاح لهذا المفتاح تلقائياً
sudo ayfam --gemini-models

# بحث Google Grounding عن آخر 48 ساعة ثم مطابقة محلية
sudo ayfam --gemini-threats
```

يستخدم AI AYFAM افتراضياً `gemini-2.5-flash` ثم `gemini-2.5-flash-lite` مع أداة
`google_search_retrieval`، لأن بحث Google متاح لهذين النموذجين على Free tier حتى
500 طلب grounded يومياً (الحد مشترك بينهما). أما `gemini-3.8-flash` فتوليد النص
فيه مجاني، لكن Grounding with Google Search غير متاح على Free tier ويتطلب Paid tier.

يدعم البرنامج `GOOGLE_API_KEY` و`GEMINI_API_KEY`؛ وتتقدم قيم البيئة على المفتاح
المحفوظ في الإعدادات. عند التشغيل عبر `sudo`، يجب أن تكون قيمة البيئة متاحة
للعملية، أو استخدم إعداد المفتاح المحلي.

يحتفظ AI AYFAM برسالة Google ورمز الخطأ وتفاصيل الحصة. إذا ظهرت أخطاء `429`،
راجع صفحة Rate Limit في AI Studio؛ لا يمكن للكود تجاوز حدود Google.

```bash
# وضع تفاعلي / Interactive mode
sudo ayfam

# فحص الشبكة / Network scan
sudo ayfam --scan network

# فحص المنافذ / Port scan
sudo ayfam --scan ports --target 192.168.1.1
sudo ayfam --scan ports --target 127.0.0.1

# فحص USB والأجهزة / USB & devices
sudo ayfam --scan usb

# فحص النظام الكامل / Full system scan
sudo ayfam --scan system

# تحليل السجلات / Log analysis
sudo ayfam --scan logs

# فحص شامل لكل شيء / Full comprehensive scan
sudo ayfam --scan full

# إنشاء تقرير / Generate report
sudo ayfam --report

# تحديث قاعدة بيانات CVE / Update CVE database
sudo ayfam --update

# إصلاح تلقائي / Auto-fix
sudo ayfam --fix

# إعداد GitHub (اختياري) / GitHub setup (optional)
ayfam --set-github-token YOUR_GITHUB_TOKEN
```

### الواجهة الرسومية ومكتبة المعرفة

بعد تشغيل `./setup.sh` ابحث عن **مركز AI AYFAM الأمني** في قائمة التطبيقات، أو شغّل `ayfam-gui`. يحتاج التشغيل الرسومي إلى كلمة مرور النظام عبر نافذة التفويض. إذا لم تظهر النافذة، راجع سجل التشغيل في `~/.local/state/ayfam/gui.log`.

من تبويب **مكتبة المعرفة** أضف ملفات PDF أو TXT أو Markdown. تعرض المكتبة عدد المقاطع المستخرجة، وتتيح البحث النصي فورًا. بعد إضافة الكتب اضغط **إعادة بناء فهرس الذكاء** لتفعيل ترتيب الصلة والربط بين الكتب. ملفات PDF الممسوحة ضوئيًا كصور تحتاج OCR، وهو غير مضمّن حاليًا.

التعلّم محلي ويعتمد على استخراج النص والبحث وTF-IDF وملخصات استخلاصية؛ لا يستخدم نموذجًا لغويًا ولا ينبغي أن يدّعي استنتاج معلومات غير موجودة في المصادر. تفاصيل النتيجة تعرض الدليل والثقة والتوصية عندما يوفرها الفاحص.

---

## 🐙 إعداد GitHub / GitHub Setup

الوكيل يستخدم **مفتاحك الشخصي** للاتصال بـ GitHub (لا يُشارك مع أحد).
The agent uses **your personal token** to connect to GitHub (never shared).

1. اذهب إلى / Go to: [github.com/settings/tokens](https://github.com/settings/tokens)
2. أنشئ Token جديد بصلاحيات / Create token with permissions: `repo`, `read:user`
3. ثبّته / Set it:
```bash
ayfam --set-github-token ghp_XXXXXXXXXXXXXXXX
```

يُخزَّن المفتاح محلياً في `~/.ayfam/config.json` بشكل آمن.
Token is stored locally in `~/.ayfam/config.json`.

---

## 🔍 أمثلة من وضع التفاعل / Interactive Mode Examples

```
[AI AYFAM] أدخل أمراً ❯ scan full
[AI AYFAM] أدخل أمراً ❯ cve linux kernel
[AI AYFAM] أدخل أمراً ❯ ip 185.220.101.1
[AI AYFAM] أدخل أمراً ❯ ثغرات حزمة requests
[AI AYFAM] أدخل أمراً ❯ تطور الوضع الأمني
[AI AYFAM] أدخل أمراً ❯ إعادة بناء فهرس الذكاء
[AI AYFAM] أدخل أمراً ❯ اشرح مفهوم SQL injection
[AI AYFAM] أدخل أمراً ❯ اربط بين buffer overflow و ASLR
[AI AYFAM] أدخل أمراً ❯ fix
[AI AYFAM] أدخل أمراً ❯ github
[AI AYFAM] أدخل أمراً ❯ update
```

---

## 📊 مستويات الخطر / Risk Levels

| المستوى | Level | الوصف |
|---------|-------|-------|
| 🔴 خطير جداً | CRITICAL | يستوجب تدخلاً فورياً |
| 🟠 خطير | HIGH | أولوية عالية — 24 ساعة |
| 🟡 متوسط | MEDIUM | أولوية متوسطة — أسبوع |
| 🔵 منخفض | LOW | للمراجعة |
| 🟢 آمن | SAFE | لا مشاكل مكتشفة |

---

## 📋 مجالات الفحص / Scan Domains

### 🌐 الشبكة / Network
- واجهات الشبكة والعناوين
- الاتصالات النشطة والمشبوهة
- فحص جدار الحماية (UFW/iptables)
- كشف منافذ الاستماع المكشوفة
- شبكات WiFi المفتوحة

### 🔌 USB والأجهزة / USB & Devices
- قائمة كل الأجهزة المتصلة
- كشف BadUSB و Rubber Ducky
- فحص الفلاشات عن Autorun والبرمجيات الخبيثة
- تحليل الهواتف المتصلة (Android/ADB)

### 🖥️ النظام / System
- ملفات SUID الخطيرة
- المهام المجدولة المشبوهة (Cron)
- العمليات المشبوهة
- حسابات المستخدمين والصلاحيات
- إعدادات SSH
- التحديثات الأمنية الناقصة
- الملفات القابلة للكتابة من الجميع

### 📋 السجلات / Logs
- هجمات Brute Force
- محاولات الاختراق
- أخطاء النواة (kernel)
- أحداث جدار الحماية

---

## 🔧 الإصلاحات التلقائية / Auto-Fixes

| الإصلاح | Fix |
|---------|-----|
| `enable_firewall` | تفعيل UFW |
| `disable_root_ssh` | منع root من SSH |
| `disable_ssh_password_auth` | تعطيل كلمة المرور في SSH |
| `ban_ip` | حجب IP مشبوه |
| `kill_process` | إيقاف عملية مشبوهة |
| `remove_suid` | إزالة SUID خطير |
| `update_system` | تحديث النظام |
| `setup_fail2ban` | تثبيت وتفعيل fail2ban |
| `change_dns` | تغيير DNS إلى 1.1.1.1 |

---

## 🏗️ بنية المشروع / Project Structure

```
AI-AYFAM/
├── main.py              # نقطة البداية / Entry point
├── setup.sh             # سكريبت التثبيت / Setup script
├── requirements.txt     # متطلبات Python
├── core/
│   ├── agent.py         # العقل الرئيسي / Main agent brain
│   └── intelligence.py  # محرك التحليل / Analysis engine
├── tools/
│   ├── network.py       # أدوات الشبكة / Network tools
│   ├── usb.py           # أدوات USB / USB tools
│   ├── system.py        # أدوات النظام / System tools
│   ├── web.py           # ذكاء الإنترنت / Web intelligence
│   ├── github_tool.py   # تكامل GitHub / GitHub integration
│   └── fix.py           # محرك الإصلاح / Fix engine
├── ui/
│   └── terminal.py      # واجهة الترمينال / Terminal UI
├── reports/
│   └── generator.py     # مولّد التقارير / Report generator
└── config/
    └── settings.py      # إدارة الإعدادات / Settings manager
```

---

## 📡 مصادر البيانات (مجانية) / Data Sources (Free)

- **NVD (National Vulnerability Database)** — CVE، بدون مفتاح (مفتاح اختياري لرفع حد الطلبات)
- **CISA KEV** — قائمة الثغرات المستغَلة فعلياً
- **OSV.dev** — ثغرات حزم مفتوحة المصدر (PyPI/npm/Go/crates.io/...) بدون مفتاح
- **Exploit-DB** — فهرس محلي (يُحمَّل مرة واحدة عبر "تحديث المعلومات الاستخباراتية")، بحث بلا اتصال بعدها
- **GitHub Security Advisories** — تنبيهات أمان GitHub
- **DuckDuckGo + Wikipedia (ar/en)** — بحث ويب عام متعدد المصادر
- **ipapi.co + ip-api.com** — سمعة IP (AbuseIPDB اختياري بمفتاحك الخاص)
- **أدوات Linux** — nmap, lsusb, ss, journalctl, etc.

راجع `SEARCH-AND-ANALYSIS-UPGRADE.md` لتفاصيل هذه المصادر، و
`V4-LOCAL-INTELLIGENCE-AND-UI-UPGRADE.md` لمحرك الربط الذكي بين النتائج
ومحرك الذكاء المحلي (TF-IDF + خريطة مفاهيم) وإعادة تصميم الواجهة.

---

## 🔒 الخصوصية / Privacy

- ✅ يعمل **محلياً بالكامل** — لا يُرسل بيانات لأي خادم خارجي إلا عند طلبك بحثاً/فحصاً صريحاً
- ✅ مفتاح GitHub وأي مفاتيح اختيارية أخرى (AbuseIPDB/NVD) **محلية** في `~/.ayfam/config.json` فقط
- ✅ التقارير **محلية** في `~/ayfam-reports/`
- ✅ اتصال الإنترنت فقط عند: بحث CVE/OSV، فحص سمعة IP، بحث ويب، GitHub، أو تحديث فهرس Exploit-DB المحلي

---

## 🤝 المساهمة / Contributing

نرحب بمساهماتك! / Contributions welcome!

```bash
git clone https://github.com/AYFAM-Security/AI-AYFAM.git
cd AI-AYFAM
# أضف ميزتك / Add your feature
git push origin feature/your-feature
```

---

## 📄 الرخصة / License

MIT License — مفتوح المصدر بالكامل / Fully open source

---

*صُنع بـ ❤️ لمجتمع الأمن السيبراني العربي وما هو أبعد*
*Made with ❤️ for the Arabic cybersecurity community and beyond*
