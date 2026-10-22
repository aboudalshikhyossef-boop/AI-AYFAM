# 🛡️ AI AYFAM — وكيل الأمن السيبراني الذكي

**AI AYFAM** هو تطبيق سطح مكتب PyQt6 متخصص للأمن السيبراني يعمل على **Linux Mint**. هذا المشروع ليس موقعاً ويبياً ولا منتجاً SaaS؛ الواجهة الأساسية هي واجهة سطح المكتب المحلية.

> **AI AYFAM** is a Linux Mint desktop cybersecurity application built with PyQt6. It is not a website or SaaS product.

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

### مصادر البحث داخل تطبيق سطح المكتب

تعمل مصادر البحث وCVE من داخل تطبيق سطح المكتب عبر المحركات المحلية والتكاملات
الاختيارية. لا توجد واجهة ويب مطلوبة لتشغيل التطبيق.

لتمكين بحث Google الاختياري من داخل الإعدادات، يمكن إضافة:

```bash
GOOGLE_CSE_KEY=your_google_custom_search_api_key
GOOGLE_CSE_CX=f5fbcd40fda484bc7
```

> ملاحظة: هذه الإعدادات اختيارية ولا تغيّر طبيعة المشروع كتطبيق سطح مكتب.

---

## 📦 التثبيت / Installation

```bash
# 1. نسخ المشروع / Clone the project
git clone https://github.com/AYFAM-Security/AI-AYFAM.git
cd AI-AYFAM

# 2. تشغيل سكريبت التثبيت / Run setup
chmod +x setup.sh
./setup.sh

# 3. تشغيل تطبيق سطح المكتب / Run the desktop application
ayfam
```

**المتطلبات / Requirements:**
- Linux Mint 20+ (أو أي Ubuntu/Debian)
- Python 3.10+
- اتصال إنترنت (لبحث CVE والتحديثات فقط)

> ينشئ المثبت بيئة `.venv` خاصة بالتطبيق ولا يثبت مكتبات AI AYFAM داخل Python النظام.

---

## 🚀 الاستخدام / Usage

> **مهم / Important:** شغّل واجهة سطح المكتب بحساب المستخدم للحفاظ على جلسة Linux Mint الرسومية. العمليات التي تحتاج امتيازاً تطلبه عبر طبقة التنفيذ الآمن.

### Gemini CTI — استخبارات تهديدات خاصة بالتصميم

التكامل اختياري ويعمل وفق مبدأ الخصوصية أولاً: يُرسل إلى Gemini مفتاح API
والسؤال العام عن التهديدات فقط. لا تُرسل قائمة الحزم أو الملفات أو عناوين الجهاز.
بعد عودة النتائج، تتم المطابقة مع الجهاز **محلياً بالكامل** وتُحفظ النتائج في
`~/.ayfam/gemini_cti.db` والتقارير في مجلد التقارير المحلي.

تتم إدارة مفاتيح Gemini من إعدادات تطبيق سطح المكتب، ولا تُضاف إلى أوامر shell.

يستخدم AI AYFAM افتراضياً `gemini-3.8-flash`. يبقى اختيار النموذج المحفوظ كما هو
ولا يتم استبداله قسراً أثناء تحميل الإعدادات.

يدعم البرنامج `GOOGLE_API_KEY` و`GEMINI_API_KEY`؛ وتتقدم قيم البيئة على المفتاح
المحفوظ في الإعدادات. عند التشغيل عبر `sudo`، يجب أن تكون قيمة البيئة متاحة
للعملية، أو استخدم إعداد المفتاح المحلي.

يحتفظ AI AYFAM برسالة Google ورمز الخطأ وتفاصيل الحصة. إذا ظهرت أخطاء `429`،
راجع صفحة Rate Limit في AI Studio؛ لا يمكن للكود تجاوز حدود Google.

```bash
# تشغيل التطبيق
ayfam

# تشغيل التطبيق دون شاشة المقدمة
ayfam --no-splash

# فحص المتطلبات فقط دون تشغيل الواجهة
ayfam --check

# عرض الإصدار
ayfam --version
```

### ملاحظة حول ملفات الويب القديمة

توجد بعض ملفات Angular و`api_server.py` في المستودع من مراحل سابقة، لكنها ليست
منتج AI AYFAM ولا تدخل في تشغيل تطبيق سطح المكتب. لا تستخدم `npm run start` أو
تشغّل `api_server.py` لتثبيت التطبيق أو تشغيله؛ نقطة الدخول المعتمدة هي `ayfam`
والمشغل الرسومي `ayfam-gui`.

### سياسة حصة Gemini والطلبات المضغوطة

تستخدم جميع مسارات Gemini بوابة مشتركة لكل مفتاح API (`~/.ayfam/gemini-rate-*.json`)
تضمن ما يلي:

- طلب توليد واحد محدد لكل عملية؛ لا توجد محاولات fallback متتالية بين النماذج أو
  بين حمولة مؤرّضة وأخرى غير مؤرّضة.
- حد أدنى قدره **30 ثانية** بين بداية أي طلب Gemini والطلب التالي، وكذلك بين
  اكتمال نتيجة وبدء/إتاحة النتيجة التالية. تعمل البوابة بين العمليات المتوازية
  أيضاً باستخدام قفل ملف.
- ضغط المسافات والطلبات الطويلة قبل الإرسال، وتحديد المخرج إلى 256 token للمحادثة
  و900 token لـ CTI و180 token للبحث المؤرّض.
- CTI يعيد بحد أقصى 5 تهديدات مهمة، مع وصف وتوصية قصيرة ومصدرين كحد أقصى لكل عنصر.

يمكن تغيير الحد الأدنى للاختبارات المحلية فقط عبر متغير البيئة التالي؛ اتركه غير
مضبوط في التشغيل الحقيقي حتى تبقى حماية الحصة 30 ثانية:

```bash
export AYFAM_GEMINI_MIN_INTERVAL=30
```

### الواجهة الرسومية ومكتبة المعرفة

بعد تشغيل `./setup.sh` ابحث عن **مركز AI AYFAM الأمني** في قائمة التطبيقات، أو شغّل `ayfam-gui`. تعمل الواجهة بحساب المستخدم داخل جلسة الرسوميات للحفاظ على `DISPLAY`/Wayland وDBus وXAuthority؛ لا تشغّلها عبر `sudo` من اختصار سطح المكتب. العمليات التي تحتاج امتيازًا تطلبه فقط عند تنفيذها عبر طبقة التنفيذ الآمن. إذا فشل startup، راجع سجل التشغيل في `~/.local/state/ayfam/gui.log`.

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

## 🔒 الخصوصية وتغطية الذكاء الاصطناعي الهجين / Privacy & Hybrid AI CTI

- ✅ المعالجة الأساسية والفحوصات تعمل **محلياً بالكامل** على جهازك.
- ✅ **تكامل Gemini CTI والمساعد:** اختياري ويحتاج مفتاح API صريح. عند استخدام المساعد أو فحص Gemini CTI، يُرسل النص أو سؤال الاستعلام فقط إلى خدمات Google Gemini عبر الإنترنت. لا يتم إرسال سجلات الجهاز الكاملة أو قوائم الملفات الخاصة دون إذنك.
- ✅ مفاتيح APIs (مثل Gemini/AbuseIPDB/NVD/GitHub) تُخزّن محلياً ومشفرة بحسب إعداداتك في `~/.ayfam/config.json`.
- ✅ جميع التقارير المُنشأة تُحفظ محلياً في `~/ayfam-reports/`.
- ✅ اتصال الإنترنت يُستخدم فقط عند: استعلام Gemini CTI، بحث CVE/OSV، فحص سمعة IP، البحث في الإنترنت، تصدير GitHub، أو تحديث فاحص Exploit-DB.

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
