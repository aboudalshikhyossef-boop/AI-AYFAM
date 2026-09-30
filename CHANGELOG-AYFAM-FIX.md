# AI AYFAM — تقرير الإصلاح والتحسين

> ⚠️ **تحديث لاحق:** بعد هذا الإصلاح، خضعت الأداة لمراجعة أمنية منفصلة
> وأعمق كشفت وأغلقت عدة ثغرات حقن أوامر حرجة لم تُذكر هنا. راجع
> [`SECURITY-HARDENING.md`](./SECURITY-HARDENING.md) للتفاصيل الكاملة.

## 🐛 الأخطاء التي تم إصلاحها

| # | الملف | المشكلة | الحل |
|---|---|---|---|
| 1 | `core/agent.py:613` | `fix_flash_issues(path)` ينقص argument → TypeError | يتم جمع `findings` من `deep_scan_flash` أولاً ثم تمريرها |
| 2 | `tools/network.py:288` | `":::" `حرفياً = True دائماً → بلاغات أمنية وهمية | تصحيح إلى `":::" in line` |
| 3 | `core/agent.py:640` | `result.get("details")` بينما الـ key الصحيح `"info"` → تشخيص الهاتف يضيع | تصحيح المفتاح |
| 4 | `brain/nlp.py:10` | `"إ" → "و"` يحوّل "إصلاح" إلى "وصلاح" → كسر فهم العربية | `str.maketrans("أإآى", "اااي")` |
| 5 | `core/agent.py:594` | `or True` يجعل النظام يفحص كل الأقراص حتى السيستم | إزالة `or True` |
| 6 | `tools/usb_control.py:74` | shell glob خاطئ `.../authorized` | تنظيف dead code |
| 7 | `brain/knowledge_base.py:14-15` | `mkdir` يعمل عند الـ import → crash إذا كان home read-only | نقل إلى `__init__` مع fallback إلى /tmp |
| 8 | `brain/context_engine.py:142` | curl لـ public IP في كل تشغيل → تأخير 3-6 ثواني | cache في الذاكرة لكل عمر العملية |
| 9 | `core/agent.py:170` | duplicate `entities.get("keyword","")` | الثاني صار `entities.get("domain","")` |
| 10 | `tools/network.py:393` | crash لو port من nmap مش رقم | try/except في sort key |
| 11 | `brain/knowledge_base.py:334` | `apply_improvement` يضع `applied=1` حتى لو ما طبّق شي | الآن يرجع `False` إذا لم يطبق |
| 12 | `config/settings.py:40` | `except: pass` يبلع الـ JSON corruption → فقدان GitHub token | يطبع warning + backup للملف الفاسد |

## 🧠 تحسينات الذكاء (محلي 100٪، بدون APIs خارجية)

### A. بحث FTS5 بدل LIKE
- جدول `knowledge_fts` افتراضي مع tokenizer `unicode61 remove_diacritics 2` → بحث عربي حقيقي
- ترتيب بـ `rank` (BM25) بدل ترتيب عشوائي
- triggers تلقائية للحفاظ على الـ index متزامن مع `knowledge`
- fallback لـ LIKE إذا FTS5 غير متاح

### B. ذاكرة المحادثة الفعلية
- `_last_entities` الآن **يُقرأ**: إذا قلت "افحص 192.168.1.5" ثم "وفحص المنافذ" — الـ IP يُحمل تلقائياً
- ذكاء سياقي بدون APIs

### C. NLP scoring أذكى
- Tokenizer يدعم Unicode/Arabic كاملاً (`[\w\u0600-\u06FF]+`)
- Jaccard similarity بدل overlap بسيط
- usage-frequency boost: النوايا اللي تستخدمها كثير ترتفع تلقائياً
- exact phrase score: 0.5-0.95 (كان 0.4-0.9)

### D. تعلّم ذاتي حقيقي (autonomous)
- لما يتكرر نفس الخطأ ≥ 2 مرات → يُضاف **تلقائياً** لـ `error_patterns` بدون موافقة
- `match_error()` يستخدم الأنماط المتعلَّمة في كل crash لاحق
- `apply_improvement` يدعم كل الفئات (knowledge / error_pattern / intent)

### E. تجميع حقيقي لمستوى التهديد
- دالة جديدة `ContextEngine.update_threat_level(findings)`
- يحسب من critical/high/medium الفعلية للـ scan بدل failed_logins فقط
- نادها بعد كل scan: `self.ctx.update_threat_level(all_findings)`

## ⚡ التشغيل
```bash
cd AI-AYFAM
pip3 install -r requirements.txt
python3 main.py
```

## 🔮 خطوات اختيارية للمستقبل (إذا حبيت)
- إضافة `sentence-transformers` (محلي، ~80MB) لـ embeddings دلالية حقيقية
- تكامل مع Lovable AI Gateway لقفزة ذكاء كبيرة (اختياري)
- اختبارات pytest للـ tools/
