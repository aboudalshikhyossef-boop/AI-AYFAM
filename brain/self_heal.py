"""
AI AYFAM — Self-Heal Engine
يشخّص أخطاءه بدقة — يقترح الإصلاح — ينتظر موافقتك
"""

import traceback
import sys
import re
import shlex
from datetime import datetime

from utils import safe_exec


class SelfHealEngine:
    def __init__(self, knowledge_base=None, ui=None):
        self.kb = knowledge_base
        self.ui = ui
        self._error_log = []

    # ─── Error Interceptor ───────────────────────────────────────────────────
    def intercept(self, func, *args, **kwargs):
        """تشغيل دالة مع اعتراض أي خطأ وتشخيصه"""
        try:
            return func(*args, **kwargs), None
        except Exception as e:
            error_info = self._analyze_error(e)
            self._error_log.append(error_info)
            return None, error_info

    def _analyze_error(self, exc: Exception) -> dict:
        tb = traceback.format_exc()
        error_text = str(exc)
        error_type = type(exc).__name__

        info = {
            "type": error_type,
            "message": error_text,
            "traceback": tb,
            "timestamp": datetime.now().isoformat(),
            "explanation": "خطأ غير معروف",
            "fix": "",
            "severity": "medium",
            "can_auto_fix": False,
            "reference": None,
        }

        # Match against KB
        if self.kb:
            match = self.kb.match_error(error_text)
            if match:
                info["explanation"] = match["explanation"]
                info["fix"] = match["fix"]
                info["can_auto_fix"] = True
            else:
                # Try to learn from this new error
                self._propose_learning(exc, error_text, tb)
                # استشر مكتبتك الشخصية وما علّمتني إياه سابقاً — قد يكون
                # فيها دليل مفيد حتى لو لم يكن لديّ إصلاح جاهز رسمياً.
                info["reference"] = self._consult_library(error_type, error_text)
        else:
            info["explanation"] = self._builtin_explain(error_type, error_text)
            info["fix"] = self._builtin_fix(error_type, error_text)

        # Severity
        if any(w in error_text.lower() for w in ["permission denied", "access denied", "root"]):
            info["severity"] = "high"
        elif any(w in error_text.lower() for w in ["connection", "network", "timeout"]):
            info["severity"] = "medium"
        elif "not found" in error_text.lower() or "no module" in error_text.lower():
            info["severity"] = "low"
            info["can_auto_fix"] = True

        return info

    def _consult_library(self, error_type: str, error_text: str):
        """يبحث في المكتبة الشخصية (كتب علّمها المستخدم) وفي ما عُلِّم مباشرة
        عبر المحادثة عن أي مرجع قد يفيد في فهم خطأ لا نملك له إصلاحاً جاهزاً.
        لا يستبدل الحل الرسمي — مجرد دليل إضافي شفاف المصدر."""
        if not self.kb:
            return None
        query = f"{error_type} {error_text}"[:200]
        try:
            combined = self.kb.search_everything(query, limit=1)
        except Exception:
            return None
        if combined.get("library"):
            r = combined["library"][0]
            loc = f" ({r['page_hint']})" if r.get("page_hint") else ""
            return {
                "source": f"📖 من مكتبتك: «{r['title']}»{loc}",
                "excerpt": r["content"][:300].strip(),
            }
        for k in combined.get("knowledge", []):
            if k.get("source") == "user":
                return {"source": "💬 مما علّمتني إياه سابقاً", "excerpt": k["content"][:300].strip()}
        return None

    def _builtin_explain(self, error_type: str, message: str) -> str:
        EXPLANATIONS = {
            "ModuleNotFoundError": "مكتبة Python مطلوبة غير مثبتة",
            "FileNotFoundError":   "الملف أو الأمر غير موجود في النظام",
            "PermissionError":     "لا توجد صلاحيات كافية لتنفيذ هذا الأمر",
            "ConnectionRefusedError": "رُفض الاتصال — الخدمة لا تستجيب",
            "TimeoutError":        "انتهت المهلة الزمنية — الخدمة بطيئة أو معطلة",
            "ValueError":          "قيمة غير صحيحة — تحقق من البيانات المُدخلة",
            "KeyError":            "مفتاح غير موجود في البيانات — هيكل البيانات مختلف",
            "AttributeError":      "خاصية أو دالة غير موجودة في الكائن",
            "ImportError":         "فشل استيراد مكتبة — تحقق من التثبيت",
            "OSError":             "خطأ في نظام التشغيل — الملف أو الجهاز غير متاح",
        }
        return EXPLANATIONS.get(error_type, f"خطأ من نوع {error_type}: {message[:100]}")

    def _builtin_fix(self, error_type: str, message: str) -> str:
        if "No module named" in message:
            mod = message.split("'")[1] if "'" in message else "unknown"
            # اسم حزمة pip يجب أن يطابق نمطاً آمناً معروفاً فقط — إن لم يطابق
            # (قد يكون نص خطأ متلاعَباً به من مصدر خارجي) لا نولّد أمراً قابلاً
            # للتنفيذ إطلاقاً، بل نص إرشادي فقط.
            if re.match(r"^[A-Za-z0-9_.\-]{1,100}$", mod):
                return f"pip3 install {mod}"
            return "اسم المكتبة المفقودة يحتوي على رموز غير متوقعة — راجعه يدوياً قبل التثبيت"
        if error_type == "PermissionError":
            return "شغّل الأمر بـ sudo أو تحقق من صلاحياتك"
        if error_type == "FileNotFoundError":
            return "تحقق أن الأداة مثبتة يدوياً (لا يوجد أمر تلقائي آمن هنا)"
        if error_type == "ConnectionRefusedError":
            return "تحقق أن الخدمة تعمل: systemctl status <service>"
        return "راجع السجلات للمزيد من التفاصيل: journalctl -xe"

    def _propose_learning(self, exc: Exception, error_text: str, tb: str):
        """يقترح إضافة نمط خطأ جديد لقاعدة المعرفة.
        إذا تكرر نفس الخطأ ≥ 2 مرات → يُضاف تلقائياً (autonomous learning)."""
        if not (self.kb and len(error_text) > 5):
            return
        error_key = error_text[:80]
        # Don't re-learn known patterns
        if self.kb.match_error(error_text):
            return
        fix_guess = self._builtin_fix(type(exc).__name__, error_text)
        explanation = self._builtin_explain(type(exc).__name__, error_text)
        # Count previous proposals of this exact pattern
        try:
            conn = self.kb._connect()
            count = conn.execute(
                "SELECT COUNT(*) FROM self_improvements WHERE description LIKE ?",
                (f"%{error_key[:40]}%",)
            ).fetchone()[0]
        except Exception:
            count = 0
        if count >= 1:
            # Seen before — auto-promote to permanent error pattern (autonomous)
            try:
                self.kb.add_error_pattern(error_key, explanation, fix_guess)
            except Exception:
                pass
        self.kb.propose_improvement(
            category="error_pattern",
            description=f"خطأ جديد مكتشف: {error_key}",
            data={
                "pattern": error_key,
                "explanation": explanation,
                "fix": fix_guess,
            }
        )

    # ─── Display Error ────────────────────────────────────────────────────────
    def display_error(self, error_info: dict):
        if not self.ui:
            print(f"\n[ماذا حدث] {error_info['type']}: {error_info['message'][:200]}")
            print(f"[لماذا]   {error_info['explanation']}")
            if error_info.get("fix"):
                print(f"[سأفعل]   {error_info['fix']}")
            if error_info.get("reference"):
                print(f"[مرجع]    {error_info['reference']['source']}: {error_info['reference']['excerpt'][:150]}")
            return

        self.ui.section("⚠️  تشخيص الخطأ / Error Diagnosis", color="red")
        self.ui.error(f"ماذا حدث؟  [{error_info['type']}] {error_info['message'][:200]}")
        self.ui.warning(f"لماذا؟  {error_info['explanation']}")
        if error_info.get("fix"):
            self.ui.success(f"ماذا سأفعل بعد موافقتك؟  {error_info['fix']}")
        if error_info.get("reference"):
            ref = error_info["reference"]
            self.ui.info(f"💡 مرجع محتمل — {ref['source']}:\n     {ref['excerpt']}")

    # ─── Try Auto Fix ─────────────────────────────────────────────────────────
    def try_fix(self, error_info: dict, auto_approve: bool = False) -> bool:
        fix_cmd = error_info.get("fix", "")
        if not fix_cmd or not error_info.get("can_auto_fix", False):
            return False

        if not auto_approve:
            if not self.ui:
                ans = input(f"\n  هل تريد تطبيق الإصلاح؟ [{fix_cmd}] (y/n): ")
                if ans.lower() not in ("y", "yes", "نعم", "ن"):
                    return False
            else:
                if not self.ui.confirm(f"تطبيق الإصلاح التلقائي؟\n  [{fix_cmd}]", default=False):
                    return False

        # Execute fix — بدون shell=True إطلاقاً. نُقسّم النص إلى وسائط عبر
        # shlex (يحترم الاقتباس) ثم نمرره كقائمة، حتى لو كان fix_cmd نصاً
        # تم اشتقاقه من رسالة خطأ (قد تكون متأثرة بمحتوى خارجي في حالات نادرة).
        try:
            try:
                args = shlex.split(fix_cmd)
            except ValueError:
                args = fix_cmd.split()
            if not args:
                return False
            res = safe_exec.run(args, timeout=60)
            if self.ui:
                if res.ok:
                    self.ui.success(f"✅ تم تطبيق الإصلاح: {fix_cmd}")
                else:
                    self.ui.error(f"❌ فشل الإصلاح: {res.stderr[:200]}")
            return res.ok
        except Exception as e:
            if self.ui:
                self.ui.error(f"فشل تنفيذ الإصلاح: {e}")
            return False

    # ─── Diagnostics Report ───────────────────────────────────────────────────
    def full_diagnostics(self) -> dict:
        """تشخيص كامل للوكيل نفسه"""
        checks = {}

        # Python version
        checks["python"] = {
            "status": "ok",
            "value": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        }

        # Required libraries
        for lib in ["rich", "requests", "sqlite3", "json", "subprocess"]:
            try:
                __import__(lib)
                checks[f"lib_{lib}"] = {"status": "ok", "value": "installed"}
            except ImportError:
                checks[f"lib_{lib}"] = {"status": "missing", "value": "NOT INSTALLED",
                                         "fix": f"pip3 install {lib}"}

        # Required system tools
        import shutil as _shutil
        for tool in ["nmap", "ufw", "lsusb", "ss", "ip", "adb"]:
            found = _shutil.which(tool) is not None
            checks[f"tool_{tool}"] = {
                "status": "ok" if found else "missing",
                "value": "found" if found else f"missing — install: apt install {tool}",
            }

        # Knowledge base
        if self.kb:
            stats = self.kb.get_stats()
            checks["knowledge_base"] = {
                "status": "ok",
                "value": f"{stats['knowledge_entries']} entries, {stats['db_size_mb']}MB"
            }

        # Error log
        checks["recent_errors"] = {
            "status": "ok" if len(self._error_log) == 0 else "warning",
            "value": f"{len(self._error_log)} errors in this session"
        }

        return checks

    def get_error_log(self) -> list:
        return self._error_log[-20:]
