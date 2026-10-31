"""
AI AYFAM - Safe Process Execution Layer
طبقة تنفيذ آمنة — نقطة العبور الوحيدة نحو subprocess في كل الأداة

القاعدة الذهبية:
  * أي قيمة قادمة من مستخدم، شبكة، USB، ADB، أو أي مصدر غير موثوق
    يجب أن تُمرَّر كعنصر منفصل داخل قائمة (list) عبر run() — وليس أبداً
    مدمجة كنص داخل أمر shell.
  * run_trusted_shell() مخصصة فقط لأوامر ثابتة 100% (بدون أي جزء متغيّر
    قادم من مستخدم أو ملف خارجي). لا توجد أي متغيرات مُدرجة فيها إطلاقاً.

لماذا هذا مهم / Why this matters:
  subprocess.run(cmd, shell=True) مع f-string يعني أن أي محتوى غير متوقع
  (مثال: اسم ملف على فلاشة يحتوي على ' أو ; أو `) يمكن أن يُنفَّذ كأمر
  نظام إضافي. بما أن هذه أداة أمنية تتعامل مع مصادر غير موثوقة أصلاً
  (فلاشات مجهولة، هواتف، شبكات)، فإن استخدام shell=True هنا يحوّل الأداة
  نفسها إلى ثغرة.
"""

import os
import shutil
import subprocess


class ExecResult:
    """نتيجة تنفيذ أمر — قابلة للتفكيك (unpack) كـ (ok, stdout, stderr) للتوافق
    مع الشكل القديم المستخدم في كل أنحاء الكود."""

    __slots__ = ("ok", "stdout", "stderr", "returncode")

    def __init__(self, ok, stdout, stderr, returncode=None):
        self.ok = ok
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode

    def __iter__(self):
        return iter((self.ok, self.stdout, self.stderr))

    def __bool__(self):
        return self.ok

    def __repr__(self):
        return f"ExecResult(ok={self.ok}, stdout={self.stdout[:60]!r}, stderr={self.stderr[:60]!r})"


def _needs_sudo(sudo: bool) -> bool:
    try:
        return bool(sudo) and os.geteuid() != 0
    except AttributeError:
        return bool(sudo)


def validate_sudo_password(password: str, timeout=15) -> ExecResult:
    """تحقق فعلي من كلمة مرور sudo دون تنفيذ أمر نظام.

    -k يمنع الاعتماد على جلسة sudo مخزنة، و-S يقرأ كلمة المرور من stdin.
    لا تُعاد كلمة المرور في النتيجة أو في أي رسالة خطأ.
    """
    if not password:
        return ExecResult(False, "", "لم تُدخل كلمة مرور")
    try:
        r = subprocess.run(
            ["sudo", "-k", "-S", "-p", "", "-v"],
            input=f"{password}\n", capture_output=True, text=True, timeout=timeout,
        )
        return ExecResult(r.returncode == 0, "", r.stderr.strip(), r.returncode)
    except Exception as e:
        return ExecResult(False, "", str(e))


def run(args, timeout=30, sudo=False, input_data=None, check_binary=True, sudo_password=None):
    """
    نفّذ أمراً بدون أي تفسير shell إطلاقاً.
    `args` يجب أن تكون قائمة (list)، مثل: ["nmap", "-p", port_range, target]
    كل عنصر يُمرَّر للنواة كوسيطة (argv) منفصلة تماماً — بدون اقتباس، بدون
    توسيع رموز خاصة، بدون أي احتمال لحقن أوامر.
    """
    if isinstance(args, str):
        raise TypeError(
            "safe_exec.run() يتطلب قائمة (list) من الوسائط وليس نصاً. "
            "استخدم run_trusted_shell() فقط لأوامر ثابتة تماماً بلا متغيرات."
        )
    args = [str(a) for a in list(args)]
    if not args:
        return ExecResult(False, "", "لم يُمرَّر أي أمر")

    if check_binary and shutil.which(args[0]) is None:
        return ExecResult(False, "", f"الأداة غير مثبتة أو غير موجودة في PATH: {args[0]}")

    needs_sudo = _needs_sudo(sudo)
    if needs_sudo and sudo_password is not None:
        # -S forces sudo to read the one-time credential from stdin instead of
        # requiring a terminal. Never include the password in logs or errors.
        final_args = ["sudo", "-S", "-p", ""] + args
        input_data = f"{sudo_password}\n" + (input_data or "")
    else:
        final_args = (["sudo"] + args) if needs_sudo else args
    try:
        r = subprocess.run(
            final_args, capture_output=True, text=True, timeout=timeout,
            input=input_data, shell=False,
        )
        return ExecResult(r.returncode == 0, r.stdout.strip(), r.stderr.strip(), r.returncode)
    except subprocess.TimeoutExpired:
        return ExecResult(False, "", "timeout")
    except FileNotFoundError as e:
        return ExecResult(False, "", str(e))
    except Exception as e:
        return ExecResult(False, "", str(e))


def run_trusted_shell(cmd: str, timeout=30):
    """
    ⚠️ للاستخدام فقط مع أوامر ثابتة 100% (لا f-string، لا .format، لا تركيب
    نصوص من متغيرات خارجية). إن احتجت لإدراج متغيّر، استخدم run() بدلاً منها.
    """
    if not isinstance(cmd, str):
        raise TypeError("run_trusted_shell() يتطلب نصاً ثابتاً")
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)  # nosec B602 - trusted constant-command API only; never pass external input
        return ExecResult(r.returncode == 0, r.stdout.strip(), r.stderr.strip(), r.returncode)
    except subprocess.TimeoutExpired:
        return ExecResult(False, "", "timeout")
    except Exception as e:
        return ExecResult(False, "", str(e))


def write_file_privileged(path: str, content: str, timeout=30, append=False, sudo_password=None):
    """كتابة إلى ملف يملكه root بدون أي shell — عبر `sudo tee` مع تمرير
    المحتوى من stdin مباشرة (بدون echo/pipe عبر shell)."""
    args = ["tee"] + (["-a"] if append else []) + [path]
    try:
        if sudo_password is not None and _needs_sudo(True):
            args = ["sudo", "-S", "-p", ""] + args
            content = f"{sudo_password}\n{content}"
        elif _needs_sudo(True):
            args = ["sudo"] + args
        r = subprocess.run(args, input=content, capture_output=True, text=True, timeout=timeout)
        return ExecResult(r.returncode == 0, r.stdout.strip(), r.stderr.strip(), r.returncode)
    except Exception as e:
        return ExecResult(False, "", str(e))


def remove_path_privileged(path: str, timeout=30, sudo=True, sudo_password=None):
    """حذف مسار بأمان — يستخدم `--` لمنع تفسير مسار يبدأ بـ '-' كخيار أمر."""
    base = ["rm", "-f", "--", path]
    if _needs_sudo(sudo) and sudo_password is not None:
        args = ["sudo", "-S", "-p", ""] + base
        input_data = f"{sudo_password}\n"
    else:
        args = (["sudo"] + base) if _needs_sudo(sudo) else base
        input_data = None
    try:
        r = subprocess.run(args, input=input_data, capture_output=True, text=True, timeout=timeout)
        return ExecResult(r.returncode == 0, r.stdout.strip(), r.stderr.strip(), r.returncode)
    except Exception as e:
        return ExecResult(False, "", str(e))
