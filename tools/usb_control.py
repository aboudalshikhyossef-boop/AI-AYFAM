"""
AI AYFAM - Full USB Control Center
مركز التحكم الكامل بمنافذ USB والأجهزة المتصلة

هذا الملف يتعامل مع أكثر المصادر خطورة في الأداة كلها: فلاشات وهواتف
*غير موثوقة* قد تكون مصمَّمة خصيصاً لمهاجمة أداة الفحص نفسها (أسماء ملفات
تحتوي رموز shell، أرقام تسلسلية ADB مزيَّفة...). لذلك:
  - كل تنفيذ أوامر يمر عبر utils.safe_exec (بدون shell=True مطلقاً).
  - كل قيمة قادمة من الجهاز الخارجي (bus/dev/serial/iface/mountpoint) تُتحقق
    منها عبر utils.validators قبل استخدامها.
  - أي حذف تلقائي يُقيَّد بمسار الفلاشة نفسها فقط (حماية من symlink/traversal).
"""

import os
import re
import time
import json
import sys
import stat
from pathlib import Path
from datetime import datetime

from utils import safe_exec, validators


# ─────────────────────────────────────────────────────────────────────────────
#  USB Authorization (sysfs)
# ─────────────────────────────────────────────────────────────────────────────

def _find_sysfs_path(bus: str, dev: str) -> str:
    """ابحث عن مسار sysfs لجهاز USB بأمان — bus/dev يجب أن يكونا أرقاماً فقط."""
    if not (str(bus).isdigit() and str(dev).isdigit()):
        return ""
    bus_i, dev_i = int(bus), int(dev)
    for root, dirs, _files in os.walk("/sys/bus/usb/devices"):
        for d in dirs:
            dp = os.path.join(root, d)
            busnum_f = os.path.join(dp, "busnum")
            devnum_f = os.path.join(dp, "devnum")
            try:
                if (Path(busnum_f).read_text().strip() == str(bus_i) and
                        Path(devnum_f).read_text().strip() == str(dev_i)):
                    return dp
            except Exception:
                pass
        break  # top level only
    return ""


def authorize_device(bus: str, dev: str, sudo_password=None) -> dict:
    """السماح بجهاز USB — يكتب 1 في ملف authorized بدون أي shell."""
    if not (str(bus).isdigit() and str(dev).isdigit()):
        return {"success": False, "error": f"Bus/Dev غير صالحين: Bus={bus} Dev={dev}"}
    path = _find_sysfs_path(bus, dev)
    if not path:
        return {"success": False, "error": f"لم يتم العثور على الجهاز Bus={bus} Dev={dev}"}
    auth_file = os.path.join(path, "authorized")
    r = safe_exec.write_file_privileged(auth_file, "1", sudo_password=sudo_password)
    return {"success": r.ok, "path": auth_file, "error": r.stderr}


def deauthorize_device(bus: str, dev: str, sudo_password=None) -> dict:
    """حجب جهاز USB — يكتب 0 في ملف authorized بدون أي shell."""
    if not (str(bus).isdigit() and str(dev).isdigit()):
        return {"success": False, "error": f"Bus/Dev غير صالحين: Bus={bus} Dev={dev}"}
    path = _find_sysfs_path(bus, dev)
    if not path:
        return {"success": False, "error": f"لم يتم العثور على مسار sysfs للجهاز Bus={bus} Dev={dev}"}
    auth_file = os.path.join(path, "authorized")
    r = safe_exec.write_file_privileged(auth_file, "0", sudo_password=sudo_password)
    return {"success": r.ok, "path": auth_file, "error": r.stderr}


def eject_storage_device(device_path: str, sudo_password=None) -> dict:
    """إخراج آمن لجهاز تخزين — يتحقق أن المسار /dev/... صالح، يُفرغ التخزين المؤقت،
    ويفصل جميع الأقسام التابعة بأمان قبل إيقاف طاقة الجهاز."""
    ok, path_or_err = validators.validate_device_path(device_path)
    if not ok:
        return {"success": False, "steps": [], "error": path_or_err}
    device_path = path_or_err

    steps = []

    # 1. إفراغ التخزين المؤقت (sync) لضمان كتابة كافة البيانات ومنع تلف نظام الملفات
    r_sync = safe_exec.run(["sync"])
    steps.append({"cmd": "sync", "ok": r_sync.ok, "out": r_sync.stdout})

    # 2. تحديد الأقسام الموصولة التابعة لهذا القرص أو القسم
    partitions_to_unmount = []
    r_lsblk = safe_exec.run(["lsblk", "-ln", "-o", "NAME,MOUNTPOINT", device_path], check_binary=False)
    if r_lsblk.ok and r_lsblk.stdout:
        for line in r_lsblk.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) >= 2 and parts[1]:  # لها نقطة توصيل نشطة
                part_dev = f"/dev/{parts[0]}"
                if part_dev not in partitions_to_unmount:
                    partitions_to_unmount.append(part_dev)

    if not partitions_to_unmount:
        partitions_to_unmount.append(device_path)

    # 3. فصل كل قسم بأمان
    all_unmounted = True
    for part in partitions_to_unmount:
        r1 = safe_exec.run(["udisksctl", "unmount", "-b", part], sudo=False, check_binary=False)
        steps.append({"cmd": f"unmount {part}", "ok": r1.ok, "out": r1.stdout or r1.stderr})
        if not r1.ok:
            r3 = safe_exec.run(["umount", part], sudo=True, sudo_password=sudo_password)
            steps.append({"cmd": f"sudo umount {part}", "ok": r3.ok, "out": r3.stdout or r3.stderr})
            if not r3.ok:
                all_unmounted = False

    # 4. إيقاف الطاقة عن القرص الأب
    parent_device = device_path
    m_disk = re.match(r"^(/dev/[a-zA-Z]+)\d+$", device_path)
    if m_disk:
        parent_device = m_disk.group(1)

    r2 = safe_exec.run(["udisksctl", "power-off", "-b", parent_device], sudo=False, check_binary=False)
    steps.append({"cmd": f"power-off {parent_device}", "ok": r2.ok, "out": r2.stdout or r2.stderr})
    if not r2.ok and all_unmounted:
        r4 = safe_exec.run(["udisksctl", "power-off", "-b", parent_device], sudo=True, sudo_password=sudo_password, check_binary=False)
        steps.append({"cmd": f"sudo power-off {parent_device}", "ok": r4.ok, "out": r4.stdout or r4.stderr})

    success = any(s.get("ok") for s in steps if "unmount" in s.get("cmd", "") or "power-off" in s.get("cmd", ""))
    return {"success": success, "steps": steps}


def mount_storage_device_readonly(device_path: str, mount_dir: str = None, sudo_password=None) -> dict:
    """توصيل وحدة تخزين USB للقراءة فقط وبأعلى معايير الأمان (ro,noexec,nosuid,nodev) للفحص الجنائي."""
    ok_dev, dev_clean = validators.validate_device_path(device_path)
    if not ok_dev:
        return {"success": False, "error": dev_clean, "mountpoint": ""}

    if mount_dir:
        ok_mp, mp_clean = validators.validate_mountpoint(mount_dir)
        if not ok_mp:
            return {"success": False, "error": mp_clean, "mountpoint": ""}
    else:
        dev_base = os.path.basename(dev_clean)
        mp_clean = f"/run/media/readonly_{dev_base}"

    try:
        os.makedirs(mp_clean, exist_ok=True)
    except Exception as e:
        return {"success": False, "error": f"تعذر إنشاء مجلد التوصيل: {e}", "mountpoint": mp_clean}

    mount_opts = "ro,noexec,nosuid,nodev"
    r = safe_exec.run(["mount", "-o", mount_opts, dev_clean, mp_clean], sudo=True, sudo_password=sudo_password)
    if r.ok:
        return {"success": True, "mountpoint": mp_clean, "options": mount_opts, "error": ""}
    return {"success": False, "mountpoint": mp_clean, "error": r.stderr or r.stdout}


# ─────────────────────────────────────────────────────────────────────────────
#  Flash Drive Deep Scanner
# ─────────────────────────────────────────────────────────────────────────────

# توقيع EICAR القياسي لاختبار مضادات الفيروسات — نص ثابت معروف عالمياً،
# وجوده لا يعني برمجية خبيثة حقيقية بل ملف اختبار متعارف عليه.
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"

# أنماط دقيقة (regex) لسلوك خبيث حقيقي — وليس مجرد "الملف سكربت bash عادي".
# هذا يمنع الإنذارات الكاذبة الجماعية التي كانت تُصنِّف أي ملف .sh عادي
# كـ"توقيع خبيث خطير" لمجرد أنه يبدأ بـ #!/bin/bash.
DANGEROUS_SCRIPT_PATTERNS = [
    (re.compile(rb"(nc|ncat|netcat)\s+-[a-zA-Z]*e\b"), "Netcat reverse shell (-e)"),
    (re.compile(rb"bash\s+-i\s*>&\s*/dev/tcp/"), "Bash interactive reverse shell عبر /dev/tcp"),
    (re.compile(rb"/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+"), "اتصال عكسي مباشر عبر /dev/tcp"),
    (re.compile(rb"(curl|wget)\s[^\n|]{0,200}\|\s*(sudo\s+)?(sh|bash)\b", re.IGNORECASE), "تحميل وتنفيذ فوري (curl/wget | sh)"),
    (re.compile(rb"base64\s+-d[^\n|]{0,120}\|\s*(sh|bash)\b", re.IGNORECASE), "تنفيذ حمولة مشفّرة base64"),
    (re.compile(rb"powershell(\.exe)?\s+-(enc|e|nop\b|w(indowstyle)?\s+hidden)", re.IGNORECASE), "PowerShell معتم/مخفي"),
    (re.compile(rb"certutil[^\n]{0,80}-urlcache", re.IGNORECASE), "تقنية تحميل عبر certutil (LOLBin)"),
    (re.compile(rb"regsvr32[^\n]{0,80}/i:https?://", re.IGNORECASE), "تنفيذ scriptlet عن بعد عبر regsvr32"),
    (re.compile(rb"mshta\s+https?://", re.IGNORECASE), "تنفيذ HTA عن بعد عبر mshta"),
    (re.compile(rb":(){ ?:\|:& ?};:"), "Fork bomb"),
]

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".com", ".lnk", ".pif"}
AUTORUN_FILES = {"autorun.inf", "autorun.sh", "autoplay.inf", ".autorun", "launch.bat", "open.exe"}
SCRIPT_EXTENSIONS = {".sh", ".py", ".rb", ".pl", ".php"}
_CLAMAV_BIN = "clamscan"


def _clamav_available() -> bool:
    import shutil as _sh
    return _sh.which(_CLAMAV_BIN) is not None


def _clamav_scan(mountpoint: str, timeout: int = 90):
    """فحص إضافي حقيقي بتوقيعات ClamAV إن كانت مثبتة — طبقة كشف حقيقية
    تكمّل الفحص السلوكي بدل الاعتماد على أنماط نصية فقط."""
    if not _clamav_available():
        return None
    r = safe_exec.run(["clamscan", "-r", "-i", "--no-summary", mountpoint], timeout=timeout)
    hits = []
    for line in r.stdout.split("\n"):
        line = line.strip()
        if line.endswith("FOUND"):
            hits.append(line)
    return hits


def deep_scan_flash(mountpoint: str, ui=None) -> dict:
    """فحص أمني شامل لفلاشة — دقيق بما يكفي ليفرّق بين سكربت عادي وسلوك خبيث حقيقي."""
    result = {
        "mountpoint": mountpoint,
        "timestamp": datetime.now().isoformat(),
        "total_files": 0,
        "suspicious_files": [],
        "autorun_files": [],
        "malware_hits": [],
        "hidden_dirs": [],
        "script_files": [],
        "findings": [],
        "score": 0,
        "clamav_used": False,
    }

    ok_mp, mp_or_err = validators.validate_mountpoint(mountpoint)
    if not ok_mp:
        result["findings"].append({"severity": "info", "title": f"مسار غير صالح: {mp_or_err}", "detail": "", "fix": ""})
        return result
    mountpoint = mp_or_err

    if not os.path.exists(mountpoint):
        result["findings"].append({"severity": "info", "title": f"المسار غير موجود: {mountpoint}", "detail": "", "fix": ""})
        return result

    real_mount = os.path.realpath(mountpoint)

    suspicious_patterns = [
        (re.compile(r"(hack|malware|virus|trojan|backdoor|rootkit|keylog|exploit)", re.I), "اسم مشبوه"),
        (re.compile(r"(password|passwd|creds?|credential|secret|token)\.(txt|dat|csv|xls|json)", re.I), "ملف بيانات حساسة"),
        (re.compile(r"\.bash_history|\.zsh_history|\.python_history", re.I), "سجل أوامر"),
    ]

    try:
        for root, dirs, files in os.walk(mountpoint, followlinks=False):
            # لا تدخل أبداً في مجلدات هي روابط رمزية (symlink) — قد تخرج من الفلاشة
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]

            for d in dirs:
                if d.startswith(".") and d not in (".Trash-1000", ".Spotlight-V100", ".fseventsd"):
                    result["hidden_dirs"].append(os.path.join(root, d).replace(mountpoint, ""))
            dirs[:] = [d for d in dirs if d != ".Trash-1000"]

            for fname in files:
                fpath = os.path.join(root, fname)

                # لا تتبع الروابط الرمزية للملفات — قد تشير لأي مكان في النظام
                if os.path.islink(fpath):
                    continue

                try:
                    st = os.lstat(fpath)
                    if not stat.S_ISREG(st.st_mode):
                        continue
                except (OSError, PermissionError):
                    continue

                result["total_files"] += 1
                flower = fname.lower()
                rel = fpath.replace(mountpoint, "")

                if flower in AUTORUN_FILES:
                    result["autorun_files"].append(rel)
                    result["findings"].append({
                        "severity": "critical",
                        "title": f"🚨 ملف Autorun خطير: {fname}",
                        "detail": f"الملف {rel} يمكن أن يُشغَّل تلقائياً عند توصيل الجهاز.",
                        "fix": f"احذف: rm -f -- {_shell_display(fpath)}",
                        "target_path": fpath,
                    })
                    result["score"] += 50

                # كشف التمويه بالامتداد المزدوج (Double Extension Masquerading)
                name_parts = fname.rsplit(".", 2)
                if len(name_parts) == 3:
                    inner_ext = f".{name_parts[1].lower()}"
                    outer_ext = f".{name_parts[2].lower()}"
                    if outer_ext in SUSPICIOUS_EXTENSIONS and inner_ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}:
                        result["suspicious_files"].append({"file": rel, "ext": outer_ext, "masquerade": inner_ext})
                        result["findings"].append({
                            "severity": "critical",
                            "title": f"⚠️ ملف متنكّر بامتداد مزدوج: {fname}",
                            "detail": f"الملف {rel} يتظاهر بأنه {inner_ext} بينما هو في الواقع تنفيذي {outer_ext}.",
                            "fix": f"احذر من تشغيله! افحصه أو احذفه: rm -f -- {_shell_display(fpath)}",
                            "target_path": fpath,
                        })
                        result["score"] += 80

                ext = os.path.splitext(flower)[1]
                if ext in SUSPICIOUS_EXTENSIONS:
                    result["suspicious_files"].append({"file": rel, "ext": ext})
                    result["score"] += 10
                    if ext in {".exe", ".dll", ".scr"}:
                        result["findings"].append({
                            "severity": "high",
                            "title": f"ملف تنفيذي Windows: {fname}",
                            "detail": f"الملف {rel} — قد يكون برنامج ضار. لا يُحذف تلقائياً، يحتاج مراجعتك.",
                            "fix": f"افحص: file {_shell_display(fpath)}",
                        })

                if ext in SCRIPT_EXTENSIONS:
                    result["script_files"].append(rel)
                    try:
                        with open(fpath, "rb") as f:
                            content = f.read(65536)
                        if EICAR_SIGNATURE in content:
                            result["malware_hits"].append({"file": rel, "signature": "EICAR test file"})
                            result["findings"].append({
                                "severity": "low",
                                "title": f"ملف اختبار EICAR القياسي: {fname}",
                                "detail": "هذا ملف اختبار مضاد فيروسات قياسي ومعروف عالمياً — غير ضار بحد ذاته، لكن وجوده قد يعني أن أداة فحص استخدمته هنا.",
                                "fix": "",
                            })
                        for pattern, label in DANGEROUS_SCRIPT_PATTERNS:
                            if pattern.search(content):
                                result["malware_hits"].append({"file": rel, "signature": label})
                                result["findings"].append({
                                    "severity": "critical",
                                    "title": f"🔴 سلوك خبيث حقيقي في: {fname}",
                                    "detail": f"تم رصد نمط: {label}",
                                    "fix": f"راجع ثم احذف إن تأكد الخطر: rm -f -- {_shell_display(fpath)}",
                                    "target_path": fpath,
                                })
                                result["score"] += 100
                                break
                    except Exception:
                        pass

                for pattern, label in suspicious_patterns:
                    if pattern.search(flower):
                        result["suspicious_files"].append({"file": rel, "reason": label})
                        result["findings"].append({
                            "severity": "medium",
                            "title": f"ملف باسم مشبوه ({label}): {fname}",
                            "detail": f"المسار: {rel}",
                            "fix": f"افحص المحتوى: cat {_shell_display(fpath)} | head -20",
                        })
                        break

                if result["total_files"] > 10000:
                    result["findings"].append({"severity": "info", "title": "توقف الفحص عند 10000 ملف", "detail": "", "fix": ""})
                    break
            if result["total_files"] > 10000:
                break

    except PermissionError:
        result["findings"].append({
            "severity": "info",
            "title": "بعض الملفات تحتاج صلاحيات أعلى",
            "detail": "شغّل بـ sudo للفحص الكامل",
            "fix": "sudo ayfam scan usb",
        })

    # طبقة كشف إضافية حقيقية بتوقيعات ClamAV إن كانت متوفرة
    clam_hits = _clamav_scan(mountpoint)
    if clam_hits is not None:
        result["clamav_used"] = True
        for line in clam_hits:
            result["findings"].append({
                "severity": "critical",
                "title": f"🦠 ClamAV اكتشف تهديداً: {line}",
                "detail": "توقيع مضاد فيروسات حقيقي (ClamAV) — ليس مجرد نمط نصي.",
                "fix": "احذف الملف المصاب بعد التأكد.",
            })
            result["score"] += 100

    if result["score"] == 0 and not result["findings"]:
        result["findings"].append({
            "severity": "safe",
            "title": f"✅ الجهاز نظيف — لا توجد تهديدات ({result['total_files']} ملف مفحوص)",
            "detail": "لم يتم اكتشاف أي تهديدات أمنية." + (" (تم أيضاً فحص ClamAV)" if result["clamav_used"] else ""),
            "fix": "",
        })

    return result


def deep_scan_flash_privileged(mountpoint: str, sudo_password=None) -> dict:
    """إعادة الفحص تحت sudo عند وجود ملفات لا يستطيع المستخدم قراءتها.

    يمر المسار كوسيط مستقل إلى Python، وليس داخل shell، وتُمرّر كلمة المرور
    مرة واحدة إلى sudo عبر stdin ولا تُعاد في النتيجة أو السجل.
    """
    ok_mp, mp_or_err = validators.validate_mountpoint(mountpoint)
    if not ok_mp:
        return {"mountpoint": mountpoint, "findings": [{"severity": "info", "title": f"مسار غير صالح: {mp_or_err}"}]}
    code = (
        "import json, sys; "
        "from tools.usb_control import deep_scan_flash; "
        "print(json.dumps(deep_scan_flash(sys.argv[1]), ensure_ascii=False))"
    )
    r = safe_exec.run(
        [sys.executable, "-c", code, mp_or_err],
        timeout=180,
        sudo=True,
        sudo_password=sudo_password,
    )
    if not r.ok:
        return {"mountpoint": mp_or_err, "findings": [{"severity": "high", "title": "فشل الفحص بصلاحيات مرتفعة", "detail": r.stderr or r.stdout}]}
    try:
        return json.loads(r.stdout)
    except (TypeError, ValueError):
        return {"mountpoint": mp_or_err, "findings": [{"severity": "high", "title": "نتيجة الفحص غير صالحة", "detail": r.stdout[-500:]}]}


def _shell_display(path: str) -> str:
    """اقتباس آمن للعرض فقط (shlex.quote) — حتى لو نسخ المستخدم هذا الأمر
    يدوياً في طرفيته الخاصة، لن ينكسر أو يُحقن حتى لو احتوى اسم الملف على
    رموز خاصة."""
    import shlex
    return shlex.quote(path)


def fix_flash_issues(mountpoint: str, findings: list, sudo_password=None) -> list:
    """إصلاح تلقائي مقيَّد صارم: يحذف فقط ملفات autorun/توقيعات خبيثة
    المؤكدة، ولن يحذف أي مسار يقع خارج الفلاشة نفسها (حماية من هروب عبر
    symlink أو مسار مُتلاعَب به)."""
    actions = []
    ok_mp, mp_or_err = validators.validate_mountpoint(mountpoint)
    if not ok_mp:
        return [{"action": f"رُفض: {mp_or_err}", "ok": False}]
    real_mount = os.path.realpath(mp_or_err)

    for f in findings:
        sev = f.get("severity", "")
        target_path = f.get("target_path", "")
        if not target_path or sev not in ("critical", "high"):
            continue
        title_l = f.get("title", "").lower()
        if "autorun" not in title_l and "خبيث" not in f.get("title", ""):
            continue  # الحذف التلقائي يقتصر على autorun وتوقيعات خبيثة مؤكدة فقط

        real_target = os.path.realpath(target_path)
        if not (real_target == real_mount or real_target.startswith(real_mount + os.sep)):
            actions.append({"action": f"🚫 رُفض حذف مسار خارج نطاق الفلاشة: {target_path}", "ok": False})
            continue
        if os.path.islink(target_path):
            actions.append({"action": f"🚫 تخطي رابط رمزي مشبوه: {target_path}", "ok": False})
            continue
        try:
            os.remove(target_path)
            actions.append({"action": f"✅ حُذف: {target_path}", "ok": True})
        except FileNotFoundError:
            actions.append({"action": f"غير موجود أصلاً: {target_path}", "ok": True})
        except PermissionError:
            r = safe_exec.remove_path_privileged(target_path, sudo_password=sudo_password)
            actions.append({"action": f"حُذف (sudo): {target_path}", "ok": r.ok, "out": r.stderr})
        except Exception as e:
            actions.append({"action": f"❌ فشل حذف {target_path}: {e}", "ok": False})
    return actions


# ─────────────────────────────────────────────────────────────────────────────
#  WiFi Adapter Control
# ─────────────────────────────────────────────────────────────────────────────

def get_wifi_adapters():
    """كل أوامر هذه الدالة ثابتة (iw dev) باستثناء iface الذي يُستخرج من
    مُخرَجات iw نفسها — يُتحقق منه قبل استخدامه في أي أمر لاحق."""
    adapters = []
    r = safe_exec.run(["iw", "dev"], check_binary=False)
    out = r.stdout
    current = {}
    for line in out.split("\n"):
        line = line.strip()
        if line.startswith("Interface"):
            if current:
                adapters.append(current)
            iface_raw = line.split()[-1]
            current = {"interface": iface_raw, "type": "", "ssid": "", "state": "", "mac": "", "channel": ""}
        elif "type" in line and current:
            current["type"] = line.split()[-1]
        elif "ssid" in line.lower() and current:
            current["ssid"] = line.split()[-1]
        elif "channel" in line.lower() and current:
            m = re.search(r"channel (\d+)", line)
            if m:
                current["channel"] = m.group(1)
        elif "addr" in line.lower() and current:
            m = re.search(r"([0-9a-f:]{17})", line)
            if m:
                current["mac"] = m.group(1)
    if current:
        adapters.append(current)

    for adapter in adapters:
        ok, iface = validators.validate_interface(adapter["interface"])
        if not ok:
            adapter["state"] = "UNKNOWN"
            continue
        r1 = safe_exec.run(["ip", "link", "show", iface], check_binary=False)
        adapter["state"] = "UP" if "UP" in r1.stdout else "DOWN"
        r2 = safe_exec.run(["iw", iface, "link"], check_binary=False)
        if "Connected" in r2.stdout:
            m = re.search(r"SSID: (.+)", r2.stdout)
            if m:
                adapter["ssid"] = m.group(1)
    return adapters


def wifi_adapter_control(interface: str, action: str, **kwargs) -> dict:
    """كل تحكم بواجهة WiFi يمر أولاً عبر التحقق من صحة اسم الواجهة، ثم يُنفَّذ
    بدون shell إطلاقاً (لا نستخدم && في نص واحد؛ بل خطوات Python متسلسلة)."""
    ok_iface, iface_or_err = validators.validate_interface(interface)
    if not ok_iface:
        return {"success": False, "error": iface_or_err}
    interface = iface_or_err

    if action == "connect":
        ssid = kwargs.get("ssid", "")
        password = kwargs.get("password", "")
        ok_ssid, ssid_or_err = validators.validate_ssid(ssid)
        if not ok_ssid:
            return {"success": False, "error": ssid_or_err}
        ssid = ssid_or_err
        if password:
            ok_pw, pw_or_err = validators.validate_wifi_password(password)
            if not ok_pw:
                return {"success": False, "error": pw_or_err}
            password = pw_or_err
            args = ["nmcli", "dev", "wifi", "connect", ssid, "password", password, "ifname", interface]
        else:
            args = ["nmcli", "dev", "wifi", "connect", ssid, "ifname", interface]
        r = safe_exec.run(args, sudo=True, timeout=30)
        return {"success": r.ok, "action": "connect", "out": r.stdout, "error": r.stderr}

    if action == "scan":
        r = safe_exec.run(["iw", "dev", interface, "scan"], timeout=15)
        networks = [m.group(1) for m in re.finditer(r"SSID: (.+)", r.stdout)]
        return {"success": r.ok, "networks": networks, "raw": r.stdout[:2000]}

    single_step = {
        "enable":     ["ip", "link", "set", interface, "up"],
        "disable":    ["ip", "link", "set", interface, "down"],
        "disconnect": ["nmcli", "dev", "disconnect", interface],
    }
    multi_step = {
        "monitor": [["ip", "link", "set", interface, "down"],
                    ["iw", "dev", interface, "set", "type", "monitor"],
                    ["ip", "link", "set", interface, "up"]],
        "managed": [["ip", "link", "set", interface, "down"],
                    ["iw", "dev", interface, "set", "type", "managed"],
                    ["ip", "link", "set", interface, "up"]],
    }

    if action in single_step:
        r = safe_exec.run(single_step[action], sudo=True)
        return {"success": r.ok, "action": action, "out": r.stdout, "error": r.stderr}

    if action in multi_step:
        last = None
        for step_args in multi_step[action]:
            last = safe_exec.run(step_args, sudo=True)
            if not last.ok:
                break
        return {"success": bool(last and last.ok), "action": action, "out": last.stdout if last else "", "error": last.stderr if last else ""}

    return {"success": False, "error": f"Unknown action: {action}"}


# ─────────────────────────────────────────────────────────────────────────────
#  Bluetooth Adapter Control
# ─────────────────────────────────────────────────────────────────────────────

def get_bluetooth_adapters():
    r = safe_exec.run(["hciconfig"], check_binary=False)
    adapters = []
    current = {}
    for line in r.stdout.split("\n"):
        m = re.match(r"(hci\d+):", line)
        if m:
            if current:
                adapters.append(current)
            current = {"interface": m.group(1), "state": "", "mac": "", "name": ""}
        elif "BD Address" in line and current:
            m2 = re.search(r"([0-9A-F:]{17})", line)
            if m2:
                current["mac"] = m2.group(1)
        elif "UP" in line and current:
            current["state"] = "UP"
        elif "DOWN" in line and current:
            current["state"] = "DOWN"
        elif "Name:" in line and current:
            current["name"] = line.split("'")[-2] if "'" in line else ""
    if current:
        adapters.append(current)

    if not adapters:
        r2 = safe_exec.run(["bluetoothctl", "list"], check_binary=False)
        for line in r2.stdout.split("\n"):
            m = re.search(r"Controller ([0-9A-F:]{17}) (.+)", line)
            if m:
                adapters.append({"interface": "hci0", "mac": m.group(1), "name": m.group(2), "state": "unknown"})
    return adapters


def bluetooth_control(interface: str, action: str) -> dict:
    ok_iface, iface_or_err = validators.validate_interface(interface)
    if not ok_iface:
        return {"success": False, "error": iface_or_err}
    interface = iface_or_err

    if action == "scan":
        # bluetoothctl scan on يعمل في الخلفية بلا توقف — يُشغَّل بدون انتظار
        import subprocess as _sp, shutil as _sh
        if _sh.which("bluetoothctl") is None:
            return {"success": False, "error": "bluetoothctl غير مثبتة"}
        _sp.Popen(["bluetoothctl", "scan", "on"], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, start_new_session=True)
        return {"success": True, "action": "scan", "out": "بدأ الفحص في الخلفية"}

    if action == "devices":
        r = safe_exec.run(["bluetoothctl", "devices"], timeout=15, check_binary=False)
        return {"success": r.ok, "action": action, "out": r.stdout, "error": r.stderr}

    commands = {
        "enable":  ["hciconfig", interface, "up"],
        "disable": ["hciconfig", interface, "down"],
        "reset":   ["hciconfig", interface, "reset"],
        "info":    ["hciconfig", interface, "-a"],
    }
    if action not in commands:
        return {"success": False, "error": f"Unknown action: {action}"}
    r = safe_exec.run(commands[action], sudo=True, timeout=15)
    return {"success": r.ok, "action": action, "out": r.stdout, "error": r.stderr}


# ─────────────────────────────────────────────────────────────────────────────
#  Phone Diagnostics via ADB
# ─────────────────────────────────────────────────────────────────────────────

def diagnose_android_phone(serial: str) -> dict:
    """كل قراءة من الهاتف تمر عبر adb بدون shell على الجهاز المضيف؛ serial
    يُتحقق منه أولاً لأن الهاتف نفسه قد يكون غير موثوق (BadUSB-like)."""
    ok_serial, serial_or_err = validators.validate_adb_serial(serial)
    if not ok_serial:
        return {"serial": serial, "info": {}, "health": {}, "storage": {}, "battery": {},
                "apps": {}, "security": {}, "findings": [{
                    "severity": "info", "title": f"رقم تسلسلي غير صالح: {serial_or_err}", "detail": "", "fix": "",
                }]}
    serial = serial_or_err

    def adb_shell(cmd_parts, timeout=15):
        r = safe_exec.run(["adb", "-s", serial, "shell"] + list(cmd_parts), timeout=timeout, check_binary=False)
        return r.stdout

    result = {
        "serial": serial, "info": {}, "health": {}, "storage": {},
        "battery": {}, "apps": {}, "security": {}, "findings": [],
    }

    result["info"] = {
        "brand": adb_shell(["getprop", "ro.product.brand"]),
        "model": adb_shell(["getprop", "ro.product.model"]),
        "android": adb_shell(["getprop", "ro.build.version.release"]),
        "sdk": adb_shell(["getprop", "ro.build.version.sdk"]),
        "security_patch": adb_shell(["getprop", "ro.build.version.security_patch"]),
        "serial": serial,
        "build": adb_shell(["getprop", "ro.build.display.id"]),
    }

    bat = adb_shell(["dumpsys", "battery"])
    for line in bat.split("\n"):
        if "level:" in line:
            m = re.search(r"level: (\d+)", line)
            if m:
                result["battery"]["level"] = int(m.group(1))
        if "health:" in line:
            m = re.search(r"health: (\d+)", line)
            if m:
                health_map = {1: "Unknown", 2: "Good", 3: "Overheat", 4: "Dead", 5: "Over voltage", 6: "Unspecified failure", 7: "Cold"}
                result["battery"]["health"] = health_map.get(int(m.group(1)), "Unknown")
        if "temperature:" in line:
            m = re.search(r"temperature: (\d+)", line)
            if m:
                result["battery"]["temp_c"] = int(m.group(1)) / 10

    storage = adb_shell(["df", "/data"])
    for line in storage.split("\n")[1:]:
        parts = line.split()
        if len(parts) >= 5:
            result["storage"] = {"total": parts[1], "used": parts[2], "available": parts[3], "use_pct": parts[4]}

    rooted = adb_shell(["which", "su"])
    result["security"]["rooted"] = bool(rooted and rooted.strip())
    if result["security"]["rooted"]:
        result["findings"].append({
            "severity": "high",
            "title": "الهاتف مفتوح الجذر (Rooted)!",
            "detail": "وُجد /system/bin/su — يعني صلاحيات Root متاحة.",
            "fix": "لا تثق بالتطبيقات على هاتف Rooted. فكّر في إعادة ضبط المصنع.",
        })

    usb_debug = adb_shell(["getprop", "persist.service.adb.enable"])
    result["security"]["usb_debug_always"] = usb_debug.strip() == "1"

    dev_mode = adb_shell(["settings", "get", "global", "development_settings_enabled"])
    result["security"]["dev_mode"] = dev_mode.strip() == "1"

    app_list = adb_shell(["pm", "list", "packages"])
    app_lines = [l for l in app_list.split("\n") if l.strip()]
    result["apps"]["total"] = str(len(app_lines))

    suspicious_kw = ("spy", "hack", "monitor", "keylog", "tracker")
    suspicious = [l for l in app_lines if any(k in l.lower() for k in suspicious_kw)]
    if suspicious:
        result["security"]["suspicious_apps"] = suspicious
        result["findings"].append({
            "severity": "critical",
            "title": f"تطبيقات مشبوهة! {suspicious[0][:100]}",
            "detail": "تطبيقات بأسماء تشير إلى مراقبة أو تجسس.",
            "fix": f"أزل: adb -s {serial} uninstall <package_name>",
        })

    sdk = result["info"].get("sdk", "")
    try:
        sdk_num = int(sdk)
        if sdk_num < 28:
            result["findings"].append({
                "severity": "high",
                "title": f"إصدار Android قديم: {result['info'].get('android')} (SDK {sdk})",
                "detail": "النظام قديم ولا يتلقى تحديثات أمان.",
                "fix": "حدّث نظام Android أو استبدل الجهاز.",
            })
    except ValueError:
        pass

    battery_level = result["battery"].get("level", 100)
    if battery_level < 20:
        result["findings"].append({
            "severity": "low", "title": f"بطارية منخفضة: {battery_level}%",
            "detail": "مستوى البطارية منخفض جداً.", "fix": "اشحن الهاتف.",
        })

    battery_temp = result["battery"].get("temp_c", 0)
    if battery_temp > 45:
        result["findings"].append({
            "severity": "medium", "title": f"حرارة البطارية مرتفعة: {battery_temp}°C",
            "detail": "درجة حرارة البطارية مرتفعة — قد يؤثر على الأداء والسلامة.",
            "fix": "أبعد الهاتف عن مصادر الحرارة وأغلق التطبيقات الثقيلة.",
        })

    return result


def adb_fix_action(serial: str, action: str, **kwargs) -> dict:
    ok_serial, serial_or_err = validators.validate_adb_serial(serial)
    if not ok_serial:
        return {"success": False, "error": serial_or_err}
    serial = serial_or_err

    def adb(args_tail, timeout=30, input_data=None):
        r = safe_exec.run(["adb", "-s", serial] + list(args_tail), timeout=timeout, input_data=input_data, check_binary=False)
        return r.ok, r.stdout, r.stderr

    if action == "clear_app_cache":
        ok_pkg, pkg_or_err = validators.validate_android_package(kwargs.get("package", ""))
        if not ok_pkg:
            return {"success": False, "error": pkg_or_err}
        ok, out, err = adb(["shell", "pm", "clear", pkg_or_err])
        return {"success": ok, "out": out}

    elif action == "uninstall_app":
        ok_pkg, pkg_or_err = validators.validate_android_package(kwargs.get("package", ""))
        if not ok_pkg:
            return {"success": False, "error": pkg_or_err}
        ok, out, err = adb(["uninstall", pkg_or_err])
        return {"success": ok, "out": out}

    elif action == "enable_storage":
        ok, out, err = adb(["shell", "svc", "data", "enable"])
        return {"success": ok, "out": out}

    elif action == "force_stop":
        ok_pkg, pkg_or_err = validators.validate_android_package(kwargs.get("package", ""))
        if not ok_pkg:
            return {"success": False, "error": pkg_or_err}
        ok, out, err = adb(["shell", "am", "force-stop", pkg_or_err])
        return {"success": ok, "out": out}

    elif action == "factory_reset":
        ok, out, err = adb(["shell", "am", "broadcast", "-a", "android.intent.action.MASTER_CLEAR"])
        return {"success": ok, "out": out, "warning": "هذا سيمسح جميع البيانات!"}

    elif action == "pull_file":
        remote = (kwargs.get("remote") or "").strip()
        if not remote or "\x00" in remote:
            return {"success": False, "error": "مسار remote غير صالح"}
        # مسار الحفظ محلياً مقيَّد دائماً بمجلد ثابت آمن — لا يمكن لأي مدخل
        # من المستخدم أن يخرج عن /tmp/ayfam_pulled/ مهما كان.
        safe_base = "/tmp/ayfam_pulled"
        requested_name = os.path.basename((kwargs.get("local") or "").strip()) or "pulled"
        local = os.path.join(safe_base, requested_name)
        os.makedirs(safe_base, exist_ok=True)
        ok, out, err = adb(["pull", remote, local])
        return {"success": ok, "out": out, "local": local}

    elif action == "list_files":
        path = (kwargs.get("path") or "/sdcard/").strip()
        if not path or "\x00" in path:
            return {"success": False, "error": "مسار غير صالح"}
        ok, out, err = adb(["shell", "ls", "-la", path])
        return {"success": ok, "out": out}

    return {"success": False, "error": f"Unknown action: {action}"}


# ─────────────────────────────────────────────────────────────────────────────
#  Generic USB Device Info Enhancement
# ─────────────────────────────────────────────────────────────────────────────

DEVICE_TYPE_DESCRIPTIONS = {
    "WiFi": {"desc_ar": "محوّل شبكة لاسلكية", "desc_en": "Wireless Network Adapter", "controls": ["enable", "disable", "scan", "connect", "monitor_mode"]},
    "Bluetooth": {"desc_ar": "جهاز بلوتوث", "desc_en": "Bluetooth Adapter", "controls": ["enable", "disable", "scan_devices", "pair"]},
    "Storage": {"desc_ar": "جهاز تخزين / فلاشة", "desc_en": "Mass Storage / Flash Drive", "controls": ["scan", "deep_scan", "eject", "mount", "format"]},
    "Camera": {"desc_ar": "كاميرا", "desc_en": "Camera / Webcam", "controls": ["view_stream", "disable", "check_access"]},
    "Phone": {"desc_ar": "هاتف / جهاز Android", "desc_en": "Phone / Android Device", "controls": ["diagnose", "files", "apps", "fix", "disconnect"]},
    "Keyboard": {"desc_ar": "لوحة مفاتيح", "desc_en": "Keyboard / HID", "controls": ["allow", "block", "verify"]},
    "Hub": {"desc_ar": "موزّع USB", "desc_en": "USB Hub", "controls": ["info", "list_connected"]},
    "Unknown": {"desc_ar": "جهاز غير معروف", "desc_en": "Unknown Device", "controls": ["allow", "block", "info"]},
}


def detect_device_type(device: dict) -> str:
    desc = (device.get("product", "") + " " + device.get("description", "") + " " + device.get("class_name", "")).lower()
    vid = device.get("vendor_id", "").lower()
    cls = device.get("device_class", "").lower()

    if any(k in desc for k in ["wifi", "wireless", "802.11", "wlan", "wi-fi"]) or cls == "ff":
        return "WiFi"
    if any(k in desc for k in ["bluetooth", "bt adapter"]):
        return "Bluetooth"
    if any(k in desc for k in ["mass storage", "flash", "disk", "crw", "card reader"]) or cls == "08":
        return "Storage"
    if any(k in desc for k in ["camera", "webcam", "uvc"]) or cls == "0e":
        return "Camera"
    if any(k in desc for k in ["phone", "android", "samsung", "xiaomi", "huawei", "oneplus"]) or cls in ("02", "ff"):
        return "Phone"
    if any(k in desc for k in ["keyboard", "hid"]) or cls == "03":
        return "Keyboard"
    if any(k in desc for k in ["hub"]) or cls == "09":
        return "Hub"
    return "Unknown"


def get_device_controls(device_type: str) -> list:
    return DEVICE_TYPE_DESCRIPTIONS.get(device_type, DEVICE_TYPE_DESCRIPTIONS["Unknown"])["controls"]
