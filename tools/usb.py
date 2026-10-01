"""
AI AYFAM - USB & Device Scanner
فحص أجهزة USB والهواتف والفلاشات
"""

import subprocess
import re
import os
import json
import shlex
from datetime import datetime

from utils import safe_exec, validators


def _run(cmd, timeout=30):
    """⚠️ لأوامر shell ثابتة فقط — بدون أي متغيّر مُدرَج. أي قيمة متغيّرة
    (serial جهاز، مسار...) يجب أن تمر عبر safe_exec.run() بقائمة وسائط."""
    res = safe_exec.run_trusted_shell(cmd, timeout=timeout)
    return res.stdout, res.stderr


KNOWN_MALICIOUS_DEVICES = {
    "rubber_ducky_keywords": ["HID Keyboard", "USB Rubber Ducky"],
    "bad_usb_vid_pid": [("03eb", "2042"), ("16d0", "0753")],
}

DEVICE_CLASS_NAMES = {
    "00": "Unspecified", "01": "Audio", "02": "Communications",
    "03": "Human Interface Device (HID)", "05": "Physical", "06": "Image",
    "07": "Printer", "08": "Mass Storage", "09": "Hub",
    "0a": "CDC Data", "0b": "Smart Card", "0d": "Content Security",
    "0e": "Video", "0f": "Personal Healthcare", "10": "Audio/Video",
    "dc": "Diagnostic", "e0": "Wireless Controller", "ef": "Miscellaneous",
    "fe": "Application Specific", "ff": "Vendor Specific",
}


def list_usb_devices():
    devices = []
    out, _ = _run("lsusb -v 2>/dev/null | grep -E 'Bus|idVendor|idProduct|iManufacturer|iProduct|bDeviceClass|bDeviceSubClass' | head -200")
    current = {}
    for line in out.split("\n"):
        line = line.strip()
        if line.startswith("Bus"):
            if current:
                devices.append(_analyze_usb_device(current))
                current = {}
            m = re.search(r"Bus (\d+) Device (\d+): ID ([0-9a-f]+):([0-9a-f]+)\s*(.*)", line)
            if m:
                current = {
                    "bus": m.group(1), "device": m.group(2),
                    "vendor_id": m.group(3), "product_id": m.group(4),
                    "description": m.group(5).strip(),
                    "manufacturer": "", "product": "", "device_class": "", "class_name": "",
                }
        elif "idVendor" in line:
            m = re.search(r"idVendor\s+0x([0-9a-f]+)\s*(.*)", line)
            if m and current:
                current["vendor_id"] = m.group(1)
                current["manufacturer"] = m.group(2).strip()
        elif "idProduct" in line:
            m = re.search(r"idProduct\s+0x([0-9a-f]+)\s*(.*)", line)
            if m and current:
                current["product_id"] = m.group(1)
                current["product"] = m.group(2).strip()
        elif "iManufacturer" in line:
            m = re.search(r"iManufacturer\s+\d+\s*(.*)", line)
            if m and current and m.group(1).strip():
                current["manufacturer"] = m.group(1).strip()
        elif "iProduct" in line:
            m = re.search(r"iProduct\s+\d+\s*(.*)", line)
            if m and current and m.group(1).strip():
                current["product"] = m.group(1).strip()
        elif "bDeviceClass" in line:
            m = re.search(r"bDeviceClass\s+(\w+)\s*(.*)", line)
            if m and current:
                cls = m.group(1).lower().zfill(2)
                current["device_class"] = cls
                current["class_name"] = DEVICE_CLASS_NAMES.get(cls, m.group(2).strip())

    if current:
        devices.append(_analyze_usb_device(current))

    if not devices:
        out2, _ = _run("lsusb 2>/dev/null")
        for line in out2.split("\n"):
            if not line.strip():
                continue
            m = re.search(r"Bus (\d+) Device (\d+): ID ([0-9a-f]+):([0-9a-f]+)\s*(.*)", line)
            if m:
                dev = {
                    "bus": m.group(1), "device": m.group(2),
                    "vendor_id": m.group(3), "product_id": m.group(4),
                    "description": m.group(5).strip(),
                    "manufacturer": "", "product": m.group(5).strip(),
                    "device_class": "", "class_name": "",
                }
                devices.append(_analyze_usb_device(dev))
    return devices


def _analyze_usb_device(dev):
    risk = "low"
    flags = []
    recommendations = []

    vid = dev.get("vendor_id", "").lower()
    pid = dev.get("product_id", "").lower()
    desc = (dev.get("description", "") + " " + dev.get("product", "")).lower()
    cls = dev.get("device_class", "")

    for bad_vid, bad_pid in KNOWN_MALICIOUS_DEVICES["bad_usb_vid_pid"]:
        if vid == bad_vid and pid == bad_pid:
            risk = "critical"
            flags.append("⚠️  جهاز BadUSB معروف! / Known BadUSB device!")
            recommendations.append("افصل هذا الجهاز فوراً / Disconnect this device immediately!")

    for keyword in KNOWN_MALICIOUS_DEVICES["rubber_ducky_keywords"]:
        if keyword.lower() in desc:
            risk = "critical"
            flags.append(f"⚠️  يشبه Rubber Ducky / Resembles {keyword}")

    if cls == "03" or "hid" in desc:
        if any(k in desc for k in ["keyboard", "input", "hid"]):
            if not any(k in desc for k in ["mouse", "touchpad", "trackpad"]):
                flags.append("لوحة مفاتيح HID — تحقق من مصدرها / HID Keyboard detected")
                if risk == "low":
                    risk = "medium"
                recommendations.append("تحقق من أن لوحة المفاتيح معروفة لك / Verify this keyboard is known to you")

    if cls == "ef" or "wireless" in desc or "bluetooth" in desc.lower():
        flags.append("جهاز لاسلكي / Wireless device detected")
        if risk == "low":
            risk = "medium"

    if cls == "08" or "storage" in desc or "flash" in desc or "disk" in desc:
        flags.append("جهاز تخزين / Mass storage device")

    dev["risk"] = risk
    dev["flags"] = flags
    dev["recommendations"] = recommendations
    return dev


def scan_mounted_drives(usb_only: bool = False):
    drives = []
    out, _ = _run("lsblk -J -o NAME,SIZE,TYPE,MOUNTPOINT,VENDOR,MODEL,TRAN,HOTPLUG 2>/dev/null")
    try:
        data = json.loads(out)
        for block in data.get("blockdevices", []):
            is_usb = block.get("tran") == "usb" or block.get("hotplug") == "1"
            if usb_only and not is_usb:
                continue
            if is_usb or block.get("type") in ("disk",):
                info = {
                    "name": block.get("name", ""),
                    "size": block.get("size", ""),
                    "type": block.get("type", ""),
                    "vendor": block.get("vendor", ""),
                    "model": block.get("model", ""),
                    "transport": block.get("tran", ""),
                    "is_usb": is_usb,
                    "partitions": [],
                    "findings": [],
                }
                for child in block.get("children", []):
                    part = {
                        "name": child.get("name", ""),
                        "size": child.get("size", ""),
                        "mountpoint": child.get("mountpoint", ""),
                    }
                    if child.get("mountpoint"):
                        part["analysis"] = analyze_mounted_filesystem(child["mountpoint"])
                    info["partitions"].append(part)
                drives.append(info)
    except Exception:
        out2, _ = _run("df -h 2>/dev/null")
        for line in out2.split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 6:
                device = parts[0]
                mount = parts[5]
                if "/media/" in mount or "/mnt/" in mount:
                    drives.append({
                        "name": device, "size": parts[1], "mountpoint": mount,
                        "is_usb": True, "findings": [],
                        "analysis": analyze_mounted_filesystem(mount),
                    })
    return drives


def analyze_mounted_filesystem(mountpoint: str) -> dict:
    result = {
        "path": mountpoint,
        "suspicious_files": [],
        "autorun_files": [],
        "hidden_files": [],
        "executable_count": 0,
        "total_files_checked": 0,
        "findings": [],
    }

    dangerous_extensions = {".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".vbs", ".ps1",
                            ".sh", ".py", ".rb", ".pl", ".jar", ".apk", ".deb", ".rpm"}
    autorun_names = {"autorun.inf", "autorun.sh", "autoplay.inf", ".autorun", "launch.bat"}
    suspicious_names_patterns = [
        r"(hack|malware|virus|trojan|backdoor|keylogger|exploit|payload|shell|rootkit)",
        r"(password|passwd|credential|login|secret)\.(txt|dat|csv|xls)",
    ]

    try:
        for root, dirs, files in os.walk(mountpoint, followlinks=False):
            dirs[:] = [d for d in dirs if not d.startswith(".") and not os.path.islink(os.path.join(root, d))]
            for fname in files:
                fpath_check = os.path.join(root, fname)
                if os.path.islink(fpath_check):
                    continue  # لا تتبع الروابط الرمزية — قد تشير خارج الفلاشة
                result["total_files_checked"] += 1
                fpath = os.path.join(root, fname)
                flower = fname.lower()

                if fname.startswith("."):
                    result["hidden_files"].append(fpath.replace(mountpoint, ""))

                if flower in autorun_names:
                    result["autorun_files"].append(fname)
                    result["findings"].append({
                        "severity": "high",
                        "title": f"ملف Autorun مشبوه: {fname}",
                        "detail": f"الملف {fname} في {root} يمكن أن يُشغَّل تلقائياً.",
                        "fix": f"احذف الملف: rm -- {shlex.quote(fpath)} أو افحص محتواه أولاً",
                    })

                ext = os.path.splitext(flower)[1]
                if ext in dangerous_extensions:
                    result["executable_count"] += 1
                    if ext in {".exe", ".dll", ".bat", ".scr", ".com"}:
                        result["suspicious_files"].append(fname)

                for pattern in suspicious_names_patterns:
                    if re.search(pattern, flower, re.IGNORECASE):
                        result["suspicious_files"].append(fname)
                        result["findings"].append({
                            "severity": "medium",
                            "title": f"ملف باسم مشبوه: {fname}",
                            "detail": f"اسم الملف يشير إلى محتوى خطير محتمل.",
                            "fix": f"افحص الملف: file {shlex.quote(fpath)} && strings {shlex.quote(fpath)} | head -50",
                        })
                        break

                if result["total_files_checked"] > 5000:
                    break
    except PermissionError:
        result["findings"].append({
            "severity": "info",
            "title": "لا توجد صلاحيات كافية للفحص الكامل",
            "detail": f"تعذّر الوصول لبعض المجلدات في {mountpoint}",
            "fix": "شغّل الوكيل بصلاحيات sudo لفحص أعمق",
        })
    except Exception as e:
        result["error"] = str(e)

    if result["executable_count"] > 10:
        result["findings"].append({
            "severity": "medium",
            "title": f"عدد كبير من الملفات التنفيذية: {result['executable_count']}",
            "detail": "الجهاز يحتوي على عدد مرتفع من الملفات التنفيذية.",
            "fix": "راجع كل ملف تنفيذي على حدة.",
        })

    return result


def check_usb_permissions():
    findings = []
    udev_out, _ = _run("ls /etc/udev/rules.d/ 2>/dev/null")
    if "usb" not in udev_out.lower():
        findings.append({
            "severity": "medium",
            "title": "لا توجد قواعد udev لتقييد USB",
            "detail": "يمكن لأي جهاز USB الاتصال بدون قيود.",
            "fix": 'أنشئ /etc/udev/rules.d/99-usb-restrict.rules\nمثال: SUBSYSTEM=="usb", ATTR{idVendor}!="VENDOR_ID", ATTR{idProduct}!="PRODUCT_ID", RUN+="/bin/sh -c \'echo 0 > /sys$DEVPATH/authorized\'"',
        })
    return {"udev_rules": udev_out.split(), "findings": findings}


def get_connected_phones():
    phones = []
    out, _ = _run("adb devices 2>/dev/null")
    if "List of devices attached" in out:
        for line in out.split("\n")[1:]:
            if line.strip() and "\t" in line:
                serial, status = line.split("\t")
                serial = serial.strip()
                status = status.strip()
                info = {"serial": serial, "status": status, "details": {}, "findings": []}

                ok_serial, serial_clean = validators.validate_adb_serial(serial)
                if not ok_serial:
                    info["findings"].append({
                        "severity": "medium",
                        "title": f"رقم تسلسلي غير صالح لجهاز ADB — تم تجاهله للحماية: {serial_clean}",
                        "detail": "قد يكون هذا محاولة لجهاز USB مزيَّف (BadUSB) لانتحال رقم تسلسلي خبيث.",
                        "fix": "افصل الجهاز وتحقق منه يدوياً.",
                    })
                    phones.append(info)
                    continue

                if status == "device":
                    def adb_get(prop, timeout=10):
                        r = safe_exec.run(["adb", "-s", serial_clean, "shell", "getprop", prop],
                                           timeout=timeout, check_binary=False)
                        return r.stdout

                    brand = adb_get("ro.product.brand")
                    model = adb_get("ro.product.model")
                    android = adb_get("ro.build.version.release")
                    su_check = safe_exec.run(["adb", "-s", serial_clean, "shell", "which", "su"],
                                              timeout=10, check_binary=False)
                    rooted = su_check.stdout
                    info["details"] = {"brand": brand, "model": model, "android": android, "rooted": bool(rooted)}
                    if rooted:
                        info["findings"].append({
                            "severity": "high",
                            "title": f"الهاتف {brand} {model} مفتوح الجذر (Rooted)!",
                            "detail": "الهاتف مفتوح الجذر مما يزيد من مخاطر الأمان بشكل كبير.",
                            "fix": "لا تقم بتوصيل هاتف مفتوح الجذر بأجهزة حساسة.",
                        })
                phones.append(info)

    if not phones:
        mtp_out, _ = _run("ls /run/user/*/gvfs/mtp* 2>/dev/null || ls /tmp/gvfs*/mtp* 2>/dev/null")
        if mtp_out:
            phones.append({"status": "MTP device detected", "path": mtp_out, "findings": []})
    return phones
