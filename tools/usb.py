"""
AI AYFAM - USB & Device Scanner
فحص أجهزة USB والهواتف والفلاشات
"""

import subprocess
import re
import os
import json
import shlex
import stat
from pathlib import Path
from datetime import datetime

from utils import safe_exec, validators


def _run(cmd, timeout=30):
    """⚠️ لأوامر shell ثابتة فقط — بدون أي متغيّر مُدرَج. أي قيمة متغيّرة
    (serial جهاز، مسار...) يجب أن تمر عبر safe_exec.run() بقائمة وسائط."""
    res = safe_exec.run_trusted_shell(cmd, timeout=timeout)
    return res.stdout, res.stderr


KNOWN_MALICIOUS_DEVICES = {
    "rubber_ducky_keywords": [
        "rubber ducky", "flipper zero", "bash bunny", "teensyduino",
        "malduino", "whid", "omg cable", "badusb", "usb armory",
        "lan turtle", "packet squirrel"
    ],
    "bad_usb_vid_pid": [
        ("03eb", "2042"),  # LUFA / ATmega32U4 USB Keyboard demo
        ("03eb", "2403"),  # USB Rubber Ducky (Hak5)
        ("16d0", "0753"),  # Digispark Attiny85 USB Keyboard
        ("16c0", "0486"),  # Teensy USB Serial/Keyboard/Mouse
        ("16c0", "0476"),  # Teensy RawHID
        ("16c0", "0478"),  # Teensy Halfkay bootloader
        ("0483", "5740"),  # Flipper Zero Virtual COM Port / BadUSB
        ("0483", "df11"),  # STM32 DFU / Flipper DFU
        ("2341", "8036"),  # Arduino Leonardo
        ("2341", "8037"),  # Arduino Micro
        ("1b4f", "9205"),  # SparkFun Pro Micro 3.3V / MalDuino
        ("1b4f", "9206"),  # SparkFun Pro Micro 5V
        ("1d6b", "0104"),  # Multifunction Composite Gadget / USB Armory
        ("1fc9", "0083"),  # NXP LPC microcontroller BadUSB
    ],
}

KNOWN_SAFE_KEYBOARD_VENDORS = {
    "046d",  # Logitech
    "045e",  # Microsoft
    "1532",  # Razer
    "413c",  # Dell
    "17ef",  # Lenovo
    "03f0",  # HP
    "04f2",  # Chicony
    "04ca",  # Lite-On
    "05ac",  # Apple
    "04b4",  # Cypress Semiconductor
    "1bcf",  # Sunplus Innovation
}

DEVICE_CLASS_NAMES = {
    "00": "Unspecified (Interface-defined)", "01": "Audio", "02": "Communications",
    "03": "Human Interface Device (HID)", "05": "Physical", "06": "Image",
    "07": "Printer", "08": "Mass Storage", "09": "Hub",
    "0a": "CDC Data", "0b": "Smart Card", "0d": "Content Security",
    "0e": "Video", "0f": "Personal Healthcare", "10": "Audio/Video",
    "dc": "Diagnostic", "e0": "Wireless Controller", "ef": "Miscellaneous",
    "fe": "Application Specific", "ff": "Vendor Specific",
}


def _list_usb_devices_sysfs(sysfs_root: str = "/sys/bus/usb/devices") -> list[dict]:
    """استكشاف أجهزة USB عبر قراءة sysfs مباشرة (يعمل دون الحاجة لأداة lsusb)."""
    devices = []
    if not os.path.exists(sysfs_root):
        return devices

    try:
        entries = sorted(os.listdir(sysfs_root))
    except Exception:
        return devices

    for entry in entries:
        # واجهات الأجهزة تحتوي على نقطتين مثل 1-1:1.0 بينما الأجهزة الفعلية لا تحتويها
        if ":" in entry:
            continue
        dev_dir = os.path.join(sysfs_root, entry)
        if not os.path.isdir(dev_dir):
            continue

        busnum_path = os.path.join(dev_dir, "busnum")
        devnum_path = os.path.join(dev_dir, "devnum")
        vid_path = os.path.join(dev_dir, "idVendor")

        if not (os.path.exists(busnum_path) and os.path.exists(devnum_path) and os.path.exists(vid_path)):
            continue

        def _read_attr(filename):
            try:
                p = os.path.join(dev_dir, filename)
                if os.path.isfile(p):
                    return Path(p).read_text(encoding="utf-8", errors="ignore").strip()
            except Exception:
                pass
            return ""

        bus = _read_attr("busnum")
        dev_num = _read_attr("devnum")
        vid = _read_attr("idVendor").lower()
        pid = _read_attr("idProduct").lower()
        mfr = _read_attr("manufacturer")
        prod = _read_attr("product")
        raw_cls = _read_attr("bDeviceClass")
        cls = raw_cls.lower().zfill(2) if raw_cls else ""
        serial = _read_attr("serial")

        iface_classes = []
        try:
            for sub in os.listdir(dev_dir):
                if sub.startswith(entry + ":"):
                    sub_cls_path = os.path.join(dev_dir, sub, "bInterfaceClass")
                    if os.path.isfile(sub_cls_path):
                        ic = Path(sub_cls_path).read_text(encoding="utf-8", errors="ignore").strip().lower().zfill(2)
                        if ic and ic not in iface_classes:
                            iface_classes.append(ic)
        except Exception:
            pass

        desc = f"{mfr} {prod}".strip() or f"USB Device {vid}:{pid}"
        dev_dict = {
            "bus": bus,
            "device": dev_num,
            "vendor_id": vid,
            "product_id": pid,
            "description": desc,
            "manufacturer": mfr,
            "product": prod or desc,
            "device_class": cls,
            "class_name": DEVICE_CLASS_NAMES.get(cls, ""),
            "interface_classes": iface_classes,
            "serial": serial,
        }
        devices.append(_analyze_usb_device(dev_dict))

    return devices


def list_usb_devices():
    devices = []
    # فحص موسع عبر lsusb -v مع التقاط الواجهات وفئات الأجهزة
    out, _ = _run("lsusb -v 2>/dev/null | grep -E 'Bus|idVendor|idProduct|iManufacturer|iProduct|bDeviceClass|bDeviceSubClass|bInterfaceClass' | head -4000")
    current = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Bus"):
            if current:
                devices.append(_analyze_usb_device(current))
                current = {}
            m = re.search(r"Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\s*(.*)", line, re.IGNORECASE)
            if m:
                current = {
                    "bus": m.group(1),
                    "device": m.group(2),
                    "vendor_id": m.group(3).lower(),
                    "product_id": m.group(4).lower(),
                    "description": m.group(5).strip(),
                    "manufacturer": "",
                    "product": "",
                    "device_class": "",
                    "class_name": "",
                    "interface_classes": [],
                }
        elif "idVendor" in line:
            m = re.search(r"idVendor\s+0x([0-9a-fA-F]+)\s*(.*)", line, re.IGNORECASE)
            if m and current:
                current["vendor_id"] = m.group(1).lower()
                current["manufacturer"] = m.group(2).strip()
        elif "idProduct" in line:
            m = re.search(r"idProduct\s+0x([0-9a-fA-F]+)\s*(.*)", line, re.IGNORECASE)
            if m and current:
                current["product_id"] = m.group(1).lower()
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
        elif "bInterfaceClass" in line:
            m = re.search(r"bInterfaceClass\s+(\w+)\s*(.*)", line)
            if m and current:
                icls = m.group(1).lower().zfill(2)
                if icls not in current.get("interface_classes", []):
                    current.setdefault("interface_classes", []).append(icls)

    if current:
        devices.append(_analyze_usb_device(current))

    # Fallback 1: lsusb القياسي المختصر
    if not devices:
        out2, _ = _run("lsusb 2>/dev/null")
        for line in out2.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.search(r"Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\s*(.*)", line, re.IGNORECASE)
            if m:
                dev = {
                    "bus": m.group(1),
                    "device": m.group(2),
                    "vendor_id": m.group(3).lower(),
                    "product_id": m.group(4).lower(),
                    "description": m.group(5).strip(),
                    "manufacturer": "",
                    "product": m.group(5).strip(),
                    "device_class": "",
                    "class_name": "",
                    "interface_classes": [],
                }
                devices.append(_analyze_usb_device(dev))

    # Fallback 2: قراءة sysfs مباشرة عند غياب أداة lsusb
    if not devices:
        devices = _list_usb_devices_sysfs()

    return devices


def _analyze_usb_device(dev):
    risk = "low"
    flags = []
    recommendations = []

    vid = str(dev.get("vendor_id") or "").lower()
    pid = str(dev.get("product_id") or "").lower()
    desc = (str(dev.get("description", "")) + " " + str(dev.get("product", "")) + " " + str(dev.get("manufacturer", "")) + " " + str(dev.get("device", ""))).lower()
    cls = str(dev.get("device_class") or "").lower().zfill(2) if dev.get("device_class") else ""
    ifaces = [str(x).lower().zfill(2) for x in dev.get("interface_classes", [])]
    for ifc in dev.get("interfaces", []):
        if isinstance(ifc, dict) and "class_code" in ifc:
            ifaces.append(str(ifc["class_code"]).lower().zfill(2))
        elif isinstance(ifc, str):
            ifaces.append(ifc.lower().zfill(2))

    # 1. مطابقة معرفات الأجهزة الخبيثة المعروفة بدقة (BadUSB / Hardware Injection)
    for bad_vid, bad_pid in KNOWN_MALICIOUS_DEVICES["bad_usb_vid_pid"]:
        if vid == bad_vid and pid == bad_pid:
            risk = "critical"
            flags.append("⚠️  جهاز BadUSB معروف! / Known BadUSB device!")
            recommendations.append("افصل هذا الجهاز فوراً — قد يحقن أوامر برمجية تلقائياً.")

    # 2. كلمات مفتاحية لأجهزة الاختراق الشهيرة
    for keyword in KNOWN_MALICIOUS_DEVICES["rubber_ducky_keywords"]:
        if keyword in desc:
            risk = "critical"
            flags.append(f"⚠️  يشبه أجهزة الحقن ({keyword}) / Resembles {keyword}")
            if not any("افصل هذا الجهاز" in r for r in recommendations):
                recommendations.append("تحقق من طبيعة هذا الجهاز — يطابق أدوات حقن العتاد المعروفة.")

    # 3. كشف الأجهزة الهجينة والمتنكّرة (Composite Device Masquerading)
    has_hid = (cls == "03" or "03" in ifaces or any(k in desc for k in ["keyboard", "input", "hid"]))
    has_storage = (cls == "08" or "08" in ifaces or any(k in desc for k in ["storage", "flash", "disk", "mass storage"]))
    has_net = (cls in ("02", "0a", "ef") or any(c in ifaces for c in ("02", "0a")) or any(k in desc for k in ["ethernet", "rndis", "cdc"]))

    if has_hid and has_storage:
        risk = "critical"
        flags.append("⚠️ جهاز هجين (Storage + HID Injection) مشتبه به!")
        recommendations.append("تحذير: يحتوي هذا الجهاز على واجهة تخزين وواجهة لوحة مفاتيح معاً (نمط هجوم BadUSB).")

    # 4. كشف انتحال بطاقات الشبكة (PoisonTap / USB Ethernet attack)
    if has_net and (has_storage or "usb" in desc) and not any(safe_v in vid for safe_v in ("0b95", "0bda")):
        if risk != "critical":
            risk = "medium"
        flags.append("بطاقة شبكة USB افتراضية (CDC/RNDIS) — قد تستهدف تحويل مسار الاتصال")
        recommendations.append("تحقق من أنك قمت بتوصيل محول شبكة حقيقي وليس جهازاً متخفياً.")

    # 5. تحليل لوحات المفاتيح وأجهزة الإدخال (HID Keystroke Injection Risk)
    if has_hid:
        is_mouse = any(k in desc for k in ["mouse", "touchpad", "trackpad"])
        is_keyboard = any(k in desc for k in ["keyboard", "input", "hid"]) or not is_mouse
        if is_keyboard and not is_mouse:
            flags.append("لوحة مفاتيح HID — تحقق من مصدرها / HID Keyboard detected")
            if vid not in KNOWN_SAFE_KEYBOARD_VENDORS:
                if risk == "low":
                    risk = "medium"
                recommendations.append("لوحة مفاتيح من مصدر غير قياسي — تأكد من هوية المصنّع.")

    # 6. الأجهزة اللاسلكية
    if cls == "ef" or "wireless" in desc or "bluetooth" in desc:
        flags.append("جهاز لاسلكي / Wireless device detected")
        if risk == "low":
            risk = "medium"

    # 7. وسائط التخزين
    if has_storage:
        flags.append("جهاز تخزين / Mass storage device")

    device_type = "Standard USB Device"
    if "rubber ducky" in desc or (vid, pid) in [("03eb", "2403"), ("16d0", "0753"), ("16c0", "0486")]:
        device_type = "Rubber Ducky / BadUSB"
    elif "flipper" in desc or (vid, pid) in [("0483", "5740"), ("0483", "df11")]:
        device_type = "Flipper Zero"
    elif has_hid and has_storage:
        device_type = "Hybrid (HID + Mass Storage)"
    elif has_hid:
        device_type = "HID (Keyboard/Input)"
    elif has_storage:
        device_type = "Mass Storage"

    is_bad = (risk == "critical" or any("BadUSB" in f or "أجهزة الحقن" in f for f in flags))

    dev["risk"] = risk
    dev["risk_level"] = risk.upper()
    dev["is_known_bad_device"] = is_bad
    dev["is_hybrid_device"] = (has_hid and has_storage)
    dev["device_type"] = device_type
    dev["flags"] = flags
    dev["risks"] = flags
    dev["recommendations"] = recommendations
    return dev


def _truthy_block_value(value) -> bool:
    """توحيد قيم lsblk التي قد تصل Boolean أو رقمًا أو نصًا."""
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _mountpoints(block: dict) -> list[str]:
    """قراءة MOUNTPOINT وMOUNTPOINTS من إصدارات lsblk المختلفة."""
    values = block.get("mountpoints")
    if values is None:
        values = block.get("mountpoint")
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple)):
        return []
    return [str(value).strip() for value in values if value and str(value).strip()]


def _block_is_usb(block: dict, parent_is_usb: bool = False) -> bool:
    if parent_is_usb:
        return True
    transport = str(block.get("tran") or "").strip().lower()
    if transport == "usb" or _truthy_block_value(block.get("hotplug")):
        return True
    subsystems = str(block.get("subsystems") or "").lower()
    return "usb" in subsystems


def _partition_info(block: dict, is_usb: bool = False, analyze: bool = True) -> dict:
    mounts = _mountpoints(block)
    name = str(block.get("name") or "")
    dev_name = name.removeprefix("/dev/")
    part = {
        "name": name,
        "path": f"/dev/{dev_name}",
        "size": str(block.get("size") or ""),
        "size_bytes": block.get("size_bytes"),
        "type": block.get("type", ""),
        "fstype": str(block.get("fstype") or "").strip(),
        "label": str(block.get("label") or "").strip(),
        "uuid": str(block.get("uuid") or "").strip(),
        "is_usb": is_usb or _block_is_usb(block),
        "mountpoint": mounts[0] if mounts else "",
        "mountpoints": mounts,
    }
    if mounts and analyze:
        part["analysis"] = analyze_mounted_filesystem(mounts[0])
    return part


def _flatten_leaf_partitions(block, inherited_tran: str = "", inherited_usb: bool = False, analyze: bool = True) -> list[dict]:
    parts = []
    if isinstance(block, list):
        for item in block:
            parts.extend(_flatten_leaf_partitions(item, inherited_tran=inherited_tran, inherited_usb=inherited_usb, analyze=analyze))
        return parts
    children = block.get("children") or []
    is_usb = inherited_usb or _block_is_usb(block)
    tran = inherited_tran or str(block.get("tran") or "").strip()

    if children:
        for child in children:
            parts.extend(_flatten_leaf_partitions(child, inherited_tran=tran, inherited_usb=is_usb, analyze=analyze))
    else:
        parts.append(_partition_info(block, is_usb=is_usb, analyze=analyze))
    return parts


def _parse_lsblk_devices(payload: str, usb_only: bool = False, analyze: bool = True) -> list[dict]:
    data = json.loads(payload)
    drives = []
    for block in data.get("blockdevices", []):
        is_usb = _block_is_usb(block)
        if usb_only and not is_usb:
            continue
        if not (is_usb or block.get("type") in ("disk",)):
            continue
        children = block.get("children") or []
        name = str(block.get("name") or "")
        dev_name = name.removeprefix("/dev/")

        partitions = []
        if children:
            for child in children:
                partitions.extend(_flatten_leaf_partitions(child, inherited_tran=str(block.get("tran") or ""), inherited_usb=is_usb, analyze=analyze))
        else:
            partitions = [_partition_info(block, is_usb=is_usb, analyze=analyze)]

        # بعض إصدارات lsblk تضع نقطة التوصيل على القرص الأب فقط
        parent_mounts = _mountpoints(block)
        if parent_mounts and len(partitions) == 1 and not partitions[0].get("mountpoint"):
            parent_mount = parent_mounts[0]
            partitions[0]["mountpoint"] = parent_mount
            partitions[0]["mountpoints"] = [parent_mount]
            if analyze:
                partitions[0]["analysis"] = analyze_mounted_filesystem(parent_mount)

        info = {
            "name": name,
            "path": f"/dev/{dev_name}",
            "size": str(block.get("size") or ""),
            "size_bytes": block.get("size_bytes"),
            "type": block.get("type", ""),
            "fstype": str(block.get("fstype") or "").strip(),
            "label": str(block.get("label") or "").strip(),
            "uuid": str(block.get("uuid") or "").strip(),
            "vendor": str(block.get("vendor") or "").strip(),
            "model": str(block.get("model") or "").strip(),
            "transport": str(block.get("tran") or "").strip(),
            "is_usb": is_usb,
            "partitions": partitions,
            "findings": [],
        }
        drives.append(info)
    return drives


def scan_mounted_drives(usb_only: bool = False):
    """Return block devices discovered by lsblk.

    A mounted path is not evidence that a device is USB.  In particular,
    ``df`` cannot distinguish ordinary system mounts under /media or /mnt
    from removable media, so it is deliberately not used as a USB fallback.
    """
    drives = []
    lsblk_result = safe_exec.run([
        "lsblk", "-J", "-b", "--tree",
        "-o", "NAME,SIZE,TYPE,MOUNTPOINTS,VENDOR,MODEL,TRAN,HOTPLUG,FSTYPE,LABEL,UUID",
    ], check_binary=False)
    out = lsblk_result.stdout if lsblk_result.ok else ""
    try:
        if out:
            drives = _parse_lsblk_devices(out, usb_only=usb_only)
    except (TypeError, ValueError, KeyError):
        drives = []
    return drives


def analyze_mounted_filesystem(mountpoint: str, max_files: int = 5000) -> dict:
    result = {
        "path": mountpoint,
        "suspicious_files": [],
        "autorun_files": [],
        "hidden_files": [],
        "executable_count": 0,
        "total_files_checked": 0,
        "total_files_scanned": 0,
        "truncated": False,
        "findings": [],
    }

    # 1. التحقق الصارم من مسار نقطة التوصيل لمنع هجمات التجاوز
    ok_mp, mp_or_err = validators.validate_mountpoint(mountpoint)
    if not ok_mp:
        result["error"] = mp_or_err
        result["findings"].append({
            "severity": "info",
            "title": f"مسار غير صالح أو غير آمن: {mp_or_err}",
            "detail": "تم رفض المسار لحماية النظام من هجمات التجاوز (Directory Traversal).",
            "fix": "تحقق من مسار التوصيل.",
        })
        return result
    mountpoint = mp_or_err

    if not os.path.exists(mountpoint) or not os.path.isdir(mountpoint):
        result["error"] = f"نقطة التوصيل غير موجودة أو ليست مجلداً: {mountpoint}"
        return result

    real_mount = os.path.realpath(mountpoint)

    dangerous_extensions = {".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".vbs", ".ps1",
                            ".sh", ".py", ".rb", ".pl", ".jar", ".apk", ".deb", ".rpm"}
    autorun_names = {"autorun.inf", "autorun.sh", "autoplay.inf", ".autorun", "launch.bat", "autorun.exe"}
    suspicious_names_patterns = [
        r"(hack|malware|virus|trojan|backdoor|keylogger|exploit|payload|shell|rootkit)",
        r"(password|passwd|credential|login|secret)\.(txt|dat|csv|xls)",
    ]

    try:
        for root, dirs, files in os.walk(mountpoint, followlinks=False):
            # التأكد من عدم الخروج عن مسار الفلاشة الحقيقي
            curr_real = os.path.realpath(root)
            if not (curr_real == real_mount or curr_real.startswith(real_mount + os.sep)):
                dirs[:] = []
                continue

            # تصفية المجلدات: منع تتبع الروابط الرمزية وتخطي مجلدات النظام غير الضارة
            filtered_dirs = []
            for d in dirs:
                full_d = os.path.join(root, d)
                if os.path.islink(full_d):
                    continue
                if d in (".Trash-1000", ".Trash", ".Spotlight-V100", ".fseventsd"):
                    continue
                filtered_dirs.append(d)
            dirs[:] = filtered_dirs

            for fname in files:
                fpath = os.path.join(root, fname)
                if os.path.islink(fpath):
                    continue  # لا تتبع الروابط الرمزية — قد تشير خارج الفلاشة

                try:
                    st = os.lstat(fpath)
                    # فحص الملفات العادية فقط وتخطي الأنابيب والأجهزة التلقائية
                    if not stat.S_ISREG(st.st_mode):
                        continue
                except (OSError, PermissionError):
                    continue

                result["total_files_checked"] += 1
                result["total_files_scanned"] = result["total_files_checked"]
                flower = fname.lower()
                rel_path = fpath.replace(mountpoint, "").lstrip(os.sep)

                if fname.startswith("."):
                    result["hidden_files"].append(rel_path)

                if flower in autorun_names or flower.startswith("autorun."):
                    result["autorun_files"].append(rel_path)
                    result["findings"].append({
                        "severity": "high",
                        "title": f"ملف Autorun مشبوه: {fname}",
                        "detail": f"الملف {rel_path} في {root} يمكن أن يُشغَّل تلقائياً.",
                        "fix": f"احذف الملف: rm -f -- {shlex.quote(fpath)} أو افحص محتواه أولاً",
                        "target_path": fpath,
                    })

                # كشف التمويه بالامتداد المزدوج (Double Extension Masquerading)
                name_parts = fname.rsplit(".", 2)
                if len(name_parts) == 3:
                    inner_ext = f".{name_parts[1].lower()}"
                    outer_ext = f".{name_parts[2].lower()}"
                    if outer_ext in dangerous_extensions and inner_ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}:
                        result["suspicious_files"].append(rel_path)
                        result["findings"].append({
                            "severity": "critical",
                            "title": f"⚠️ ملف متنكّر بامتداد مزدوج: {fname}",
                            "detail": f"الملف {rel_path} يتظاهر بأنه {inner_ext} بينما هو في الواقع تنفيذي {outer_ext}.",
                            "fix": f"احذر من فتحه وافحصه فوراً أو احذفه: rm -f -- {shlex.quote(fpath)}",
                            "target_path": fpath,
                        })

                ext = os.path.splitext(flower)[1]
                if ext in dangerous_extensions:
                    result["executable_count"] += 1
                    if ext in {".exe", ".dll", ".bat", ".scr", ".com", ".vbs", ".ps1"}:
                        result["suspicious_files"].append(rel_path)

                for pattern in suspicious_names_patterns:
                    if re.search(pattern, flower, re.IGNORECASE):
                        result["suspicious_files"].append(rel_path)
                        result["findings"].append({
                            "severity": "medium",
                            "title": f"ملف باسم مشبوه: {fname}",
                            "detail": f"اسم الملف يشير إلى محتوى خطير محتمل: {rel_path}",
                            "fix": f"افحص الملف: file {shlex.quote(fpath)} && head -n 20 {shlex.quote(fpath)}",
                            "target_path": fpath,
                        })
                        break

                if result["total_files_checked"] >= 5000:
                    result["findings"].append({
                        "severity": "info",
                        "title": "تم بلوغ الحد الأقصى للملفات المفحوصة (5000 ملف)",
                        "detail": "توقف الفحص السريع لتجنب استهلاك الموارد.",
                        "fix": "",
                    })
                    break
            if result["total_files_checked"] >= 5000:
                break
    except PermissionError:
        result["findings"].append({
            "severity": "info",
            "title": "لا توجد صلاحيات كافية للفحص الكامل",
            "detail": f"تعذّر الوصول لبعض المجلدات في {mountpoint}",
            "fix": "شغّل الفحص بصلاحيات sudo لفحص أعمق",
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
        for line in out.splitlines()[1:]:
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
