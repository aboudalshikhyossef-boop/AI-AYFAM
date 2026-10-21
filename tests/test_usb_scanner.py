import json
import os
import stat
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from tools.usb import (
    _parse_lsblk_devices,
    _analyze_usb_device,
    _flatten_leaf_partitions,
    _list_usb_devices_sysfs,
    analyze_mounted_filesystem,
    scan_mounted_drives,
)
from tools.usb_control import (
    eject_storage_device,
    mount_storage_device_readonly,
    deep_scan_flash,
)


class UsbScannerParsingTests(unittest.TestCase):
    @patch("tools.usb.safe_exec.run")
    def test_scan_does_not_classify_ordinary_mount_as_usb(self, mock_run):
        payload = {"blockdevices": [{
            "name": "sda", "size": "100000000000", "type": "disk",
            "tran": "sata", "hotplug": False,
            "children": [{"name": "sda1", "type": "part", "mountpoints": ["/media/data"]}],
        }]}
        mock_run.return_value = MagicMock(ok=True, stdout=json.dumps(payload), stderr="")
        self.assertEqual(scan_mounted_drives(usb_only=True), [])
        self.assertEqual(mock_run.call_count, 1)

    @patch("tools.usb.safe_exec.run")
    def test_scan_does_not_use_df_as_usb_fallback(self, mock_run):
        mock_run.return_value = MagicMock(ok=False, stdout="", stderr="lsblk missing")
        self.assertEqual(scan_mounted_drives(usb_only=True), [])
        self.assertEqual(mock_run.call_count, 1)

    def test_boolean_hotplug_and_mountpoints_are_supported(self):
        payload = {
            "blockdevices": [{
                "name": "sdb", "size": "64000000000", "type": "disk",
                "vendor": "ACME", "model": "Flash", "tran": "usb", "hotplug": True,
                "children": [{
                    "name": "sdb1", "size": "63900000000", "type": "part",
                    "mountpoints": ["/run/media/user/FLASH"],
                }],
            }]
        }
        drives = _parse_lsblk_devices(json.dumps(payload), usb_only=True)
        self.assertEqual(len(drives), 1)
        self.assertTrue(drives[0]["is_usb"])
        partition = drives[0]["partitions"][0]
        self.assertEqual(partition["path"], "/dev/sdb1")
        self.assertEqual(partition["size"], "63900000000")
        self.assertEqual(partition["mountpoint"], "/run/media/user/FLASH")

    def test_parent_mountpoint_is_propagated_to_single_partition(self):
        payload = {
            "blockdevices": [{
                "name": "sdc", "size": "16000000000", "type": "disk",
                "tran": "usb", "hotplug": "true", "mountpoints": ["/media/USB"],
                "children": [{"name": "sdc1", "size": "15900000000", "type": "part"}],
            }]
        }
        drives = _parse_lsblk_devices(json.dumps(payload), usb_only=True)
        self.assertEqual(drives[0]["partitions"][0]["mountpoint"], "/media/USB")

    def test_nested_children_partition_flattening(self):
        """اختبار التعامل مع الأقسام المتداخلة (مثل التشفير أو LVM)."""
        raw_children = [{
            "name": "sdd1", "size": "32000000000", "type": "part",
            "children": [{
                "name": "luks-uuid", "size": "31900000000", "type": "crypt",
                "mountpoint": "/media/encrypted_vault"
            }]
        }]
        leaves = _flatten_leaf_partitions(raw_children)
        self.assertEqual(len(leaves), 1)
        self.assertEqual(leaves[0]["mountpoint"], "/media/encrypted_vault")
        self.assertEqual(leaves[0]["path"], "/dev/luks-uuid")


class UsbSecurityAnalysisTests(unittest.TestCase):
    def test_rubber_ducky_vid_pid_detection(self):
        """كشف أجهزة BadUSB عبر VID/PID المعروفة."""
        # 03eb:2403 is Hak5 USB Rubber Ducky
        dev = {
            "vendor_id": "03eb",
            "product_id": "2403",
            "device": "Atmel Rubber Ducky",
            "interfaces": [{"class_code": "03", "class_name": "Human Interface Device (HID)"}],
        }
        analysis = _analyze_usb_device(dev)
        self.assertIn("CRITICAL", analysis["risk_level"])
        self.assertTrue(analysis["is_known_bad_device"])
        self.assertIn("Rubber Ducky", analysis["device_type"])

    def test_flipper_zero_keyword_detection(self):
        """كشف الأجهزة من خلال الكلمات المفتاحية بالاسم."""
        dev = {
            "vendor_id": "ffff",
            "product_id": "aaaa",
            "device": "Flipper Zero White Edition",
            "interfaces": [{"class_code": "03", "class_name": "HID"}],
        }
        analysis = _analyze_usb_device(dev)
        self.assertTrue(analysis["is_known_bad_device"])
        self.assertIn("Flipper Zero", analysis["device_type"])

    def test_hybrid_hid_and_storage_device_flagged(self):
        """كشف الأجهزة الهجينة الخطرة (تحوي لوحة مفاتيح HID + ذاكرة تخزين معاً)."""
        dev = {
            "vendor_id": "1234",
            "product_id": "5678",
            "device": "Generic Composite USB Device",
            "interfaces": [
                {"class_code": "03", "class_name": "Human Interface Device (HID)"},
                {"class_code": "08", "class_name": "Mass Storage"},
            ],
        }
        analysis = _analyze_usb_device(dev)
        self.assertTrue(analysis["is_hybrid_device"])
        self.assertIn(analysis["risk_level"], ("HIGH", "CRITICAL"))
        self.assertTrue(any("هجين" in risk for risk in analysis["risks"]))

    def test_safe_keyboard_vendor_low_risk(self):
        """التأكد من أن لوحات المفاتيح من مصنّعين موثوقين تأخذ تصنيف منخفض المخاطر."""
        # 046d is Logitech
        dev = {
            "vendor_id": "046d",
            "product_id": "c31c",
            "device": "Logitech USB Keyboard",
            "interfaces": [{"class_code": "03", "class_name": "Human Interface Device (HID)"}],
        }
        analysis = _analyze_usb_device(dev)
        self.assertEqual(analysis["risk_level"], "LOW")
        self.assertFalse(analysis["is_known_bad_device"])


class FilesystemAndDeepScanTests(unittest.TestCase):
    def test_deep_scan_ignores_symlinks_and_fifos(self):
        """التأكد من أن الفحص يتجاهل الروابط الرمزية وملفات FIFO الخاصة لمنع التعليق أو الهروب."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # ملف عادي
            normal_file = os.path.join(tmpdir, "doc.txt")
            with open(normal_file, "w") as f:
                f.write("test content")

            # رابط رمزي يشير لملف في /etc
            symlink_file = os.path.join(tmpdir, "link_to_passwd")
            try:
                os.symlink("/etc/passwd", symlink_file)
            except OSError:
                pass

            # ملف FIFO خاص إن سمح النظام
            fifo_file = os.path.join(tmpdir, "test_fifo")
            try:
                os.mkfifo(fifo_file)
            except (OSError, AttributeError):
                fifo_file = None

            res = deep_scan_flash(tmpdir)
            self.assertEqual(res["total_files"], 1)

    def test_deep_scan_detects_double_extension(self):
        """كشف التمويه بالامتدادات المزدوجة مثل invoice.pdf.exe"""
        with tempfile.TemporaryDirectory() as tmpdir:
            masq_file = os.path.join(tmpdir, "salary_report.pdf.exe")
            with open(masq_file, "wb") as f:
                f.write(b"MZ\x90\x00fake pe binary")

            res = deep_scan_flash(tmpdir)
            self.assertTrue(any(f.get("masquerade") == ".pdf" for f in res["suspicious_files"]))
            self.assertTrue(any("امتداد مزدوج" in finding["title"] for finding in res["findings"]))

    def test_analyze_mounted_filesystem_caps_file_count(self):
        """التحقق من سقف فحص الملفات (5000 ملف كحد أقصى لمنع استهلاك الموارد)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "test.txt")
            with open(file_path, "w") as f:
                f.write("hello")
            fs_report = analyze_mounted_filesystem(tmpdir, max_files=2)
            self.assertFalse(fs_report["truncated"])
            self.assertEqual(fs_report["total_files_scanned"], 1)


class UsbControlSafetyTests(unittest.TestCase):
    def test_eject_rejects_invalid_device_path(self):
        """رفض المسارات المشبوهة أو التي تحاول مسار traversal."""
        res = eject_storage_device("../../dev/sda")
        self.assertFalse(res["success"])
        self.assertIn("error", res)

        res2 = eject_storage_device("/etc/shadow")
        self.assertFalse(res2["success"])

    def test_mount_readonly_rejects_invalid_path(self):
        """رفض محاولات التوصيل بمسارات أجهزة غير مطابقة."""
        res = mount_storage_device_readonly("; rm -rf /")
        self.assertFalse(res["success"])
        self.assertIn("error", res)

    @patch("utils.safe_exec.run")
    def test_eject_unmounts_all_partitions_and_powers_off(self, mock_run):
        """التحقق من أن دالة الإخراج تفصل كافة الأقسام التابعة وتطفئ القرص الأب."""
        mock_sync_out = MagicMock(ok=True, stdout="")
        mock_unmount_out = MagicMock(ok=True, stdout="unmounted")
        mock_poweroff_out = MagicMock(ok=True, stdout="powered off")
        mount_queries = 0

        def side_effect(cmd, **kwargs):
            if cmd[0] == "sync":
                return mock_sync_out
            elif cmd[0] == "lsblk":
                nonlocal mount_queries
                columns = cmd[3]
                if columns == "PKNAME":
                    return MagicMock(ok=True, stdout="sdb\n")
                if columns == "RM,TRAN,TYPE":
                    return MagicMock(ok=True, stdout="1 usb disk\n")
                mount_queries += 1
                mounts = "sdb1 /run/media/p1\nsdb2 /run/media/p2\n" if mount_queries == 1 else ""
                return MagicMock(ok=True, stdout=mounts)
            elif "unmount" in cmd:
                return mock_unmount_out
            elif "power-off" in cmd:
                return mock_poweroff_out
            return MagicMock(ok=True, stdout="")

        mock_run.side_effect = side_effect

        res = eject_storage_device("/dev/sdb1")
        self.assertTrue(res["success"])
        # Verify sync was executed
        commands_run = [call_args[0][0][0] for call_args in mock_run.call_args_list]
        self.assertIn("sync", commands_run)

    @patch("utils.safe_exec.run")
    def test_eject_rejects_non_removable_disk(self, mock_run):
        def side_effect(cmd, **kwargs):
            if cmd[0] == "lsblk" and cmd[3] == "PKNAME":
                return MagicMock(ok=True, stdout="sda\n")
            if cmd[0] == "lsblk" and cmd[3] == "RM,TRAN,TYPE":
                return MagicMock(ok=True, stdout="0 sata disk\n")
            return MagicMock(ok=True, stdout="")
        mock_run.side_effect = side_effect
        result = eject_storage_device("/dev/sda1")
        self.assertFalse(result["success"])
        self.assertIn("قابلة للإزالة", result["error"])

    @patch("utils.safe_exec.run")
    def test_eject_fails_when_power_off_fails(self, mock_run):
        def side_effect(cmd, **kwargs):
            if cmd[0] == "lsblk" and cmd[3] == "PKNAME":
                return MagicMock(ok=True, stdout="sdb\n")
            if cmd[0] == "lsblk" and cmd[3] == "RM,TRAN,TYPE":
                return MagicMock(ok=True, stdout="1 usb disk\n")
            if cmd[0] == "udisksctl" and "power-off" in cmd:
                return MagicMock(ok=False, stdout="", stderr="power denied")
            return MagicMock(ok=True, stdout="")
        mock_run.side_effect = side_effect
        result = eject_storage_device("/dev/sdb1")
        self.assertFalse(result["success"])


if __name__ == "__main__":
    unittest.main()
