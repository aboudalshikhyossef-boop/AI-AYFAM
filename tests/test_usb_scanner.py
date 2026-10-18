import json
import unittest

from tools.usb import _parse_lsblk_devices


class UsbScannerParsingTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
