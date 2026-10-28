"""
Tests for AYFAMAgent core functionality in core/agent.py
"""

import sys
from unittest.mock import MagicMock, patch

# Stub cryptography if missing in environment
try:
    import cryptography
except ImportError:
    crypto_mock = MagicMock()
    sys.modules["cryptography"] = crypto_mock
    sys.modules["cryptography.hazmat"] = crypto_mock
    sys.modules["cryptography.hazmat.primitives"] = crypto_mock
    sys.modules["cryptography.hazmat.primitives.asymmetric"] = crypto_mock
    sys.modules["cryptography.hazmat.primitives.asymmetric.ed25519"] = crypto_mock
    sys.modules["cryptography.hazmat.primitives.serialization"] = crypto_mock

import unittest

from config.settings import Settings
from core.agent import AYFAMAgent
from ui.terminal import TerminalUI


class TestCoreAgentCVEEnrichment(unittest.TestCase):
    def setUp(self):
        self.settings = Settings()
        self.settings._data["language"] = "en"
        self.ui = MagicMock(spec=TerminalUI)
        self.agent = AYFAMAgent(settings=self.settings, ui=self.ui)

    def test_enrich_packages_empty_and_non_list(self):
        """Test with empty or non-list inputs."""
        self.assertEqual(self.agent._enrich_packages_with_cve([]), [])
        self.assertEqual(self.agent._enrich_packages_with_cve(None), [])
        self.assertEqual(self.agent._enrich_packages_with_cve("invalid"), [])
        self.assertEqual(self.agent._enrich_packages_with_cve(123), [])

    def test_enrich_packages_missing_key_or_invalid_type(self):
        """Test with missing 'package' key or invalid package data structures."""
        invalid_packages = [
            None,
            123,
            "not_a_dict",
            ["list_item"],
            {},
            {"version": "1.0.0"},
            {"package": None},
            {"package": 456},
            {"package": ""},
            {"package": "   "},
        ]
        with patch("tools.web.get_cisa_known_exploited", return_value=[{"product": "openssl"}]):
            findings = self.agent._enrich_packages_with_cve(invalid_packages)
            self.assertEqual(findings, [], "Invalid package entries must be safely skipped without errors or false findings")

    def test_enrich_packages_cisa_kev_case_insensitive(self):
        """Test that matching against CISA KEV products is case-insensitive."""
        mock_kev = [
            {"product": "openssl"},
            {"product": "curl"},
        ]
        packages = [
            {"package": "OpenSSL"},
            {"package": "CURL"},
        ]
        with patch("tools.web.get_cisa_known_exploited", return_value=mock_kev):
            findings = self.agent._enrich_packages_with_cve(packages)
            self.assertEqual(len(findings), 2)
            for f in findings:
                self.assertEqual(f["severity"], "critical")
                self.assertTrue(f["cve_enriched"])
                self.assertIn("apt-get install --only-upgrade", f["fix"])

            # Ensure title and fix preserve original package case
            self.assertIn("OpenSSL", findings[0]["title"])
            self.assertIn("OpenSSL", findings[0]["fix"])
            self.assertIn("CURL", findings[1]["title"])
            self.assertIn("CURL", findings[1]["fix"])

    def test_enrich_packages_limits(self):
        """Test that inspects max 8 packages and performs max 5 NVD searches."""
        mock_kev = []
        mock_cves = [
            {"id": "CVE-2024-1234", "severity": "HIGH", "description": "Test CVE", "cvss_score": 8.5}
        ]

        # 10 packages total
        packages = [{"package": f"pkg_{i}"} for i in range(10)]

        with patch("tools.web.get_cisa_known_exploited", return_value=mock_kev), \
             patch("tools.web.search_cve", return_value=mock_cves) as mock_search_cve:
            findings = self.agent._enrich_packages_with_cve(packages)

            # Must check max 5 via NVD
            self.assertEqual(mock_search_cve.call_count, 5)
            self.assertEqual(len(findings), 5)
            for f in findings:
                self.assertEqual(f["severity"], "high")
                self.assertTrue(f["cve_enriched"])


if __name__ == "__main__":
    unittest.main()
