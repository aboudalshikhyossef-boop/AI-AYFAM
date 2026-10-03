import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.gemini_cti import LocalSnapshot, ThreatHistory, GeminiCTIError, markdown_report, validate_threat_feed


class GeminiCTITests(unittest.TestCase):
    def setUp(self):
        self.feed = validate_threat_feed({
            "generated_at": "2026-10-03T00:00:00Z",
            "threats": [{
                "id": "CVE-2099-0001",
                "title": "Example Linux vulnerability",
                "severity": "high",
                "description": "A test vulnerability.",
                "products": ["openssh"],
                "affected_versions": ["1.0"],
                "iocs": ["evil.example"],
                "recommendations": ["Upgrade the package"],
                "sources": ["https://nvd.nist.gov/"],
                "published_at": "2026-10-03",
            }],
        })

    def test_schema_normalizes_feed(self):
        self.assertEqual(self.feed["threats"][0]["severity"], "high")
        self.assertEqual(self.feed["window_hours"], 48)

    def test_local_matching_never_needs_api(self):
        from engine.gemini_cti import LocalThreatMatcher
        snapshot = LocalSnapshot("linux", {"openssh:amd64"}, {"bash"}, set())
        matches = LocalThreatMatcher().match(self.feed, snapshot)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["local_match"]["products"], ["openssh"])

    def test_unmatched_feed_is_empty(self):
        from engine.gemini_cti import LocalThreatMatcher
        snapshot = LocalSnapshot("linux", {"curl"}, {"bash"}, set())
        self.assertEqual(LocalThreatMatcher().match(self.feed, snapshot), [])

    def test_history_and_report_are_local(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "cti.db"
            row_id = ThreatHistory(db_path).save(self.feed, [], "gemini-test")
            self.assertEqual(row_id, 1)
            report = markdown_report(self.feed, [], "gemini-test")
            self.assertIn("not sent to Gemini", report)
            self.assertIn("No locally matched", report)

    def test_invalid_feed_rejected(self):
        with self.assertRaises(GeminiCTIError):
            validate_threat_feed({"threats": "not-an-array"})


if __name__ == "__main__":
    unittest.main()
