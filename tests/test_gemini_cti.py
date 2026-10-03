import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.gemini_cti import LocalSnapshot, ThreatHistory, GeminiCTIError, GeminiThreatClient, ModelInfo, _is_text_research_model, markdown_report, validate_threat_feed


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

    def test_interactions_request_returns_structured_json(self):
        class Response:
            status_code = 200
            def json(self):
                return {"output_text": json.dumps({"generated_at": "now", "threats": []})}
        client = GeminiThreatClient("test-key")
        client.discover_models = lambda force=False: [ModelInfo("models/gemini-test-flash")]
        with patch("engine.gemini_cti.requests.post", return_value=Response()) as post:
            result = client.fetch_threats()
        self.assertEqual(result["threats"], [])
        self.assertEqual(post.call_args.kwargs["json"]["tools"], [{"type": "google_search"}])
        self.assertEqual(post.call_args.kwargs["timeout"], (10, 45.0))

    def test_quota_failure_falls_back_to_next_dynamic_model(self):
        class Response:
            status_code = 429
            text = "RESOURCE_EXHAUSTED quota limit: 0"
        client = GeminiThreatClient("test-key")
        client.discover_models = lambda force=False: [ModelInfo("models/first"), ModelInfo("models/second")]
        with patch("engine.gemini_cti.requests.post", return_value=Response()) as post:
            with self.assertRaises(GeminiCTIError):
                client.fetch_threats()
        # A quota error must stop after one request, not burn quota on fallbacks.
        self.assertEqual(post.call_count, 1)

    def test_specialized_audio_models_are_not_text_research_models(self):
        self.assertFalse(_is_text_research_model("gemini-2.5-flash-native-audio-latest"))
        self.assertFalse(_is_text_research_model("gemini-2.5-flash-preview-tts"))
        self.assertTrue(_is_text_research_model("gemini-2.5-flash"))

    def test_invalid_listed_model_falls_back_to_next_model(self):
        class Response:
            def __init__(self, status_code, text, output=None):
                self.status_code, self.text, self._output = status_code, text, output
            def json(self):
                return {"output_text": self._output}
        client = GeminiThreatClient("test-key")
        client.discover_models = lambda force=False: [ModelInfo("models/stale"), ModelInfo("models/gemini-2.5-flash")]
        responses = [Response(400, "Model stale not found"), Response(200, "", json.dumps({"generated_at": "now", "threats": []}))]
        with patch("engine.gemini_cti.requests.post", side_effect=responses) as post:
            result = client.fetch_threats()
        self.assertEqual(result["threats"], [])
        self.assertEqual(post.call_count, 2)


if __name__ == "__main__":
    unittest.main()
