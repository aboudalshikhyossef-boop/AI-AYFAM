import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.gemini_cti import LocalSnapshot, ThreatHistory, GeminiCTIError, GeminiThreatClient, ModelInfo, _is_text_research_model, markdown_report, resolve_api_key, validate_threat_feed


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

    def test_interactions_request_parses_current_rest_steps_schema(self):
        payload_text = json.dumps({"generated_at": "now", "threats": []})
        class Response:
            status_code = 200
            def json(self):
                return {"status": "completed", "steps": [{"type": "model_output", "content": [{"type": "text", "text": payload_text}]}]}
        client = GeminiThreatClient("test-key")
        client.discover_models = lambda force=False: [ModelInfo("models/gemini-2.5-flash")]
        with patch("engine.gemini_cti.requests.post", return_value=Response()) as post:
            result = client.fetch_threats()
        self.assertEqual(result["threats"], [])
        self.assertTrue(post.call_args.args[0].startswith("https://generativelanguage.googleapis.com/v1"))
        self.assertEqual(post.call_args.kwargs["headers"]["x-goog-api-key"], "test-key")
        self.assertEqual(post.call_args.kwargs["timeout"], (10, 45.0))

    def test_legacy_rest_text_is_still_accepted(self):
        class Response:
            status_code = 200
            def json(self):
                return {"outputs": [{"type": "text", "text": json.dumps({"generated_at": "now", "threats": []})}]}
        client = GeminiThreatClient("test-key")
        client.discover_models = lambda force=False: [ModelInfo("models/gemini-2.5-flash")]
        with patch("engine.gemini_cti.requests.post", return_value=Response()):
            self.assertEqual(client.fetch_threats()["threats"], [])

    def test_model_scoped_quota_tries_one_alternate_and_keeps_details(self):
        class Response:
            def __init__(self, status_code, payload):
                self.status_code = status_code
                self._payload = payload
                self.text = json.dumps(payload)
            def json(self):
                return self._payload
        quota = Response(429, {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "model request limit exceeded", "details": [{"@type": "type.googleapis.com/google.rpc.QuotaFailure", "violations": [{"quotaId": "GenerateRequestsPerMinutePerProjectPerModel-FreeTier", "quotaDimensions": {"model": "gemini-test-flash"}}]}]}})
        success = Response(200, {"steps": [{"type": "model_output", "content": [{"type": "text", "text": json.dumps({"generated_at": "now", "threats": []})}]}]})
        client = GeminiThreatClient("test-key")
        client.discover_models = lambda force=False: [ModelInfo("models/gemini-2.5-flash"), ModelInfo("models/gemini-2.5-flash-lite")]
        with patch("engine.gemini_cti.requests.post", side_effect=[quota, success]) as post:
            result = client.fetch_threats()
        self.assertEqual(result["threats"], [])
        self.assertEqual(post.call_count, 2)

    def test_project_wide_429_preserves_google_diagnostic_and_stops(self):
        class Response:
            status_code = 429
            text = "project-wide request limit"
            def json(self):
                return {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "project-wide request limit", "details": [{"@type": "type.googleapis.com/google.rpc.QuotaFailure", "violations": [{"quotaId": "ProjectSpendPerTenMinutes", "quotaDimensions": {"location": "global"}}]}]}}
        client = GeminiThreatClient("test-key")
        client.discover_models = lambda force=False: [ModelInfo("models/gemini-2.5-flash"), ModelInfo("models/gemini-2.5-flash-lite")]
        with patch("engine.gemini_cti.requests.post", return_value=Response()) as post:
            with self.assertRaises(GeminiCTIError) as caught:
                client.fetch_threats()
        self.assertEqual(post.call_count, 1)
        self.assertIn("project-wide request limit", str(caught.exception))
        self.assertNotIn("free-tier quota is 0", str(caught.exception))

    def test_environment_key_precedence_matches_google_docs(self):
        self.assertEqual(resolve_api_key("saved", {"GEMINI_API_KEY": "gemini-env"}), "gemini-env")
        self.assertEqual(resolve_api_key("saved", {"GEMINI_API_KEY": "gemini-env", "GOOGLE_API_KEY": "google-env"}), "google-env")
        self.assertEqual(resolve_api_key("saved", {}), "saved")

    def test_specialized_audio_models_are_not_text_research_models(self):
        self.assertFalse(_is_text_research_model("gemini-2.5-flash-native-audio-latest"))
        self.assertFalse(_is_text_research_model("gemini-2.5-flash-preview-tts"))
        self.assertTrue(_is_text_research_model("gemini-2.5-flash"))

    def test_discovery_prefers_free_tier_search_models_over_gemini_3(self):
        class Response:
            status_code = 200
            def json(self):
                return {"models": [
                    {"name": "models/gemini-3.8-flash", "supportedGenerationMethods": ["generateContent"]},
                    {"name": "models/gemini-2.5-flash-lite", "supportedGenerationMethods": ["generateContent"]},
                    {"name": "models/gemini-2.5-flash", "supportedGenerationMethods": ["generateContent"]},
                ]}
        client = GeminiThreatClient("test-key")
        with patch("engine.gemini_cti.requests.get", return_value=Response()):
            models = client.discover_models()
        self.assertEqual([model.short_name for model in models], ["gemini-3.8-flash", "gemini-2.5-flash", "gemini-2.5-flash-lite"])
        self.assertEqual(client.selected_model.short_name, "gemini-3.8-flash")

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
