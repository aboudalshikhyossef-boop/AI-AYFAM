import json
import os
import sys
import tempfile

os.environ.setdefault("AYFAM_GEMINI_MIN_INTERVAL", "0")
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.ai_assistant import clear_model_cache
from engine.gemini_cti import CTI_SEARCH_MODEL, LocalSnapshot, ThreatHistory, GeminiCTIError, GeminiThreatClient, ModelInfo, _is_text_research_model, markdown_report, resolve_api_key, validate_threat_feed, GeminiHTTPError


class GeminiCTITests(unittest.TestCase):
    def setUp(self):
        clear_model_cache()
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
        client.discover_models = lambda force=False: [ModelInfo(f"models/{CTI_SEARCH_MODEL}")]
        with patch("engine.gemini_cti.requests.post", return_value=Response()) as post:
            result = client.fetch_threats()
        self.assertEqual(result["threats"], [])
        self.assertTrue(post.call_args.args[0].startswith("https://generativelanguage.googleapis.com/v1"))
        self.assertEqual(post.call_args.kwargs["headers"]["x-goog-api-key"], "test-key")
        self.assertEqual(post.call_args.kwargs["timeout"][0], 10)
        self.assertGreater(post.call_args.kwargs["timeout"][1], 44.0)
        self.assertLessEqual(post.call_args.kwargs["timeout"][1], 45.0)
        payload = post.call_args.kwargs["json_data"]
        self.assertIn("google_search_retrieval", payload["tools"][0])
        self.assertEqual(payload["generationConfig"]["maxOutputTokens"], 900)
        self.assertNotIn("temperature", payload["generationConfig"])

    def test_legacy_rest_text_is_still_accepted(self):
        class Response:
            status_code = 200
            def json(self):
                return {"outputs": [{"type": "text", "text": json.dumps({"generated_at": "now", "threats": []})}]}
        client = GeminiThreatClient("test-key")
        client.discover_models = lambda force=False: [ModelInfo(f"models/{CTI_SEARCH_MODEL}")]
        with patch("engine.gemini_cti.requests.post", return_value=Response()):
            self.assertEqual(client.fetch_threats()["threats"], [])

    def test_model_scoped_quota_stops_after_one_request(self):
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
            with self.assertRaises(GeminiCTIError):
                client.fetch_threats()
        self.assertEqual(post.call_count, 1)

    def test_project_spend_quota_uses_secret_safe_permanent_diagnostic(self):
        class Response:
            status_code = 429
            text = "project-wide request limit with private provider details"
            def json(self):
                return {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "project-wide request limit", "details": [{"@type": "type.googleapis.com/google.rpc.QuotaFailure", "violations": [{"quotaId": "ProjectSpendPerTenMinutes", "quotaDimensions": {"location": "global"}}]}]}}
        client = GeminiThreatClient("test-key")
        client.discover_models = lambda force=False: [ModelInfo(f"models/{CTI_SEARCH_MODEL}")]
        with patch("engine.gemini_cti.requests.post", return_value=Response()) as post:
            with self.assertRaises(GeminiCTIError) as caught:
                client.fetch_threats()
        self.assertEqual(post.call_count, 1)
        self.assertEqual(caught.exception.category, "quota_exhausted")
        self.assertNotIn("project-wide request limit", str(caught.exception))

    def test_environment_key_precedence_matches_google_docs(self):
        self.assertEqual(resolve_api_key("saved", {"GEMINI_API_KEY": "gemini-env"}), "gemini-env")
        self.assertEqual(resolve_api_key("saved", {"GEMINI_API_KEY": "gemini-env", "GOOGLE_API_KEY": "google-env"}), "google-env")
        self.assertEqual(resolve_api_key("saved", {}), "saved")

    def test_specialized_audio_models_are_not_text_research_models(self):
        self.assertFalse(_is_text_research_model("gemini-2.5-flash-native-audio-latest"))
        self.assertFalse(_is_text_research_model("gemini-2.5-flash-preview-tts"))
        self.assertTrue(_is_text_research_model("gemini-2.5-flash"))

    def test_discovery_preserves_available_models_and_prioritizes_default(self):
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
        self.assertEqual(models[0].short_name, "gemini-3.8-flash")
        self.assertEqual(
            {model.short_name for model in models},
            {"gemini-3.8-flash", "gemini-2.5-flash", "gemini-2.5-flash-lite"},
        )
        self.assertEqual(client.selected_model.short_name, "gemini-3.8-flash")

    def test_cti_search_uses_free_tier_search_model(self):
        self.assertEqual(CTI_SEARCH_MODEL, "gemini-2.5-flash-lite")

    def test_cti_http_error_uses_shared_diagnostic_without_echoing_secret(self):
        fake_secret = "AIzaSyFAKE-CTI-SECRET-123456789012345678"
        class Response:
            status_code = 429
            def json(self):
                return {"error": {
                    "code": 429,
                    "status": "RESOURCE_EXHAUSTED",
                    "message": f"private quota text {fake_secret}",
                    "details": [{"violations": [{
                        "quotaId": "ProjectSpendPerTenMinutes",
                    }]}],
                }}
        error = GeminiHTTPError(Response())
        self.assertEqual(error.category, "quota_exhausted")
        self.assertFalse(error.transient)
        self.assertEqual(error.status_code, 429)
        self.assertNotIn(fake_secret, str(error))

    def test_unavailable_cti_model_has_model_not_found_category(self):
        class Response:
            status_code = 200
            def json(self):
                return {"models": [{
                    "name": "models/gemini-2.5-flash-lite",
                    "supportedGenerationMethods": ["generateContent"],
                }]}
        client = GeminiThreatClient("test-key")
        with patch.dict(os.environ, {"AYFAM_GEMINI_CTI_MODEL": "custom-unlisted"}), patch(
            "engine.gemini_cti.requests.get", return_value=Response()
        ), patch("engine.gemini_cti.requests.post") as post:
            with self.assertRaises(GeminiCTIError) as caught:
                client.fetch_threats()
        self.assertEqual(caught.exception.category, "model_not_found")
        post.assert_not_called()

    def test_cti_model_discovery_reuses_shared_catalog_cache(self):
        class Response:
            status_code = 200
            def json(self):
                return {"models": [{
                    "name": "models/gemini-3.8-flash",
                    "supportedGenerationMethods": ["generateContent"],
                    "outputTokenLimit": 4096,
                }]}
        first = GeminiThreatClient("test-key")
        second = GeminiThreatClient("test-key")
        with patch("engine.gemini_cti.requests.get", return_value=Response()) as get:
            first_models = first.discover_models()
            second_models = second.discover_models()
        self.assertEqual(first_models[0].short_name, "gemini-3.8-flash")
        self.assertEqual(second_models[0].short_name, "gemini-3.8-flash")
        self.assertEqual(get.call_count, 1)


    def test_validate_threat_feed_http_source(self):
        raw_feed = {
            "threats": [{
                "id": "CVE-HTTP-1",
                "title": "HTTP Advisory",
                "sources": ["http://example.com/advisory"],
            }]
        }
        validated = validate_threat_feed(raw_feed)
        self.assertEqual(len(validated["threats"]), 1)
        self.assertEqual(validated["threats"][0]["id"], "CVE-HTTP-1")

    def test_validate_threat_feed_https_source(self):
        raw_feed = {
            "threats": [{
                "id": "CVE-HTTPS-1",
                "title": "HTTPS Advisory",
                "sources": ["https://example.com/advisory"],
            }]
        }
        validated = validate_threat_feed(raw_feed)
        self.assertEqual(len(validated["threats"]), 1)
        self.assertEqual(validated["threats"][0]["id"], "CVE-HTTPS-1")

    def test_validate_threat_feed_non_http_https_source(self):
        raw_feed = {
            "threats": [{
                "id": "CVE-FTP-1",
                "title": "FTP Advisory",
                "sources": ["ftp://example.com/advisory"],
            }]
        }
        validated = validate_threat_feed(raw_feed)
        self.assertEqual(len(validated["threats"]), 0)

    def test_validate_threat_feed_empty_sources(self):
        raw_feed = {
            "threats": [{
                "id": "CVE-EMPTY-1",
                "title": "Empty Sources Advisory",
                "sources": [],
            }]
        }
        validated = validate_threat_feed(raw_feed)
        self.assertEqual(len(validated["threats"]), 0)

    def test_validate_threat_feed_missing_sources(self):
        raw_feed = {
            "threats": [{
                "id": "CVE-MISSING-1",
                "title": "Missing Sources Advisory",
            }]
        }
        validated = validate_threat_feed(raw_feed)
        self.assertEqual(len(validated["threats"]), 0)

    def test_explicit_unavailable_cti_model_is_rejected_before_generation(self):
        class Response:
            status_code = 200
            def json(self):
                return {"models": [{
                    "name": "models/gemini-2.5-flash-lite",
                    "supportedGenerationMethods": ["generateContent"],
                }]}
        client = GeminiThreatClient("test-key")
        with patch.dict(os.environ, {"AYFAM_GEMINI_CTI_MODEL": "user-selected-model"}), patch(
            "engine.gemini_cti.requests.get", return_value=Response()
        ), patch("engine.gemini_cti.requests.post") as post:
            with self.assertRaises(GeminiCTIError) as caught:
                client.fetch_threats()
        self.assertIn("user-selected-model", str(caught.exception))
        self.assertIn("Choose an available model", str(caught.exception))
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
