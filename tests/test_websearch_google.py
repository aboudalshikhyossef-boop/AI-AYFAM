"""اختبارات محرك البحث البرمجي: Google CSE وBing RSS والبدائل بعد الفشل."""
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import websearch


def response(status: int, payload: dict | None = None, text: str = ""):
    obj = MagicMock(status_code=status, text=text)
    obj.json.return_value = payload or {}
    return obj


def test_google_cse_reports_google_400_details():
    bad = response(400, {"error": {"code": 400, "message": "Request contains an invalid argument.", "errors": [{"reason": "badRequest"}]}})
    with patch.object(websearch.http_client, "get", return_value=bad):
        try:
            websearch.google_cse("linux security", "valid-key", "f5fbcd40fda484bc7", "en")
        except websearch.SearchProviderError as exc:
            assert exc.status == 400
            assert "invalid argument" in str(exc)
        else:
            raise AssertionError("Google 400 must be raised as SearchProviderError")


def test_google_cse_does_not_call_api_without_key():
    with patch.object(websearch.http_client, "get") as mocked:
        try:
            websearch.google_cse("linux", "", "f5fbcd40fda484bc7", "en")
        except websearch.SearchProviderError as exc:
            assert "GOOGLE_CSE_KEY" in str(exc)
        else:
            raise AssertionError("Missing API key must be diagnosed")
        mocked.assert_not_called()


def test_bing_rss_parser_returns_hits():
    xml = """<?xml version=\"1.0\"?><rss><channel>
      <item><title>Linux security guide</title><link>https://example.com/linux</link>
      <description>Security &amp; hardening guide</description></item>
    </channel></rss>"""
    with patch.object(websearch.http_client, "get", return_value=response(200, text=xml)):
        hits = websearch.bing_rss("linux security", "en", 3)
    assert len(hits) == 1
    assert hits[0].engine == "bing-rss"
    assert hits[0].snippet == "Security & hardening guide"


def test_explicit_google_search_falls_back_with_visible_status():
    with patch.object(websearch, "wants_source", return_value={"google"}), \
         patch.object(websearch, "clean_search_query", return_value="linux security"), \
         patch.object(websearch, "check_connectivity", return_value=True), \
         patch.object(websearch, "google_cse", side_effect=websearch.SearchProviderError("Google CSE", 400, reason="badRequest")), \
         patch.object(websearch, "bing_rss", return_value=[]), \
         patch.object(websearch, "duckduckgo", return_value=[websearch.SearchHit("Linux Security", "https://example.com", "linux security guide", "duckduckgo")]), \
         patch.object(websearch, "wikipedia", return_value=[]):
        report = websearch.search("ابحث في جوجل عن linux security", {"google_cse_key": "key"})
    assert any("400" in status and "badRequest" in status for status in report.engines.values())
    assert any("DuckDuckGo" in name for name in report.engines)
    assert report.hits


def test_google_wants_source_and_clean_query_variations():
    from brain.language import wants_source, clean_search_query

    cases = [
        ("ابحث في جوجل عن لينكس", "لينكس"),
        ("ابحث جوجل عن ثغرات SSH", "ثغرات SSH"),
        ("بحث جوجل عن أمن المعلومات", "أمن المعلومات"),
        ("google search for linux security", "linux security"),
        ("search google for firewall", "firewall"),
        ("ابحث بـ جوجل عن CVE-2024-1234", "CVE-2024-1234"),
    ]
    for raw, expected_clean in cases:
        assert wants_source(raw) == {"google"}, f"Failed wants_source for {raw}"
        assert clean_search_query(raw) == expected_clean, f"Failed clean_search_query for {raw}: got {clean_search_query(raw)}"


def test_execute_google_search_falls_back_from_cse_to_gemini():
    with patch.object(websearch, "google_cse", side_effect=websearch.SearchProviderError("Google CSE", 400, reason="invalidKey")), \
         patch.object(websearch, "google_grounded", return_value=("Summary", [websearch.SearchHit("Title", "https://example.com", "Snippet", "google")])):
        engine_name, kind, payload = websearch.execute_google_search("linux", "bad-key", "cx", "gemini-key", "en")
        assert engine_name == "Google (Gemini)"
        assert kind == "grounded"
        assert payload[0] == "Summary"
        assert len(payload[1]) == 1


def test_google_grounded_parses_grounding_metadata():
    gemini_resp = response(200, {
        "candidates": [{
            "content": {"parts": [{"text": "Grounding summary"}]},
            "groundingMetadata": {
                "groundingChunks": [{"web": {"title": "Example", "uri": "https://example.com/item"}}],
                "groundingSupports": [{"segment": {"text": "Supporting snippet"}, "groundingChunkIndices": [0]}]
            }
        }]
    })
    with patch.object(websearch.http_client, "post", return_value=gemini_resp), \
         patch("engine.gemini_rate_limit.wait_for_slot", return_value=0.0):
        answer, hits = websearch.google_grounded("linux", "valid-gemini-key", "en")
        assert answer == "Grounding summary"
        assert len(hits) == 1
        assert hits[0].title == "Example"
        assert hits[0].url == "https://example.com/item"
        assert hits[0].snippet == "Supporting snippet"
