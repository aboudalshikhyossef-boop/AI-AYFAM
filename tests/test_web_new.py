"""اختبارات محلية (بدون إنترنت فعلي) للتأكد من صحة منطق الدوال الجديدة في tools/web.py"""
import sys, os, json, tempfile, csv
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unittest.mock import patch, MagicMock
from tools import web

passed = 0
failed = 0

def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}")


# ── 1) unwrap DDG redirect ───────────────────────────────────────────────
print("\n[1] _unwrap_ddg_redirect")
wrapped = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fnmap.org%2F&rut=abc123"
real = web._unwrap_ddg_redirect(wrapped)
check("unwraps to nmap.org", real == "https://nmap.org/")
check("plain url unchanged", web._unwrap_ddg_redirect("https://example.com") == "https://example.com")


# ── 2) DDG HTML parsing (realistic sample markup) ───────────────────────
print("\n[2] _ddg_html_search parsing")
SAMPLE_HTML = """
<div class="result results_links results_links_deep web-result">
  <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fnmap.org%2Fbook%2F&amp;rut=x">
    Nmap Reference Guide
  </a>
  <a class="result__snippet">Official &amp; complete Nmap reference guide.</a>
</div>
<div class="result">
  <a class="result__a" href="https://www.kali.org/tools/nmap/">Nmap | Kali Linux Tools</a>
  <a class="result__snippet">Nmap package description for Kali.</a>
</div>
"""
with patch("tools.web.requests.get") as mock_get:
    mock_get.return_value = MagicMock(status_code=200, text=SAMPLE_HTML)
    results = web._ddg_html_search("nmap", max_results=5)

check("found 2 results", len(results) == 2)
check("first title clean", results[0]["title"] == "Nmap Reference Guide")
check("first url unwrapped", results[0]["url"] == "https://nmap.org/book/")
check("first snippet has & decoded", results[0]["snippet"] == "Official & complete Nmap reference guide.")
check("second url passthrough", results[1]["url"] == "https://www.kali.org/tools/nmap/")


# ── 3) web_search aggregation + dedup ────────────────────────────────────
print("\n[3] web_search multi-source aggregation")
with patch("tools.web._ddg_instant_answer", return_value=[
        {"title": "Nmap", "url": "https://nmap.org/", "snippet": "abstract", "source": "Wikipedia", "type": "instant_answer"}]), \
     patch("tools.web._ddg_html_search", return_value=[
        {"title": "Nmap dup", "url": "https://nmap.org/", "snippet": "dup", "source": "DuckDuckGo", "type": "search"},
        {"title": "Kali nmap", "url": "https://kali.org/tools/nmap", "snippet": "s", "source": "DuckDuckGo", "type": "search"}]), \
     patch("tools.web._wikipedia_search", return_value=[]):
    out = web.web_search("nmap", max_results=8)

check("dedup by url works (3 unique in, 1 dup removed)", len(out) == 2)
check("instant answer kept first", out[0]["url"] == "https://nmap.org/")

with patch("tools.web._ddg_instant_answer", return_value=[]), \
     patch("tools.web._ddg_html_search", return_value=[]), \
     patch("tools.web._wikipedia_search", return_value=[]):
    empty = web.web_search("asdkjaslkdjalksjd")
check("graceful empty-result message (not a crash)", len(empty) == 1 and "error" in empty[0])


# ── 4) search_osv with realistic OSV.dev-shaped response ────────────────
print("\n[4] search_osv")
OSV_SAMPLE = {
    "vulns": [
        {
            "id": "PYSEC-2022-1",
            "summary": "Jinja2 XSS vulnerability",
            "aliases": ["CVE-2019-10906", "GHSA-xxxx-yyyy-zzzz"],
            "published": "2022-01-01T00:00:00Z",
            "severity": [{"type": "CVSS_V3", "score": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}],
        }
    ]
}
with patch("tools.web.requests.post") as mock_post:
    mock_post.return_value = MagicMock(status_code=200, json=lambda: OSV_SAMPLE)
    osv_res = web.search_osv("jinja2", ecosystem="PyPI")

check("returns 1 vuln", len(osv_res) == 1)
check("extracts CVE alias", osv_res[0]["cve_ids"] == ["CVE-2019-10906"])
check("keeps OSV id", osv_res[0]["id"] == "PYSEC-2022-1")
check("captures cvss vector", osv_res[0]["cvss_vector"].startswith("AV:N"))


# ── 5) local ExploitDB index update + search (using a fake CSV, no network) ──
print("\n[5] update_exploitdb_index + search_exploitdb (local CSV logic)")
FAKE_CSV = (
    "id,file,description,date_published,author,type,platform,port,date_added,"
    "date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url\n"
    '50001,exploits/linux/remote/50001.py,"OpenSSH 8.2 - Remote Code Execution",'
    '2023-05-01,someone,remote,linux,22,2023-05-01,2023-05-01,1,,,,,,\n'
    '50002,exploits/windows/local/50002.py,"Windows SMB - Local Privilege Escalation",'
    '2023-06-01,someone2,local,windows,445,2023-06-01,2023-06-01,1,,,,,,\n'
)

with tempfile.TemporaryDirectory() as tmpdir:
    fake_cache = os_path = os.path.join(tmpdir, "exploitdb_index.csv")
    with patch("tools.web.EXPLOITDB_CACHE") as mock_path:
        # Configure the mock Path object to behave like a real path pointing at tmpdir
        import pathlib
        real_path = pathlib.Path(fake_cache)
        mock_path.parent = real_path.parent
        mock_path.exists.side_effect = lambda: real_path.exists()
        mock_path.with_suffix.side_effect = lambda suf: real_path.with_suffix(suf)
        mock_path.__str__.return_value = str(real_path)

        class FakeResp:
            status_code = 200
            def iter_content(self, chunk_size=65536):
                yield FAKE_CSV.encode("utf-8")

        with patch("tools.web.requests.get", return_value=FakeResp()):
            # We can't easily patch open() to redirect EXPLOITDB_CACHE since it's a MagicMock;
            # instead call the real functions against the real path temporarily.
            pass

# Simpler/robust approach: monkeypatch the module-level EXPLOITDB_CACHE constant directly
import importlib
from pathlib import Path as _P
orig_cache = web.EXPLOITDB_CACHE
with tempfile.TemporaryDirectory() as tmpdir:
    web.EXPLOITDB_CACHE = _P(tmpdir) / "exploitdb_index.csv"

    class FakeResp2:
        status_code = 200
        def iter_content(self, chunk_size=65536):
            yield FAKE_CSV.encode("utf-8")

    with patch("tools.web.requests.get", return_value=FakeResp2()):
        upd = web.update_exploitdb_index()
    check("update reports success", upd.get("success") is True)
    check("update counts 2 rows", upd.get("count") == 2)

    ssh_hits = web.search_exploitdb("openssh")
    check("finds the openssh entry", len(ssh_hits) == 1 and ssh_hits[0]["edb_id"] == "50001")
    check("edb url built correctly", ssh_hits[0]["url"] == "https://www.exploit-db.com/exploits/50001")

    none_hits = web.search_exploitdb("totallynotpresentxyz")
    check("no false positive matches", len(none_hits) == 0)

web.EXPLOITDB_CACHE = orig_cache
# Also check the "index not downloaded yet" honest message path
with tempfile.TemporaryDirectory() as tmpdir2:
    web.EXPLOITDB_CACHE = _P(tmpdir2) / "does_not_exist.csv"
    missing = web.search_exploitdb("anything")
    check("clear message when index missing", len(missing) == 1 and "error" in missing[0])
web.EXPLOITDB_CACHE = orig_cache


# ── 6) check_ip_reputation: no more fake 'PUBLIC' key, transparent skip ─
print("\n[6] check_ip_reputation")
with patch("tools.web.validators.is_valid_ip", return_value=True), \
     patch("tools.web.requests.get") as mock_get2:
    def side_effect(url, *a, **kw):
        if "ipapi.co" in url:
            return MagicMock(status_code=200, json=lambda: {
                "country_name": "Germany", "city": "Falkenstein", "org": "Hetzner Online GmbH (hosting)",
                "asn": "AS24940", "latitude": 1, "longitude": 1,
            })
        if "ip-api.com" in url:
            return MagicMock(status_code=200, json=lambda: {
                "status": "success", "isp": "Hetzner", "org": "Hetzner Online GmbH",
                "as": "AS24940", "proxy": False, "hosting": True, "mobile": False,
            })
        return MagicMock(status_code=500, json=lambda: {})
    mock_get2.side_effect = side_effect
    rep_no_key = web.check_ip_reputation("1.2.3.4")

check("no AbuseIPDB call attempted without key", "AbuseIPDB" not in rep_no_key["sources_checked"])
check("transparent skip-notice present", any("AbuseIPDB" in f["title"] for f in rep_no_key["findings"]))
check("hosting flag detected via ip-api.com", rep_no_key["reputation"] == "suspicious")

with patch("tools.web.validators.is_valid_ip", return_value=True), \
     patch("tools.web.requests.get") as mock_get3:
    def side_effect2(url, *a, **kw):
        if "ipapi.co" in url:
            return MagicMock(status_code=200, json=lambda: {"country_name": "US", "org": "Comcast", "asn": "AS1"})
        if "ip-api.com" in url:
            return MagicMock(status_code=200, json=lambda: {"status": "success", "isp": "Comcast", "org": "Comcast",
                                                              "as": "AS1", "proxy": False, "hosting": False})
        if "abuseipdb.com" in url:
            return MagicMock(status_code=200, json=lambda: {"data": {"abuseConfidenceScore": 90, "totalReports": 12, "isp": "Comcast"}})
        return MagicMock(status_code=500, json=lambda: {})
    mock_get3.side_effect = side_effect2
    rep_with_key = web.check_ip_reputation("5.6.7.8", abuseipdb_key="FAKEKEY123")

check("AbuseIPDB used when key provided", "AbuseIPDB" in rep_with_key["sources_checked"])
check("malicious flagged from abuse score", rep_with_key["reputation"] == "malicious")


print(f"\n{'='*50}\nTOTAL: {passed} passed, {failed} failed\n{'='*50}")
sys.exit(1 if failed else 0)
