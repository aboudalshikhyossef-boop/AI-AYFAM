"""
AI AYFAM - Web Intelligence + Browser Integration
ذكاء الإنترنت والمتصفح وفحص المواقع
"""

from utils import http_client as requests
import re
import json
import csv
import subprocess
import shutil
import socket
import ssl
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from html import unescape as _html_unescape

from utils import validators
from tools.vuln_match import cpe_from_cve, package_match_keys, match_package_to_kev, match_package_to_nvd


HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}
API_HEADERS = {
    "User-Agent": "AI-AYFAM-SecurityAgent/2.0",
    "Accept": "application/json",
}

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_ADVISORIES = "https://api.github.com/advisories"

# ─── مصادر بحث/CVE إضافية — كلها مجانية ولا تحتاج أي مفتاح API ─────────────
OSV_API = "https://api.osv.dev/v1/query"
# المستودع الرسمي الحالي (المستودع القديم على GitHub أُرشِف ونُقل بالكامل لهذا).
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
EXPLOITDB_CACHE = Path.home() / ".ayfam" / "exploitdb_index.csv"
WIKIPEDIA_LANGS = ("ar", "en")


def check_connectivity() -> dict:
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=5, headers=API_HEADERS)
        if r.status_code == 200:
            return {"connected": True, "public_ip": r.json().get("ip", "?")}
    except Exception:
        pass
    return {"connected": False, "public_ip": None}


# ─────────────────────────────────────────────────────────────────────────────
#  CVE / Vulnerability Intelligence
# ─────────────────────────────────────────────────────────────────────────────

def search_cve(keyword: str, days_back: int = 90, max_results: int = 10, api_key: str = "") -> list:
    try:
        end = datetime.utcnow()
        start = end - timedelta(days=days_back)
        params = {
            "keywordSearch": keyword,
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": max_results,
        }
        # مفتاح NVD اختياري بالكامل: بدونه الحد 5 طلبات/30ث، ومعه يرتفع لـ50/30ث.
        headers = {**API_HEADERS, "apiKey": api_key} if api_key else API_HEADERS
        r = requests.get(NVD_API, params=params, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            results = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                descs = cve.get("descriptions", [])
                desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                metrics = cve.get("metrics", {})
                score, severity = None, "UNKNOWN"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        m = metrics[key][0].get("cvssData", {})
                        score = m.get("baseScore")
                        severity = m.get("baseSeverity", "UNKNOWN")
                        break
                results.append({
                    "id": cve_id, "description": desc[:300],
                    "cvss_score": score, "severity": severity,
                    "published": cve.get("published", "")[:10],
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "cpe": cpe_from_cve(cve),
                })
            return results
        return [{"error": f"HTTP {r.status_code}"}]
    except Exception as e:
        return [{"error": str(e)}]


def get_cve_detail(cve_id: str, api_key: str = "") -> dict:
    try:
        headers = {**API_HEADERS, "apiKey": api_key} if api_key else API_HEADERS
        r = requests.get(f"{NVD_API}?cveId={cve_id}", headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve = vulns[0].get("cve", {})
                descs = cve.get("descriptions", [])
                desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                refs = [ref.get("url") for ref in cve.get("references", [])][:5]
                metrics = cve.get("metrics", {})
                cvss = {}
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        cvss = metrics[key][0].get("cvssData", {})
                        break
                return {
                    "id": cve_id, "description": desc,
                    "cvss": cvss, "severity": cvss.get("baseSeverity", "?"),
                    "score": cvss.get("baseScore"),
                    "references": refs,
                    "published": cve.get("published", "")[:10],
                }
    except Exception as e:
        return {"error": str(e)}
    return {"error": "Not found"}


def get_cisa_known_exploited(max_results: int = 15) -> list:
    try:
        r = requests.get(CISA_KEV, headers=API_HEADERS, timeout=15)
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            vulns.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
            return [{
                "cve_id": v.get("cveID"), "vendor": v.get("vendorProject"),
                "product": v.get("product"), "description": v.get("vulnerabilityName"),
                "date_added": v.get("dateAdded"), "required_action": v.get("requiredAction", ""),
                "severity": "CRITICAL",
            } for v in (vulns if max_results is None or max_results <= 0 else vulns[:max_results])]
    except Exception as e:
        return [{"error": str(e)}]
    return []


def search_osv(package: str, ecosystem: str = "PyPI", version: str = "", max_results: int = 10) -> list:
    """
    بحث ثغرات حزم مفتوحة المصدر عبر OSV.dev (مشروع Google) — مجاني بالكامل، بدون
    مفتاح API، ويغطي مصادر لا تغطيها NVD بنفس التفصيل (GHSA، PYSEC، RUSTSEC...).
    قيم ecosystem الشائعة (حسّاسة لحالة الأحرف — استخدم الشكل الرسمي تماماً):
    PyPI, npm, Go, crates.io, Packagist, RubyGems, Maven, NuGet, Debian, Alpine.
    """
    if not package or not package.strip():
        return []
    try:
        body = {"package": {"name": package.strip(), "ecosystem": ecosystem}}
        if version:
            body["version"] = version
        r = requests.post(OSV_API, json=body, headers=API_HEADERS, timeout=15)
        if r.status_code != 200:
            return [{"error": f"HTTP {r.status_code}"}]
        vulns = r.json().get("vulns", [])
        results = []
        for v in vulns[:max_results]:
            aliases = v.get("aliases", []) or []
            cve_ids = [a for a in aliases if a.startswith("CVE-")]
            cvss_vector = ""
            for s in v.get("severity", []) or []:
                if s.get("type", "").startswith("CVSS"):
                    cvss_vector = s.get("score", "")
                    break
            results.append({
                "id": v.get("id", ""),
                "cve_ids": cve_ids,
                "summary": (v.get("summary") or v.get("details", "") or "")[:300],
                "published": (v.get("published") or "")[:10],
                "cvss_vector": cvss_vector,
                "url": f"https://osv.dev/vulnerability/{v.get('id','')}",
                "package": package,
                "ecosystem": ecosystem,
            })
        return results
    except Exception as e:
        return [{"error": str(e)}]


def update_exploitdb_index() -> dict:
    """
    يحمّل فهرس Exploit-DB الكامل (ملف CSV واحد من عدة ميغابايت) من المستودع
    الرسمي مرة واحدة، ثم يُخزَّن محلياً في ~/.ayfam/exploitdb_index.csv.
    بعدها search_exploitdb() يبحث فيه محلياً بالكامل — بدون اتصال، وبدون أي
    حد لعدد الطلبات، بما يطابق فلسفة الأداة في تفضيل التخزين المحلي.
    ملاحظة صادقة: هذا فهرس عناوين/أوصاف فقط (لا يحمّل أكواد الاستغلال نفسها).
    """
    try:
        EXPLOITDB_CACHE.parent.mkdir(parents=True, exist_ok=True)
        r = requests.get(EXPLOITDB_CSV_URL, headers=HEADERS, timeout=60, stream=True)
        if r.status_code != 200:
            return {"success": False, "error": f"HTTP {r.status_code} من {EXPLOITDB_CSV_URL}"}

        tmp_path = EXPLOITDB_CACHE.with_suffix(".tmp")
        with open(tmp_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)

        # تحقّق من صحة الملف قبل استبدال أي نسخة قديمة صالحة
        count = 0
        with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header or "id" not in [h.strip().lower() for h in header]:
                tmp_path.unlink(missing_ok=True)
                return {"success": False, "error": "تنسيق الملف المُحمَّل غير متوقع — قد يكون رابط المصدر تغيّر"}
            for _ in reader:
                count += 1
        tmp_path.replace(EXPLOITDB_CACHE)
        return {"success": True, "count": count}
    except Exception as e:
        return {"success": False, "error": str(e)}


def search_exploitdb(keyword: str, max_results: int = 10) -> list:
    """
    بحث محلي بالكامل (بدون أي اتصال) داخل فهرس Exploit-DB الذي حمّلته
    update_exploitdb_index() مسبقاً. إن لم يوجد الفهرس بعد نعيد رسالة واضحة
    تطلب تحديثه أولاً — بدل نتيجة فارغة تبدو وكأن لا استغلالات معروفة أصلاً.
    """
    if not keyword or not keyword.strip():
        return []
    if not EXPLOITDB_CACHE.exists():
        return [{"error": "فهرس Exploit-DB المحلي غير موجود بعد — شغّل 'تحديث المعلومات الاستخباراتية' أولاً"}]

    keyword_l = keyword.strip().lower()
    results = []
    try:
        with open(EXPLOITDB_CACHE, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                desc = row.get("description") or ""
                if keyword_l in desc.lower():
                    edb_id = row.get("id", "")
                    results.append({
                        "edb_id": edb_id,
                        "description": desc,
                        "type": row.get("type", ""),
                        "platform": row.get("platform", ""),
                        "date_published": row.get("date_published", ""),
                        "author": row.get("author", ""),
                        "url": f"https://www.exploit-db.com/exploits/{edb_id}",
                    })
                    if len(results) >= max_results:
                        break
    except Exception as e:
        return [{"error": str(e)}]
    return results


def fetch_security_news(max_items: int = 8) -> list:
    feeds = [
        ("https://feeds.feedburner.com/TheHackersNews", "The Hacker News"),
        ("https://www.bleepingcomputer.com/feed/", "BleepingComputer"),
        ("https://krebsonsecurity.com/feed/", "KrebsOnSecurity"),
    ]
    items = []
    for feed_url, source in feeds:
        try:
            r = requests.get(feed_url, headers={**HEADERS, "Accept": "text/xml"}, timeout=8)
            if r.status_code == 200:
                # Parse RSS
                titles = re.findall(r"<title><!\[CDATA\[(.*?)\]\]></title>", r.text)
                if not titles:
                    titles = re.findall(r"<title>(.*?)</title>", r.text)
                links = re.findall(r"<link>(https?://[^<]+)</link>", r.text)
                pub_dates = re.findall(r"<pubDate>(.*?)</pubDate>", r.text)
                for i, title in enumerate(titles[1:6]):  # skip channel title
                    link = links[i + 1] if i + 1 < len(links) else feed_url
                    date = pub_dates[i][:16] if i < len(pub_dates) else ""
                    items.append({"title": title.strip(), "url": link.strip(), "source": source, "date": date})
            if len(items) >= max_items:
                break
        except Exception:
            continue
    return items[:max_items]


# ─────────────────────────────────────────────────────────────────────────────
#  Website Security Testing
# ─────────────────────────────────────────────────────────────────────────────

def test_website_security(url: str) -> dict:
    """Comprehensive website security test — headers, SSL, open ports, etc."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    scheme = parsed.scheme

    result = {
        "url": url,
        "host": host,
        "timestamp": datetime.now().isoformat(),
        "reachable": False,
        "ssl": {},
        "headers": {},
        "missing_headers": [],
        "open_ports": [],
        "findings": [],
        "score": 100,  # Start at 100, deduct for issues
    }

    # ── 1. Basic connectivity ──────────────────────────────────────────────
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True, verify=True)
        result["reachable"] = True
        result["status_code"] = r.status_code
        result["final_url"] = r.url
        result["server"] = r.headers.get("Server", "")
        result["response_time_ms"] = int(r.elapsed.total_seconds() * 1000)
        headers = {k.lower(): v for k, v in r.headers.items()}
        result["headers"] = dict(r.headers)

        # ── 2. Security Headers Check ────────────────────────────────────
        security_headers = {
            "strict-transport-security": ("HSTS", "حماية من هجمات HTTPS downgrade"),
            "content-security-policy": ("CSP", "حماية من XSS"),
            "x-frame-options": ("X-Frame-Options", "حماية من Clickjacking"),
            "x-content-type-options": ("X-Content-Type-Options", "حماية MIME sniffing"),
            "referrer-policy": ("Referrer-Policy", "التحكم في مشاركة Referrer"),
            "permissions-policy": ("Permissions-Policy", "التحكم في صلاحيات المتصفح"),
        }
        for header_key, (header_name, desc) in security_headers.items():
            if header_key not in headers:
                result["missing_headers"].append(header_name)
                result["findings"].append({
                    "severity": "medium",
                    "title": f"رأس أمان مفقود: {header_name}",
                    "detail": desc,
                    "fix": f"أضف: {header_name}: <value> في إعدادات الخادم",
                })
                result["score"] -= 8

        # ── 3. Information Disclosure ────────────────────────────────────
        if result["server"]:
            srv = result["server"]
            if any(tech in srv for tech in ["Apache/", "nginx/", "IIS/", "PHP/"]):
                result["findings"].append({
                    "severity": "low",
                    "title": f"الخادم يكشف عن نفسه: {srv}",
                    "detail": "إخفاء إصدار الخادم يجعل الاستهداف أصعب.",
                    "fix": "Apache: ServerTokens Prod | Nginx: server_tokens off",
                })
                result["score"] -= 5

        # ── 4. Cookie Security ───────────────────────────────────────────
        for cookie in r.cookies:
            issues = []
            if not cookie.secure:
                issues.append("بدون Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("بدون HttpOnly")
            if issues:
                result["findings"].append({
                    "severity": "medium",
                    "title": f"Cookie غير آمنة: {cookie.name}",
                    "detail": " | ".join(issues),
                    "fix": f"Set-Cookie: {cookie.name}=...; Secure; HttpOnly; SameSite=Strict",
                })
                result["score"] -= 10

        # ── 5. HTTP → HTTPS redirect ─────────────────────────────────────
        if scheme == "https" and "http://" + host in r.url:
            result["findings"].append({
                "severity": "high",
                "title": "لا يوجد إعادة توجيه HTTP→HTTPS",
                "detail": "المستخدمون يمكنهم الوصول عبر HTTP غير المشفّر.",
                "fix": "أعد توجيه كل HTTP إلى HTTPS في إعدادات الخادم.",
            })
            result["score"] -= 20

    except requests.exceptions.SSLError as e:
        result["findings"].append({
            "severity": "critical",
            "title": f"خطأ SSL/TLS: {host}",
            "detail": str(e)[:200],
            "fix": "تحقق من صلاحية شهادة SSL وتكوين TLS.",
        })
        result["score"] -= 40
    except requests.exceptions.ConnectionError:
        result["findings"].append({"severity": "info", "title": f"لا يمكن الوصول: {url}", "detail": "الموقع غير متاح.", "fix": ""})
        return result
    except Exception as e:
        result["findings"].append({"severity": "info", "title": f"خطأ: {e}", "detail": "", "fix": ""})

    # ── 6. SSL Certificate check ─────────────────────────────────────────
    if host and scheme == "https":
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.create_connection((host, 443), timeout=8), server_hostname=host) as s:
                cert = s.getpeercert()
                not_after = cert.get("notAfter", "")
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.utcnow()).days
                    result["ssl"]["expires"] = not_after
                    result["ssl"]["days_left"] = days_left
                    result["ssl"]["subject"] = dict(x[0] for x in cert.get("subject", []))
                    result["ssl"]["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    result["ssl"]["version"] = s.version()
                    if days_left < 30:
                        sev = "critical" if days_left < 7 else "high"
                        result["findings"].append({
                            "severity": sev,
                            "title": f"شهادة SSL تنتهي خلال {days_left} يوم!",
                            "detail": f"تنتهي في: {not_after}",
                            "fix": "جدّد شهادة SSL قبل انتهائها.",
                        })
                        result["score"] -= 30
                    elif days_left > 30:
                        result["ssl"]["status"] = "valid"
        except Exception as e:
            result["ssl"]["error"] = str(e)[:100]

    # ── 7. Quick port scan ────────────────────────────────────────────────
    interesting_ports = [21, 22, 23, 25, 80, 443, 445, 3389, 5900, 8080, 8443]
    if host:
        try:
            for port in interesting_ports:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((host, port)) == 0:
                    result["open_ports"].append(port)
                    if port in {23, 445, 3389, 5900}:
                        result["findings"].append({
                            "severity": "high",
                            "title": f"منفذ خطير مكشوف: {port}",
                            "detail": {23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC"}.get(port, ""),
                            "fix": f"أغلق المنفذ {port} في جدار الحماية.",
                        })
                        result["score"] -= 15
                s.close()
        except Exception:
            pass

    # Normalize score
    result["score"] = max(0, min(100, result["score"]))
    if result["score"] >= 80:
        result["grade"] = "A"
    elif result["score"] >= 60:
        result["grade"] = "B"
    elif result["score"] >= 40:
        result["grade"] = "C"
    else:
        result["grade"] = "F"

    return result


# ─────────────────────────────────────────────────────────────────────────────
#  Browser Integration
# ─────────────────────────────────────────────────────────────────────────────

def open_browser(url: str) -> dict:
    """Open URL in system browser"""
    browsers = ["xdg-open", "firefox", "chromium-browser", "google-chrome", "brave-browser", "epiphany"]
    for browser in browsers:
        if shutil.which(browser):
            subprocess.Popen([browser, url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
            return {"opened": True, "browser": browser, "url": url}
    return {"opened": False, "error": "No browser found"}


_DDG_RESULT_RE = re.compile(
    r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.DOTALL
)
_DDG_SNIPPET_RE = re.compile(
    r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', re.DOTALL
)
_TAG_RE = re.compile(r"<[^>]+>")


def _clean_html_text(raw: str) -> str:
    return _html_unescape(_TAG_RE.sub("", raw)).strip()


def _unwrap_ddg_redirect(url: str) -> str:
    """روابط DuckDuckGo HTML مغلّفة بإعادة توجيه داخلية: //duckduckgo.com/l/?uddg=<encoded>.
    بدون فكّها كل نتيجة تُظهر رابطاً لـ duckduckgo.com بدل الموقع الحقيقي."""
    if "duckduckgo.com/l/" in url:
        try:
            full = url if "://" in url else f"https:{url}"
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(full).query)
            if qs.get("uddg"):
                return urllib.parse.unquote(qs["uddg"][0])
        except Exception:
            pass
    return url


def _ddg_instant_answer(query: str, max_results: int) -> list:
    """إجابات DuckDuckGo المباشرة (Instant Answer API) — سريعة حين تتوفر، لكنها
    مصممة لأسئلة موسوعية محددة وليست بحثاً عاماً؛ لذا تُستخدَم كتكملة فقط."""
    results = []
    try:
        params = {"q": query, "format": "json", "no_html": "1", "no_redirect": "1", "skip_disambig": "1"}
        r = requests.get("https://api.duckduckgo.com/", params=params, headers=API_HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("AbstractText"):
                results.append({
                    "title": data.get("Heading", query),
                    "url": data.get("AbstractURL", ""),
                    "snippet": data.get("AbstractText", "")[:300],
                    "source": data.get("AbstractSource") or "DuckDuckGo",
                    "type": "instant_answer",
                })
            for topic in data.get("RelatedTopics", [])[:max_results]:
                if isinstance(topic, dict) and topic.get("Text"):
                    results.append({
                        "title": topic.get("Text", "")[:80],
                        "url": topic.get("FirstURL", ""),
                        "snippet": topic.get("Text", "")[:200],
                        "source": "DuckDuckGo",
                        "type": "related",
                    })
    except Exception:
        pass
    return results


def _ddg_html_search(query: str, max_results: int) -> list:
    """نتائج بحث حقيقية (وليست إجابات موسوعية فقط) عبر صفحة HTML من DuckDuckGo —
    المصدر العام الأساسي لأنه الوحيد بين الاثنين الذي يرجع نتائج لأي استعلام
    عادي، وليس فقط للأسئلة المعروفة لديه كـ'إجابة مباشرة'."""
    results = []
    try:
        search_url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
        r = requests.get(search_url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            links = _DDG_RESULT_RE.findall(r.text)
            snippets = _DDG_SNIPPET_RE.findall(r.text)
            for i, (href, title_html) in enumerate(links[:max_results]):
                results.append({
                    "title": _clean_html_text(title_html),
                    "url": _unwrap_ddg_redirect(href),
                    "snippet": _clean_html_text(snippets[i]) if i < len(snippets) else "",
                    "source": "DuckDuckGo",
                    "type": "search",
                })
    except Exception:
        pass
    return results


def _wikipedia_search(query: str, lang: str, max_results: int = 2) -> list:
    """بحث ويكيبيديا (OpenSearch + ملخص أول نتيجة) — مصدر موسوعي مجاني ومستقر
    جداً على المدى الطويل، ويعمل جيداً بالعربية والإنجليزية معاً، خلافاً لمحرك
    DuckDuckGo Instant Answer الذي غالباً ما يُرجع فراغاً للاستعلامات العربية."""
    results = []
    try:
        r = requests.get(
            f"https://{lang}.wikipedia.org/w/api.php",
            params={"action": "opensearch", "search": query, "limit": max_results,
                    "namespace": 0, "format": "json"},
            headers=API_HEADERS, timeout=8,
        )
        if r.status_code != 200:
            return results
        data = r.json()
        titles = data[1] if len(data) > 1 else []
        urls = data[3] if len(data) > 3 else []
        for i, title in enumerate(titles[:max_results]):
            extract = ""
            try:
                sr = requests.get(
                    f"https://{lang}.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(title)}",
                    headers=API_HEADERS, timeout=8,
                )
                if sr.status_code == 200:
                    extract = sr.json().get("extract", "")
            except Exception:
                pass
            results.append({
                "title": title,
                "url": urls[i] if i < len(urls) else f"https://{lang}.wikipedia.org/wiki/{urllib.parse.quote(title)}",
                "snippet": (extract or "")[:300],
                "source": f"Wikipedia ({lang})",
                "type": "encyclopedia",
            })
    except Exception:
        pass
    return results


def web_search(query: str, max_results: int = 8) -> list:
    """
    بحث ويب متعدد المصادر — بدون أي مفتاح API:
      1) DuckDuckGo HTML   — نتائج بحث عامة حقيقية (المصدر الأساسي)
      2) DuckDuckGo Instant — إجابات مباشرة سريعة حين تنطبق (تكميلي)
      3) Wikipedia (ar+en)  — مصدر موسوعي مستقر لمفاهيم/مصطلحات عامة (تكميلي)
    قبل هذا التحديث كان الاعتماد فقط على Instant Answer API، وهو صُمم لأسئلة
    موسوعية ضيقة ويُرجع فراغاً لمعظم الاستعلامات التقنية العادية؛ الآن نتائج
    HTML الفعلية هي الأساس، والباقي تكميلي فقط.
    """
    if not query or not query.strip():
        return []

    combined = []
    combined.extend(_ddg_instant_answer(query, max_results))
    combined.extend(_ddg_html_search(query, max_results))
    combined.extend(_wikipedia_search(query, "ar", max_results=2))
    combined.extend(_wikipedia_search(query, "en", max_results=2))

    # إزالة التكرار حسب الرابط (أو العنوان إن كان الرابط فارغاً) دون تفضيل
    # مصدر على آخر في الترتيب — الإجابات المباشرة تبقى أولاً لأنها أُضيفت أولاً
    seen = set()
    deduped = []
    for item in combined:
        key = (item.get("url") or item.get("title", "")).strip().lower()
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        deduped.append(item)

    if not deduped:
        return [{"error": "لا نتائج من أي مصدر (DuckDuckGo/Wikipedia) — تحقق من اتصالك بالإنترنت.", "query": query}]

    # الإجابات المباشرة تبقى أولاً (مُنسَّقة ومُختصَرة أصلاً من مصدرها)،
    # وباقي النتائج (بحث عام + ويكيبيديا) تُعاد ترتيبها بحسب صلتها
    # الإحصائية الفعلية بالاستعلام بدل ترتيبها حسب مصدرها فقط فقط —
    # هذا ما يجعل البحث "منظّماً" بدل نتائج مبعثرة بترتيب عشوائي المصدر.
    instant = [r for r in deduped if r.get("type") == "instant_answer"]
    rest = [r for r in deduped if r.get("type") != "instant_answer"]
    if len(rest) > 1:
        try:
            from brain.relevance_engine import rank_texts
            texts = [f"{r.get('title','')} {r.get('snippet','')}" for r in rest]
            order = rank_texts(query, texts)
            rest = [rest[i] for i in order]
        except Exception:
            pass  # تدهور رشيق: يبقى الترتيب الأصلي إن تعذّر حساب الصلة لأي سبب

    return (instant + rest)[:max_results]


def fetch_page_content(url: str, max_length: int = 3000) -> dict:
    """Fetch and extract text content from a webpage"""
    try:
        r = requests.get(url, headers=HEADERS, timeout=12)
        if r.status_code != 200:
            return {"success": False, "error": f"HTTP {r.status_code}"}

        html = r.text
        # Remove scripts and styles
        html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL)
        html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL)
        # Remove tags
        text = re.sub(r"<[^>]+>", " ", html)
        # Clean whitespace
        text = re.sub(r"\s+", " ", text).strip()

        return {
            "success": True,
            "url": url,
            "title": re.search(r"<title[^>]*>([^<]+)</title>", r.text, re.I),
            "content": text[:max_length],
            "length": len(text),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def check_ip_reputation(ip: str, abuseipdb_key: str = "") -> dict:
    """
    فحص سمعة IP من عدة مصادر:
      1) ipapi.co    — مجاني بدون مفتاح: جغرافيا + تخمين نصي من اسم الـISP
      2) ip-api.com  — مجاني بدون مفتاح: أعلام proxy/hosting/mobile فعلية
         من المزوّد نفسه (أدق من التخمين النصي وحده)
      3) AbuseIPDB   — اختياري بالكامل: يعمل فقط إن أضاف المستخدم مفتاحه
         المجاني في الإعدادات. سابقاً كان الكود يرسل "Key": "PUBLIC" —
         وهو ليس مفتاحاً صالحاً، فكان الطلب يفشل صامتاً في كل مرة (0%
         نتائج حقيقية طوال الوقت). الآن: بدون مفتاح نتخطّى هذا المصدر
         بوضوح بدل التظاهر بفحصه.
    """
    result = {"ip": ip, "reputation": "unknown", "info": {}, "findings": [], "sources_checked": []}

    if not validators.is_valid_ip(ip):
        result["reputation"] = "invalid"
        result["findings"].append({
            "severity": "info",
            "title": f"عنوان IP غير صالح: {ip}",
            "detail": "تم رفض الطلب قبل إرسال أي استعلام خارجي.",
            "fix": "",
        })
        return result

    # 1) ipapi.co
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", headers=API_HEADERS, timeout=8)
        if r.status_code == 200:
            d = r.json()
            if not d.get("error"):
                result["info"].update({
                    "country": d.get("country_name", ""), "city": d.get("city", ""),
                    "isp": d.get("org", ""), "asn": d.get("asn", ""),
                    "latitude": d.get("latitude"), "longitude": d.get("longitude"),
                })
                result["sources_checked"].append("ipapi.co")
                isp = (d.get("org") or "").lower()
                if any(k in isp for k in ["tor", "vpn", "anonymous", "proxy", "hosting", "linode", "digitalocean", "vultr"]):
                    result["reputation"] = "suspicious"
                    result["findings"].append({
                        "severity": "medium",
                        "title": f"IP من شبكة استضافة/VPN (تخمين من اسم المزوّد): {d.get('org')}",
                        "detail": f"الدولة: {d.get('country_name')} | ASN: {d.get('asn')}",
                        "fix": "راقب الاتصالات من هذا IP.",
                    })
    except Exception:
        pass

    # 2) ip-api.com — أعلام proxy/hosting/mobile فعلية من المزوّد، لا تخميناً بالاسم
    try:
        r2 = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,isp,org,as,proxy,hosting,mobile"},
            headers=API_HEADERS, timeout=8,
        )
        if r2.status_code == 200:
            d2 = r2.json()
            if d2.get("status") == "success":
                result["sources_checked"].append("ip-api.com")
                result["info"].setdefault("isp", d2.get("isp", ""))
                result["info"]["as"] = d2.get("as", "")
                if d2.get("proxy") or d2.get("hosting"):
                    result["reputation"] = "suspicious"
                    kind = "Proxy/VPN مؤكَّد" if d2.get("proxy") else "خادم استضافة (Hosting) مؤكَّد"
                    result["findings"].append({
                        "severity": "medium",
                        "title": f"{kind} من مزوّد الشبكة: {d2.get('org') or d2.get('isp','')}",
                        "detail": f"AS: {d2.get('as','')}",
                        "fix": "راقب الاتصالات من هذا IP — هذا النوع من الشبكات كثيراً ما يُستخدم لإخفاء الهوية.",
                    })
    except Exception:
        pass

    # 3) AbuseIPDB — اختياري بالكامل، يحتاج مفتاح المستخدم الخاص (مجاني بالتسجيل)
    if abuseipdb_key:
        try:
            r3 = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={**API_HEADERS, "Key": abuseipdb_key},
                timeout=8,
            )
            if r3.status_code == 200:
                data = r3.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                result["abuse_score"] = score
                result["sources_checked"].append("AbuseIPDB")
                if score > 50:
                    result["reputation"] = "malicious"
                    result["findings"].append({
                        "severity": "critical",
                        "title": f"IP خطير معروف: {ip} (نقاط الإساءة: {score}%)",
                        "detail": f"تقارير: {data.get('totalReports', 0)} | ISP: {data.get('isp', '')}",
                        "fix": f"احجب فوراً: sudo ufw deny from {ip}",
                    })
            elif r3.status_code == 401:
                result["findings"].append({
                    "severity": "info",
                    "title": "مفتاح AbuseIPDB غير صالح",
                    "detail": "تحقق من المفتاح المحفوظ في الإعدادات (⚙️).",
                    "fix": "",
                })
        except Exception:
            pass
    else:
        result["findings"].append({
            "severity": "info",
            "title": "لم يُفحص مصدر AbuseIPDB (لا يوجد مفتاح محفوظ)",
            "detail": "احصل على مفتاح مجاني من abuseipdb.com وأضِفه من قائمة الإعدادات لتفعيل هذا المصدر.",
            "fix": "",
        })

    if result["reputation"] == "unknown":
        result["reputation"] = "clean"

    return result


# Re-export matching helpers so callers can use tools.web.*
__all_match__ = (package_match_keys, match_package_to_kev, match_package_to_nvd, cpe_from_cve)
