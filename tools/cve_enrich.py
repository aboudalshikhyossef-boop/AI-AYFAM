"""CVE/KEV enrichment for upgradable packages — used by agent and GUI."""
from tools import web, vuln_match


def enrich_packages_with_cve(packages: list, settings: dict | None = None, lang: str = "ar") -> list:
    """يطابق الحزم القابلة للترقية مع CISA KEV وNVD بمطابقة اسم/إصدار مضبوطة."""
    findings = []
    if not packages:
        return findings

    settings = settings or {}
    kev = web.get_cisa_known_exploited(max_results=0)
    nvd_key = settings.get("nvd_api_key", "")
    checked_via_nvd = 0

    def _t(ar: str, en: str) -> str:
        return ar if lang == "ar" else en

    for pkg in packages[:8]:
        name = pkg["package"]
        hits = vuln_match.match_package_to_kev(name, kev)
        if hits:
            cves = ", ".join((hit.get("cve_id") or "?") for hit in hits[:3])
            findings.append({
                "severity": "high",
                "confidence": 0.55,
                "title": _t(
                    f"حزمة {name} تطابق اسم منتج في CISA KEV ({cves}) دون تحقق من الإصدار",
                    f"Package {name} matches a CISA KEV product name ({cves}) without a version check"),
                "detail": _t(
                    "المطابقة على الاسم فقط. لا تُعامل كنتيجة حرجة قبل مقارنة الإصدار المثبت بالنشرة.",
                    "Name-only match. Do not treat as critical until the installed version is compared with the advisory."),
                "fix": f"sudo apt-get install --only-upgrade {name}",
                "cve_enriched": True,
                "source": "cisa_kev",
            })
            continue
        if checked_via_nvd >= 5:
            continue
        checked_via_nvd += 1
        version = pkg.get("version") or ""
        stem = next(iter(vuln_match.package_match_keys(name)), name)
        records = web.search_cve(stem, days_back=180, max_results=5, api_key=nvd_key)
        matched = vuln_match.match_package_to_nvd(name, version, records)
        if not matched:
            continue
        top = matched[0]
        version_hit = top.get("match") == "version"
        nvd_severity = (top.get("severity") or "").upper()
        findings.append({
            "severity": ("critical" if nvd_severity == "CRITICAL" else "high") if version_hit else "medium",
            "confidence": 0.85 if version_hit else 0.4,
            "title": _t(
                f"حزمة {name} {version} ضمن نطاق {top['id']}" if version_hit
                else f"حزمة {name} تطابق منتج {top['id']} في NVD دون تطابق إصدار",
                f"Package {name} {version} is inside {top['id']}" if version_hit
                else f"Package {name} matches the NVD product in {top['id']} without a version match",
            ),
            "detail": f"{(top.get('description') or '')[:150]} (CVSS: {top.get('cvss_score','?')})",
            "fix": f"sudo apt-get install --only-upgrade {name}\n{top.get('url','')}",
            "cve_enriched": True,
            "source": "nvd",
        })
    return findings
