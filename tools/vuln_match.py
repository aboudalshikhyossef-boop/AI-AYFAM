"""KEV/NVD package matching helpers."""
import re

_PKG_SUFFIXES = ("-server", "-client", "-common", "-data", "-bin", "-dev", "-doc", "-dbg", "-core")


def package_match_keys(name: str) -> set:
    """مفاتيح مطابقة لاسم حزمة ديبيان: الاسم كاملاً ثم بعد حذف لاحقات الدور."""
    base = (name or "").lower().replace("_", "-").strip()
    keys = set()
    while base:
        keys.add(base)
        for suffix in _PKG_SUFFIXES:
            if base.endswith(suffix) and len(base) - len(suffix) >= 3:
                base = base[: -len(suffix)]
                break
        else:
            break
    return {key for key in keys if len(key) >= 3}


def match_package_to_kev(package: str, entries: list) -> list:
    """طابق اسم الحزمة مع منتج KEV بالمساواة فقط، بلا احتواء نصي."""
    keys = package_match_keys(package)
    hits = []
    for entry in entries or []:
        if not isinstance(entry, dict) or "error" in entry:
            continue
        product = (entry.get("product") or "").lower().replace("_", "-").replace(" ", "-")
        while "--" in product:
            product = product.replace("--", "-")
        product = product.strip("-")
        if product in keys:
            hits.append(entry)
    return hits


def _version_tuple(value: str) -> tuple:
    # تجاهل epoch الديبيان (الرقم قبل :) حتى لا تُقارن 1:9.6 مع 8.5 خطأً
    if value and ":" in value:
        value = value.split(":", 1)[1]
    numbers = re.findall(r"\d+", value or "")
    return tuple(int(number) for number in numbers[:6]) or (0,)


def _version_affected(installed: str, cpe: dict) -> bool:
    """تحقق من وقوع الإصدار المثبت داخل حدود CPE. بلا حدود رقمية لا تُعد مطابقة إصدار."""
    if not installed:
        return False
    current = _version_tuple(installed)
    start_incl = cpe.get("start_incl")
    start_excl = cpe.get("start_excl")
    end_incl = cpe.get("end_incl")
    end_excl = cpe.get("end_excl")
    if any((start_incl, start_excl, end_incl, end_excl)):
        if start_incl and current < _version_tuple(start_incl):
            return False
        if start_excl and current <= _version_tuple(start_excl):
            return False
        if end_incl and current > _version_tuple(end_incl):
            return False
        if end_excl and current >= _version_tuple(end_excl):
            return False
        return True
    pinned = (cpe.get("version") or "").lower()
    if pinned in ("", "*", "-"):
        return False
    return current == _version_tuple(pinned)


def match_package_to_nvd(package: str, version: str, records: list) -> list:
    """أبقِ سجلات NVD التي يطابق منتج CPE فيها الحزمة. الحالة version أو name."""
    keys = package_match_keys(package)
    matched = []
    for record in records or []:
        if not isinstance(record, dict) or "error" in record:
            continue
        status = ""
        for cpe in record.get("cpe") or []:
            product = (cpe.get("product") or "").lower().replace("_", "-")
            if product not in keys:
                continue
            status = "version" if _version_affected(version, cpe) else (status or "name")
            if status == "version":
                break
        if status:
            matched.append({**record, "match": status})
    matched.sort(key=lambda item: item.get("match") != "version")
    return matched


def _cpe_from_cve(cve: dict) -> list:
    found = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if match.get("vulnerable") is False:
                    continue
                parts = (match.get("criteria") or "").split(":")
                if len(parts) < 6:
                    continue
                found.append({
                    "vendor": parts[3],
                    "product": parts[4],
                    "version": parts[5],
                    "start_incl": match.get("versionStartIncluding"),
                    "start_excl": match.get("versionStartExcluding"),
                    "end_incl": match.get("versionEndIncluding"),
                    "end_excl": match.get("versionEndExcluding"),
                })
    return found
