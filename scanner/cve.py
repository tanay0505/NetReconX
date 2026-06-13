import re
import time
import logging
import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD public rate limit: 5 requests per 30 seconds (no API key)
RATE_LIMIT_DELAY = 6.5

_cve_cache = {}
_last_request_time = 0.0


# ---------------------------------------------------------------------------
# Banner parsing -> (product, version)
# ---------------------------------------------------------------------------

# Each pattern: (regex, group_for_product, group_for_version)
BANNER_PATTERNS = [
    # HTTP "Server: Apache/2.4.49" or "Server: nginx/1.18.0"
    re.compile(r"Server:\s*([A-Za-z][\w\-]*)/?([\d][\d\.]*)?", re.IGNORECASE),

    # FTP "220 (vsFTPd 3.0.3)" / "220 ProFTPD 1.3.5 Server"
    re.compile(r"\b(vsftpd|proftpd|pure-ftpd|filezilla)\b\)?\s*([\d][\d\.]*)?", re.IGNORECASE),

    # SSH "SSH-2.0-OpenSSH_7.4"
    re.compile(r"SSH-[\d.]+-([A-Za-z]+)[_\-]([\d][\w.]*)", re.IGNORECASE),

    # SMTP "220 mail.example.com ESMTP Postfix" / "Microsoft ESMTP MAIL Service"
    re.compile(r"\b(Postfix|Exim|Sendmail|Microsoft ESMTP)\b\s*([\d][\d\.]*)?", re.IGNORECASE),
]


def extract_product_version(banner: str):
    """
    Try to extract a (product, version) tuple from a banner string.
    Returns None if nothing useful was found.
    """
    if not banner or banner == "N/A":
        return None

    for pattern in BANNER_PATTERNS:
        match = pattern.search(banner)
        if match:
            product = match.group(1)
            version = match.group(2) if match.lastindex and match.lastindex >= 2 else None

            if not product:
                continue

            version = version.strip() if version else None
            if version:
                # Strip trailing non-numeric patch suffixes (e.g. "6.6.1p1" -> "6.6.1")
                numeric_match = re.match(r"[\d.]+", version)
                if numeric_match:
                    version = numeric_match.group(0).rstrip(".")
                else:
                    version = None

            return product.strip(), version

    return None


# ---------------------------------------------------------------------------
# NVD API lookup
# ---------------------------------------------------------------------------

def _query_nvd(query: str, max_results: int) -> list:
    """Run a single rate-limited NVD query and return parsed CVE list."""
    global _last_request_time

    elapsed = time.time() - _last_request_time
    if elapsed < RATE_LIMIT_DELAY:
        time.sleep(RATE_LIMIT_DELAY - elapsed)

    try:
        params = {
            "keywordSearch": query,
            "resultsPerPage": max_results,
        }
        resp = requests.get(NVD_API_URL, params=params, timeout=15)
        _last_request_time = time.time()

        if resp.status_code != 200:
            logging.warning(f"NVD API returned {resp.status_code} for query '{query}'")
            return []

        data = resp.json()
        cves = []

        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id")

            description = "N/A"
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "N/A")
                    break

            severity = "N/A"
            score = None
            metrics = cve_data.get("metrics", {})
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metric_key in metrics and metrics[metric_key]:
                    cvss = metrics[metric_key][0].get("cvssData", {})
                    score = cvss.get("baseScore")
                    severity = cvss.get("baseSeverity") or metrics[metric_key][0].get("baseSeverity", "N/A")
                    break

            if len(description) > 200:
                description = description[:200] + "..."

            cves.append({
                "id": cve_id,
                "severity": severity,
                "score": score,
                "description": description,
            })

        return cves

    except Exception as e:
        logging.error(f"CVE lookup failed for '{query}': {e}")
        return []


def lookup_cves(product: str, version: str = None, max_results: int = 5) -> list:
    """
    Query the NVD CVE 2.0 API for known vulnerabilities matching
    the given product (and optionally version).

    Tries the full version first (e.g. "openssh 6.6.1"). If that
    returns nothing and the version has multiple segments, falls
    back to a "major.minor" search (e.g. "openssh 6.6"), since CVE
    descriptions rarely contain exact patch-level versions.

    Results are cached in-memory and rate-limited to respect
    NVD's public limit of 5 requests / 30 seconds.
    """
    if not product:
        return []

    queries_to_try = []

    if version:
        queries_to_try.append(f"{product} {version}")

        parts = version.split(".")
        if len(parts) > 2:
            major_minor = ".".join(parts[:2])
            queries_to_try.append(f"{product} {major_minor}")
    else:
        queries_to_try.append(product)

    for query in queries_to_try:
        cache_key = query.lower()

        if cache_key in _cve_cache:
            if _cve_cache[cache_key]:
                return _cve_cache[cache_key]
            continue

        cves = _query_nvd(query, max_results)
        _cve_cache[cache_key] = cves

        if cves:
            return cves

    # Nothing found with any variant
    return []
