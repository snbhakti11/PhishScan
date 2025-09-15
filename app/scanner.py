"""
scanner.py
Main orchestration of phishing detection pipeline.
"""

from urllib.parse import urlparse
from heuristics import analyze_url
from ssl_check import check_ssl
from threat_intel import check_threat_feeds


def scan_url(url: str) -> dict:
    """
    Run all checks (heuristics, SSL, threat intel) on a given URL.
    """
    result = {"url": url}

    # 1. Heuristic analysis
    result["heuristics"] = analyze_url(url)

    # 2. SSL/TLS certificate check
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.split(":", 1)[0]  # remove port if any
        result["ssl"] = check_ssl(domain)
    except Exception as e:
        result["ssl"] = {"error": str(e)}

    # 3. Threat intelligence feeds
    result["threat_feed"] = check_threat_feeds(url)

    return result


# CLI testing
if __name__ == "__main__":
    test_urls = [
        "http://example.com",
        "https://www.google.com",
    ]
    for u in test_urls:
        print("=" * 80)
        res = scan_url(u)
        print(res)
