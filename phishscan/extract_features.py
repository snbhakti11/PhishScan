# extract_features.py
"""
Extracts ML-friendly features from:
- URL lexical characteristics
- Domain & SSL properties
- HTML scanner output
"""

import math
import re
from urllib.parse import urlparse
from app.heuristics import analyze_url
from app.ssl_check import check_ssl
from html_scanner import scan_url_html


def shannon_entropy(data: str) -> float:
    """Calculate entropy for URL randomness detection."""
    if not data:
        return 0.0
    probabilities = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum(p * math.log(p, 2) for p in probabilities)


def extract_lexical_features(url: str) -> dict:
    parsed = urlparse(url if "://" in url else "http://" + url)
    url_str = url.lower()

    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_slashes": url.count("/"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": sum(not c.isalnum() for c in url),
        "has_ip": 1 if re.match(r".*://\d+\.\d+\.\d+\.\d+", url) else 0,
        "entropy": shannon_entropy(url),
        "keyword_login": 1 if "login" in url_str else 0,
        "keyword_verify": 1 if "verify" in url_str else 0,
        "keyword_secure": 1 if "secure" in url_str else 0,
    }


def extract_ssl_features(url: str) -> dict:
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc.split(":")[0]

    ssl_info = check_ssl(domain) or {}

    ssl_block = ssl_info.get("ssl") or {}
    expiry_days = ssl_block.get("expiry_days", -1)
    expired = 1 if ssl_block.get("expired") else 0
    self_signed = 1 if ssl_block.get("self_signed") else 0
    cn_mismatch = 1 if ssl_block.get("cn_mismatch") else 0
    domain_age = ssl_info.get("domain_age_days") or -1

    return {
        "ssl_expiry_days": expiry_days,
        "ssl_expired": expired,
        "ssl_self_signed": self_signed,
        "ssl_cn_mismatch": cn_mismatch,
        "domain_age_days": domain_age,
    }


def extract_html_features(url: str) -> dict:
    html = scan_url_html(url)

    if not html["fetched"]:
        return {
            "form_count": 0,
            "login_form_present": 0,
            "hidden_input_count": 0,
            "script_count": 0,
            "external_form_action": 0,
        }

    forms = html.get("forms", [])
    login_forms = html.get("login_forms", [])
    form_count = len(forms)
    login_present = 1 if login_forms else 0

    hidden_count = 0
    external_action = 0
    for f in forms:
        hidden_count += len(f.get("hidden_inputs", []))
        if f.get("suspicious"):
            external_action = 1

    scripts = html.get("script_count", len(forms))

    return {
        "form_count": form_count,
        "login_form_present": login_present,
        "hidden_input_count": hidden_count,
        "script_count": scripts,
        "external_form_action": external_action,
    }


def extract_features(url: str) -> dict:
    """
    Main ML feature extraction pipeline.
    Produces a single dict of numeric-only features.
    """
    features = {}

    # 1. URL lexical
    features.update(extract_lexical_features(url))

    # 2. SSL/domain
    features.update(extract_ssl_features(url))

    # 3. HTML scanner
    features.update(extract_html_features(url))

    return features


if __name__ == "__main__":
    test = extract_features("http://example.com/login")
    print(test)
