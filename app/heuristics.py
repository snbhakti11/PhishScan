"""
heuristics.py

Lightweight, explainable URL heuristic engine for phishing detection.

Public function:
    analyze_url(url: str) -> dict

Example:
    >>> from heuristics import analyze_url
    >>> analyze_url("http://192.168.1.10/login?verify=true")
    { ... }
"""

import re
from urllib.parse import urlparse, unquote

# Configuration: thresholds and keyword list (tweakable)
MAX_LENGTH_SUSPICIOUS = 75
SPECIAL_CHAR_THRESHOLDS = {
    '-': 4,
    '_': 4,
    '@': 1,
    '?': 2,
    '=': 2,
    '%': 2,
}
SUSPICIOUS_SUBDOMAIN_DEPTH = 3  # > 3 => suspicious
SUSPICIOUS_KEYWORDS = {
    'login', 'signin', 'verify', 'update', 'secure', 'account', 'bank',
    'paypal', 'password', 'confirm', 'ebay', 'amazon', 'appleid', 'billing'
}

IP_RE = re.compile(r'^(?:http[s]?://)?\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(/|$)')

def _ensure_scheme(url: str) -> str:
    """Ensure URL has a scheme so urlparse works predictably."""
    if not re.match(r'^[a-zA-Z]+://', url):
        return 'http://' + url
    return url

def _count_special_chars(s: str) -> dict:
    """Count occurrences of particular special characters in the input string."""
    counts = {}
    for ch in SPECIAL_CHAR_THRESHOLDS:
        counts[ch] = s.count(ch)
    return counts

def _is_ip_domain(netloc: str) -> bool:
    """Return True if netloc is an IP address (with optional port)."""
    # strip possible credentials user:pass@
    if '@' in netloc:
        netloc = netloc.split('@', 1)[1]
    # remove port
    host = netloc.split(':', 1)[0]
    # match IPv4
    parts = host.split('.')
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False

def _subdomain_depth(host: str) -> int:
    """Return number of subdomain parts excluding TLD+domain heuristic (approx)."""
    # remove possible trailing dot
    host = host.rstrip('.')
    parts = host.split('.')
    # crude domain detection: treat last 2 parts as domain+TLD (works for most cases)
    return max(0, len(parts) - 2)

def _find_keywords(s: str) -> list:
    """Return suspicious keywords found in the (decoded & lowercased) string."""
    s = unquote(s).lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in s]
    return sorted(found, key=lambda x: s.index(x))  # order by appearance

def analyze_url(url: str) -> dict:
    """
    Analyze URL with heuristic rules and produce an explainable result.

    Returns a dict:
    {
      "url": "<original>",
      "heuristics": {
         "length": { "value": 120, "verdict": "suspicious", "explanation": "URL length > 75" },
         "special_chars": { "counts": {...}, "verdict": "suspicious", "explanation": "too many '-' (6)" },
         "ip_in_domain": { "value": True, "verdict": "suspicious", "explanation": "domain is IP address" },
         "subdomain_depth": { "value": 4, "verdict": "suspicious", "explanation": "4 subdomains (>3)" },
         "keywords": { "found": ["verify","login"], "verdict": "suspicious", ... }
      },
      "score": 70,          # 0-100 numeric score (higher -> more suspicious)
      "final_verdict": "Likely Phishing"
    }
    """
    original_url = url
    url_for_parse = _ensure_scheme(url)
    parsed = urlparse(url_for_parse)

    # Compose a working string to search (host + path + query)
    host = parsed.netloc
    path_and_query = (parsed.path or '') + (('?' + parsed.query) if parsed.query else '')
    full = host + path_and_query

    heur = {}

    # 1) Length-based
    url_length = len(original_url)
    if url_length > MAX_LENGTH_SUSPICIOUS:
        length_verdict = "suspicious"
        length_expl = f"URL length {url_length} > {MAX_LENGTH_SUSPICIOUS}"
    else:
        length_verdict = "safe"
        length_expl = f"URL length {url_length} <= {MAX_LENGTH_SUSPICIOUS}"
    heur['length'] = {
        "value": url_length,
        "verdict": length_verdict,
        "explanation": length_expl
    }

    # 2) Special characters
    special_counts = _count_special_chars(full)
    special_issues = []
    for ch, cnt in special_counts.items():
        threshold = SPECIAL_CHAR_THRESHOLDS.get(ch, 9999)
        if cnt > threshold:
            special_issues.append((ch, cnt, threshold))
    if special_issues:
        sc_verdict = "suspicious"
        issues = ", ".join([f"'{c}'={cnt} (>{th})" for c, cnt, th in special_issues])
        sc_expl = f"Too many special characters: {issues}"
    else:
        sc_verdict = "safe"
        sc_expl = "Special character counts within expected thresholds"
    heur['special_chars'] = {
        "counts": special_counts,
        "verdict": sc_verdict,
        "explanation": sc_expl
    }

    # 3) IP-based domain
    ip_domain = _is_ip_domain(host)
    heur['ip_in_domain'] = {
        "value": ip_domain,
        "verdict": "suspicious" if ip_domain else "safe",
        "explanation": "Domain is an IP address" if ip_domain else "Domain is a hostname"
    }

    # 4) Subdomain depth
    depth = _subdomain_depth(host)
    if depth > SUSPICIOUS_SUBDOMAIN_DEPTH:
        sd_verdict = "suspicious"
        sd_expl = f"{depth} subdomain parts (>{SUSPICIOUS_SUBDOMAIN_DEPTH})"
    else:
        sd_verdict = "safe"
        sd_expl = f"{depth} subdomain parts (<= {SUSPICIOUS_SUBDOMAIN_DEPTH})"
    heur['subdomain_depth'] = {
        "value": depth,
        "verdict": sd_verdict,
        "explanation": sd_expl
    }

    # 5) Keyword check
    keywords_found = _find_keywords(full)
    if keywords_found:
        kw_verdict = "suspicious"
        kw_expl = f"Suspicious keywords found: {', '.join(keywords_found)}"
    else:
        kw_verdict = "safe"
        kw_expl = "No suspicious keywords found"
    heur['keywords'] = {
        "found": keywords_found,
        "verdict": kw_verdict,
        "explanation": kw_expl
    }

    # Scoring: simple weighted sum (tweak weights as needed)
    # Each rule contributes a fixed weight if suspicious.
    # We produce a 0-100 score (higher = more suspicious).
    score = 0
    weights = {
        'length': 20,
        'special_chars': 20,
        'ip_in_domain': 25,
        'subdomain_depth': 15,
        'keywords': 20
    }
    if heur['length']['verdict'] == 'suspicious':
        score += weights['length']
    if heur['special_chars']['verdict'] == 'suspicious':
        score += weights['special_chars']
    if heur['ip_in_domain']['verdict'] == 'suspicious':
        score += weights['ip_in_domain']
    if heur['subdomain_depth']['verdict'] == 'suspicious':
        score += weights['subdomain_depth']
    if heur['keywords']['verdict'] == 'suspicious':
        # increase proportionally by how many keywords found (cap at weight)
        num_kw = len(heur['keywords']['found'])
        # e.g., 1 keyword -> 10, 2+ -> full 20 (this is arbitrary, adjust as needed)
        kw_score = min(weights['keywords'], 10 * num_kw) if num_kw > 0 else 0
        score += kw_score

    # Normalize score to 0-100 (already designed to fit)
    score = max(0, min(100, score))

    # Final verdict thresholds
    if score >= 60:
        final = "Likely Phishing"
    elif score >= 30:
        final = "Suspicious — Review"
    else:
        final = "Likely Safe"

    result = {
        "url": original_url,
        "heuristics": heur,
        "score": score,
        "final_verdict": final
    }
    return result


# Simple CLI / quick tests
if __name__ == "__main__":
    test_urls = [
        "http://example.com",  # safe
        "http://192.168.0.1/login?verify=true",  # ip + keyword
        "https://secure-login.paypal.com.example.evil.com/confirm?user=abc",  # subdomain trick + keyword
        "http://very-long-url-" + "a"*80 + ".com/path",  # very long
        "https://accounts.google.com/signin",  # keyword but legitimate domain
    ]

    for u in test_urls:
        res = analyze_url(u)
        print("="*80)
        print("URL:", u)
        print("Score:", res['score'], "Verdict:", res['final_verdict'])
        for k, v in res['heuristics'].items():
            print(f"- {k}: {v['verdict']} -> {v['explanation']}")
        print()
