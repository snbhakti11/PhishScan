# threat_intel.py
# Integrates with threat intelligence sources
"""
threat_intel.py

Threat intelligence feed module for phishing detection using PhishTank.

Uses:
    - PhishTank online-valid JSON feed
    - Local cache to avoid repeated downloads

Public functions:
    - update_phishtank_feed() → fetch & cache feed
    - check_threat_feeds(url: str) → returns dict whether URL is found in feed

Requirements:
    pip install requests
"""

import os
import json
import requests
from urllib.parse import urlparse

# Configuration
FEED_DIR = "feeds"
PHISHTANK_FEED_URL = "http://data.phishtank.com/data/online-valid.json"
CACHE_FILE = os.path.join(FEED_DIR, "phishtank_online_valid.json")
CACHE_TTL_SECONDS = 24 * 3600  # refresh daily

def _ensure_feed_dir():
    if not os.path.isdir(FEED_DIR):
        os.makedirs(FEED_DIR)

def update_phishtank_feed():
    """
    Download the PhishTank online-valid JSON feed and save to local cache.
    Only downloads if cache is older than CACHE_TTL_SECONDS or missing.
    """
    _ensure_feed_dir()
    do_download = False

    if not os.path.exists(CACHE_FILE):
        do_download = True
    else:
        # check file modified time
        mtime = os.path.getmtime(CACHE_FILE)
        import time
        if (time.time() - mtime) > CACHE_TTL_SECONDS:
            do_download = True

    if do_download:
        try:
            print(f"Downloading PhishTank feed from {PHISHTANK_FEED_URL} ...")
            resp = requests.get(PHISHTANK_FEED_URL, timeout=30)
            resp.raise_for_status()
            data = resp.text
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                f.write(data)
            print("PhishTank feed updated.")
        except Exception as e:
            print(f"Error downloading PhishTank feed: {e}")

def _load_phishtank_feed():
    """
    Load cached PhishTank feed JSON. Returns list of entries or None.
    Each entry is a dict (according to PhishTank schema).
    """
    if not os.path.exists(CACHE_FILE):
        return None
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            entries = json.load(f)
        return entries
    except Exception as e:
        print(f"Error loading PhishTank feed cache: {e}")
        return None

def normalize_url(url: str) -> str:
    """
    Normalize URL for comparison: lowercase, strip trailing slash, remove fragments.
    """
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower() if parsed.scheme else "http"
    netloc = parsed.netloc.lower()
    path = parsed.path
    if path.endswith('/'):
        path = path.rstrip('/')
    # ignore query params and fragments for basic lookup, or include if needed
    # Here, include path and optionally query; skip fragment
    query = parsed.query
    normalized = f"{scheme}://{netloc}{path}"
    if query:
        normalized = normalized + "?" + query
    return normalized

def check_threat_feeds(url: str) -> dict:
    """
    Check if the given URL is present in the PhishTank feed.

    Returns:
        {
            "url": "<input URL>",
            "normalized_url": "<normalized form>",
            "found": True/False,
            "feed": "PhishTank" or None,
            "entry": <feed entry dict> or None
        }
    """
    update_phishtank_feed()
    entries = _load_phishtank_feed()
    if entries is None:
        return {
            "url": url,
            "normalized_url": normalize_url(url),
            "found": False,
            "feed": None,
            "entry": None,
            "explanation": "Feed not available"
        }

    norm = normalize_url(url)

    # PhishTank's JSON schema: each entry has "url" field among others
    # Sometimes, entries have normalized and unnormalized forms
    for entry in entries:
        try:
            feed_url = entry.get("url", "")
            if not feed_url:
                continue
            feed_norm = normalize_url(feed_url)
            if norm == feed_norm:
                return {
                    "url": url,
                    "normalized_url": norm,
                    "found": True,
                    "feed": "PhishTank",
                    "entry": entry,
                    "explanation": "URL found in PhishTank online-valid feed"
                }
        except Exception:
            continue

    return {
        "url": url,
        "normalized_url": norm,
        "found": False,
        "feed": None,
        "entry": None,
        "explanation": "URL not found in PhishTank feed"
    }

# Simple test harness
if __name__ == "__main__":
    test_urls = [
        "http://example.com",
        "https://www.paypal.com/login",   # likely not in feed
        # you may include a known phishing URL if you have one
    ]

    for u in test_urls:
        res = check_threat_feeds(u)
        print("-" * 80)
        print("URL:", u)
        print("Normalized:", res["normalized_url"])
        print("Found:", res["found"])
        print("Feed:", res["feed"])
        print("Explanation:", res["explanation"])
        if res["entry"]:
            print("Entry fields:", {k: res["entry"].get(k) for k in ("url", "verified","phish_id")})
        print()
