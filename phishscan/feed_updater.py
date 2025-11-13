# feed_updater.py
"""
Feed updater: downloads PhishTank and OpenPhish, normalizes and builds an index
for fast lookup by threat_intel.check_threat_feeds().

Run:
    python feed_updater.py
"""

import os
import json
import time
import logging
from urllib.parse import urlparse

import requests

# Config
FEED_DIR = "feeds"
PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.json"
# feed_updater.py
"""
Feed updater: downloads PhishTank and OpenPhish, normalizes and builds an index
for fast lookup by threat_intel.check_threat_feeds().

Run:
    python feed_updater.py
"""

import os
import json
import time
import logging
from urllib.parse import urlparse

import requests

# Config
FEED_DIR = "feeds"
PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.json"
OPENPHISH_URL = "https://openphish.com/feed.txt"
INDEX_FILE = os.path.join(FEED_DIR, "index.json")
CACHE_TTL = 24 * 3600  # seconds

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("feed_updater")


def ensure_feed_dir() -> None:
    os.makedirs(FEED_DIR, exist_ok=True)


def normalize_url(url: str) -> str:
    try:
        url = url.strip()
        parsed = urlparse(url if "://" in url else "http://" + url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/")
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        return url.lower()


def download_phishtank() -> list:
    logger.info("Downloading PhishTank feed...")
    resp = requests.get(PHISHTANK_URL, timeout=30)
    resp.raise_for_status()
    entries = resp.json()
    # phishtank returns list or dict; ensure list
    if isinstance(entries, dict):
        # sometimes phishtank returns an object with key 'data' or similar
        # we'll try to find list inside
        for v in entries.values():
            if isinstance(v, list):
                entries = v
                break
        else:
            entries = []
    logger.info("PhishTank entries: %d", len(entries))
    return entries


def download_openphish() -> list:
    logger.info("Downloading OpenPhish feed...")
    resp = requests.get(OPENPHISH_URL, timeout=30)
    resp.raise_for_status()
    lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
    logger.info("OpenPhish entries: %d", len(lines))
    return lines


def build_index(phishtank_entries: list, openphish_lines: list) -> dict:
    index = {}
    # PhishTank: entries are dicts with "url" and meta fields
    for e in phishtank_entries:
        url = e.get("url") or e.get("phish_url") or ""
        if not url:
            continue
        norm = normalize_url(url)
        index[norm] = {"feed": "PhishTank", "entry": e}

    # OpenPhish: each line is a URL
    for url in openphish_lines:
        norm = normalize_url(url)
        # if already present, keep PhishTank as higher priority (no overwrite)
        if norm not in index:
            index[norm] = {"feed": "OpenPhish", "entry": {"url": url}}

    return index


def save_index(index: dict) -> None:
    with open(INDEX_FILE, "w", encoding="utf-8") as fh:
        json.dump({"updated_at": int(time.time()), "index": index}, fh)
    logger.info("Saved index to %s (entries=%d)", INDEX_FILE, len(index))


def load_index() -> dict:
    if not os.path.exists(INDEX_FILE):
        return {}
    try:
        with open(INDEX_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data.get("index", {})
    except Exception:
        return {}


def main():
    ensure_feed_dir()

    try:
        phishtank_entries = download_phishtank()
    except Exception as e:
        logger.exception("Failed to download PhishTank: %s", e)
        phishtank_entries = []

    try:
        openphish_entries = download_openphish()
    except Exception as e:
        logger.exception("Failed to download OpenPhish: %s", e)
        openphish_entries = []

    index = build_index(phishtank_entries, openphish_entries)
    save_index(index)
    logger.info("Feed update complete. total=%d", len(index))


if __name__ == "__main__":
    main()
