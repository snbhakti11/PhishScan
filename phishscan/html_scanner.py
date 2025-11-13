# html_scanner.py
"""
HTML scanner: fetch page HTML (safe defaults) and look for login/credential forms.

Primary function:
    scan_url_html(url: str) -> dict
"""

from typing import Dict, List, Any
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("html_scanner")

# Safety/config
REQUEST_TIMEOUT = 8  # seconds
MAX_BYTES = 1024 * 1024  # 1 MB


def safe_fetch(url: str) -> Dict[str, Any]:
    """
    Fetch page safely with timeouts and size limit.
    Returns dict: {fetched: bool, status: int, text: str or None, error: str or None}
    """
    headers = {"User-Agent": "PhishScan/1.0 (+https://example.com)"}
    try:
        with requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, stream=True) as r:
            size = 0
            chunks = []
            for chunk in r.iter_content(1024):
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_BYTES:
                    # stop reading large responses
                    try:
                        r.close()
                    except Exception:
                        pass
                    return {"fetched": False, "status": r.status_code, "text": None, "error": "response-too-large"}
            text = b"".join(chunks).decode(errors="replace")
            return {"fetched": True, "status": r.status_code, "text": text, "error": None}
    except Exception as e:
        logger.debug("safe_fetch error: %s", e)
        return {"fetched": False, "status": None, "text": None, "error": str(e)}


def analyze_forms(soup: BeautifulSoup, base_url: str) -> Dict[str, Any]:
    forms = soup.find_all("form")
    results: List[Dict[str, Any]] = []
    login_forms = []
    for form in forms:
        action = form.get("action") or ""
        method = (form.get("method") or "GET").upper()
        action_full = urljoin(base_url, action)
        inputs = form.find_all("input")
        types = [inp.get("type", "").lower() for inp in inputs]
        names = [inp.get("name", "") or "" for inp in inputs]
        hidden_inputs = [n for inp, n in zip(inputs, names) if (inp.get("type", "").lower() == "hidden")]

        has_password = any(t == "password" for t in types)
        suspicious = False
        reasons = []

        # If form posts to a different origin than page base, suspicious
        page_origin = urlparse(base_url).netloc.lower()
        action_origin = urlparse(action_full).netloc.lower()
        if action_origin and action_origin != page_origin:
            suspicious = True
            reasons.append(f"form posts to external origin: {action_origin}")

        # Hidden tokens + password is suspicious
        if has_password and hidden_inputs:
            suspicious = True
            reasons.append("hidden inputs present with password field")

        # weird input names (token-like)
        token_like = [n for n in names if any(x in n.lower() for x in ("token", "auth", "session", "csrf"))]
        if token_like:
            reasons.append(f"token-like input names: {token_like}")

        # large number of scripts may indicate obfuscation
        scripts = len(soup.find_all("script"))
        if scripts > 10:
            reasons.append(f"many scripts ({scripts}) - check for obfuscation")

        form_info = {
            "action": action_full,
            "method": method,
            "has_password": has_password,
            "hidden_inputs": hidden_inputs,
            "input_names": names,
            "suspicious": suspicious,
            "reasons": reasons,
        }
        results.append(form_info)
        if has_password:
            login_forms.append(form_info)

    return {"form_count": len(results), "forms": results, "login_forms": login_forms}


def scan_url_html(url: str) -> Dict[str, Any]:
    """
    Main entry point.
    Returns a dict summarizing findings.
    """
    fetch = safe_fetch(url)
    if not fetch["fetched"] or not fetch["text"]:
        return {"fetched": False, "status": fetch["status"], "error": fetch["error"], "form_count": 0, "login_forms": []}

    soup = BeautifulSoup(fetch["text"], "html.parser")
    analysis = analyze_forms(soup, url)
    explanation = "No login forms detected"
    if analysis["login_forms"]:
        explanation = f"{len(analysis['login_forms'])} login form(s) detected"
    return {
        "fetched": True,
        "status": fetch["status"],
        "explanation": explanation,
        **analysis,
    }


# quick CLI test
if __name__ == "__main__":
    examples = [
        "https://example.com",
        # add test URLs as needed
    ]
    for u in examples:
        print("-" * 80)
        print(u)
        print(scan_url_html(u))
