"""Minimal threat intelligence helper used by scanner.
This simple implementation returns 'found': False. The real version should
load `feeds/index.json` and check for matches.
"""

from typing import Dict


def check_threat_feeds(url: str) -> Dict:
    return {"found": False, "feed": None}

