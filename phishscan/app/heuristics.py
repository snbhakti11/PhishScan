
"""Simple heuristic URL analyzer used by the scanner.

This implementation returns a dict with keys:
- score: int 0..100
- final_verdict: 'phishing' | 'legitimate'
- reasons: list of rule ids that triggered

Weights for individual rules are defined as constants below for easy tuning.
"""

from urllib.parse import urlparse
import re

# Tunable weights (0-100 scale)
WEIGHT_LONG_URL = 15
WEIGHT_WEIRD_CHARS = 10
WEIGHT_IP_IN_DOMAIN = 20
WEIGHT_MANY_SUBDOMAINS = 10
WEIGHT_SUSPICIOUS_KEYWORD = 15


def analyze_url(url: str) -> dict:
	url = (url or "").strip()
	parsed = urlparse(url if "://" in url else "http://" + url)
	host = parsed.netloc.lower()

	score = 0
	reasons = []

	# long URL
	if len(url) > 75:
		score += WEIGHT_LONG_URL
		reasons.append("long_url")

	# many special chars
	special = len(re.findall(r"[^a-zA-Z0-9./:?&=_-]", url))
	if special > 5:
		score += WEIGHT_WEIRD_CHARS
		reasons.append("weird_chars")

	# IP address in host
	if re.match(r"^\d+\.\d+\.\d+\.\d+$", host.split(":")[0]):
		score += WEIGHT_IP_IN_DOMAIN
		reasons.append("ip_in_domain")

	# many subdomains
	if host.count(".") >= 3:
		score += WEIGHT_MANY_SUBDOMAINS
		reasons.append("many_subdomains")

	# suspicious keywords
	keywords = ("login", "secure", "account", "update", "verify", "bank")
	if any(k in url.lower() for k in keywords):
		score += WEIGHT_SUSPICIOUS_KEYWORD
		reasons.append("suspicious_keyword")

	score = int(max(0, min(100, round(score))))

	# normalized verdict labels
	final_verdict = 'phishing' if score >= 50 else 'legitimate'

	return {"score": score, "final_verdict": final_verdict, "reasons": reasons}

