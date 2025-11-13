"""
ML-enabled scanner module.
"""

from urllib.parse import urlparse
from .heuristics import analyze_url
from .ssl_check import check_ssl
from .threat_intel import check_threat_feeds
import html_scanner
from extract_features import extract_features
from ml_model import predict_phishing_prob


def scan_url(url: str) -> dict:
	result = {"url": url}

	# Normalize URL
	parsed = urlparse(url if url.startswith("http") else "http://" + url)
	domain = parsed.netloc.split(":")[0]

	# -------------------------------------
	# 1. HEURISTICS
	# -------------------------------------
	heur = analyze_url(url) or {}
	# Ensure heuristics always provide a numeric score in 0..100
	heuristic_score_raw = heur.get("score", 0)
	try:
		hs = float(heuristic_score_raw)
	except Exception:
		hs = 0.0
	# if heuristics already on 0..1 scale, rescale to 0..100
	if hs <= 1.0:
		hs = max(0.0, min(1.0, hs)) * 100.0
	else:
		hs = max(0.0, min(100.0, hs))
	# store normalized 0..100 integer score back into heur
	heur['score'] = int(round(hs))
	heuristic_score = heur['score']
	# Provide a consistent final_verdict from heuristics alone
	if heur.get('final_verdict'):
		heur_final = heur.get('final_verdict')
	else:
		heur_final = 'phishing' if heuristic_score >= 60 else 'legitimate'
	heur['final_verdict'] = heur_final

	# -------------------------------------
	# 2. SSL / DOMAIN
	# -------------------------------------
	ssl_result = check_ssl(domain)
	ssl_risk = ssl_result.get("risk_score", 0)

	# -------------------------------------
	# 3. THREAT FEED
	# -------------------------------------
	feed_result = check_threat_feeds(url)
	feed_hit = 1 if feed_result.get("found") else 0

	# -------------------------------------
	# 4. HTML SCANNER
	# -------------------------------------
	html_result = html_scanner.scan_url_html(url)
	html_risk = 1 if html_result.get("login_form_present") or html_result.get("login_forms") else 0

	# -------------------------------------
	# 5. ML FEATURE EXTRACTION
	# -------------------------------------
	features = extract_features(url)
	ml_prob = predict_phishing_prob(features)

	# -------------------------------------
	# 6. Weighted Score Combination
	# -------------------------------------
	# Normalize heuristic score to 0..1 for combination
	h_norm = float(heuristic_score) / 100.0
	final_risk = (
		0.30 * h_norm +
		0.15 * float(ssl_risk) +
		0.15 * float(html_risk) +
		0.20 * float(ml_prob) +
		0.20 * float(feed_hit)
	)

	verdict = "phishing" if final_risk >= 0.6 else "legitimate"

	# -------------------------------------
	# Package results
	# -------------------------------------
	result.update({
		"heuristics": heur,
		"ssl": ssl_result,
		"threat_feed": feed_result,
		"html_scan": html_result,
		"ml_probability": ml_prob,
		"final_risk_score": round(final_risk, 3),
		# Expose combined_probability to match /predict's combined field and
		# allow frontends to consistently read the multi-factor score.
		"combined_probability": round(final_risk, 3),
		"final_verdict": verdict,
		"features_used": features,
	})

	return result

