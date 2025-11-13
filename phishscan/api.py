
"""Main Flask API for PhishScan.

Run: python api.py
"""

import os
import logging
from flask import Flask, request, jsonify, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis as redis_lib
from urllib.parse import urlparse

from scanner import scan_url  # uses heuristics, ssl_check, threat_intel
from html_scanner import scan_url_html
from feed_updater import ensure_feed_dir
from db import init_db, save_scan, list_scans, get_scan
from extract_features import extract_features
from ml_model import predict_phishing_prob

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api")

# Flask app
app = Flask(__name__)

# Production defaults tuned from grid search results
# These can be overridden via environment variables in deployment
DEFAULT_WEIGHT_ML = float(os.getenv('PHISHSCAN_WEIGHT_ML', '0.8'))
DEFAULT_WEIGHT_H = float(os.getenv('PHISHSCAN_WEIGHT_HEURISTIC', '0.2'))

# Runtime-configurable threshold (default from env, can be updated via API)
PHISHSCAN_THRESHOLD = float(os.getenv('PHISHSCAN_THRESHOLD', '0.45'))

# Rate limiter: prefer Redis storage in production when REDIS_URL is set
REDIS_URL = os.getenv("REDIS_URL")
if REDIS_URL:
    try:
        redis_client = redis_lib.from_url(REDIS_URL)
        limiter = Limiter(app=app, key_func=get_remote_address,
                          default_limits=["60 per minute"], storage_uri=REDIS_URL)
        logger.info("Using Redis at %s for rate limiting", REDIS_URL)
    except Exception:
        logger.exception("Failed to connect to Redis, falling back to in-memory limiter")
        limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["60 per minute"])
else:
    limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["60 per minute"])

# API key
API_KEY = os.getenv("PHISHSCAN_API_KEY", None)
if API_KEY:
    logger.info("API key enabled")

# Initialize DB and feeds folder
init_db()
ensure_feed_dir()


def require_api_key() -> None:
    if not API_KEY:
        return
    key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if not key or key != API_KEY:
        abort(401, description="Invalid or missing API key")


def normalize_for_storage(url: str) -> str:
    parsed = urlparse(url if "://" in url else "http://" + url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{netloc}{path}{query}"


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0"})


@app.route("/scan", methods=["POST"])
@limiter.limit("30 per minute")
def scan():
    require_api_key()
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "missing 'url' in JSON body"}), 400

    url = data["url"].strip()
    if not url:
        return jsonify({"error": "empty url"}), 400

    try:
        result = scan_url(url)
    except Exception as e:
        logger.exception("Scanner failed: %s", e)
        return jsonify({"error": "scanner_failed", "detail": str(e)}), 500

    try:
        html_result = scan_url_html(url)
        result["html_scan"] = html_result
    except Exception:
        result["html_scan"] = {"error": "html_scan_failed"}

    score = None
    verdict = None
    if isinstance(result.get("heuristics"), dict):
        score = result["heuristics"].get("score")
        verdict = result["heuristics"].get("final_verdict")
    score = score or result.get("score") or 0
    verdict = verdict or result.get("final_verdict") or "Unknown"

    normalized = normalize_for_storage(url)
    scan_id = save_scan(url, normalized, verdict, int(score or 0), result)

    return jsonify({
        "scan_id": scan_id,
        "url": url,
        "normalized_url": normalized,
        "verdict": verdict,
        "score": score,
        "result": result
    }), 200


@app.route("/history", methods=["GET"])
@limiter.limit("20 per minute")
def history():
    require_api_key()
    try:
        limit = int(request.args.get("limit", 50))
        page = int(request.args.get("page", 0))
    except ValueError:
        return jsonify({"error": "limit/page must be integer"}), 400
    limit = min(200, max(1, limit))
    offset = page * limit
    rows = list_scans(limit=limit, offset=offset)
    return jsonify({"count": len(rows), "rows": rows})


@app.route("/history/<int:scan_id>", methods=["GET"])
@limiter.limit("20 per minute")
def get_history_item(scan_id: int):
    require_api_key()
    item = get_scan(scan_id)
    if not item:
        return jsonify({"error": "not_found"}), 404
    return jsonify(item)


@app.route("/predict", methods=["POST"])
@limiter.limit("20 per minute")
def predict():
    require_api_key()
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "missing 'url' in JSON body"}), 400
    url = data["url"].strip()
    if not url:
        return jsonify({"error": "empty url"}), 400

    try:
        features = extract_features(url)
    except Exception as e:
        logger.exception("Feature extraction failed: %s", e)
        return jsonify({"error": "feature_extraction_failed", "detail": str(e)}), 500

    try:
        prob = predict_phishing_prob(features)
    except Exception as e:
        logger.exception("Model prediction failed: %s", e)
        return jsonify({"error": "model_prediction_failed", "detail": str(e)}), 500

    # Multi-layer aggregation: combine ML probability with heuristic score
    # Heuristic info is available via scanner.scan_url (fast, heuristics-only)
    heuristic_score = None
    heuristic_verdict = None
    try:
        # call scan_url but prefer heuristics-only behavior if implemented
        scan_result = scan_url(url)
        if isinstance(scan_result.get('heuristics'), dict):
            heuristic = scan_result['heuristics']
            heuristic_score = heuristic.get('score') if heuristic.get('score') is not None else None
            heuristic_verdict = heuristic.get('final_verdict')
        else:
            heuristic_score = scan_result.get('score')
            heuristic_verdict = scan_result.get('final_verdict')
    except Exception:
        # heuristics are optional for prediction; continue without them
        heuristic_score = None
        heuristic_verdict = None

    # normalize heuristic_score to [0,1] if present (assume heuristics use 0-100 scale)
    h_norm = None
    if heuristic_score is not None:
        try:
            hs = float(heuristic_score)
            # if score looks like 0..100 scale, clamp
            if hs > 1.0:
                h_norm = max(0.0, min(1.0, hs / 100.0))
            else:
                h_norm = max(0.0, min(1.0, hs))
        except Exception:
            h_norm = None

    # combine probabilities using configurable weights
    try:
        w_ml = float(os.getenv('PHISHSCAN_WEIGHT_ML', str(DEFAULT_WEIGHT_ML)))
        w_h = float(os.getenv('PHISHSCAN_WEIGHT_HEURISTIC', str(DEFAULT_WEIGHT_H)))
    except Exception:
        w_ml, w_h = DEFAULT_WEIGHT_ML, DEFAULT_WEIGHT_H

    combined = None
    if h_norm is not None:
        combined = float(max(0.0, min(1.0, w_ml * float(prob) + w_h * float(h_norm))))
    else:
        combined = float(prob)

    # final verdict threshold (configurable runtime variable)
    threshold = PHISHSCAN_THRESHOLD
    final_verdict = 'phishing' if combined >= threshold else 'legitimate'

    # do not reassign module-level PHISHSCAN_THRESHOLD here (avoids UnboundLocalError)

    return jsonify({
        "url": url,
        "ml_probability": prob,
        "heuristic_score": heuristic_score,
        "heuristic_score_normalized": h_norm,
        "heuristic_verdict": heuristic_verdict,
        "combined_probability": combined,
        "final_verdict": final_verdict,
        "features": features
    }), 200


@app.route('/config/threshold', methods=['GET', 'POST'])
def config_threshold():
    """GET returns current threshold; POST with JSON {"threshold": 0.6} updates it."""
    global PHISHSCAN_THRESHOLD
    if request.method == 'GET':
        return jsonify({'threshold': PHISHSCAN_THRESHOLD}), 200
    data = request.get_json(silent=True)
    if not data or 'threshold' not in data:
        return jsonify({'error': "missing 'threshold' in JSON body"}), 400
    try:
        t = float(data['threshold'])
        if not (0.0 <= t <= 1.0):
            raise ValueError('threshold must be 0..1')
    except Exception as e:
        return jsonify({'error': 'invalid threshold', 'detail': str(e)}), 400
    PHISHSCAN_THRESHOLD = t
    return jsonify({'threshold': PHISHSCAN_THRESHOLD}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5050)), debug=False)
