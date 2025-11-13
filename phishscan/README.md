````markdown
# PhishScan: Heuristic, Threat-Intel & ML Enhanced Phishing Detector

PhishScan is a lightweight, explainable phishing URL scanner. It combines
heuristic rules, SSL/TLS checks, threat-intelligence feeds (PhishTank &
OpenPhish), HTML analysis, and an optional ML Random Forest model into a
single REST API service.

## 🚀 Features

- Heuristic URL analysis (length, symbols, IP-in-URL, keywords)
- SSL certificate inspection (expiry, issuer, CN mismatch)
# PhishScan — Explained simply

PhishScan is a phishing URL scanner that combines simple rules, internet
threat feeds, page analysis and a machine learning model. The goal is a
practical, explainable score for whether a URL is likely phishing.

Run the code from the `phishscan/` folder. The API runs on port 5050 by
default and provides `/scan` (full analysis) and `/predict` (ML-only).

Contents (short):

- `extract_features.py` — build numeric features from a URL + page
- `html_scanner.py` — analyze page HTML (forms, hidden inputs, scripts)
- `train_model.py` — train RandomForest and save a `.pkl` model
- `ml_model.py` — load model and predict phishing probability
- `api.py` — Flask API exposing `/scan` and `/predict`

Quick start

```bash
cd phishscan
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 api.py
```

Simple demo (single URL):

```bash
curl -X POST http://127.0.0.1:5050/predict -H "Content-Type: application/json" -d '{"url":"http://example.com"}'
```

Process / Methodology (simple words)
- Data collection: collect URLs labeled phishing vs legitimate to train the model.
- Feature extraction: for each URL we compute simple numeric features (URL
	length, number of dots/slashes, presence of login keywords, page entropy,
	SSL flags, presence of login forms, etc.). These are human-readable.
- Heuristics: apply rule-based checks (e.g., IP in URL, suspicious keywords,
	short-lived SSL) to get quick signals.
- Model training: the numeric features feed a RandomForest classifier trained
	on labeled examples. Training saves the model and its feature order.
- Runtime inference: when a URL is scanned we extract the same features,
	call the ML model for a probability, normalize heuristic signals, and
	combine them (weighted) into a final score.

Why this approach?
- Simple features and heuristics are explainable and cheap to compute.
- ML captures combinations of signals that heuristics miss.
- Combining both gives more robust, interpretable predictions.

Smoke tests and saved outputs

- `smoke_100_results.json` — reference run (older)
- `tools/smoke_100_live.json` — latest live-run outputs (keep this file for
	debugging and reporting)
- `tools/verify_smoke_results.py` — recompute stats from saved results

Recommendations

- Keep model feature ordering consistent between training and runtime.
- Add a startup check that verifies loaded model's feature names match the
	extractor's expected list — fail-fast on mismatch.
- Add a CI smoke test that runs a few sample predictions after builds.

License / Disclaimer

For research and educational use only. Not a replacement for production
phishing defenses.


	```bash
	curl -X POST http://127.0.0.1:5050/scan -H "Content-Type: application/json" -d '{"url":"http://example.com"}'

	curl -X POST http://127.0.0.1:5050/predict -H "Content-Type: application/json" -d '{"url":"http://example.com/login"}'
	```

	## Recommendations / next steps

	- Add startup validation to compare `model.feature_names_in_` vs the extractor
		feature list and fail-fast on mismatch.
	- Add a CI smoke test that loads the runtime model and runs sample predictions
		to detect regressions early.

	## License / Disclaimer

	For research and educational use only. Not a replacement for commercial
	phishing defenses.

