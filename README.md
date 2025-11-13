# PhishScan

PhishScan is a lightweight phishing detection and scanning service. It provides a Flask API to scan URLs using heuristics, HTML scanning, SSL checks and an ML model trained to predict phishing probability. The project supports containerized deployment (Docker + docker-compose) and uses Redis for production-ready rate limiting.

## Main features
- REST API with endpoints: `/health`, `/scan`, `/history`, `/predict`.
- Heuristic scanner combining URL heuristics, SSL information, threat intelligence and HTML analysis.
- ML model (RandomForest) for phishing probability predictions.
- Training pipeline with optional randomized hyperparameter search; exports model, feature importances and metadata.
- Redis-backed rate limiting via `flask-limiter` when `REDIS_URL` is configured.
- Simple SQLite storage for scan history and feed updater for threat lists.

## Repository layout
- `api.py` — Flask application exposing the endpoints.
- `extract_features.py` — runtime feature extractor for a single URL (lexical, SSL, HTML features).
- `ml_model.py` — model loader and prediction helper (loads `phishscan_model.pkl`).
- `train_model.py` — training script to build the RandomForest model and export feature importances.
- `build_features.py` — helper to build a dataset by running `extract_features` over a CSV of URLs.
- `phishscan_model.pkl` — trained model artifact (not always present; created by training).
- `phishscan_model.pkl.feature_importances.csv` — CSV that contains training feature order and importances.
- `docker-compose.yml` and `Dockerfile` — containerization for API, feed updater, and Redis.
- `feeds/`, `data/` — directories for threat feeds and persistent DB.

## API Endpoints
- `GET /health` — basic health check.
- `POST /scan` — runs full scanner (heuristics, SSL, HTML) and stores result in SQLite. JSON body: `{ "url": "http://..." }`.
- `GET /history?limit=50&page=0` — paginated list of past scans.
- `GET /history/<id>` — retrieve a single saved scan.
- `POST /predict` — runs `extract_features` and returns `phishing_probability` from the ML model. JSON body: `{ "url": "http://..." }`.

Notes:
- If `PHISHSCAN_API_KEY` is set in the environment, requests must include `X-API-Key` header or `?api_key=` query param.
- Rate limits are enforced (default: 60 req/min globally, endpoints override with tighter limits). When `REDIS_URL` is set, rate limiting uses Redis storage for durability across processes.

## Running locally (development)
Prerequisites: Python 3.11, virtualenv recommended.

1. Create and activate a venv, install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r phishscan/requirements.txt
```

2. Create required directories and DB (the app will create them automatically, but for first-run you can):

```bash
mkdir -p phishscan/feeds phishscan/data
```

3. Run the API locally:

```bash
cd phishscan
python api.py
```

Default service runs on port 5050.

## Running with Docker (recommended for parity)
1. Ensure Docker and docker-compose are installed.
2. Build and start the stack (this will start API, feed_updater and Redis):

```bash
docker-compose up --build -d
```

3. API will be available at `http://localhost:5050`.

Notes:
- The `docker-compose.yml` mounts model files (if present) into the container. If you train a model locally, place `phishscan_model.pkl` and `phishscan_model.pkl.feature_importances.csv` in the repository root so the API container can load them.

## Training the ML model
Training produces a RandomForestClassifier stored as `phishscan_model.pkl`. The training script also exports feature importances and a small JSON metadata file.

Basic usage:

```bash
cd phishscan
python train_model.py --dataset dataset.csv --model-out phishscan_model.pkl
```

Optional hyperparameter search (light randomized search):

```bash
python train_model.py --dataset dataset.csv --model-out phishscan_model.pkl --search
```

Important: the training script expects either a numeric `label` column (0/1) or a `status` column with `phishing`/`legitimate` values (it will map automatically). The script drops `url`/`status` columns before training.

Model artifacts:
- `phishscan_model.pkl` — joblib dump of the trained model.
- `phishscan_model.pkl.feature_importances.csv` — feature order + importance values. This file is used by the runtime `ml_model.py` to assemble input vectors in the same column order the model was trained on.
- `phishscan_model.pkl.meta.json` — basic metrics and counts.

## Feature handling and runtime model contract
- At runtime `extract_features.py` returns a dict of numeric features for a given URL.
- `ml_model.py` will attempt to load the training feature-order from `phishscan_model.pkl.feature_importances.csv`. If that file is present, the runtime constructs an input vector in the same column order, filling any missing features with `0.0`. This prevents shape mismatch errors between runtime features and the trained model.
- If the feature-order file is absent, `ml_model.py` falls back to a best-effort mapping from the `features` dict (not recommended for production).

Recommended workflow:
- Option A (best accuracy): regenerate a training dataset using `build_features.py` (it calls `extract_features` for every URL in your CSV), then retrain. This ensures training and runtime features match exactly.
- Option B (quick deploy): train a model on the full feature CSV and mount `phishscan_model.pkl.feature_importances.csv` with your model so runtime pads missing features.

## Rate limiting (production-ready)
- When `REDIS_URL` env var is set (for example `redis://redis:6379/0`), the app configures `flask-limiter` to use Redis storage. The included `docker-compose.yml` spins up `redis:7-alpine` for this purpose.

## Troubleshooting
- ValueError: "X has N features, but RandomForestClassifier is expecting M features"
  - Ensure `phishscan_model.pkl.feature_importances.csv` is present and mounted into the container. The runtime will read it and pad missing features.
  - Alternatively, rebuild training data using `build_features.py` and retrain so the model expects the exact runtime features.
- Redis connection errors
  - Check `REDIS_URL` env var and that the `redis` service is running. In Docker Compose the service name `redis` is used and the `REDIS_URL` is set to `redis://redis:6379/0`.

## Next improvements (recommended)
- Add unit tests for `extract_features` and `ml_model.predict_phishing_prob`.
- Add a small CI pipeline to run lint/tests and build the Docker image.
- Implement a robust feature transformer (e.g., sklearn ColumnTransformer + Pipeline) and export the transformer along with the model so runtime uses identical preprocessing.

## Contact / Contribution
Open issues and pull requests are welcome. When reporting bugs include: steps to reproduce, API request payload, logs and the model artifacts used.

---
Generated: 10-Nov-2025

## Quick examples & docs
The sections below provide fast, copy-paste examples for manual testing and running from Docker.

1) Quick curl examples (local / container)

```bash
# Health
curl -s http://127.0.0.1:5050/health | jq

# Predict (POST JSON)
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"url":"http://example.com/login"}' \
  http://127.0.0.1:5050/predict | jq

# Full scan (heuristics + html + ssl):
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"url":"http://example.com/login"}' \
  http://127.0.0.1:5050/scan | jq

# History (list)
curl -s http://127.0.0.1:5050/history?limit=10 | jq
```

If `PHISHSCAN_API_KEY` is set, include header `-H "X-API-Key: <key>"` on requests.

2) Docker commands (run with model mounted)

```bash
# Build and start services (compose brings redis)
docker-compose up --build -d

# If you prefer a single container and want to mount the model from host:
# (adjust paths; this starts only the API container)
docker build -t phishscan-api .
docker run -p 5050:5050 \
  -v $(pwd)/phishscan_model.pkl:/app/phishscan_model.pkl:ro \
  -v $(pwd)/phishscan_model.pkl.feature_importances.csv:/app/phishscan_model.pkl.feature_importances.csv:ro \
  -e REDIS_URL=redis://<redis-host>:6379/0 \
  -e PHISHSCAN_API_KEY=${PHISHSCAN_API_KEY:-} \
  --name phishscan_api phishscan-api
```

3) Feature extraction & processing (how data flows)

- Request `POST /predict` with `{ "url": "http://..." }`.
- `api.py` calls `extract_features(url)` from `extract_features.py`.
  - `extract_features` composes a feature dict from:
    - lexical features (URL length, number of dots, digits, entropy, keywords),
    - SSL checks (`ssl_expiry_days`, `ssl_self_signed`, `domain_age_days`, ...),
    - HTML scan results (form counts, hidden inputs, scripts, external actions).
- The features dict is passed to `ml_model.predict_phishing_prob(features)`.
  - `ml_model.py` loads the trained model (`phishscan_model.pkl`) and attempts to read `phishscan_model.pkl.feature_importances.csv` to get the exact training feature order.
  - If this file is present, `ml_model` builds a numeric vector in the same column order (missing keys -> `0.0`) and calls `model.predict_proba(X)`.
  - If no feature-order file exists, `ml_model` falls back to a best-effort mapping from `features.values()` (less safe).
- Response JSON includes `phishing_probability` and the `features` used.

4) Recommended quick checks after deploy

- Confirm Redis is reachable when using Docker Compose: `docker ps` and `docker logs phishscan_redis`.
- Confirm model artifacts are visible inside container: `docker exec -it phishscan_api ls -l /app/phishscan_model.pkl*`.
- Run the curl `POST /predict` example and check logs if prediction fails; common error: feature mismatch (see Troubleshooting section).

