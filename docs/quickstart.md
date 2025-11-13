# Quickstart — PhishScan

This quickstart shows the minimal steps to run PhishScan locally or in Docker, test the API, and (optionally) retrain a runtime-matched model.

1. Run with Docker Compose (recommended):

```bash
docker-compose up --build -d
```

2. Quick sanity test (predict):

```bash
curl -s -X POST -H "Content-Type: application/json" -d '{"url":"http://example.com/login"}' http://127.0.0.1:5050/predict | jq
```

3. Re-generate training data from runtime features and retrain (optional):

```bash
cd phishscan
python build_features.py   # produces dataset_extracted.csv
python train_model.py --dataset dataset_extracted.csv --model-out phishscan_runtime_model.pkl
```

After training, place `phishscan_runtime_model.pkl` and `phishscan_runtime_model.pkl.feature_importances.csv` in the repo root (or mounted into the container) to use the retrained model.
# Quickstart — PhishScan

This quickstart walks through the fastest path to run PhishScan locally or in Docker and test the `/predict` and `/scan` endpoints.

Prerequisites
- Python 3.11 (or Docker if you prefer containers)
- Optional: `jq` for pretty JSON in the shell

Run locally (dev)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r phishscan/requirements.txt
mkdir -p phishscan/feeds phishscan/data
cd phishscan
python api.py
```

Run with Docker Compose

```bash
docker-compose up --build -d
```

Quick checks

- Health: `curl http://127.0.0.1:5050/health`
- Predict: `curl -X POST -H "Content-Type: application/json" -d '{"url":"http://example.com/login"}' http://127.0.0.1:5050/predict`

If using an API key, add `-H "X-API-Key: <key>"` to the curl commands.
