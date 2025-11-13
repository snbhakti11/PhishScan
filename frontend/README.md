# PhishScan Frontend (Microservice)

Small frontend microservice for PhishScan. It provides a minimal web UI
where a user can paste a URL and get a short, human-friendly verdict
("legitimate" or "phishing") plus probabilities reported by the
backend services.

Run (development):

```bash
cd frontend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open http://127.0.0.1:8080 in your browser. The frontend calls the backend
at `BACKEND_URL` (default `http://127.0.0.1:5050`) — set that env var to point
to your API if needed.

What it does
- POSTs the provided URL to `/predict` (ML probability) and `/scan` (full)
  on the backend.
- Displays ML probability and the combined/final verdict + probability.

Notes
- This is a simple dev/test frontend. Use a proper reverse proxy and
  secure configuration for production deployments.
