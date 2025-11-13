#!/usr/bin/env bash
# quick curl examples for PhishScan
set -euo pipefail

BASE=${BASE:-http://127.0.0.1:5050}

echo "Health:"
curl -s ${BASE}/health | jq

echo "Predict:"
curl -s -X POST -H "Content-Type: application/json" -d '{"url":"http://example.com/login"}' ${BASE}/predict | jq

echo "Scan:"
curl -s -X POST -H "Content-Type: application/json" -d '{"url":"http://example.com/login"}' ${BASE}/scan | jq

echo "History:"
curl -s ${BASE}/history?limit=5 | jq
#!/usr/bin/env bash
# Simple curl examples for PhishScan
set -euo pipefail

BASE=${BASE:-http://127.0.0.1:5050}
API_KEY=${PHISHSCAN_API_KEY:-}
KEY_HEADER=""
if [ -n "$API_KEY" ]; then
  KEY_HEADER="-H X-API-Key: $API_KEY"
fi

echo "Health"
curl -s "$BASE/health" | jq

echo "\nPredict"
curl -s -X POST -H "Content-Type: application/json" $KEY_HEADER \
  -d '{"url":"http://example.com/login"}' \
  "$BASE/predict" | jq

echo "\nScan"
curl -s -X POST -H "Content-Type: application/json" $KEY_HEADER \
  -d '{"url":"http://example.com/login"}' \
  "$BASE/scan" | jq

echo "\nHistory"
curl -s "$BASE/history?limit=5" | jq
