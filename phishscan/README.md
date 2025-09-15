# PhishScan: Heuristic & Threat-Intel Driven Phishing Detector

PhishScan is a lightweight, explainable, and real-time phishing URL scanner. It combines heuristic rules, SSL/TLS checks, and threat-intelligence feeds (PhishTank & OpenPhish) into a single REST API service.

## 🚀 Features

- 🔍 Heuristic URL Analysis (length, symbols, IP in URL, etc.)
- 🔒 SSL Certificate Validation (expiry, issuer, CN mismatch)
- 🌐 Threat Intelligence Integration (PhishTank JSON feed, OpenPhish feed)
- ⚡ REST API with JSON responses
- 📊 Explainable Output → clear breakdown of why a URL is suspicious

## 📂 Project Structure

```
phishscan/
│
├── heuristics.py        # heuristic rules for URL analysis
├── ssl_check.py         # SSL/TLS certificate inspection
├── threat_intel.py      # integration with PhishTank & OpenPhish feeds
├── scanner.py           # orchestrates all checks
├── api.py               # Flask REST API (runs on port 5050)
├── requirements.txt     # dependencies
└── README.md            # project documentation
```

## 🛠️ Installation & Setup

Clone the repo:

```bash
git clone https://github.com/your-username/phishscan.git
cd phishscan
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Update Threat Feeds (PhishTank + OpenPhish):

```bash
python -m threat_intel
```

## ⚡ Running the API

Start the API server:

```bash
python api.py
```

The API will start at:

👉 http://127.0.0.1:5050

## 🔍 Scanning a URL

Using curl:

```bash
curl -X POST http://127.0.0.1:5050/scan \
		 -H "Content-Type: application/json" \
		 -d '{"url":"http://example.com"}'
```

### Example Response

```
{
	"url": "http://example.com",
	"heuristics": {
		"suspicious_length": false,
		"has_ip": false,
		"special_chars": 0
	},
	"ssl": {
		"valid": true,
		"issuer": "Let's Encrypt",
		"expiry_days": 45
	},
	"threat_feed": {
		"found": false,
		"source": null
	}
}
```

## 📊 Roadmap

- Heuristic detection engine
- SSL/TLS inspection
- PhishTank & OpenPhish integration
- REST API service (port 5050)
- HTML page scanner (detect login forms, hidden inputs)
- Frontend dashboard for results/history

## ⚠️ Disclaimer

This project is for educational and research purposes only. Do not rely on it as your sole line of defense against phishing attacks.
