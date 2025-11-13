"""
Quick local smoke test: load runtime model via phishscan.ml_model and run predict_phishing_prob
on a few sample URLs. Prints model path, feature count, feature name sample, and per-URL
ml_probability and combined output using the local API aggregation logic.

Run: python3 tools/run_local_smoke.py
"""
import os
import json

from phishscan import ml_model

SAMPLES = [
    "http://example.com",
    "https://wikipedia.org",
    "http://phishingsite.biz/login",
    "http://malicious.test/login",
    "https://github.com",
]

def main():
    print("MODEL_PATH (env override):", os.getenv('PHISHSCAN_MODEL_PATH'))
    # load model and inspect
    try:
        model = ml_model.load_model()
    except Exception as e:
        print("Failed to load model:", e)
        return

    try:
        names = list(getattr(model, 'feature_names_in_', []))
        n = getattr(model, 'n_features_in_', None)
        print("model.feature_names_in_ length:", len(names))
        print("model.n_features_in_:", n)
        print("sample feature names:", names[:10])
    except Exception as e:
        print("Failed to inspect model attributes:", e)

    for u in SAMPLES:
        try:
            # try to use extractor when available
            from phishscan.extract_features import extract_features
            features = extract_features(u)
        except Exception as _:
            # fallback: build a tiny feature dict similar to API's small extractor
            features = {
                'url_length': float(len(u)),
                'num_dots': float(u.count('.')),
                'entropy': 3.5,
            }
        try:
            mlp = ml_model.predict_phishing_prob(features)
        except Exception as e:
            mlp = f"error: {e}"
        print(json.dumps({"url": u, "ml_probability": mlp, "features": list(features.keys())}))

if __name__ == '__main__':
    main()
