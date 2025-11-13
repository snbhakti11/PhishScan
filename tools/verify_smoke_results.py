"""
Load existing phishscan/smoke_100_results.json entries, run ml_model.predict_phishing_prob on the
`features` field and compute statistics (min/max/mean/stdev, buckets) for ml_probability and
combined_probability using the same aggregation logic as the API.

Run: PYTHONPATH=. python3 tools/verify_smoke_results.py
"""
import json
import os
import math
from statistics import mean, stdev

from phishscan import ml_model

INPUT = 'phishscan/smoke_100_results.json'


def bucket_counts(vals):
    buckets = {'<0.2':0, '0.2-0.4':0, '0.4-0.6':0, '0.6-0.8':0, '>0.8':0}
    for v in vals:
        if v < 0.2:
            buckets['<0.2'] += 1
        elif v < 0.4:
            buckets['0.2-0.4'] += 1
        elif v < 0.6:
            buckets['0.4-0.6'] += 1
        elif v < 0.8:
            buckets['0.6-0.8'] += 1
        else:
            buckets['>0.8'] += 1
    return buckets


def main():
    PYTHONPATH = os.getenv('PYTHONPATH') or '.'
    print('PYTHONPATH used:', PYTHONPATH)
    # load file
    with open(INPUT, 'r') as fh:
        data = json.load(fh)

    results = data.get('results', [])
    ml_probs = []
    combined_probs = []

    model = ml_model.load_model()
    for r in results:
        features = r.get('result', {}).get('features', {})
        try:
            mlp = ml_model.predict_phishing_prob(features)
        except Exception as e:
            mlp = None
        ml_probs.append(mlp)
        # compute heuristic normalized if present
        hscore = r.get('result', {}).get('heuristic_score')
        hnorm = None
        if hscore is not None:
            try:
                hs = float(hscore)
                hnorm = hs/100.0 if hs>1.0 else max(0.0, min(1.0, hs))
            except Exception:
                hnorm = None
        # aggregation with default weights
        w_ml = float(os.getenv('PHISHSCAN_WEIGHT_ML', '0.8'))
        w_h = float(os.getenv('PHISHSCAN_WEIGHT_HEURISTIC', '0.2'))
        if hnorm is not None:
            combined = max(0.0, min(1.0, w_ml*float(mlp) + w_h*hnorm))
        else:
            combined = float(mlp)
        combined_probs.append(combined)

    # stats
    def stats(vals):
        valsf = [float(v) for v in vals if v is not None]
        if not valsf:
            return {}
        s = {
            'count': len(valsf),
            'min': min(valsf),
            'max': max(valsf),
            'mean': mean(valsf),
            'stdev': stdev(valsf) if len(valsf)>1 else 0.0,
            'buckets': bucket_counts(valsf)
        }
        return s

    out = {
        'ml_summary': stats(ml_probs),
        'combined_summary': stats(combined_probs)
    }
    print(json.dumps(out, indent=2))

if __name__ == '__main__':
    main()
