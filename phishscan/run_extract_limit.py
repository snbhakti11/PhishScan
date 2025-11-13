#!/usr/bin/env python3
"""
run_extract_limit.py
Extract features for the first N rows of the input CSV and write dataset_extracted_{N}.csv
Usage: python3 run_extract_limit.py --limit 2000
"""
import argparse
import pandas as pd
from extract_features import extract_features

parser = argparse.ArgumentParser()
parser.add_argument('--in', dest='infile', default='dataset_phishing.csv')
parser.add_argument('--limit', type=int, default=2000)
parser.add_argument('--out', default=None)
args = parser.parse_args()

IN = args.infile
LIMIT = args.limit
OUT = args.out or f'dataset_extracted_{LIMIT}.csv'

print(f'Loading {IN} (limit={LIMIT})')
df = pd.read_csv(IN)

rows = []
count = 0
for i, row in df.iterrows():
    if count >= LIMIT:
        break
    url = row.get('url')
    if not isinstance(url, str) or not url.strip():
        continue
    try:
        feats = extract_features(url)
    except Exception as e:
        print(f'warning: extract_features failed for row {i}:', e)
        feats = {}
    feats['label'] = 1 if row.get('status') == 'phishing' else 0
    rows.append(feats)
    count += 1
    if count % 100 == 0:
        print('processed', count)

if not rows:
    raise SystemExit('No features extracted')

out_df = pd.DataFrame(rows)
out_df = out_df.fillna(out_df.median().fillna(0))

print('Saving', OUT, 'shape', out_df.shape)
out_df.to_csv(OUT, index=False)
print('done')
