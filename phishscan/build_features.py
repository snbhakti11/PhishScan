"""build_features.py

Run extract_features(url) for every row in the provided phishing CSV and
save a dataset with the runtime feature set and numeric label.
"""
import pandas as pd
from extract_features import extract_features

IN = 'dataset_phishing.csv'
OUT = 'dataset_extracted.csv'

print('Loading', IN)
df = pd.read_csv(IN)

rows = []
for i, row in df.iterrows():
    url = row.get('url')
    if not isinstance(url, str) or not url.strip():
        continue
    try:
        feats = extract_features(url)
    except Exception as e:
        # fallback: skip or fill with default zeros
        print(f'warning: extract_features failed for row {i}:', e)
        feats = {}
    feats['label'] = 1 if row.get('status') == 'phishing' else 0
    rows.append(feats)
    if (i+1) % 200 == 0:
        print('processed', i+1)

if not rows:
    raise SystemExit('No features extracted')

out_df = pd.DataFrame(rows)
# fill missing feature columns with median/zeros
out_df = out_df.fillna(out_df.median().fillna(0))

print('Saving', OUT, 'shape', out_df.shape)
out_df.to_csv(OUT, index=False)
print('done')
