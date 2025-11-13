#!/usr/bin/env bash
# Run feature extraction on a small CSV and produce dataset_extracted.csv
set -euo pipefail
cd "$(dirname "$0")"
python3 - <<'PY'
import pandas as pd
from extract_features import extract_features

IN='dataset_phishing_small.csv'
OUT='dataset_extracted.csv'
print('Loading', IN)
df = pd.read_csv(IN)
rows=[]
for i,row in df.iterrows():
    url=row.get('url')
    if not isinstance(url,str) or not url.strip():
        continue
    try:
        feats=extract_features(url)
    except Exception as e:
        print('warning: extract_features failed for',url,e)
        feats={}
    feats['label']=1 if row.get('status')=='phishing' else 0
    rows.append(feats)

out=pd.DataFrame(rows)
out=out.fillna(out.median().fillna(0))
out.to_csv(OUT,index=False)
print('wrote',OUT,'shape',out.shape)
PY
