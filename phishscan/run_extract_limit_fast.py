#!/usr/bin/env python3
"""
run_extract_limit_fast.py
Extract features for the first N rows but skip HTML fetching to avoid long network waits.
Usage: python3 run_extract_limit_fast.py --limit 2000
"""
import argparse
import pandas as pd

# Monkeypatch scan_url_html to a fast stub to avoid network fetches
import os
import sys
import importlib
from typing import TYPE_CHECKING

# Ensure local package path is available so `from extract_features import ...` works
here = os.path.dirname(os.path.abspath(__file__))
# also ensure repo root is on sys.path so `import phishcan` works when running
# the script from the repo root: python3 phishcan/run_extract_limit_fast.py
repo_root = os.path.dirname(here)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
if here not in sys.path:
    sys.path.insert(0, here)

try:
    # prefer package-relative import when run as module
    from . import html_scanner as _html_scanner
except Exception:
    try:
        import html_scanner as _html_scanner
    except Exception:
        _html_scanner = None

if _html_scanner is not None:
    def _stub_scan(url):
        return {"fetched": False}
    try:
        _html_scanner.scan_url_html = _stub_scan
    except Exception:
        pass

if TYPE_CHECKING:
    # allow static analysis (Pylance) to see the modules
    try:
        from .extract_features import extract_features  # type: ignore
    except Exception:
        from extract_features import extract_features  # type: ignore

# runtime dynamic import: prefer package import, fallback to top-level, then
# fallback to loading by file path. This makes the script resilient to being
# executed from the repo root, inside the package, or via -m.
extract_features = None
load_errors = []
try:
    ef_mod = importlib.import_module('phishcan.extract_features')
    extract_features = getattr(ef_mod, 'extract_features')
except Exception as e:
    load_errors.append(('phishcan.extract_features', e))
    try:
        ef_mod = importlib.import_module('extract_features')
        extract_features = getattr(ef_mod, 'extract_features')
    except Exception as e2:
        load_errors.append(('extract_features', e2))

if extract_features is None:
    # final fallback: locate the file next to this script and load it
    try:
        from importlib.machinery import SourceFileLoader
        ef_path = os.path.join(here, 'extract_features.py')
        if os.path.exists(ef_path):
            ef_mod = SourceFileLoader('extract_features', ef_path).load_module()
            extract_features = getattr(ef_mod, 'extract_features')
        else:
            raise FileNotFoundError(ef_path)
    except Exception as e:
        load_errors.append(('sourcefile', e))

if extract_features is None:
    # present a clearer error showing attempts
    msg_lines = ['Could not import extract_features; attempted:']
    for name, err in load_errors:
        msg_lines.append(f" - {name}: {type(err).__name__}: {err}")
    raise ImportError('\n'.join(msg_lines))

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
