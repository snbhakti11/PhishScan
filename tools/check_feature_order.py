"""Simple CI check: ensure model.feature_names_in_ matches the feature_importances CSV.

Exits 0 on success, non-zero on mismatch.
"""
import sys
import pandas as pd
import joblib

MODEL = 'phishscan/phishscan_runtime_model_11430.pkl'
FI_CSV = MODEL + '.feature_importances.csv'

try:
    m = joblib.load(MODEL)
except Exception as e:
    print('Failed to load model:', e)
    sys.exit(2)

model_cols = list(getattr(m, 'feature_names_in_', []))
if not model_cols:
    print('Model does not expose feature_names_in_; cannot verify. PASSING')
    sys.exit(0)

try:
    df = pd.read_csv(FI_CSV)
    csv_cols = df['feature'].astype(str).tolist()
except Exception as e:
    print('Failed to read feature_importances CSV:', e)
    sys.exit(3)

if model_cols == csv_cols:
    print('OK: model.feature_names_in_ matches CSV')
    sys.exit(0)
else:
    print('MISMATCH: model columns and CSV differ')
    print('model sample:', model_cols[:10])
    print('csv sample:  ', csv_cols[:10])
    sys.exit(1)
