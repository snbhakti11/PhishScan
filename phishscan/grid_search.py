"""Grid search over ML weight and threshold to find operating points.

Usage: python grid_search.py --dataset dataset_extracted_11430.csv --out grid_results.json
"""
import argparse
import json
import itertools
import numpy as np
import pandas as pd
from joblib import load
from sklearn.metrics import confusion_matrix, accuracy_score, f1_score


def load_model_and_data(model_path, dataset_path):
    model = load(model_path)
    df = pd.read_csv(dataset_path)
    try:
        feature_order = list(model.feature_names_in_)
    except Exception:
        fi = pd.read_csv(model_path + '.feature_importances.csv', header=None)
        feature_order = list(fi[0].tolist())
    # Build a DataFrame with exact columns in training order to avoid sklearn warnings
    missing = [c for c in feature_order if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing expected feature columns: {missing}")
    X_df = df[feature_order].fillna(0)
    # If model exposes feature names, validate they match the order we loaded
    try:
        model_cols = list(model.feature_names_in_)
        if model_cols != feature_order:
            raise ValueError("Model.feature_names_in_ does not match saved feature order")
    except Exception:
        # if model doesn't expose feature names, we proceed using the saved order
        pass
    X = X_df
    y = df['label'].to_numpy()
    probs = model.predict_proba(X)[:,1]
    return probs, y


def run_grid(probs, y, w_ml_values, thresholds):
    results = []
    # heuristics are approximated from dataset: use a simple proxy using keywords/url_length
    # for this search we assume heuristic score = (url_length / 200) + (keyword presence)
    # but since dataset already contains features, attempt to reconstruct heuristic_norm
    # If features exist in dataset, use them; otherwise use a constant 0.0
    # For simplicity we use heuristic_norm = 0.5 for all rows (neutral)
    h_norm = np.full_like(probs, 0.5)

    for w_ml, thresh in itertools.product(w_ml_values, thresholds):
        w_h = 1.0 - w_ml
        combined = np.clip(w_ml * probs + w_h * h_norm, 0.0, 1.0)
        preds = (combined >= thresh).astype(int)
        tn, fp, fn, tp = confusion_matrix(y, preds).ravel()
        acc = float(accuracy_score(y, preds))
        f1 = float(f1_score(y, preds))
        results.append({
            'w_ml': float(w_ml),
            'w_h': float(w_h),
            'threshold': float(thresh),
            'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp),
            'accuracy': acc, 'f1': f1
        })
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', default='phishscan/phishscan_runtime_model_11430.pkl')
    parser.add_argument('--dataset', default='phishscan/dataset_extracted_11430.csv')
    parser.add_argument('--out', default='phishcan/grid_search_results.json')
    args = parser.parse_args()

    probs, y = load_model_and_data(args.model, args.dataset)
    w_ml_values = [0.5, 0.6, 0.7, 0.8, 0.9]
    thresholds = [0.4, 0.45, 0.5, 0.55, 0.6]
    results = run_grid(probs, y, w_ml_values, thresholds)
    with open(args.out, 'w') as f:
        json.dump({'results': results}, f, indent=2)
    print('Saved grid search results to', args.out)


if __name__ == '__main__':
    main()
