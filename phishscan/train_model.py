# train_model.py
"""
Train Random Forest model using extracted features.

This script accepts datasets that contain either a numeric `label` column
(0 = legitimate, 1 = phishing) or a `status` column with values
"phishing" / "legitimate" (it will map automatically).

It supports optional cross-validation and a small randomized search for
hyperparameter tuning, and will export feature importances to
`<model-out>.feature_importances.csv`.
"""

import argparse
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, RandomizedSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import json


def prepare_dataset(df: pd.DataFrame) -> (pd.DataFrame, pd.Series):
    # map status -> label if necessary
    if 'label' not in df.columns:
        if 'status' in df.columns:
            df = df.copy()
            df['label'] = df['status'].map({'phishing': 1, 'legitimate': 0})
        else:
            raise RuntimeError("Dataset must include 'label' or 'status' column")

    # Drop non-numeric columns commonly present
    drop_cols = [c for c in ['url', 'status'] if c in df.columns]
    X = df.drop(drop_cols + ['label'], axis=1)

    # Ensure numeric dtypes; coerce if necessary
    X = X.apply(pd.to_numeric, errors='coerce')
    # If any NaNs introduced, fill with column median
    if X.isnull().any().any():
        X = X.fillna(X.median())

    y = df['label'].astype(int)
    return X, y


def train(dataset_path: str, model_out: str, do_search: bool = False, cv_folds: int = 5):
    print(f"Loading dataset: {dataset_path}")
    df = pd.read_csv(dataset_path)

    X, y = prepare_dataset(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    base_model = RandomForestClassifier(n_estimators=300, max_depth=20,
                                        random_state=42, class_weight='balanced')

    if do_search:
        print('Running randomized hyperparameter search (light)')
        param_dist = {
            'n_estimators': [100, 200, 300, 400],
            'max_depth': [None, 10, 20, 30],
            'max_features': ['sqrt', 'log2', 0.5, 0.8],
            'min_samples_split': [2, 5, 10]
        }
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        rs = RandomizedSearchCV(base_model, param_dist, n_iter=10, cv=cv, n_jobs=-1,
                                random_state=42, scoring='f1')
        rs.fit(X_train, y_train)
        model = rs.best_estimator_
        print('Best params:', rs.best_params_)
    else:
        model = base_model
        model.fit(X_train, y_train)

    # If do_search, ensure model is fitted (rs already fits). If base_model used, fitted above.
    if not hasattr(model, 'predict'):
        raise RuntimeError('Model is not fitted')

    y_pred = model.predict(X_test)

    print('✅ Training Completed')
    print('Accuracy:', accuracy_score(y_test, y_pred))
    print('Precision:', precision_score(y_test, y_pred, zero_division=0))
    print('Recall:', recall_score(y_test, y_pred, zero_division=0))
    print('F1 Score:', f1_score(y_test, y_pred, zero_division=0))

    joblib.dump(model, model_out)
    print(f'✅ Model saved to {model_out}')

    # Export feature importances
    try:
        importances = model.feature_importances_
        feat_df = pd.DataFrame({'feature': X.columns, 'importance': importances})
        feat_df = feat_df.sort_values('importance', ascending=False)
        fi_path = model_out + '.feature_importances.csv'
        feat_df.to_csv(fi_path, index=False)
        print(f'✅ Feature importances saved to {fi_path}')
    except Exception as e:
        print('Could not save feature importances:', e)

    # Save a tiny metadata file with metrics
    meta = {
        'accuracy': float(accuracy_score(y_test, y_pred)),
        'precision': float(precision_score(y_test, y_pred, zero_division=0)),
        'recall': float(recall_score(y_test, y_pred, zero_division=0)),
        'f1': float(f1_score(y_test, y_pred, zero_division=0)),
        'n_features': int(X.shape[1]),
        'n_train': int(X_train.shape[0]),
        'n_test': int(X_test.shape[0])
    }
    with open(model_out + '.meta.json', 'w') as fh:
        json.dump(meta, fh)
    print('✅ Metadata saved to', model_out + '.meta.json')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', default='dataset.csv', help='Path to CSV dataset')
    parser.add_argument('--model-out', default='phishscan_model.pkl', help='Output model path')
    parser.add_argument('--search', action='store_true', help='Run randomized hyperparameter search')
    parser.add_argument('--cv-folds', type=int, default=5, help='Cross-validation folds for search')
    args = parser.parse_args()
    train(args.dataset, args.model_out, do_search=args.search, cv_folds=args.cv_folds)
