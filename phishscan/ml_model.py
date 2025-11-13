# ml_model.py
"""
Load pre-trained Random Forest model and return phishing probability.
"""

import joblib
import numpy as np
import csv
import logging
import os
from typing import Optional, Any, List
import pandas as pd

logger = logging.getLogger("ml_model")
# Ensure ml_model logger is at INFO level so our debug/info messages appear in container logs
logger.setLevel(logging.INFO)
logger.propagate = True

_env_path = os.getenv('PHISHSCAN_MODEL_PATH')
if _env_path:
    MODEL_PATH = _env_path
else:
    # Prefer model file in repository root or inside the phishscan package
    candidates = [
        'phishscan_runtime_model_11430.pkl',
        os.path.join(os.path.dirname(__file__), 'phishscan_runtime_model_11430.pkl'),
        os.path.join('phishscan', 'phishscan_runtime_model_11430.pkl')
    ]
    MODEL_PATH = None
    for c in candidates:
        if os.path.exists(c):
            MODEL_PATH = c
            break
    if MODEL_PATH is None:
        # fallback to the repo-root candidate (most-common in CI/docker setups)
        MODEL_PATH = candidates[0]
logger.info("Runtime MODEL_PATH resolved to %s", MODEL_PATH)

_model: Optional[Any] = None
_feature_order: Optional[List[str]] = None


def _load_feature_order(model_path: str) -> Optional[List[str]]:
    """Attempt to load feature order from `<model_path>.feature_importances.csv`.
    Returns None if file not found.
    """
    fi_path = model_path + ".feature_importances.csv"
    try:
        logger.info("Attempting to load feature importances from %s", fi_path)
        with open(fi_path, newline="") as fh:
            reader = csv.DictReader(fh)
            names = [row.get('feature') for row in reader if row.get('feature')]
            logger.info("Found %d feature lines in %s", len(names), fi_path)
            if names:
                # Log first 10 feature names for debugging
                logger.info("Sample feature names: %s", names[:10])
                return names
    except FileNotFoundError:
        logger.warning("Feature importances file not found at %s", fi_path)
        return None
    except Exception:
        logger.exception("Failed to read feature importances from %s", fi_path)
        return None
    return None


def load_model():
    """Lazy-load the model from disk and feature order if available."""
    global _model, _feature_order
    if _model is None:
        logger.info("Loading model from %s (exists=%s)", MODEL_PATH, os.path.exists(MODEL_PATH))
        print(f"[ml_model] Loading model from {MODEL_PATH}, exists={os.path.exists(MODEL_PATH)}")
        _model = joblib.load(MODEL_PATH)
        print(f"[ml_model] Model loaded from {MODEL_PATH}")
        # Log model inspection info
        try:
            nfi = getattr(_model, 'n_features_in_', None)
            logger.info("Model loaded. n_features_in_=%s", nfi)
            print(f"[ml_model] Model n_features_in_={nfi}")
        except Exception:
            logger.exception("Model loaded but failed to inspect attributes")
            print("[ml_model] Failed to inspect model attributes")
        # Try to load saved order from CSV
        _feature_order = _load_feature_order(MODEL_PATH)
        if _feature_order:
            logger.info("Loaded feature order from CSV, count=%d", len(_feature_order))
        else:
            logger.info("No feature order loaded from %s; _feature_order is None", MODEL_PATH)

        # If model exposes feature names, prefer them (they are authoritative)
        try:
            model_cols = list(getattr(_model, 'feature_names_in_', []))
            if model_cols:
                if _feature_order and model_cols != _feature_order:
                    logger.warning("Model.feature_names_in_ differs from saved feature order; using model's names")
                    logger.debug("model columns: %s", model_cols[:20])
                    logger.debug("saved order: %s", _feature_order[:20])
                # Overwrite runtime feature order with model's feature names
                _feature_order = model_cols
                # Do not attempt to write files into the container root; environments
                # may mount the repo read-only. Log that we prefer the model's names
                # and skip regenerating the CSV when the FS is not writable.
                logger.info('Using model.feature_names_in_ as runtime feature order (count=%d)', len(model_cols))
        except Exception:
            logger.exception('Failed to inspect model.feature_names_in_')
            # If we couldn't load names, but model has attribute n_features_in_,
            # we leave _feature_order as None and the caller must pass an ordered mapping.
    return _model


def predict_phishing_prob(features: dict) -> float:
    """
    Predict probability (0 to 1) that URL is phishing.

    `features` may be a dict with a subset of feature names; when the
    trained model's feature order is available (saved as
    `<model>.feature_importances.csv`) the function will construct the
    input vector in the correct column order. Missing features default
    to 0.0.
    """
    model = load_model()

    # If we have a saved feature order, use it to build a named DataFrame
    global _feature_order
    if _feature_order:
        # Build a single-row DataFrame in the exact training column order
        row = {name: float(features.get(name, 0.0)) for name in _feature_order}
        X_df = pd.DataFrame([row], columns=_feature_order)
        # Validate shapes against the model if possible
        try:
            model_n = getattr(model, 'n_features_in_', None)
            if model_n is not None and model_n != X_df.shape[1]:
                raise ValueError(f"Model expects {model_n} features but input has {X_df.shape[1]}")
        except Exception as e:
            logger.exception("Feature shape validation failed: %s", e)
        try:
            prob = model.predict_proba(X_df)[0][1]
            return float(prob)
        except Exception as e:
            raise ValueError(f"Model prediction failed when using DataFrame input: {e}")
    else:
        # Fallback: try to build from provided dict values (best-effort)
        X = np.array([list(features.values())])
        # Ensure correct 2D shape
        if X.ndim == 1:
            X = X.reshape(1, -1)
        try:
            prob = model.predict_proba(X)[0][1]
            return float(prob)
        except Exception as e:
            raise ValueError(f"Model prediction failed: {e}")
