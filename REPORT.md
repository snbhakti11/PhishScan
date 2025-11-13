PhishScan — Project Report (Post-Midsem)

Overview
--------
PhishScan is a lightweight, explainable phishing URL scanner that combines heuristic rules, SSL/TLS checks, threat-intel feeds (PhishTank & OpenPhish), HTML page analysis, and an optional ML classifier (Random Forest) behind a REST API.

This report collects the content available up to the midsem evaluation and adds new results from recent runs (model training and artifacts). It documents dataset, pipeline, model metrics, limitations observed in the small sample, and next steps.

Contents included from repository
---------------------------------
- Project description, architecture and features (summarised from `README.md` and `phishscan/README.md`).
- Heuristic rules and SSL checks (implemented under `phishscan/app/heuristics.py` and `phishscan/app/ssl_check.py`).
- HTML scanner and form analysis (`phishscan/html_scanner.py` and `tests/test_html_scanner.py`).
- ML pipeline files: `extract_features.py`, `train_model.py`, `ml_model.py` and dataset template `phishscan/dataset.csv`.

Dataset
-------
- Location: `phishscan/dataset.csv` (small example dataset included in repo root `phishscan/`).
- Format: CSV with columns for extracted numeric features and a `label` column (0 = safe, 1 = phishing).
- Notes: The included dataset is small (a few rows), intended as a template/example for training. It contains both realistic and synthetic rows to demonstrate feature ranges.

Feature extraction & ML pipeline
--------------------------------
- `extract_features.py` produces a numeric feature vector per URL from:
  - URL lexical features (length, digits, special chars, entropy, keywords)
  - SSL/domain features (expiry days, expired, self-signed, CN mismatch, domain age)
  - HTML features (form count, login form presence, hidden inputs, script count, external form action)

- `train_model.py` trains a RandomForestClassifier (300 trees, depth 20, balanced class_weight) and saves `phishscan_model.pkl`.

Training run (new)
------------------
I trained the model locally using the repository's example dataset (`phishscan/dataset.csv`). Commands run:

```bash
cd phishscan
python3 train_model.py
```

Output (captured):
- Training completed successfully and model saved to `phishscan/phishscan_model.pkl`.
- Reported metrics on the small example test split:
  - Accuracy: 1.0
  - Precision: 0.0 (undefined / ill-defined due to no predicted positive samples)
  - Recall: 0.0 (undefined / ill-defined due to no true positive samples)
  - F1 Score: 0.0 (undefined / ill-defined)

Notes on metrics:
- The metrics above are not meaningful because the example dataset is tiny and the train/test split resulted in either no positive labels in the test set or no positive predictions. Warnings from scikit-learn flagged these as undefined metrics and set them to 0.0.
- The perfect accuracy with zero precision/recall indicates class imbalance or small-sample artifacts — do NOT treat this model as production-ready.

Model artifact
--------------
- Saved model: `phishscan/phishscan_model.pkl` (produced by the training run). This can be loaded via `ml_model.py`.

Limitations observed
--------------------
- Dataset size and class balance: The provided `dataset.csv` is too small and possibly skewed, producing unreliable metrics.

Evaluation metrics (11,430-row run)
----------------------------------
We trained a RandomForest model on an extracted dataset of 11,430 examples and evaluated it on the same extracted set (see `phishscan/phishscan_runtime_model_11430.pkl` and `phishscan/dataset_extracted_11430.csv`). The key metrics saved to `phishscan/metrics_11430.json` are:

- Accuracy: 0.93097
- ROC AUC: 0.97644

Confusion matrix (rows = true class 0/1, columns = predicted 0/1):

[[5457, 258],
 [531, 5184]]

Per-class precision/recall/f1 (from classification report):
- Class 0 (not-phishing): precision 0.9113, recall 0.9549, f1 0.9326
- Class 1 (phishing): precision 0.9526, recall 0.9071, f1 0.9293

Notes:
- These results show strong discrimination (high AUC) on the extracted dataset. However, this is an evaluation on the same extracted data and should be treated as an internal validation rather than a held-out test — consider cross-validation or a separate test set for robust estimates.
- The model appears to rely heavily on lexical features (entropy, url_length, num_digits, etc.). Adding higher-signal features (domain reputation, WHOIS age, threat-intel lookups) would likely improve robustness.

- Feature ordering contract: `ml_model.predict_phishing_prob` assumes the features dict preserves insertion order and matches training order — this can be fragile. A stricter feature vector builder (fixed column order) is recommended.
- HTML fetching: `extract_features` relies on live HTML fetching which may be slow or blocked; use caching or timeout controls for batch feature extraction.
- Environment reproducibility: training was performed on local machine; for reproducible experiments, pin package versions and use a virtualenv or container.

Immediate recommendations / next steps
------------------------------------
1. Expand dataset: collect more labeled URLs (PhishTank, OpenPhish, and benign URLs) to reach thousands of samples and multiple domains.
2. Fix feature ordering: implement a canonical feature list used by both `extract_features` and the model loader to ensure columns match.
3. Add cross-validation and class-stratified sampling: to correctly estimate metrics and mitigate sample-split artifacts.
4. Add basic evaluation notebook or script that plots ROC, confusion matrix, and feature importances.
5. Improve tests: add unit tests for `extract_features` to validate consistent feature ordering and types.

ROC / PR curve points and metadata
---------------------------------
I computed ROC and Precision-Recall curve points and saved them in `phishcan/` as CSV files (for local plotting):

- `phishcan/roc_11430_points.csv` — (fpr, tpr)
- `phishcan/pr_11430_points.csv` — (recall, precision)
- `phishcan/roc_pr_meta_11430.json` — contains the summary metrics:
  - roc_auc: 0.9764386210253901
  - average_precision (AP): 0.9795225522472706

Note: I attempted to generate PNG images (`roc.png`, `pr.png`) here but matplotlib failed to import due to a NumPy/matplotlib binary incompatibility in this environment. To reproduce the plots locally, run the following snippet in an environment where `matplotlib` works:

```python
import pandas as pd, matplotlib.pyplot as plt
r = pd.read_csv('phishcan/roc_11430_points.csv')
plt.plot(r.fpr, r.tpr); plt.plot([0,1],[0,1],'--'); plt.xlabel('FPR'); plt.ylabel('TPR'); plt.title('ROC'); plt.savefig('roc.png')
p = pd.read_csv('phishcan/pr_11430_points.csv')
plt.plot(p.recall, p.precision); plt.xlabel('Recall'); plt.ylabel('Precision'); plt.title('PR'); plt.savefig('pr.png')
```

If you want, I can attempt to fix the environment here (downgrade `numpy` to <2 or reinstall `matplotlib`) and produce the PNGs directly.

Appendix: Files of interest
---------------------------
- `phishscan/extract_features.py`
- `phishscan/train_model.py`
- `phishscan/ml_model.py`
- `phishscan/html_scanner.py`
- `phishscan/phishscan_model.pkl`
- `phishscan/dataset.csv`

Report generation
-----------------
I created this `REPORT.md` in the repository root. If you want a PDF, I can convert `REPORT.md` to PDF using `pandoc` and a local LaTeX installation (if available), or generate a simple HTML export.

Summary of changes
------------------
- Added `REPORT.md` summarizing project content, the included dataset, results of a fresh training run, observed metric issues, and recommended next steps.

Recent large training run (11,430 rows)
--------------------------------------
I also ran a larger training job using the runtime-extracted features (fast mode) that processed 11,430 rows and produced a model and metadata.

Commands run:

```bash
python3 phishscan/run_extract_limit_fast.py --in phishscan/dataset_phishing.csv --limit 11430 --out phishscan/dataset_extracted_11430.csv
python3 phishscan/train_model.py --dataset phishscan/dataset_extracted_11430.csv --model-out phishscan/phishscan_runtime_model_11430.pkl
```

Results (captured):

- Training completed successfully.
- Accuracy: 0.8140857392825896
- Precision: 0.8171378091872792
- Recall: 0.8092738407699037
- F1 Score: 0.8131868131868132

Artifacts produced:

- Model: `phishscan/phishscan_runtime_model_11430.pkl`
- Feature importances: `phishscan/phishscan_runtime_model_11430.pkl.feature_importances.csv`
- Metadata: `phishscan/phishscan_runtime_model_11430.pkl.meta.json`

Notes:

- These metrics were computed on a train/test split from the 11,430-row runtime-extracted dataset. They are a useful sign that the model is learning meaningful patterns, but further validation with cross-validation and held-out external test sets is recommended before trusting the model in production.


Requirement coverage
--------------------
- "Add all contents that we have included" — Done: README content, dataset description, code modules and pipeline described.
- "Generate new report" — Done: `REPORT.md` created and includes new training results.

What's next (if you'd like me to continue)
-----------------------------------------
- Expand `dataset.csv` programmatically by pulling feeds and labeling entries.
- Implement a full evaluation pipeline and regenerate model metrics.
- Produce a PDF version of the report.


