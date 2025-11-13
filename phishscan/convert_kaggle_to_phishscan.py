"""Convert Kaggle 'Web page Phishing Detection Dataset' CSV into PhishScan schema.
Usage: python convert_kaggle_to_phishscan.py <kaggle_csv> <out_csv>
This script maps common Kaggle columns to the feature names expected by train_model.py
"""
import sys
import pandas as pd

MAPPING = {
    # example mappings - adjust if Kaggle CSV uses different names
    "UrlLength": "url_length",
    "NumDots": "num_dots",
    "NumSlashes": "num_slashes",
    "HaveIP": "has_ip",
    "Entropy": "entropy",
    "IsLoginForm": "login_form_present",
    "DomainAge": "domain_age_days",
    "JSLength": "script_count",
    "NumDigits": "num_digits",
    "NumSpecialChars": "num_special_chars",
    # add more mappings as you discover them
}

def convert(in_path, out_path):
    df = pd.read_csv(in_path)
    out = pd.DataFrame()
    for kaggle_col, out_col in MAPPING.items():
        if kaggle_col in df.columns:
            out[out_col] = df[kaggle_col]
        else:
            out[out_col] = 0

    # Ensure label is present
    if "phishing" in df.columns:
        out["label"] = df["phishing"].astype(int)
    elif "Label" in df.columns:
        out["label"] = df["Label"].astype(int)
    else:
        # Fallback: if there's a 'Status' or similar
        if "Status" in df.columns:
            out["label"] = (df["Status"].str.lower() == "phishing").astype(int)
        else:
            raise RuntimeError("No label column found in Kaggle CSV; please inspect file and set mapping.")

    out.to_csv(out_path, index=False)
    print(f"Converted {in_path} -> {out_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python convert_kaggle_to_phishscan.py <kaggle_csv> <out_csv>")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
