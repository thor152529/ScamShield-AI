from __future__ import annotations

from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split

from features import FEATURE_NAMES, extract_feature_vector

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT_DIR / "data" / "malicious_phish.csv"
MODEL_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODEL_DIR / "scamshield.joblib"

MAX_PER_CLASS = 15_000


def main() -> None:
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found at {DATA_PATH}. Download the Kaggle Malicious URLs Dataset "
            "(sid321axn/malicious-urls-dataset) into data/malicious_phish.csv first."
        )

    df = pd.read_csv(DATA_PATH)
    if "url" not in df.columns or "type" not in df.columns:
        raise ValueError("Expected 'url' and 'type' columns in malicious_phish.csv")

    df = df.dropna(subset=["url", "type"]).copy()
    df["type"] = df["type"].astype(str).str.strip().str.lower()

    sampled_parts = []
    for category in ("benign", "phishing", "defacement", "malware"):
        subset = df[df["type"] == category]
        if len(subset) > MAX_PER_CLASS:
            subset = subset.sample(n=MAX_PER_CLASS, random_state=42)
        sampled_parts.append(subset)

    sampled = pd.concat(sampled_parts, ignore_index=True)
    sampled["label"] = np.where(sampled["type"] == "benign", 0, 1)

    print(f"Rows used: {len(sampled)}")

    feature_rows = []
    valid_labels = []
    for raw_url, label in zip(sampled["url"], sampled["label"]):
        candidate = str(raw_url).strip()
        if not candidate.startswith(("http://", "https://")):
            candidate = f"http://{candidate}"
        try:
            vec = extract_feature_vector(candidate)
            feature_rows.append(vec)
            valid_labels.append(int(label))
        except Exception:
            continue

    X = np.array(feature_rows, dtype=np.float32)
    y = np.array(valid_labels, dtype=np.int32)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=18,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=["benign", "malicious"],
            digits=4,
        )
    )
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_prob):.4f}")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": clf,
            "feature_names": FEATURE_NAMES,
            "rows_used": int(len(X)),
        },
        MODEL_PATH,
    )
    print(f"Saved {MODEL_PATH}")


if __name__ == "__main__":
    main()
