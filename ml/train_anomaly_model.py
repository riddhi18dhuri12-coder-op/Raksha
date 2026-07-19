"""
Trains RAKSHA's behavioral anomaly detection model on the real NSL-KDD
intrusion detection dataset.

Deliberately unsupervised: the model is fit ONLY on records labeled
"normal" in the training set -- it never sees an attack during training.
This mirrors the actual pitch of the project ("learn what normal looks
like, flag deviations") rather than training a supervised attack
classifier, which would just be signature detection with extra steps.

Run:
    python train_anomaly_model.py

Outputs:
    model.joblib          -- fitted IsolationForest + preprocessing pipeline
    metrics.json           -- detection rate / false positive rate on the
                              real NSL-KDD test set, for the dashboard and
                              the pitch deck
"""

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

DATA_DIR = Path(__file__).parent / "data"
OUT_DIR = Path(__file__).parent

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]

CATEGORICAL = ["protocol_type", "service", "flag"]
NUMERIC = [c for c in COLUMNS if c not in CATEGORICAL + ["label", "difficulty"]]


def load(path):
    df = pd.read_csv(path, names=COLUMNS)
    df["is_attack"] = (df["label"] != "normal").astype(int)
    return df


def build_pipeline():
    preprocessor = ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL),
        ("num", StandardScaler(), NUMERIC),
    ])
    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,  # assume ~5% of "normal-looking" baseline still has noise
        random_state=42,
        n_jobs=-1,
    )
    return Pipeline([("prep", preprocessor), ("model", model)])


def main():
    print("Loading NSL-KDD dataset...")
    train_df = load(DATA_DIR / "KDDTrain.txt")
    test_df = load(DATA_DIR / "KDDTest.txt")

    # Train ONLY on normal traffic -- this is the behavioral baseline approach.
    normal_train = train_df[train_df["is_attack"] == 0]
    print(f"Training on {len(normal_train)} normal-only records "
          f"(out of {len(train_df)} total training records).")

    pipeline = build_pipeline()
    t0 = time.time()
    pipeline.fit(normal_train[CATEGORICAL + NUMERIC])
    train_time = time.time() - t0
    print(f"Trained in {train_time:.1f}s.")

    # Evaluate on the held-out REAL test set, which contains real attacks
    # the model never saw during training.
    X_test = test_df[CATEGORICAL + NUMERIC]
    y_test = test_df["is_attack"].values

    raw_scores = pipeline.decision_function(X_test)  # higher = more normal
    predictions = pipeline.predict(X_test)  # -1 = anomaly, 1 = normal
    is_anomaly = (predictions == -1).astype(int)

    true_positives = np.sum((is_anomaly == 1) & (y_test == 1))
    false_negatives = np.sum((is_anomaly == 0) & (y_test == 1))
    false_positives = np.sum((is_anomaly == 1) & (y_test == 0))
    true_negatives = np.sum((is_anomaly == 0) & (y_test == 0))

    detection_rate = true_positives / (true_positives + false_negatives)
    false_positive_rate = false_positives / (false_positives + true_negatives)

    metrics = {
        "dataset": "NSL-KDD (real, public benchmark)",
        "train_records_normal_only": int(len(normal_train)),
        "test_records_total": int(len(test_df)),
        "test_records_attacks": int(y_test.sum()),
        "detection_rate": round(float(detection_rate), 4),
        "false_positive_rate": round(float(false_positive_rate), 4),
        "true_positives": int(true_positives),
        "false_negatives": int(false_negatives),
        "false_positives": int(false_positives),
        "true_negatives": int(true_negatives),
        "trained_at": time.time(),
    }

    print(json.dumps(metrics, indent=2))

    joblib.dump(pipeline, OUT_DIR / "model.joblib")
    with open(OUT_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    # Also save a small sample of test rows (mixed normal + attack) so the
    # API can serve "live" predictions on real records in a demo endpoint.
    sample = test_df.sample(n=40, random_state=7)
    sample.to_csv(OUT_DIR / "sample_rows.csv", index=False)

    print(f"\nSaved model.joblib, metrics.json, sample_rows.csv to {OUT_DIR}")


if __name__ == "__main__":
    main()
