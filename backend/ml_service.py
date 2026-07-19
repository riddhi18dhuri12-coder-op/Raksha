"""
Loads the anomaly detection model trained on real NSL-KDD data (see
ml/train_anomaly_model.py) and exposes its metrics and live predictions
to the API. If the model hasn't been trained yet, falls back gracefully
so the rest of the app still runs.
"""

import json
import random
from pathlib import Path

import joblib
import pandas as pd

ML_DIR = Path(__file__).parent.parent / "ml"

_model = None
_metrics = None
_sample_df = None
_load_error = None

CATEGORICAL = ["protocol_type", "service", "flag"]
NUMERIC_PLUS_CAT_COLUMNS = None  # set on load


def _try_load():
    global _model, _metrics, _sample_df, _load_error
    try:
        _model = joblib.load(ML_DIR / "model.joblib")
        with open(ML_DIR / "metrics.json") as f:
            _metrics = json.load(f)
        _sample_df = pd.read_csv(ML_DIR / "sample_rows.csv")
        _load_error = None
    except Exception as e:  # noqa: BLE001
        _load_error = str(e)


_try_load()


def is_ready() -> bool:
    return _model is not None


def get_metrics() -> dict:
    if not is_ready():
        return {"ready": False, "error": _load_error}
    return {"ready": True, **_metrics}


def get_random_prediction() -> dict:
    if not is_ready():
        return {"ready": False, "error": _load_error}

    row = _sample_df.sample(n=1).iloc[0]
    feature_cols = [c for c in _sample_df.columns if c not in ("label", "difficulty", "is_attack")]
    X = pd.DataFrame([row[feature_cols]])

    prediction = _model.predict(X)[0]  # -1 anomaly, 1 normal
    score = float(_model.decision_function(X)[0])

    true_label = row["label"]
    is_actually_attack = true_label != "normal"
    flagged_as_anomaly = prediction == -1

    return {
        "ready": True,
        "true_label": true_label,
        "is_actually_attack": bool(is_actually_attack),
        "flagged_as_anomaly": bool(flagged_as_anomaly),
        "correct": bool(flagged_as_anomaly == is_actually_attack),
        "anomaly_score": round(score, 4),
        "record_summary": {
            "protocol_type": row["protocol_type"],
            "service": row["service"],
            "flag": row["flag"],
            "src_bytes": int(row["src_bytes"]),
            "dst_bytes": int(row["dst_bytes"]),
            "count": int(row["count"]),
        },
    }
