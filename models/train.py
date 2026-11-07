"""Run baseline model comparison using only the prepared training/validation data.

Run from the repository root with: python -m models.train
"""

import hashlib
import json
import platform
import time
import warnings

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier

from preprocessing.prepare import ROOT, FEATURES, make_preprocessor, read_csv, validate_features


def train():
    paths = {name: ROOT / f"data/processed/{name}.csv" for name in ["train", "validation"]}
    frames = {name: read_csv(path) for name, path in paths.items()}
    inputs = {name: validate_features(frame) for name, frame in frames.items()}
    labels = {}
    for name, frame in frames.items():
        values = pd.to_numeric(frame["label"], errors="raise")
        if not values.isin([0, 1]).all() or values.nunique() != 2:
            raise ValueError(f"{name} must contain both binary label classes.")
        labels[name] = values.astype(int)
    train_groups = pd.MultiIndex.from_frame(inputs["train"])
    validation_groups = pd.MultiIndex.from_frame(inputs["validation"])
    if len(train_groups.intersection(validation_groups)):
        raise ValueError("Training and validation contain identical feature records.")

    candidates = {
        "Logistic Regression": LogisticRegression(solver="liblinear", max_iter=2000, random_state=42),
        "Decision Tree": DecisionTreeClassifier(random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, n_jobs=2, random_state=42),
    }
    results = []
    best_pipeline = None
    best_key = None
    best_name = None
    for name, classifier in candidates.items():
        print(f"Training {name}...", flush=True)
        pipeline = Pipeline([("preprocessing", make_preprocessor()), ("classifier", classifier)])
        started = time.perf_counter()
        with warnings.catch_warnings():
            warnings.simplefilter("error", ConvergenceWarning)
            pipeline.fit(inputs["train"], labels["train"])
        fit_seconds = time.perf_counter() - started
        pipeline.predict(inputs["validation"].iloc[:10])
        timings = []
        for _ in range(3):
            started = time.perf_counter()
            predictions = pipeline.predict(inputs["validation"])
            timings.append(time.perf_counter() - started)
        tn, fp, fn, tp = confusion_matrix(labels["validation"], predictions, labels=[0, 1]).ravel()
        row = {
            "model": name,
            "precision": precision_score(labels["validation"], predictions, zero_division=0),
            "recall": recall_score(labels["validation"], predictions, zero_division=0),
            "f1": f1_score(labels["validation"], predictions, zero_division=0),
            "false_positive_rate": float(fp / (fp + tn)),
            "true_negative": int(tn), "false_positive": int(fp),
            "false_negative": int(fn), "true_positive": int(tp),
            "fit_seconds": fit_seconds,
            "median_batch_prediction_seconds": float(np.median(timings)),
        }
        results.append(row)
        key = (row["f1"], -row["false_positive_rate"])
        if best_key is None or key > best_key:
            best_key, best_name, best_pipeline = key, name, pipeline
        print(json.dumps(row), flush=True)

    artifacts = ROOT / "models/artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    model_path = artifacts / "selected_pipeline.joblib"
    joblib.dump(best_pipeline, model_path)
    restored = joblib.load(model_path)
    sample = inputs["validation"].iloc[:100]
    if not np.array_equal(best_pipeline.predict(sample), restored.predict(sample)):
        raise RuntimeError("Reloaded pipeline predictions differ.")

    evaluation = ROOT / "evaluation"
    pd.DataFrame(results).to_csv(evaluation / "validation_results.csv", index=False)
    metadata = {
        "selected_model": best_name,
        "selection_rule": "Highest validation attack-class F1; ties use lower false-positive rate",
        "threshold_policy": "Each classifier's default predict decision rule; no threshold tuning",
        "seed": 42,
        "python": platform.python_version(), "scikit_learn": sklearn.__version__,
        "input_features": FEATURES,
        "source_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()},
        "rows": {name: len(frame) for name, frame in frames.items()},
        "classifier_parameters": {name: model.get_params() for name, model in candidates.items()},
        "timing_scope": "Median of 3 warm batch predictions including preprocessing, excluding CSV loading and validation",
        "reload_check": "100 validation predictions matched",
    }
    (evaluation / "model_selection.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Selected {best_name}. Saved pipeline and validation reports.", flush=True)


if __name__ == "__main__":
    train()
