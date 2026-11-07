"""Evaluate the frozen selected pipeline without training or threshold selection."""

import hashlib
import json
import time

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    ConfusionMatrixDisplay, accuracy_score, confusion_matrix,
    f1_score, precision_score, recall_score,
)

from preprocessing.prepare import ROOT, read_csv, validate_features


def evaluate():
    output = ROOT / "evaluation"
    selection = json.loads((output / "model_selection.json").read_text())
    train_path = ROOT / "data/processed/train.csv"
    test_path = ROOT / "data/raw/UNSW_NB15_testing-set.csv"
    model_path = ROOT / "models/artifacts/selected_pipeline.joblib"
    if hashlib.sha256(train_path.read_bytes()).hexdigest() != selection["source_sha256"]["train"]:
        raise ValueError("Training data differs from the recorded model-selection input.")
    train = validate_features(read_csv(train_path))
    test = read_csv(test_path)
    features = validate_features(test)
    labels = pd.to_numeric(test["label"], errors="raise")
    if not labels.isin([0, 1]).all() or labels.nunique() != 2:
        raise ValueError("Test labels must contain both binary classes.")
    model = joblib.load(model_path)
    model.predict(features.iloc[:10])
    durations = []
    for _ in range(3):
        started = time.perf_counter()
        predictions = model.predict(features)
        durations.append(time.perf_counter() - started)
    overlap = pd.MultiIndex.from_frame(features).isin(pd.MultiIndex.from_frame(train))
    subsets = {"full_test": np.ones(len(test), dtype=bool), "without_training_overlap": ~overlap}
    results = []
    categories = []
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    for axis, (name, mask) in zip(axes, subsets.items()):
        actual, predicted = labels[mask], predictions[mask]
        tn, fp, fn, tp = confusion_matrix(actual, predicted, labels=[0, 1]).ravel()
        row = {
            "subset": name, "records": int(mask.sum()),
            "normal_records": int(tn + fp), "attack_records": int(tp + fn),
            "accuracy": accuracy_score(actual, predicted),
            "precision": precision_score(actual, predicted, zero_division=0),
            "recall": recall_score(actual, predicted, zero_division=0),
            "f1": f1_score(actual, predicted, zero_division=0),
            "false_positive_rate": float(fp / (fp + tn)),
            "true_negative": int(tn), "false_positive": int(fp),
            "false_negative": int(fn), "true_positive": int(tp),
        }
        results.append(row)
        ConfusionMatrixDisplay(
            np.array([[tn, fp], [fn, tp]]), display_labels=["Normal", "Attack"]
        ).plot(ax=axis, colorbar=False, values_format="d")
        axis.set_title(name.replace("_", " ").title())
        for category in sorted(test.loc[mask, "attack_cat"].unique()):
            selected = mask & test.attack_cat.eq(category).to_numpy()
            count = int(selected.sum())
            flagged = int(predictions[selected].sum())
            categories.append({
                "subset": name, "category": category, "records": count,
                "predicted_attack": flagged, "predicted_normal": count - flagged,
                "attack_prediction_rate": flagged / count,
            })
    fig.tight_layout()
    fig.savefig(output / "test_confusion_matrices.png", dpi=180)
    plt.close(fig)
    pd.DataFrame(results).to_csv(output / "test_results.csv", index=False)
    pd.DataFrame(categories).to_csv(output / "test_category_results.csv", index=False)
    report = {
        "model": selection["selected_model"],
        "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "test_sha256": hashlib.sha256(test_path.read_bytes()).hexdigest(),
        "training_sha256": selection["source_sha256"]["train"],
        "overlapping_test_rows": int(overlap.sum()),
        "prediction_seconds": durations,
        "median_batch_prediction_seconds": float(np.median(durations)),
        "timing_scope": "Full test batch including preprocessing; excludes CSV loading, validation and HTTP/UI",
        "decision_rule": "Saved classifier predict rule; no training or threshold tuning",
        "category_rate_meaning": "Attack detection rate for attack categories; false-positive rate for Normal",
    }
    (output / "test_evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(pd.DataFrame(results).to_string(index=False))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    evaluate()
