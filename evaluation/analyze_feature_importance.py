
import joblib
import numpy as np
import pandas as pd

from sklearn.inspection import permutation_importance
from sklearn.metrics import recall_score, confusion_matrix

from preprocessing.prepare import (
    ROOT,
    read_csv,
    validate_features,
)


def false_positive_rate(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred, labels=[0, 1]
    ).ravel()

    return fp / (tn + fp)


def attack_recall(model, x, y):
    predicted = model.predict(x)
    return recall_score(y, predicted)


def negative_fpr(model, x, y):
    predicted = model.predict(x)
    return -false_positive_rate(y, predicted)


def main():
    validation = read_csv(
        ROOT / "data/processed/validation.csv"
    )

    x = validate_features(validation)
    y = validation["label"].astype(int).to_numpy()

    model = joblib.load(
        ROOT / "models/artifacts/selected_pipeline.joblib"
    )

    output = ROOT / "evaluation/fp_analysis"
    output.mkdir(parents=True, exist_ok=True)

    print("Calculating feature importance...")
    print("Metric 1: Attack recall")
    print("Metric 2: Negative false-positive rate")

    results = permutation_importance(
        model,
        x,
        y,
        scoring={
            "attack_recall": attack_recall,
            "negative_fpr": negative_fpr,
        },
        n_repeats=3,
        random_state=42,
        n_jobs=1,
    )

    recall_result = results["attack_recall"]
    fpr_result = results["negative_fpr"]

    report = pd.DataFrame({
        "feature": x.columns,
        "recall_importance": recall_result.importances_mean,
        "recall_std": recall_result.importances_std,
        "negative_fpr_importance": fpr_result.importances_mean,
        "negative_fpr_std": fpr_result.importances_std,
    })

    report = report.sort_values(
        "recall_importance",
        ascending=False,
    )

    print("\n=== TOP FEATURES BY ATTACK RECALL IMPORTANCE ===")
    print(report.head(15).to_string(index=False))

    print("\n=== TOP FEATURES BY NEGATIVE FPR IMPORTANCE ===")
    print(
        report.sort_values(
            "negative_fpr_importance",
            ascending=False,
        ).head(15).to_string(index=False)
    )

    report.to_csv(
        output / "feature_importance.csv",
        index=False,
    )

    print("\nSaved feature_importance.csv")
    print("Production model remains unchanged.")


if __name__ == "__main__":
    main()
