
import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)

from preprocessing.prepare import (
    ROOT,
    read_csv,
    validate_features,
)


def analyze():
    validation = read_csv(
        ROOT / "data/processed/validation.csv"
    )

    features = validate_features(validation)
    actual = validation["label"].astype(int).to_numpy()

    model = joblib.load(
        ROOT / "models/artifacts/selected_pipeline.joblib"
    )

    class_index = list(model.classes_).index(1)
    probabilities = model.predict_proba(features)
    scores = probabilities[:, class_index]

    # Diagnostic thresholds only.
    thresholds = [0.5, 0.6, 0.7, 0.8, 0.9]
    results = []

    for threshold in thresholds:
        # For this binary Random Forest, ties at 0.5
        # are classified as normal.
        predicted = (scores > threshold).astype(int)

        tn, fp, fn, tp = confusion_matrix(
            actual, predicted, labels=[0, 1]
        ).ravel()

        results.append({
            "threshold": threshold,
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "true_negatives": int(tn),
            "fpr": fp / (fp + tn),
            "precision": precision_score(
                actual, predicted
            ),
            "recall": recall_score(
                actual, predicted
            ),
            "f1": f1_score(
                actual, predicted
            ),
        })

    results_df = pd.DataFrame(results)

    # Ensure the original threshold reproduces
    # the existing baseline classifier decisions.
    baseline = model.predict(features)
    experimental_baseline = (
        scores > 0.5
    ).astype(int)

    assert np.array_equal(
        baseline, experimental_baseline
    ), "Baseline decision rule mismatch."

    output = ROOT / "evaluation/fp_analysis"
    output.mkdir(parents=True, exist_ok=True)

    results_df.to_csv(
        output / "threshold_analysis.csv",
        index=False,
    )

    print("\n=== THRESHOLD ANALYSIS ===")
    print(results_df.to_string(index=False))
    print("\nSaved threshold_analysis.csv")


if __name__ == "__main__":
    analyze()
