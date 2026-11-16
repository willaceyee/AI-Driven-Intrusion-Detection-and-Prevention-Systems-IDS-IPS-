
from pathlib import Path

import joblib
import pandas as pd

from preprocessing.prepare import (
    ROOT,
    CATEGORICAL,
    NUMERIC,
    read_csv,
    validate_features,
)


def analyze():
    # Use validation data for diagnosis, not the official test set.
    data_path = ROOT / "data/processed/validation.csv"
    model_path = ROOT / "models/artifacts/selected_pipeline.joblib"

    data = read_csv(data_path)
    features = validate_features(data)

    actual = pd.to_numeric(data["label"]).astype(int).to_numpy()
    model = joblib.load(model_path)
    predicted = model.predict(features)

    results = features.copy()
    results.insert(0, "row_number", range(1, len(results) + 1))
    results["actual_label"] = actual
    results["predicted_label"] = predicted

    false_positives = results[
        (results["actual_label"] == 0)
        & (results["predicted_label"] == 1)
    ]

    true_negatives = results[
        (results["actual_label"] == 0)
        & (results["predicted_label"] == 0)
    ]

    print("\n=== FALSE POSITIVE ANALYSIS ===")
    print(f"Validation records: {len(results)}")
    print(f"False positives: {len(false_positives)}")
    print(f"True negatives: {len(true_negatives)}")

    normal_count = len(false_positives) + len(true_negatives)
    print(f"False-positive rate: {len(false_positives) / normal_count:.2%}")

    # Compare numeric feature distributions.
    comparison = pd.DataFrame({
        "FP_median": false_positives[NUMERIC].median(),
        "TN_median": true_negatives[NUMERIC].median(),
        "FP_mean": false_positives[NUMERIC].mean(),
        "TN_mean": true_negatives[NUMERIC].mean(),
    })

    comparison["median_difference"] = (
        comparison["FP_median"] - comparison["TN_median"]
    )

    # Compare categorical distributions within each group.
    categorical_rows = []
    for feature in CATEGORICAL:
        for group_name, group in [
            ("false_positive", false_positives),
            ("true_negative", true_negatives),
        ]:
            proportions = group[feature].value_counts(normalize=True)
            for value, proportion in proportions.items():
                categorical_rows.append({
                    "feature": feature,
                    "value": value,
                    "group": group_name,
                    "proportion": proportion,
                })

    output = ROOT / "evaluation/fp_analysis"
    output.mkdir(parents=True, exist_ok=True)

    false_positives.to_csv(output / "false_positives.csv", index=False)
    comparison.to_csv(output / "numeric_comparison.csv")
    pd.DataFrame(categorical_rows).to_csv(
        output / "categorical_comparison.csv",
        index=False,
    )

    print("\nNumeric feature comparison:")
    print(comparison.to_string())

    print(f"\nAnalysis saved to: {output}")


if __name__ == "__main__":
    analyze()
