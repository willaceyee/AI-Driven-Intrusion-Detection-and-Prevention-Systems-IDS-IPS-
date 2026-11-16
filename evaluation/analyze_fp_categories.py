
import pandas as pd

from preprocessing.prepare import ROOT, read_csv

def analyze():
    validation = read_csv(
        ROOT / "data/processed/validation.csv"
    )

    fp = pd.read_csv(
        ROOT / "evaluation/fp_analysis/false_positives.csv"
    )

    # Previous analysis assigned row numbers starting from 1.
    validation["row_number"] = range(
        1, len(validation) + 1
    )

    # Only normal records are relevant to the FPR.
    normal = validation[
        validation["label"].astype(int) == 0
    ].copy()

    fp_rows = set(fp["row_number"])
    normal["is_false_positive"] = (
        normal["row_number"].isin(fp_rows)
    )

    output = ROOT / "evaluation/fp_analysis"
    summaries = []

    for feature in ["proto", "service", "state"]:
        summary = (
            normal.groupby(feature, dropna=False)
            ["is_false_positive"]
            .agg(["size", "sum", "mean"])
            .reset_index()
        )

        summary.columns = [
            "value", "normal_records",
            "false_positives", "false_positive_rate"
        ]

        summary.insert(0, "feature", feature)
        summaries.append(summary)

        print(f"\n=== {feature.upper()} ===")
        print(
            summary.sort_values(
                "false_positives", ascending=False
            ).head(10).to_string(index=False)
        )

    combined = pd.concat(summaries, ignore_index=True)

    combined.to_csv(
        output / "categorical_fp_rates.csv",
        index=False
    )

    print("\nSaved categorical_fp_rates.csv")


if __name__ == "__main__":
    analyze()
