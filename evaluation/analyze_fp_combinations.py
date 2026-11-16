
import pandas as pd

from preprocessing.prepare import ROOT, read_csv


def analyze():
    folder = ROOT / "evaluation/fp_analysis"

    validation = read_csv(
        ROOT / "data/processed/validation.csv"
    )

    training = read_csv(
        ROOT / "data/processed/train.csv"
    )

    fp = pd.read_csv(folder / "false_positives.csv")

    validation["row_number"] = range(
        1, len(validation) + 1
    )

    normal = validation[
        validation["label"].astype(int) == 0
    ].copy()

    normal["is_fp"] = normal["row_number"].isin(
        fp["row_number"]
    )

    columns = ["proto", "service", "state"]

    summary = (
        normal.groupby(columns)
        .agg(
            normal_records=("is_fp", "size"),
            false_positives=("is_fp", "sum")
        )
        .reset_index()
    )

    summary["fpr"] = (
        summary["false_positives"]
        / summary["normal_records"]
    )

    summary["fp_share"] = (
        summary["false_positives"]
        / normal["is_fp"].sum()
    )

    # Check normal training data representation.
    train_normal = training[
        training["label"].astype(int) == 0
    ]

    train_counts = (
        train_normal.groupby(columns)
        .size()
        .reset_index(name="train_normal_records")
    )

    summary = summary.merge(
        train_counts,
        on=columns,
        how="left"
    )

    summary["train_normal_records"] = (
        summary["train_normal_records"]
        .fillna(0)
        .astype(int)
    )

    summary = summary.sort_values(
        ["false_positives", "fpr"],
        ascending=False
    )

    summary.to_csv(
        folder / "combination_analysis.csv",
        index=False
    )

    print("\n=== TOP FALSE POSITIVE COMBINATIONS ===")
    print(
        summary[summary["normal_records"] >= 30]
        .head(20)
        .to_string(index=False)
    )

    print("\n=== COVERAGE CHECK ===")
    print("Total false positives:", summary["false_positives"].sum())
    print("Total normal records:", summary["normal_records"].sum())

    print("\nSaved combination_analysis.csv")


if __name__ == "__main__":
    analyze()
