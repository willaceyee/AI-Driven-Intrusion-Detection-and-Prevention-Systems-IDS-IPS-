
"""Exploratory TTL ablation without modifying the production model."""

import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from preprocessing.prepare import (
    ROOT, CATEGORICAL, NUMERIC, read_csv, validate_features
)

SEED = 42
THRESHOLDS = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.90]
MIN_RECALL = 0.95

CONFIGS = {
    "baseline": [],
    "without_dttl": ["dttl"],
    "without_both_ttl": ["sttl", "dttl"],
}


def split_indices(x, y, groups, n_splits):
    splitter = StratifiedGroupKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=SEED,
    )
    return next(splitter.split(x, y, groups))


def metrics(y, scores, threshold):
    predicted = (scores > threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(
        y, predicted, labels=[0, 1]
    ).ravel()

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0

    return {
        "threshold": threshold,
        "fp": int(fp),
        "fn": int(fn),
        "fpr": fp / (fp + tn),
        "recall": recall,
        "precision": precision,
        "f1": (
            2 * precision * recall / (precision + recall)
            if precision + recall else 0
        ),
    }


def run():
    frame = read_csv(ROOT / "data/processed/train.csv")
    if "attack_cat" not in frame.columns:
        raise ValueError("Training CSV requires attack_cat for category analysis.")

    x = validate_features(frame)
    y = frame["label"].astype(int).to_numpy()

    groups, _ = pd.factorize(
        pd.MultiIndex.from_frame(x), sort=False
    )

    dev_idx, eval_idx = split_indices(
        x, y, groups, 5
    )

    fit_rel, cal_rel = split_indices(
        x.iloc[dev_idx],
        y[dev_idx],
        groups[dev_idx],
        4,
    )

    fit_idx = dev_idx[fit_rel]
    cal_idx = dev_idx[cal_rel]

    partitions = [fit_idx, cal_idx, eval_idx]
    assert sum(len(p) for p in partitions) == len(x)
    assert all(
        not set(groups[a]).intersection(groups[b])
        for i, a in enumerate(partitions)
        for b in partitions[i + 1:]
    )

    output = ROOT / "evaluation/fp_analysis"
    output.mkdir(parents=True, exist_ok=True)

    calibration_rows = []
    evaluation_rows = []
    category_rows = []

    for name, excluded in CONFIGS.items():
        print(f"\n=== TRAINING {name} ===", flush=True)

        numeric = [
            feature for feature in NUMERIC
            if feature not in excluded
        ]
        columns = numeric + CATEGORICAL

        preprocessor = ColumnTransformer(
            [
                ("numeric", StandardScaler(), numeric),
                (
                    "categorical",
                    OneHotEncoder(handle_unknown="ignore"),
                    CATEGORICAL,
                ),
            ],
            sparse_threshold=1.0,
        )

        model = Pipeline([
            ("preprocessing", preprocessor),
            ("classifier", RandomForestClassifier(
                n_estimators=100,
                n_jobs=2,
                random_state=SEED,
            )),
        ])

        model.fit(x.iloc[fit_idx][columns], y[fit_idx])
        class_index = list(model.classes_).index(1)

        cal_scores = model.predict_proba(
            x.iloc[cal_idx][columns]
        )[:, class_index]

        results = [
            metrics(y[cal_idx], cal_scores, t)
            for t in THRESHOLDS
        ]

        for row in results:
            calibration_rows.append({
                "configuration": name, **row
            })

        eligible = [
            row for row in results
            if row["recall"] >= MIN_RECALL
        ]

        if not eligible:
            selected = 0.50
            meets_policy = False
        else:
            best = min(
                eligible,
                key=lambda row: (
                    row["fpr"],
                    -row["recall"],
                    row["threshold"],
                ),
            )
            selected = best["threshold"]
            meets_policy = True

        eval_scores = model.predict_proba(
            x.iloc[eval_idx][columns]
        )[:, class_index]

        # Read-only diagnostic on a previously inspected
        # internal evaluation partition.
        for threshold in sorted(set([0.50, selected])):
            row = metrics(y[eval_idx], eval_scores, threshold)
            evaluation_rows.append({
                "configuration": name,
                "selected_threshold": selected,
                "calibration_policy_met": meets_policy,
                **row,
            })

            print({
                "configuration": name,
                **row,
            }, flush=True)

        attacks = frame.iloc[eval_idx][["attack_cat"]].copy()
        attacks["label"] = y[eval_idx]
        attacks["threshold_050_missed"] = (
            eval_scores <= 0.50
        )
        attacks["selected_threshold_missed"] = (
            eval_scores <= selected
        )
        attacks = attacks[attacks["label"] == 1]

        category_summary = (
            attacks.groupby("attack_cat", dropna=False)
            .agg(
                attack_records=("label", "size"),
                threshold_050_missed=("threshold_050_missed", "sum"),
                selected_threshold_missed=("selected_threshold_missed", "sum"),
            )
            .reset_index()
        )
        category_summary["additional_missed"] = (
            category_summary["selected_threshold_missed"]
            - category_summary["threshold_050_missed"]
        )
        category_summary["threshold_050_recall"] = (
            1 - category_summary["threshold_050_missed"]
            / category_summary["attack_records"]
        )
        category_summary["selected_threshold_recall"] = (
            1 - category_summary["selected_threshold_missed"]
            / category_summary["attack_records"]
        )
        for row in category_summary.to_dict(orient="records"):
            category_rows.append({
                "configuration": name,
                "selected_threshold": selected,
                **row,
            })

    pd.DataFrame(calibration_rows).to_csv(
        output / "ttl_ablation_calibration.csv",
        index=False,
    )

    pd.DataFrame(evaluation_rows).to_csv(
        output / "ttl_ablation_evaluation.csv",
        index=False,
    )

    category_results = pd.DataFrame(category_rows).sort_values(
        ["configuration", "additional_missed"],
        ascending=[True, False],
    )
    category_results.to_csv(
        output / "ttl_ablation_attack_category_analysis.csv",
        index=False,
    )

    print("\n=== ATTACK CATEGORY ANALYSIS ===")
    print(category_results.to_string(index=False))

    print("\nExperiment completed.")
    print("No production model was modified.")


if __name__ == "__main__":
    run()
