
"""Compare Random Forest thresholds using separate development partitions."""

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline

from preprocessing.prepare import (
    ROOT,
    make_preprocessor,
    read_csv,
    validate_features,
)


THRESHOLDS = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.90]
MIN_RECALL = 0.95
SEED = 42


def evaluate_scores(actual, scores, threshold):
    predicted = (scores > threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        actual, predicted, labels=[0, 1]
    ).ravel()

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )

    return {
        "threshold": threshold,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "fpr": fpr,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def group_split(x, y, groups, n_splits):
    splitter = StratifiedGroupKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=SEED,
    )
    return next(splitter.split(x, y, groups))


def main():
    path = ROOT / "data/processed/train.csv"
    frame = read_csv(path)

    x = validate_features(frame)
    y = frame["label"].astype(int).to_numpy()

    # Identical feature rows always belong to the same group.
    groups, _ = pd.factorize(
        pd.MultiIndex.from_frame(x), sort=False
    )

    # First split: approximately 80% development,
    # 20% independent internal evaluation.
    dev_idx, eval_idx = group_split(x, y, groups, 5)

    # Second split: approximately 75% fitting,
    # 25% calibration within development.
    fit_relative, cal_relative = group_split(
        x.iloc[dev_idx],
        y[dev_idx],
        groups[dev_idx],
        4,
    )

    fit_idx = dev_idx[fit_relative]
    cal_idx = dev_idx[cal_relative]

    partitions = [fit_idx, cal_idx, eval_idx]

    assert len(set(map(int, np.concatenate(partitions)))) == len(x)
    assert all(len(set(groups[a]) & set(groups[b])) == 0
               for i, a in enumerate(partitions)
               for b in partitions[i + 1:])

    for name, idx in zip(
        ["Fitting", "Calibration", "Evaluation"], partitions
    ):
        print(
            f"{name}: {len(idx)} rows, "
            f"normal={int((y[idx] == 0).sum())}, "
            f"attack={int((y[idx] == 1).sum())}"
        )
        assert set(np.unique(y[idx])) == {0, 1}

    # Fit a NEW experimental model.
    # Do not overwrite the original saved pipeline.
    model = Pipeline([
        ("preprocessing", make_preprocessor()),
        ("classifier", RandomForestClassifier(
            n_estimators=100,
            n_jobs=2,
            random_state=SEED,
        )),
    ])

    print("\nTraining experimental Random Forest...")
    model.fit(x.iloc[fit_idx], y[fit_idx])

    class_index = list(model.classes_).index(1)

    cal_scores = model.predict_proba(
        x.iloc[cal_idx]
    )[:, class_index]

    calibration_rows = [
        evaluate_scores(y[cal_idx], cal_scores, t)
        for t in THRESHOLDS
    ]
    calibration = pd.DataFrame(calibration_rows)

    # Pick the lowest FPR that satisfies the recall floor.
    eligible = calibration[
        calibration["recall"] >= MIN_RECALL
    ]

    if eligible.empty:
        selected = 0.50
        print("\nNo threshold met recall requirement.")
        print("Retaining 0.50 as the fallback.")
    else:
        selected = float(
            eligible.sort_values(
                ["fpr", "recall", "threshold"],
                ascending=[True, False, True],
            ).iloc[0]["threshold"]
        )

    print("\n=== CALIBRATION RESULTS ===")
    print(calibration.to_string(index=False))
    print(f"\nSelected experimental threshold: {selected:.2f}")

    # Check baseline decision semantics.
    eval_x = x.iloc[eval_idx]
    baseline_predictions = model.predict(eval_x)
    eval_scores = model.predict_proba(
        eval_x
    )[:, class_index]

    np.testing.assert_array_equal(
        baseline_predictions,
        (eval_scores > 0.50).astype(int),
    )

    # Internal evaluation is used only after selection.
    comparison = pd.DataFrame([
        evaluate_scores(y[eval_idx], eval_scores, 0.50),
        evaluate_scores(y[eval_idx], eval_scores, selected),
    ])

    print("\n=== INTERNAL EVALUATION ===")
    print(comparison.to_string(index=False))

    output = ROOT / "evaluation/fp_analysis"
    output.mkdir(parents=True, exist_ok=True)


    # Analyze which attack categories lose detections.
    evaluation_records = frame.iloc[eval_idx].copy()

    evaluation_records["baseline_prediction"] = (
        eval_scores > 0.50
    ).astype(int)

    evaluation_records["candidate_prediction"] = (
        eval_scores > selected
    ).astype(int)

    # Consider malicious traffic only.
    attacks = evaluation_records[
        evaluation_records["label"].astype(int) == 1
    ].copy()

    attacks["baseline_missed"] = (
        attacks["baseline_prediction"] == 0
    )

    attacks["candidate_missed"] = (
        attacks["candidate_prediction"] == 0
    )

    category_results = (
        attacks.groupby("attack_cat")
        .agg(
            attack_records=("label", "size"),
            baseline_missed=("baseline_missed", "sum"),
            candidate_missed=("candidate_missed", "sum"),
        )
        .reset_index()
    )

    category_results["additional_missed"] = (
        category_results["candidate_missed"]
        - category_results["baseline_missed"]
    )

    category_results["baseline_recall"] = (
        1 - category_results["baseline_missed"]
        / category_results["attack_records"]
    )

    category_results["candidate_recall"] = (
        1 - category_results["candidate_missed"]
        / category_results["attack_records"]
    )

    category_results = category_results.sort_values(
        "additional_missed", ascending=False
    )

    print("\n=== ATTACK CATEGORY SAFETY ANALYSIS ===")
    print(category_results.to_string(index=False))

    print(
        "\nTotal additional missed attacks:",
        category_results["additional_missed"].sum()
    )

    category_results.to_csv(
        output / "threshold_attack_category_analysis.csv",
        index=False,
    )

    calibration.to_csv(
        output / "threshold_calibration.csv",
        index=False,
    )
    comparison.to_csv(
        output / "threshold_internal_evaluation.csv",
        index=False,
    )

    print("\nNo production model or API files were modified.")
    print(f"Reports saved to: {output}")


if __name__ == "__main__":
    main()
