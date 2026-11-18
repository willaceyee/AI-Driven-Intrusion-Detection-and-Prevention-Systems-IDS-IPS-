"""Derived statistics for the SEC3044 report, computed from committed result files.

Run from the repository root with:
    python -m evaluation.report_statistics

No model is loaded, trained or scored. Every value is arithmetic on counts or
group-level rates that earlier scripts already wrote to evaluation/. Each output
row records its source file.

Outputs (evaluation/report_stats/):
    wilson_intervals.csv        95% Wilson score intervals for rates
    fpr_gap_decomposition.csv   mix / within split of the FPR gap under three references

Caveats (also written into the CSVs' notes):
- Wilson intervals assume each record is an independent Bernoulli trial with a
  fixed rate. Network records are not independent (repeated flows, shared hosts,
  duplicates), and the intervals ignore distribution shift between datasets.
  They describe sampling uncertainty within one evaluation set only and do not
  establish external generalisation.
- The decomposition is descriptive and reference-dependent: the split between
  "traffic mix" and "within-group" changes with the reference distribution and
  with the grouping. Neither component is a causal effect.
"""

import math

import pandas as pd

from preprocessing.prepare import ROOT

EVAL = ROOT / "evaluation"
OUTPUT = EVAL / "report_stats"
Z95 = 1.959963984540054
MIN_RELIABLE = 30   # same rule as evaluation/analyze_dataset_shift.py
WILSON_NOTE = ("Assumes independent Bernoulli records; ignores correlation between records and "
               "distribution shift; not evidence of external generalisation.")


def wilson(successes, trials, z=Z95):
    """Wilson score interval for a binomial proportion."""
    if trials <= 0:
        raise ValueError("trials must be positive")
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return p, max(0.0, centre - half), min(1.0, centre + half)


def interval_row(dataset, model, scope, metric, successes, trials, source):
    estimate, low, high = wilson(successes, trials)
    return {"dataset": dataset, "model": model, "scope": scope, "metric": metric,
            "successes": int(successes), "trials": int(trials), "estimate": estimate,
            "ci95_low": low, "ci95_high": high, "source_file": source, "note": WILSON_NOTE}


def binary_rows(dataset, model, scope, tn, fp, fn, tp, source):
    return [
        interval_row(dataset, model, scope, "recall (detection rate)", tp, tp + fn, source),
        interval_row(dataset, model, scope, "false-positive rate", fp, fp + tn, source),
        interval_row(dataset, model, scope, "precision", tp, tp + fp, source),
        interval_row(dataset, model, scope, "accuracy", tp + tn, tn + fp + fn + tp, source),
    ]


def wilson_table():
    rows = []
    production = "Production Random Forest (42 features, threshold 0.50)"

    source = "evaluation/validation_results.csv"
    validation = pd.read_csv(EVAL / "validation_results.csv")
    rf = validation[validation["model"] == "Random Forest"].iloc[0]
    rows += binary_rows("Validation (model-selection split)", production, "all records",
                        rf.true_negative, rf.false_positive, rf.false_negative, rf.true_positive, source)

    source = "evaluation/test_results.csv"
    for _, row in pd.read_csv(EVAL / "test_results.csv").iterrows():
        scope = {"full_test": "all records", "without_training_overlap":
                 "excluding records whose 42 features occur in training"}[row["subset"]]
        rows += binary_rows("Official UNSW-NB15 test", production, scope,
                            row.true_negative, row.false_positive, row.false_negative, row.true_positive, source)

    source = "evaluation/test_category_results.csv"
    for _, row in pd.read_csv(EVAL / "test_category_results.csv").iterrows():
        scope = {"full_test": "all records", "without_training_overlap":
                 "excluding records whose 42 features occur in training"}[row["subset"]]
        metric = ("false-positive rate (Normal)" if row["category"] == "Normal"
                  else f"detection rate: {row['category']}")
        rows.append(interval_row("Official UNSW-NB15 test", production, scope, metric,
                                 row.predicted_attack, row.records, source))

    # Internal evaluation partition (seed 42) of train.csv, experimental Random Forest
    # fitted on the 60% fitting partition (evaluation/validate_threshold_policy.py).
    source = "evaluation/fp_analysis/threshold_attack_category_analysis.csv"
    experimental = "Experimental Random Forest (fitted on 60% of train.csv)"
    for _, row in pd.read_csv(EVAL / "fp_analysis/threshold_attack_category_analysis.csv").iterrows():
        for threshold, missed in [("0.50", row.baseline_missed), ("0.60", row.candidate_missed)]:
            rows.append(interval_row("Internal evaluation partition of train.csv (seed 42)", experimental,
                                     f"threshold {threshold}", f"detection rate: {row['attack_cat']}",
                                     row.attack_records - missed, row.attack_records, source))
    source = "evaluation/fp_analysis/threshold_internal_evaluation.csv"
    for _, row in pd.read_csv(EVAL / "fp_analysis/threshold_internal_evaluation.csv").iterrows():
        rows += binary_rows("Internal evaluation partition of train.csv (seed 42)", experimental,
                            f"threshold {row.threshold:.2f}", row.tn, row.fp, row.fn, row.tp, source)
    return pd.DataFrame(rows)


def decomposition_table():
    """Split test FPR - validation FPR into mix and within-group parts, three ways.

    With s = share of normal records in a group and r = that group's FPR:
      validation reference: mix = sum (s_t - s_v) r_v,       within = sum s_t (r_t - r_v)
      test reference:       mix = sum (s_t - s_v) r_t,       within = sum s_v (r_t - r_v)
      midpoint (Shapley):   mix = sum (s_t - s_v)(r_v+r_t)/2, within = sum (s_v+s_t)/2 (r_t - r_v)
    Each pair sums exactly to the FPR gap. Groups with fewer than 30 normal records
    in a dataset share that dataset's pooled small-group rate (the validation side
    reuses val_fpr_used from analyze_dataset_shift.py; the test side applies the
    same rule to test_normal and test_fp).
    """
    source = "evaluation/shift_analysis/fpr_decomposition.csv"
    table = pd.read_csv(EVAL / "shift_analysis/fpr_decomposition.csv")
    rows = []
    for grouping, g in table.groupby("grouping", sort=False):
        g = g.copy()
        small = g["test_normal"] < MIN_RELIABLE
        pooled_test = g.loc[small, "test_fp"].sum() / g.loc[small, "test_normal"].sum()
        g["test_fpr_used"] = g["test_fpr"].where(~small, pooled_test)
        sv, st = g["val_normal_share"], g["test_normal_share"]
        rv, rt = g["val_fpr_used"], g["test_fpr_used"]
        validation_fpr, test_fpr = float((sv * rv).sum()), float((st * rt).sum())
        observed_test_fpr = g["test_fp"].sum() / g["test_normal"].sum()
        assert abs(test_fpr - observed_test_fpr) < 1e-12, (grouping, test_fpr, observed_test_fpr)
        gap = test_fpr - validation_fpr
        for reference, mix, within in [
            ("validation (original)", ((st - sv) * rv).sum(), (st * (rt - rv)).sum()),
            ("test", ((st - sv) * rt).sum(), (sv * (rt - rv)).sum()),
            ("midpoint (Shapley average)", ((st - sv) * (rv + rt) / 2).sum(), ((sv + st) / 2 * (rt - rv)).sum()),
        ]:
            assert abs(mix + within - gap) < 1e-12
            rows.append({
                "grouping": grouping, "reference": reference,
                "validation_fpr": validation_fpr, "test_fpr": test_fpr, "gap": gap,
                "mix_effect": float(mix), "within_group_effect": float(within),
                "mix_share_of_gap": float(mix / gap),
                "groups": len(g), "test_normals_in_small_groups": int(g.loc[small, "test_normal"].sum()),
                "source_file": source,
                "note": "Descriptive and reference-dependent; not a causal decomposition.",
            })
    return pd.DataFrame(rows)


def run():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    wilson_results = wilson_table()
    decomposition = decomposition_table()
    wilson_results.to_csv(OUTPUT / "wilson_intervals.csv", index=False)
    decomposition.to_csv(OUTPUT / "fpr_gap_decomposition.csv", index=False)
    with pd.option_context("display.width", 220, "display.max_colwidth", 60, "display.float_format", "{:.4f}".format):
        print(wilson_results.drop(columns=["note", "source_file", "model"]).to_string(index=False))
        print(decomposition.drop(columns=["note", "source_file"]).to_string(index=False))
    print("No model was loaded, trained or scored.")


if __name__ == "__main__":
    run()
