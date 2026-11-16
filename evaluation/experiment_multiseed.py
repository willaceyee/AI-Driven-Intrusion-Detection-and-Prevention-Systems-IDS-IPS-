"""Paired multi-seed robustness check: 42-feature baseline vs without dttl.

Experimental only. Does not modify the production model, preprocessing
pipeline, API or dashboard.

Run from the repository root with:
    python -m evaluation.experiment_multiseed

Design (fixed before any results were viewed):
- Data: data/processed/train.csv only. validation.csv and the official
  test set are not read.
- For each split seed s, one grouped 80/20 partition is made with
  StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=s); the first
  fold is the evaluation partition. Identical feature records are one group
  and never cross the partition.
- On that SAME partition three models are fitted:
    baseline       42 features, Random Forest random_state = s
    without_dttl   41 features, Random Forest random_state = s
    baseline_alt   42 features, Random Forest random_state = s + 1000
  baseline_alt is a noise control: it differs from baseline only in the
  model seed, so |baseline_alt - baseline| estimates seed-to-seed variation.
- Decision threshold fixed at 0.50 (scores > 0.50 = attack), which equals the
  saved pipeline's predict() rule.

These are robustness checks on repeated splits of one dataset, not
independent tests. Splits overlap across seeds, so the t-based confidence
intervals below are exploratory only.
"""

import json
import platform
import time

import numpy as np
import pandas as pd
import sklearn
from scipy import stats
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from preprocessing.prepare import ROOT, CATEGORICAL, NUMERIC, read_csv, validate_features

SEEDS = [42, 7, 123, 2024, 31337]
CONTROL_SEED_OFFSET = 1000
THRESHOLD = 0.50
FOCUS_CATEGORIES = ["Fuzzers", "Analysis"]
CONFIGS = {
    # name: (excluded features, model-seed offset)
    "baseline": ([], 0),
    "without_dttl": (["dttl"], 0),
    "baseline_alt": ([], CONTROL_SEED_OFFSET),
}

# Pre-declared decision rule. without_dttl advances as a candidate only if ALL hold.
# Differences are baseline minus without_dttl, so positive = without_dttl better
# for FPR and positive = without_dttl worse for recall.
DECISION_RULE = {
    "C1": "without_dttl FPR lower than baseline on at least 4 of 5 seeds",
    "C2": "mean FPR reduction > noise-control spread, defined as "
          "mean |FPR(baseline_alt) - FPR(baseline)| across seeds",
    "C3": "mean overall recall drop <= 0.2 percentage points",
    "C4": "mean recall drop <= 1.0 percentage point for each of Fuzzers and Analysis",
}
MIN_SEEDS_IMPROVED = 4
MAX_RECALL_DROP = 0.002
MAX_CATEGORY_RECALL_DROP = 0.010


def make_pipeline(excluded, model_seed):
    numeric = [name for name in NUMERIC if name not in excluded]
    preprocessor = ColumnTransformer(
        [
            ("numeric", StandardScaler(), numeric),
            ("categorical", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL),
        ],
        sparse_threshold=1.0,
    )
    classifier = RandomForestClassifier(n_estimators=100, n_jobs=2, random_state=model_seed)
    return Pipeline([("preprocessing", preprocessor), ("classifier", classifier)]), numeric + CATEGORICAL


def score_metrics(y, predicted, categories):
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    row = {
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fpr": fp / (fp + tn),
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
    }
    for category in FOCUS_CATEGORIES:
        mask = (categories == category) & (y == 1)
        row[f"{category.lower()}_records"] = int(mask.sum())
        row[f"{category.lower()}_recall"] = float(predicted[mask].mean()) if mask.any() else np.nan
    return row


def paired_summary(differences):
    values = np.asarray(differences, dtype=float)
    mean, sd = values.mean(), values.std(ddof=1)
    half = stats.t.ppf(0.975, len(values) - 1) * sd / np.sqrt(len(values))
    return {
        "mean": mean, "sd": sd,
        "exploratory_ci95_low": mean - half, "exploratory_ci95_high": mean + half,
        "seeds_positive": int((values > 0).sum()),
        "seeds_negative": int((values < 0).sum()),
        "seeds_zero": int((values == 0).sum()),
    }


def run():
    frame = read_csv(ROOT / "data/processed/train.csv")
    x = validate_features(frame)
    y = pd.to_numeric(frame["label"], errors="raise").astype(int).to_numpy()
    categories = frame["attack_cat"].astype(str).str.strip().to_numpy()
    groups, _ = pd.factorize(pd.MultiIndex.from_frame(x), sort=False)

    runs = []
    for seed in SEEDS:
        splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
        fit_idx, eval_idx = next(splitter.split(x, y, groups))
        assert len(fit_idx) + len(eval_idx) == len(x)
        assert not set(groups[fit_idx]) & set(groups[eval_idx]), "Group crossed the partition."
        assert set(np.unique(y[eval_idx])) == {0, 1}

        for name, (excluded, offset) in CONFIGS.items():
            model_seed = seed + offset
            pipeline, columns = make_pipeline(excluded, model_seed)
            started = time.perf_counter()
            pipeline.fit(x.iloc[fit_idx][columns], y[fit_idx])
            fit_seconds = time.perf_counter() - started
            eval_x = x.iloc[eval_idx][columns]
            class_index = list(pipeline.classes_).index(1)
            scores = pipeline.predict_proba(eval_x)[:, class_index]
            predicted = (scores > THRESHOLD).astype(int)
            # The fixed 0.50 rule must equal the classifier's own predict().
            np.testing.assert_array_equal(predicted, pipeline.predict(eval_x))
            row = {
                "split_seed": seed, "configuration": name, "model_seed": model_seed,
                "n_features": len(columns), "fit_rows": len(fit_idx), "eval_rows": len(eval_idx),
                "eval_normal": int((y[eval_idx] == 0).sum()),
                "eval_attack": int((y[eval_idx] == 1).sum()),
                **score_metrics(y[eval_idx], predicted, categories[eval_idx]),
                "fit_seconds": round(fit_seconds, 1),
            }
            runs.append(row)
            print(json.dumps({k: (round(v, 5) if isinstance(v, float) else v)
                              for k, v in row.items()}), flush=True)

    runs = pd.DataFrame(runs)
    metrics = ["fpr", "precision", "recall", "f1", "fp", "fn", "fuzzers_recall", "analysis_recall"]
    wide = runs.pivot(index="split_seed", columns="configuration", values=metrics).loc[SEEDS]

    paired = pd.DataFrame(index=pd.Index(SEEDS, name="split_seed"))
    for metric in metrics:
        paired[f"{metric}__dttl_minus_base"] = wide[(metric, "without_dttl")] - wide[(metric, "baseline")]
        paired[f"{metric}__alt_minus_base"] = wide[(metric, "baseline_alt")] - wide[(metric, "baseline")]

    summary_rows = []
    for column in paired.columns:
        metric, comparison = column.split("__")
        summary_rows.append({"metric": metric, "comparison": comparison, **paired_summary(paired[column])})
    summary = pd.DataFrame(summary_rows)

    # Apply the pre-declared rule.
    fpr_reduction = -paired["fpr__dttl_minus_base"]          # positive = fewer FPs
    noise_spread = paired["fpr__alt_minus_base"].abs().mean()
    recall_drop = -paired["recall__dttl_minus_base"]          # positive = worse
    fuzzers_drop = -paired["fuzzers_recall__dttl_minus_base"]
    analysis_drop = -paired["analysis_recall__dttl_minus_base"]
    checks = {
        "C1": {"value": int((fpr_reduction > 0).sum()), "required": f">= {MIN_SEEDS_IMPROVED} of {len(SEEDS)}",
               "pass": bool((fpr_reduction > 0).sum() >= MIN_SEEDS_IMPROVED)},
        "C2": {"value": float(fpr_reduction.mean()), "noise_spread": float(noise_spread),
               "required": "mean FPR reduction > noise spread",
               "pass": bool(fpr_reduction.mean() > noise_spread)},
        "C3": {"value": float(recall_drop.mean()), "required": f"<= {MAX_RECALL_DROP}",
               "pass": bool(recall_drop.mean() <= MAX_RECALL_DROP)},
        "C4": {"fuzzers": float(fuzzers_drop.mean()), "analysis": float(analysis_drop.mean()),
               "required": f"each <= {MAX_CATEGORY_RECALL_DROP}",
               "pass": bool(fuzzers_drop.mean() <= MAX_CATEGORY_RECALL_DROP
                            and analysis_drop.mean() <= MAX_CATEGORY_RECALL_DROP)},
    }
    advance = all(check["pass"] for check in checks.values())

    output = ROOT / "evaluation/fp_analysis"
    output.mkdir(parents=True, exist_ok=True)
    runs.to_csv(output / "multiseed_runs.csv", index=False)
    paired.reset_index().to_csv(output / "multiseed_paired_differences.csv", index=False)
    summary.to_csv(output / "multiseed_summary.csv", index=False)
    report = {
        "purpose": "Robustness check of without_dttl vs 42-feature baseline; not an independent test",
        "data": "data/processed/train.csv only",
        "split_seeds": SEEDS, "control_model_seed_offset": CONTROL_SEED_OFFSET,
        "threshold": THRESHOLD,
        "ci_note": "t-based 95% CIs are exploratory: repeated splits share data and are not independent",
        "decision_rule": DECISION_RULE, "checks": checks,
        "without_dttl_advances": advance,
        "python": platform.python_version(), "scikit_learn": sklearn.__version__,
        "pandas": pd.__version__,
    }
    (output / "multiseed_decision.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    with pd.option_context("display.width", 200, "display.float_format", "{:.5f}".format):
        print("\n=== PER-SEED PAIRED DIFFERENCES ===")
        print(paired.to_string())
        print("\n=== SUMMARY ===")
        print(summary.to_string(index=False))
    print("\n=== DECISION ===")
    print(json.dumps(checks, indent=2))
    print("without_dttl advances:", advance)
    print("No production model, preprocessing pipeline, API or dashboard was modified.")


if __name__ == "__main__":
    run()
