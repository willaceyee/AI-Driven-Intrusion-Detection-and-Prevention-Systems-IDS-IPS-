"""Paired multi-seed robustness check: 42-feature baseline vs TTL-free model.

Experimental only. Does not modify the production model, preprocessing
pipeline, FastAPI or Streamlit. Does not read the official test set.

Run from the repository root with:
    python -m evaluation.experiment_ttl_free_multiseed

Motivation: evaluation/analyze_dataset_shift.py found that normal records with
sttl 62 or 254 (values that are mostly attacks in training) cause most
official-test false positives. This experiment asks whether removing all TTL
information (sttl, dttl and ct_state_ttl, which is derived from TTL) lowers
false positives on that slice without unacceptable loss of attack detection.

Design (identical to evaluation/experiment_multiseed.py, fixed before running):
- Data: data/processed/train.csv only.
- Split seeds 42, 7, 123, 2024, 31337; for each, one grouped 80/20 partition
  (StratifiedGroupKFold, first fold). Identical feature records never cross it.
- On the SAME partition per seed:
    baseline       42 features, Random Forest random_state = s
    ttl_free       39 features (no sttl, dttl, ct_state_ttl), random_state = s
    baseline_alt   42 features, random_state = s + 1000 (noise control)
- Threshold fixed at 0.50 (equals predict()).

These are robustness checks on repeated splits of one dataset, not independent
tests; t-based intervals are exploratory only.
"""

import json
import platform
import time

import numpy as np
import pandas as pd
import sklearn
from scipy import stats
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold

from evaluation.experiment_multiseed import make_pipeline
from preprocessing.prepare import ROOT, read_csv, validate_features

SEEDS = [42, 7, 123, 2024, 31337]
CONTROL_SEED_OFFSET = 1000
THRESHOLD = 0.50
TTL_FEATURES = ["sttl", "dttl", "ct_state_ttl"]
SLICE_STTL = [62, 254]
CONFIGS = {
    "baseline": ([], 0),
    "ttl_free": (TTL_FEATURES, 0),
    "baseline_alt": ([], CONTROL_SEED_OFFSET),
}

# Pre-declared exploratory acceptance criteria (approved before execution).
CRITERIA = {
    "C1": "FPR on normals with sttl in {62, 254} decreases on >= 4 of 5 seeds AND the mean "
          "decrease exceeds the noise-control variation, defined as mean |slice FPR(baseline_alt) "
          "- slice FPR(baseline)| across seeds",
    "C2": "mean overall attack recall decreases by <= 0.5 percentage points",
    "C3": "mean Fuzzers recall and mean Analysis recall each decrease by <= 2 percentage points",
    "C4": "mean overall FPR increases by <= 0.5 percentage points",
}
MIN_SEEDS_IMPROVED = 4
MAX_RECALL_DROP = 0.005
MAX_CATEGORY_RECALL_DROP = 0.020
MAX_FPR_INCREASE = 0.005


def run_metrics(y, predicted, categories, sttl):
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    slice_mask = (y == 0) & np.isin(sttl, SLICE_STTL)
    other_normal = (y == 0) & ~np.isin(sttl, SLICE_STTL)
    row = {
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "fpr": fp / (fp + tn), "precision": precision, "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "slice_normals": int(slice_mask.sum()), "slice_fp": int(predicted[slice_mask].sum()),
        "slice_fpr": float(predicted[slice_mask].mean()),
        "other_normal_fp": int(predicted[other_normal].sum()),
        "other_normal_fpr": float(predicted[other_normal].mean()),
    }
    for category in sorted(set(categories[y == 1])):
        mask = (categories == category) & (y == 1)
        row[f"recall_{category.lower()}"] = float(predicted[mask].mean())
    return row


def summarise(values):
    values = np.asarray(values, dtype=float)
    mean, sd = values.mean(), values.std(ddof=1)
    half = stats.t.ppf(0.975, len(values) - 1) * sd / np.sqrt(len(values))
    return {"mean": mean, "sd": sd, "exploratory_ci95_low": mean - half,
            "exploratory_ci95_high": mean + half, "min": values.min(), "max": values.max(),
            "seeds_positive": int((values > 0).sum()), "seeds_negative": int((values < 0).sum())}


def run():
    frame = read_csv(ROOT / "data/processed/train.csv")
    x = validate_features(frame)
    y = pd.to_numeric(frame["label"], errors="raise").astype(int).to_numpy()
    categories = frame["attack_cat"].astype(str).str.strip().to_numpy()
    sttl = x["sttl"].to_numpy()
    groups, _ = pd.factorize(pd.MultiIndex.from_frame(x), sort=False)

    runs = []
    for seed in SEEDS:
        splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
        fit_idx, eval_idx = next(splitter.split(x, y, groups))
        assert len(fit_idx) + len(eval_idx) == len(x)
        assert not set(groups[fit_idx]) & set(groups[eval_idx]), "Group crossed the partition."
        for name, (excluded, offset) in CONFIGS.items():
            pipeline, columns = make_pipeline(excluded, seed + offset)
            assert not set(excluded) & set(columns)
            started = time.perf_counter()
            pipeline.fit(x.iloc[fit_idx][columns], y[fit_idx])
            fit_seconds = time.perf_counter() - started
            eval_x = x.iloc[eval_idx][columns]
            scores = pipeline.predict_proba(eval_x)[:, list(pipeline.classes_).index(1)]
            predicted = (scores > THRESHOLD).astype(int)
            np.testing.assert_array_equal(predicted, pipeline.predict(eval_x))
            row = {"split_seed": seed, "configuration": name, "model_seed": seed + offset,
                   "n_features": len(columns), "fit_rows": len(fit_idx), "eval_rows": len(eval_idx),
                   **run_metrics(y[eval_idx], predicted, categories[eval_idx], sttl[eval_idx]),
                   "fit_seconds": round(fit_seconds, 1)}
            runs.append(row)
            print(json.dumps({k: (round(v, 5) if isinstance(v, float) else v) for k, v in row.items()}),
                  flush=True)

    runs = pd.DataFrame(runs)
    metric_columns = [c for c in runs.columns if c not in
                      {"split_seed", "configuration", "model_seed", "n_features", "fit_rows",
                       "eval_rows", "fit_seconds", "tn", "tp"}]
    wide = runs.pivot(index="split_seed", columns="configuration", values=metric_columns).loc[SEEDS]
    paired = pd.DataFrame(index=pd.Index(SEEDS, name="split_seed"))
    for metric in metric_columns:
        paired[f"{metric}__ttlfree_minus_base"] = wide[(metric, "ttl_free")] - wide[(metric, "baseline")]
        paired[f"{metric}__alt_minus_base"] = wide[(metric, "baseline_alt")] - wide[(metric, "baseline")]
    summary = pd.DataFrame([{"metric": c.split("__")[0], "comparison": c.split("__")[1], **summarise(paired[c])}
                            for c in paired.columns])

    # Apply the pre-declared criteria. Positive "reduction"/"drop" = direction named.
    slice_reduction = -paired["slice_fpr__ttlfree_minus_base"]
    slice_noise = paired["slice_fpr__alt_minus_base"].abs().mean()
    recall_drop = -paired["recall__ttlfree_minus_base"]
    fuzzers_drop = -paired["recall_fuzzers__ttlfree_minus_base"]
    analysis_drop = -paired["recall_analysis__ttlfree_minus_base"]
    fpr_increase = paired["fpr__ttlfree_minus_base"]
    per_seed = pd.DataFrame({
        "slice_fpr_reduction": slice_reduction,
        "C1_slice_fpr_decreased": slice_reduction > 0,
        "recall_drop": recall_drop, "C2_recall_drop_ok": recall_drop <= MAX_RECALL_DROP,
        "fuzzers_recall_drop": fuzzers_drop, "analysis_recall_drop": analysis_drop,
        "C3_category_drops_ok": (fuzzers_drop <= MAX_CATEGORY_RECALL_DROP)
                                & (analysis_drop <= MAX_CATEGORY_RECALL_DROP),
        "overall_fpr_increase": fpr_increase, "C4_fpr_increase_ok": fpr_increase <= MAX_FPR_INCREASE,
    })
    checks = {
        "C1": {"seeds_decreased": int(per_seed["C1_slice_fpr_decreased"].sum()),
               "mean_slice_fpr_reduction": float(slice_reduction.mean()),
               "noise_control_variation": float(slice_noise),
               "pass": bool(per_seed["C1_slice_fpr_decreased"].sum() >= MIN_SEEDS_IMPROVED
                            and slice_reduction.mean() > slice_noise)},
        "C2": {"mean_recall_drop": float(recall_drop.mean()),
               "seeds_within_limit": int(per_seed["C2_recall_drop_ok"].sum()),
               "pass": bool(recall_drop.mean() <= MAX_RECALL_DROP)},
        "C3": {"mean_fuzzers_drop": float(fuzzers_drop.mean()),
               "mean_analysis_drop": float(analysis_drop.mean()),
               "seeds_within_limit": int(per_seed["C3_category_drops_ok"].sum()),
               "pass": bool(fuzzers_drop.mean() <= MAX_CATEGORY_RECALL_DROP
                            and analysis_drop.mean() <= MAX_CATEGORY_RECALL_DROP)},
        "C4": {"mean_fpr_increase": float(fpr_increase.mean()),
               "seeds_within_limit": int(per_seed["C4_fpr_increase_ok"].sum()),
               "pass": bool(fpr_increase.mean() <= MAX_FPR_INCREASE)},
    }
    worst = {
        "worst_recall_drop": float(recall_drop.max()),
        "worst_fuzzers_recall_drop": float(fuzzers_drop.max()),
        "worst_analysis_recall_drop": float(analysis_drop.max()),
        "worst_overall_fpr_increase": float(fpr_increase.max()),
        "worst_slice_fpr_change": float(-slice_reduction.min()),
    }
    advance = all(check["pass"] for check in checks.values())

    output = ROOT / "evaluation/fp_analysis"
    output.mkdir(parents=True, exist_ok=True)
    runs.to_csv(output / "ttl_free_runs.csv", index=False)
    paired.reset_index().to_csv(output / "ttl_free_paired_differences.csv", index=False)
    summary.to_csv(output / "ttl_free_summary.csv", index=False)
    per_seed.reset_index().to_csv(output / "ttl_free_criteria_by_seed.csv", index=False)
    report = {
        "purpose": "Robustness check of TTL-free model vs 42-feature baseline; not an independent test",
        "data": "data/processed/train.csv only; official test set not read",
        "removed_features": TTL_FEATURES, "slice": f"normal records with sttl in {SLICE_STTL}",
        "split_seeds": SEEDS, "control_model_seed_offset": CONTROL_SEED_OFFSET, "threshold": THRESHOLD,
        "ci_note": "t-based 95% CIs are exploratory: repeated splits share data",
        "criteria": CRITERIA, "checks": checks, "worst_seed": worst,
        "ttl_free_advances": advance,
        "python": platform.python_version(), "scikit_learn": sklearn.__version__, "pandas": pd.__version__,
    }
    (output / "ttl_free_decision.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"checks": checks, "worst_seed": worst, "ttl_free_advances": advance}, indent=2))
    print("No production model, preprocessing pipeline, API or dashboard was modified.")


if __name__ == "__main__":
    run()
