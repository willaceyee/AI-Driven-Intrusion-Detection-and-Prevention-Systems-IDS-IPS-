"""Diagnose the validation-to-official-test false-positive gap (diagnostic only).

Run from the repository root with:
    python -m evaluation.analyze_dataset_shift

No model is trained, no threshold is tuned and no feature is removed. The saved
production pipeline is only used to score validation.csv and the official test
set at its own predict() rule (attack score > 0.50), so each false positive can
be attributed to a traffic pattern.

Datasets:
    train       data/processed/train.csv  (the rows the production model was fitted on)
    validation  data/processed/validation.csv
    test        data/raw/UNSW_NB15_testing-set.csv (official test set)

Most analyses use NORMAL records only, because false positives can only occur
on normal traffic.
"""

import hashlib
import json

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats

from preprocessing.prepare import ROOT, CATEGORICAL, NUMERIC, read_csv, validate_features

OUTPUT = ROOT / "evaluation/shift_analysis"
FIGURES = OUTPUT / "figures"
COMBO = ["proto", "service", "state"]
THRESHOLD = 0.50
MIN_RELIABLE = 30          # minimum normal records for a per-combination rate
PSI_BINS = 10
PSI_EPS = 1e-4
EXPECTED_SHA256 = {
    "model": "a171cb07a98e92d3e0025818f9e3a9ecb379616579ee09172ea6d9048e8da2e9",
    "test": "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
    "train": "870177afa2462803dfc13130dc91c035a4aa7e0d1ae2710eb975d53ac369e7f1",
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load():
    paths = {
        "train": ROOT / "data/processed/train.csv",
        "validation": ROOT / "data/processed/validation.csv",
        "test": ROOT / "data/raw/UNSW_NB15_testing-set.csv",
    }
    model_path = ROOT / "models/artifacts/selected_pipeline.joblib"
    for name, path in [("model", model_path), ("test", paths["test"]), ("train", paths["train"])]:
        if sha256(path) != EXPECTED_SHA256[name]:
            raise ValueError(f"{name} file differs from the recorded production artefact.")
    model = joblib.load(model_path)
    class_index = list(model.classes_).index(1)

    data = {}
    for name, path in paths.items():
        frame = read_csv(path)
        x = validate_features(frame)
        out = x.copy()
        out["label"] = pd.to_numeric(frame["label"], errors="raise").astype(int).to_numpy()
        out["attack_cat"] = frame["attack_cat"].astype(str).str.strip().to_numpy()
        out["combo"] = x["proto"] + "/" + x["service"] + "/" + x["state"]
        out["sttl_value"] = "sttl=" + x["sttl"].astype(int).astype(str)
        out["combo_sttl"] = out["combo"] + "|" + out["sttl_value"]
        out["row_hash"] = pd.util.hash_pandas_object(x, index=False).to_numpy()
        if name != "train":
            scores = model.predict_proba(x)[:, class_index]
            out["score"] = scores
            out["pred"] = (scores > THRESHOLD).astype(int)
            np.testing.assert_array_equal(out["pred"].to_numpy(), model.predict(x))
        data[name] = out
    return data


def normals(frame):
    return frame[frame["label"] == 0]


def fp_rate(frame):
    n = normals(frame)
    return float(n["pred"].mean()) if len(n) else np.nan


# 1. Composition ---------------------------------------------------------------
def composition(data):
    rows = []
    for name, frame in data.items():
        attacks = frame[frame["label"] == 1]
        rows.append({"dataset": name, "group": "ALL", "records": len(frame),
                     "normal": int((frame["label"] == 0).sum()), "attack": len(attacks),
                     "share_of_dataset": 1.0, "share_of_attacks": np.nan})
        for category, count in frame["attack_cat"].value_counts().items():
            rows.append({"dataset": name, "group": category, "records": int(count),
                         "normal": np.nan, "attack": np.nan,
                         "share_of_dataset": count / len(frame),
                         "share_of_attacks": count / len(attacks) if category != "Normal" else np.nan})
    return pd.DataFrame(rows)


# 2. Normal-traffic combinations -------------------------------------------------
def combinations(data):
    train, val, test = data["train"], data["validation"], data["test"]
    train_all = train.groupby("combo")["label"].agg(train_records="size", train_attack_share="mean")
    parts = [train_all]
    for name, frame in [("train", train), ("val", val), ("test", test)]:
        n = normals(frame)
        counts = n.groupby("combo").size().rename(f"{name}_normal")
        parts.append(counts)
        parts.append((counts / len(n)).rename(f"{name}_normal_share"))
        if name != "train":
            parts.append(n.groupby("combo")["pred"].sum().rename(f"{name}_fp"))
    table = pd.concat(parts, axis=1).fillna(0)
    for name in ["val", "test"]:
        table[f"{name}_fpr"] = np.where(table[f"{name}_normal"] > 0,
                                        table[f"{name}_fp"] / table[f"{name}_normal"].replace(0, 1), np.nan)
    table["test_fp_share"] = table["test_fp"] / table["test_fp"].sum()
    table["share_change_test_minus_train"] = table["test_normal_share"] - table["train_normal_share"]
    table = table[(table["val_normal"] + table["test_normal"]) > 0]
    int_cols = [c for c in table.columns if c.endswith(("_normal", "_fp", "_records"))]
    table[int_cols] = table[int_cols].astype(int)
    return table.sort_values("test_fp", ascending=False).rename_axis("combination").reset_index()


# 3. Mix vs within-group decomposition --------------------------------------------
def group_rates(data, key):
    parts = []
    for name, frame in [("val", data["validation"]), ("test", data["test"])]:
        n = normals(frame)
        g = n.groupby(key)["pred"]
        parts += [g.size().rename(f"{name}_normal"), (g.size() / len(n)).rename(f"{name}_normal_share"),
                  g.sum().rename(f"{name}_fp"), g.mean().rename(f"{name}_fpr")]
    table = pd.concat(parts, axis=1)
    for column in ["val_normal", "val_normal_share", "val_fp", "test_normal", "test_normal_share", "test_fp"]:
        table[column] = table[column].fillna(0)
    return table.rename_axis("group").reset_index()


def decomposition(data, key):
    """Split the FPR gap into a traffic-mix effect and a within-group effect.

    counterfactual = sum_g test_share_g * val_fpr_g: the test FPR expected if each
    group kept its validation FPR. mix = counterfactual - validation FPR;
    within = test FPR - counterfactual. Groups with fewer than MIN_RELIABLE
    validation normals share one pooled validation rate.
    """
    val, test = data["validation"], data["test"]
    val_fpr, test_fpr = fp_rate(val), fp_rate(test)
    combos = group_rates(data, key)
    reliable = combos["val_normal"] >= MIN_RELIABLE
    small = combos[~reliable]
    pooled = small["val_fp"].sum() / small["val_normal"].sum() if small["val_normal"].sum() else val_fpr
    table = combos[["group", "val_normal", "val_normal_share", "val_fpr",
                    "test_normal", "test_normal_share", "test_fpr", "test_fp"]].copy()
    table["val_fpr_used"] = np.where(reliable, table["val_fpr"], pooled)
    table["val_rate_source"] = np.where(reliable, "own", "pooled_small_combinations")
    table["mix_contribution"] = (table["test_normal_share"] - table["val_normal_share"]) * table["val_fpr_used"]
    table["within_contribution"] = table["test_normal_share"] * (
        table["test_fpr"].fillna(0) - table["val_fpr_used"])
    counterfactual = float((table["test_normal_share"] * table["val_fpr_used"]).sum())
    total = {
        "grouping": key,
        "validation_fpr": val_fpr, "test_fpr": test_fpr, "gap": test_fpr - val_fpr,
        "counterfactual_test_fpr_with_validation_rates": counterfactual,
        "mix_effect": counterfactual - (table["val_normal_share"] * table["val_fpr_used"]).sum(),
        "within_combination_effect": test_fpr - counterfactual,
        "pooled_rate_for_small_combinations": pooled,
        "test_normals_with_own_validation_rate": float(table.loc[reliable, "test_normal_share"].sum()),
    }
    # Reference check: val rate reconstructed from per-group rates.
    total["reconstructed_validation_fpr"] = float((table["val_normal_share"] * table["val_fpr_used"]).sum())
    assert abs(total["reconstructed_validation_fpr"] - val_fpr) < 1e-9
    table.insert(0, "grouping", key)
    return table.sort_values("test_fp", ascending=False), total


# 4. Numeric shift ----------------------------------------------------------------
def psi(reference, other):
    edges = np.unique(np.quantile(reference, np.linspace(0, 1, PSI_BINS + 1)))
    edges = np.concatenate(([-np.inf], edges[1:-1], [np.inf]))
    ref = np.histogram(reference, edges)[0] / len(reference)
    oth = np.histogram(other, edges)[0] / len(other)
    ref, oth = np.clip(ref, PSI_EPS, None), np.clip(oth, PSI_EPS, None)
    return float(np.sum((oth - ref) * np.log(oth / ref))), len(edges) - 1


def numeric_shift(data, sttl=None):
    """KS/PSI on normal records; optionally restricted to one sttl value."""
    tr, va, te = (normals(data[k]) for k in ["train", "validation", "test"])
    if sttl is not None:
        tr, va, te = (frame[frame["sttl"] == sttl] for frame in (tr, va, te))
    te_fp, te_tn = te[te["pred"] == 1], te[te["pred"] == 0]
    rows = []
    for name in NUMERIC:
        psi_val, bins = psi(tr[name], va[name])
        psi_test, _ = psi(tr[name], te[name])
        rows.append({
            "feature": name,
            "ks_train_vs_val": stats.ks_2samp(tr[name], va[name]).statistic,
            "ks_train_vs_test": stats.ks_2samp(tr[name], te[name]).statistic,
            "psi_train_vs_val": psi_val, "psi_train_vs_test": psi_test, "psi_bins_used": bins,
            "median_train_normal": tr[name].median(), "median_val_normal": va[name].median(),
            "median_test_normal": te[name].median(),
            "median_test_fp": te_fp[name].median(), "median_test_tn": te_tn[name].median(),
            "ks_test_fp_vs_test_tn": stats.ks_2samp(te_fp[name], te_tn[name]).statistic,
        })
    return pd.DataFrame(rows).sort_values("ks_train_vs_test", ascending=False)


# 5. TTL analysis -----------------------------------------------------------------
def ttl_analysis(data, features=("sttl", "dttl", "ct_state_ttl"), min_records=100):
    train, val, test = data["train"], data["validation"], data["test"]
    tn, vn, ten = normals(train), normals(val), normals(test)
    rows = []
    for feature in features:
        values = pd.concat([train[feature], val[feature], test[feature]])
        counts = values.value_counts()
        keep = set(counts[counts >= min_records].index)
        def bucket(series):
            return series.where(series.isin(keep), other=-1)
        t_b, tn_b, vn_b, ten_b = bucket(train[feature]), bucket(tn[feature]), bucket(vn[feature]), bucket(ten[feature])
        for value in sorted(set(t_b) | set(ten_b) | set(vn_b)):
            t_mask, te_mask, v_mask = t_b == value, ten_b == value, vn_b == value
            rows.append({
                "feature": feature, "value": "other" if value == -1 else value,
                "train_records": int(t_mask.sum()),
                "train_attack_share": float(train.loc[t_mask, "label"].mean()) if t_mask.any() else np.nan,
                "train_normal_share": float((tn_b == value).mean()),
                "val_normal_share": float(v_mask.mean()),
                "val_fpr": float(vn.loc[v_mask, "pred"].mean()) if v_mask.any() else np.nan,
                "test_normal": int(te_mask.sum()), "test_normal_share": float(te_mask.mean()),
                "test_fp": int(ten.loc[te_mask, "pred"].sum()),
                "test_fpr": float(ten.loc[te_mask, "pred"].mean()) if te_mask.any() else np.nan,
            })
    table = pd.DataFrame(rows)
    table["test_fp_share"] = table["test_fp"] / int(ten["pred"].sum())
    return table


# 6. Unseen / rare patterns -------------------------------------------------------
def unseen_patterns(data, combos):
    train, test = data["train"], data["test"]
    ten = normals(test)
    train_normal_counts = normals(train)["combo"].value_counts()
    train_any = set(train["combo"])
    support = ten["combo"].map(train_normal_counts).fillna(0)
    buckets = np.select(
        [~ten["combo"].isin(train_any), support == 0, support < MIN_RELIABLE],
        ["absent_from_training", "no_training_normals", f"rare_<{MIN_RELIABLE}_training_normals"],
        default="well_supported")
    rows = []
    for name in ["absent_from_training", "no_training_normals",
                 f"rare_<{MIN_RELIABLE}_training_normals", "well_supported"]:
        mask = buckets == name
        rows.append({"pattern": "combination_support", "bucket": name,
                     "test_normals": int(mask.sum()), "share_of_test_normals": float(mask.mean()),
                     "test_fp": int(ten.loc[mask, "pred"].sum()),
                     "test_fpr": float(ten.loc[mask, "pred"].mean()) if mask.any() else np.nan})
    for column in CATEGORICAL:
        unseen = ~ten[column].isin(set(train[column]))
        rows.append({"pattern": f"unseen_{column}_value", "bucket": ",".join(sorted(ten.loc[unseen, column].unique())) or "none",
                     "test_normals": int(unseen.sum()), "share_of_test_normals": float(unseen.mean()),
                     "test_fp": int(ten.loc[unseen, "pred"].sum()),
                     "test_fpr": float(ten.loc[unseen, "pred"].mean()) if unseen.any() else np.nan})
    outside = pd.DataFrame({name: (ten[name] < train[name].min()) | (ten[name] > train[name].max())
                            for name in NUMERIC})
    any_outside = outside.any(axis=1)
    rows.append({"pattern": "any_numeric_outside_training_range", "bucket": "any",
                 "test_normals": int(any_outside.sum()), "share_of_test_normals": float(any_outside.mean()),
                 "test_fp": int(ten.loc[any_outside, "pred"].sum()),
                 "test_fpr": float(ten.loc[any_outside, "pred"].mean()) if any_outside.any() else np.nan})
    for name in outside.columns[outside.sum() > 0]:
        mask = outside[name]
        rows.append({"pattern": "numeric_outside_training_range", "bucket": name,
                     "test_normals": int(mask.sum()), "share_of_test_normals": float(mask.mean()),
                     "test_fp": int(ten.loc[mask, "pred"].sum()),
                     "test_fpr": float(ten.loc[mask, "pred"].mean())})
    return pd.DataFrame(rows)


# 7. Overlap and conflicting labels -------------------------------------------------
def overlap(data):
    train, test = data["train"], data["test"]
    labels = train.groupby("row_hash")["label"].agg(["min", "max"])
    status = pd.Series("not_in_training", index=test.index)
    matched = test["row_hash"].isin(labels.index)
    lab = labels.reindex(test.loc[matched, "row_hash"])
    status.loc[matched] = np.select(
        [lab["max"].to_numpy() == 0, lab["min"].to_numpy() == 1],
        ["training_normal_only", "training_attack_only"], default="training_both_labels")
    rows = []
    for label_name, label in [("normal", 0), ("attack", 1)]:
        subset = test["label"] == label
        for name in ["not_in_training", "training_normal_only", "training_attack_only", "training_both_labels"]:
            mask = subset & (status == name)
            rows.append({"test_label": label_name, "match_status": name, "records": int(mask.sum()),
                         "share_of_label": float(mask.sum() / subset.sum()),
                         "predicted_attack": int(test.loc[mask, "pred"].sum()),
                         "predicted_attack_rate": float(test.loc[mask, "pred"].mean()) if mask.any() else np.nan})
    table = pd.DataFrame(rows)
    # Conflicting labels inside the official test set itself.
    test_labels = test.groupby("row_hash")["label"].nunique()
    internal_conflicts = int(test["row_hash"].map(test_labels).gt(1).sum())
    extra = {"test_records_in_conflicting_label_groups_within_test": internal_conflicts,
             "test_normal_duplicate_records": int(normals(test)["row_hash"].duplicated().sum())}
    return table, extra


# 8. Score distribution -----------------------------------------------------------
def score_distribution(data):
    rows = []
    for name in ["validation", "test"]:
        n = normals(data[name])
        for outcome, subset in [("false_positive", n[n["pred"] == 1]), ("true_negative", n[n["pred"] == 0])]:
            s = subset["score"]
            rows.append({"dataset": name, "outcome": outcome, "records": len(s),
                         **{f"q{int(q * 100):02d}": s.quantile(q) for q in [0.1, 0.25, 0.5, 0.75, 0.9]},
                         "share_score_gt_0.6": float((s > 0.6).mean()),
                         "share_score_gt_0.8": float((s > 0.8).mean()),
                         "share_score_gt_0.9": float((s > 0.9).mean())})
    return pd.DataFrame(rows)


# Figures --------------------------------------------------------------------------
# Reference palette (dataviz skill): slot 1 blue, slot 2 orange; neutral ink for text.
BLUE, ORANGE, INK, INK2, GRID = "#2a78d6", "#eb6834", "#0b0b0b", "#52514e", "#e4e3df"


def style(axis, grid_axis="x"):
    for side in ["top", "right"]:
        axis.spines[side].set_visible(False)
    for side in ["left", "bottom"]:
        axis.spines[side].set_color(INK2)
    axis.tick_params(colors=INK2, labelsize=8)
    axis.grid(axis=grid_axis, color=GRID, linewidth=0.8)
    axis.set_axisbelow(True)


def save(fig, name):
    fig.savefig(FIGURES / name, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def make_figures(data, results, totals):
    plt.rcParams.update({"font.family": "DejaVu Sans", "text.color": INK, "axes.labelcolor": INK2})

    # Fig 1: decomposition of the FPR gap under three groupings.
    labels = {"combo": "proto/service/state", "sttl_value": "sttl value", "combo_sttl": "combination × sttl"}
    fig, axis = plt.subplots(figsize=(7.2, 2.6))
    for row, total in enumerate(totals):
        mix, within = total["mix_effect"] * 100, total["within_combination_effect"] * 100
        axis.barh(row, mix, color=BLUE, height=0.55, edgecolor="white", linewidth=1.5,
                  label="Traffic-mix effect" if row == 0 else None)
        axis.barh(row, within, left=mix, color=ORANGE, height=0.55, edgecolor="white", linewidth=1.5,
                  label="Within-group effect" if row == 0 else None)
        for start, width in [(0, mix), (mix, within)]:
            axis.text(start + width / 2, row, f"{width:.1f}", ha="center", va="center", fontsize=8, color="white")
    axis.set_yticks(range(len(totals)), [labels[t["grouping"]] for t in totals])
    axis.invert_yaxis()
    axis.set_xlabel("Percentage points of FPR gap (validation 8.96% → test 26.77%)")
    axis.legend(frameon=False, fontsize=8, loc="lower right", ncol=2, bbox_to_anchor=(1, 1.0))
    axis.set_title("Decomposition of the 17.8-point false-positive-rate gap", fontsize=10, loc="left", pad=18)
    style(axis)
    save(fig, "fig1_fpr_gap_decomposition.png")

    # Fig 2: sttl share of normal traffic and FPR, train/validation vs test.
    ttl = results["ttl_analysis"]
    ttl = ttl[(ttl["feature"] == "sttl") & ttl["value"].isin(["0.0", "31.0", "62.0", "254.0", 0.0, 31.0, 62.0, 254.0])]
    names = [f"{int(float(v))}\n({a:.0%} attacks\nin training)" for v, a in zip(ttl["value"], ttl["train_attack_share"])]
    x = np.arange(len(ttl))
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.4))
    for axis, (left, right, title, left_name) in zip(axes, [
            ("train_normal_share", "test_normal_share", "Share of normal records", "Training"),
            ("val_fpr", "test_fpr", "False-positive rate", "Validation")]):
        axis.bar(x - 0.19, ttl[left] * 100, 0.36, color=BLUE, label=left_name, edgecolor="white", linewidth=1)
        axis.bar(x + 0.19, ttl[right] * 100, 0.36, color=ORANGE, label="Official test", edgecolor="white", linewidth=1)
        for offset, column in [(-0.19, left), (0.19, right)]:
            for xi, value in zip(x, ttl[column]):
                axis.text(xi + offset, value * 100 + 1, f"{value:.0%}", ha="center", fontsize=7, color=INK2)
        axis.set_xticks(x, names, fontsize=7.5)
        axis.set_xlabel("sttl value of normal records", fontsize=8)
        axis.set_ylabel("%", fontsize=8)
        axis.set_title(title, fontsize=9.5, loc="left")
        axis.legend(frameon=False, fontsize=8)
        style(axis, "y")
    fig.suptitle("Test normals shift toward TTL values that are mostly attacks in training",
                 fontsize=10, x=0.01, ha="left")
    fig.tight_layout()
    save(fig, "fig2_sttl_shift_and_fpr.png")

    # Fig 3: FPR of the groups producing most test false positives.
    decomposition_table = results["fpr_decomposition"]
    top = decomposition_table[decomposition_table["grouping"] == "combo_sttl"].nlargest(5, "test_fp").iloc[::-1]
    y = np.arange(len(top))
    fig, axis = plt.subplots(figsize=(7.2, 3.0))
    axis.barh(y + 0.19, top["val_fpr"] * 100, 0.36, color=BLUE, label="Validation", edgecolor="white", linewidth=1)
    axis.barh(y - 0.19, top["test_fpr"] * 100, 0.36, color=ORANGE, label="Official test", edgecolor="white", linewidth=1)
    for yi, (fpr, count) in enumerate(zip(top["test_fpr"], top["test_fp"])):
        axis.text(fpr * 100 + 1, yi - 0.19, f"{fpr:.0%}  ({int(count):,} FPs)", va="center", fontsize=7.5, color=INK2)
    axis.set_yticks(y, [g.replace("|", "  ") for g in top["group"]], fontsize=8)
    axis.set_xlim(0, 125)
    axis.set_xticks(range(0, 101, 20))
    axis.set_xlabel("False-positive rate (%)", fontsize=8)
    axis.legend(frameon=False, fontsize=8, ncol=2,
                loc="lower right", bbox_to_anchor=(1, 1.0))
    axis.set_title(f"Five groups account for {top['test_fp'].sum() / normals(data['test'])['pred'].sum():.0%} "
                   "of official-test false positives", fontsize=10, loc="left", pad=18)
    style(axis)
    save(fig, "fig3_top_fp_groups.png")

    # Fig 4: univariate shift, train-vs-validation reference vs train-vs-test.
    shift = results["numeric_shift"].nlargest(12, "ks_train_vs_test").iloc[::-1]
    y = np.arange(len(shift))
    fig, axis = plt.subplots(figsize=(7.2, 3.8))
    axis.barh(y + 0.19, shift["ks_train_vs_val"], 0.36, color=BLUE, label="Train vs validation (reference)",
              edgecolor="white", linewidth=1)
    axis.barh(y - 0.19, shift["ks_train_vs_test"], 0.36, color=ORANGE, label="Train vs official test",
              edgecolor="white", linewidth=1)
    axis.set_yticks(y, shift["feature"], fontsize=8)
    axis.set_xlabel("KS statistic, normal records only", fontsize=8)
    handles, legend_labels = axis.get_legend_handles_labels()
    axis.legend(handles[::-1], legend_labels[::-1], frameon=False, fontsize=8, loc="lower right")
    axis.set_title("Validation matches training; the official test set does not", fontsize=10, loc="left")
    style(axis)
    save(fig, "fig4_numeric_shift_ks.png")

    # Fig 5: attack-score distribution of false positives.
    fig, axis = plt.subplots(figsize=(7.2, 2.8))
    bins = np.linspace(0.5, 1.0, 26)
    for name, color, label in [("validation", BLUE, "Validation FPs (n=1,004)"),
                               ("test", ORANGE, "Official-test FPs (n=9,904)")]:
        n = normals(data[name])
        scores = n.loc[n["pred"] == 1, "score"]
        weights = np.full(len(scores), 100 / len(scores))
        axis.hist(scores, bins=bins, weights=weights, histtype="step", linewidth=2, color=color, label=label)
    axis.set_xlabel("Model attack score (decision threshold 0.50)", fontsize=8)
    axis.set_ylabel("% of false positives", fontsize=8)
    axis.legend(frameon=False, fontsize=8)
    axis.set_title("False positives spread across the whole score range, not just near 0.50",
                   fontsize=10, loc="left")
    style(axis, "y")
    save(fig, "fig5_fp_score_distribution.png")


def run():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)
    data = load()
    test = data["test"]
    cm = {"tn": int(((test.label == 0) & (test.pred == 0)).sum()), "fp": int(((test.label == 0) & (test.pred == 1)).sum()),
          "fn": int(((test.label == 1) & (test.pred == 0)).sum()), "tp": int(((test.label == 1) & (test.pred == 1)).sum())}
    # Must reproduce evaluation/test_results.csv exactly.
    assert cm == {"tn": 27096, "fp": 9904, "fn": 661, "tp": 44671}, cm
    assert int(normals(data["validation"])["pred"].sum()) == 1004

    results = {
        "composition": composition(data),
        "normal_combinations": combinations(data),
    }
    decomposition_tables, decomposition_totals = [], []
    for key in ["combo", "sttl_value", "combo_sttl"]:
        table, total = decomposition(data, key)
        decomposition_tables.append(table)
        decomposition_totals.append(total)
    results["fpr_decomposition"] = pd.concat(decomposition_tables, ignore_index=True)
    decomposition_total = decomposition_totals
    results["numeric_shift"] = numeric_shift(data)
    # Residual shift among normals that share the dominant FP TTL value.
    results["numeric_shift_sttl254"] = numeric_shift(data, sttl=254)
    results["ttl_analysis"] = ttl_analysis(data)
    results["unseen_patterns"] = unseen_patterns(data, results["normal_combinations"])
    results["overlap_analysis"], overlap_extra = overlap(data)
    results["fp_score_distribution"] = score_distribution(data)
    for name, table in results.items():
        table.to_csv(OUTPUT / f"{name}.csv", index=False)

    summary = {
        "purpose": "Diagnostic only; production model and threshold unchanged",
        "test_confusion_matrix_reproduced": cm,
        "validation_fp": 1004,
        "decomposition": decomposition_total,
        "overlap": overlap_extra,
        "notes": [
            "KS p-values are omitted: with tens of thousands of records every difference is 'significant'.",
            f"PSI uses up to {PSI_BINS} quantile bins of training normals; discrete features get fewer bins.",
            "PSI thresholds 0.1/0.25 are credit-scoring rules of thumb, not validated for NIDS data.",
            "KS and PSI are univariate and miss shifts in feature interactions.",
            "Row matching uses 64-bit hashes of all 42 features (collision risk negligible).",
        ],
    }
    (OUTPUT / "shift_summary.json").write_text(json.dumps(summary, indent=2, default=float), encoding="utf-8")
    make_figures(data, results, decomposition_total)
    return data, results, summary


if __name__ == "__main__":
    data, results, summary = run()
    print(json.dumps(summary, indent=2, default=float))
