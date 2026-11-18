"""Report-quality figures built only from committed result files.

Run from the repository root (after `python -m evaluation.report_statistics`):
    python -m evaluation.report_figures

No model is loaded, trained or scored, and no existing result file is modified.
Figures are written to evaluation/report_figures/:

    figA_validation_model_comparison.png   evaluation/validation_results.csv
    figB_threshold_tradeoff.png            evaluation/fp_analysis/threshold_analysis.csv,
                                           threshold_calibration.csv,
                                           threshold_attack_category_analysis.csv,
                                           threshold_internal_evaluation.csv
    figC_multiseed_paired_differences.png  evaluation/fp_analysis/multiseed_paired_differences.csv,
                                           ttl_free_paired_differences.csv
    figD_attack_category_detection.png     evaluation/report_stats/wilson_intervals.csv
                                           (from test_category_results.csv and
                                           threshold_attack_category_analysis.csv)
    figE_test_confusion_matrices.png       evaluation/test_results.csv

Wilson intervals assume independent Bernoulli records and ignore correlation and
distribution shift; they do not establish external generalisation.
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.lines import Line2D
import numpy as np
import pandas as pd

from evaluation.report_statistics import wilson
from preprocessing.prepare import ROOT

EVAL = ROOT / "evaluation"
FIGURES = EVAL / "report_figures"

# Reference palette (dataviz skill): categorical slots 1-3 validate all-pairs for CVD.
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK2, MUTED, GRID = "#0b0b0b", "#52514e", "#8a8984", "#e4e3df"
BLUE_RAMP = ["#f4f8fe", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#104281"]


def style(axis, grid_axis="x"):
    for side in ["top", "right"]:
        axis.spines[side].set_visible(False)
    for side in ["left", "bottom"]:
        axis.spines[side].set_color(INK2)
    axis.tick_params(colors=INK2, labelsize=8)
    if grid_axis:
        axis.grid(axis=grid_axis, color=GRID, linewidth=0.8)
    axis.set_axisbelow(True)


def save(fig, name):
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURES / name, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def ci_pct(successes, trials):
    p, low, high = wilson(successes, trials)
    return 100 * p, 100 * (p - low), 100 * (high - p)


# A ---------------------------------------------------------------------------------
def figure_a():
    data = pd.read_csv(EVAL / "validation_results.csv")
    colors = dict(zip(data["model"], [BLUE, ORANGE, AQUA]))
    fig, (left, right) = plt.subplots(1, 2, figsize=(9, 3.3), gridspec_kw={"width_ratios": [1.5, 1]})
    metrics = [("Precision", "true_positive", "false_positive"), ("Recall", "true_positive", "false_negative"),
               ("F1-score", None, None)]
    offsets = np.linspace(-0.22, 0.22, len(data))
    for offset, (_, row) in zip(offsets, data.iterrows()):
        for y, (name, s, other) in enumerate(metrics):
            if s is None:
                left.plot(100 * row["f1"], y + offset, "o", color=colors[row["model"]], ms=7)
            else:
                p, lo, hi = ci_pct(row[s], row[s] + row[other])
                left.errorbar(p, y + offset, xerr=[[lo], [hi]], fmt="o", color=colors[row["model"]],
                              ms=7, capsize=2, elinewidth=1)
    left.set_yticks(range(len(metrics)), [m[0] for m in metrics], fontsize=8.5)
    left.invert_yaxis()
    left.set_xlim(90, 100)
    left.set_xlabel("Attack-class metric (%) — axis starts at 90%", fontsize=8)
    left.set_title("Detection metrics", fontsize=9.5, loc="left")
    style(left)
    y = np.arange(len(data))
    for yi, (_, row) in zip(y, data.iterrows()):
        p, lo, hi = ci_pct(row["false_positive"], row["false_positive"] + row["true_negative"])
        right.barh(yi, p, color=colors[row["model"]], height=0.55)
        right.errorbar(p, yi, xerr=[[lo], [hi]], fmt="none", ecolor=INK, capsize=2, elinewidth=1)
        right.text(p + hi + 0.5, yi, f"{p:.2f}%  ({int(row['false_positive']):,} / "
                   f"{int(row['false_positive'] + row['true_negative']):,})", va="center", fontsize=7.5, color=INK2)
    right.set_yticks(y, data["model"], fontsize=8.5)
    right.invert_yaxis()
    right.set_xlim(0, 30)
    right.set_xlabel("False-positive rate (%) — axis starts at 0", fontsize=8)
    right.set_title("False-positive rate", fontsize=9.5, loc="left")
    style(right)
    handles = [Line2D([], [], marker="o", ls="", color=c, label=m) for m, c in colors.items()]
    left.legend(handles=handles, frameon=False, fontsize=8, loc="lower left")
    fig.suptitle("Validation comparison of default-configuration models (model-selection split, n = 35,069)",
                 fontsize=10, x=0.01, ha="left")
    fig.text(0.01, -0.04, "Error bars: 95% Wilson intervals (independent-record assumption). F1 has no Wilson "
             "interval. Validation is distributed like training, so this ranking is in-distribution only.",
             fontsize=7, color=INK2)
    fig.tight_layout()
    save(fig, "figA_validation_model_comparison.png")


# B ---------------------------------------------------------------------------------
def figure_b():
    validation = pd.read_csv(EVAL / "fp_analysis/threshold_analysis.csv")
    calibration = pd.read_csv(EVAL / "fp_analysis/threshold_calibration.csv")
    categories = pd.read_csv(EVAL / "fp_analysis/threshold_attack_category_analysis.csv").set_index("attack_cat")
    internal = pd.read_csv(EVAL / "fp_analysis/threshold_internal_evaluation.csv").set_index("threshold")
    fig, axes = plt.subplots(1, 3, figsize=(11, 3.4), gridspec_kw={"width_ratios": [1, 1, 1.15]})
    series = [
        (validation, "Validation split — production RF", BLUE, "o"),
        (calibration, "Calibration partition — experimental RF", AQUA, "s"),
    ]
    for axis, column, label in [(axes[0], "fpr", "False-positive rate (%)"), (axes[1], "recall", "Attack recall (%)")]:
        for frame, name, color, marker in series:
            axis.plot(frame["threshold"], 100 * frame[column], marker=marker, color=color, lw=2, ms=5, label=name)
        axis.axvline(0.50, color=MUTED, lw=1, ls="--")
        axis.axvline(0.60, color=MUTED, lw=1, ls=":")
        axis.set_xlabel("Decision threshold on attack score", fontsize=8)
        axis.set_title(label, fontsize=9.5, loc="left")
        style(axis, "y")
    axes[0].set_ylim(0, 12)
    axes[1].set_ylim(84, 100)
    axes[1].text(0.45, 0.03, "axis starts at 84%", transform=axes[1].transAxes, ha="left", fontsize=6.5, color=MUTED)
    handles = [Line2D([], [], color=BLUE, marker="o", lw=2, label="Validation split — production RF"),
               Line2D([], [], color=AQUA, marker="s", lw=2, label="Calibration partition — experimental RF"),
               Line2D([], [], color=MUTED, ls="--", label="0.50 (deployed)"),
               Line2D([], [], color=MUTED, ls=":", label="0.60 (selected by calibration, rejected)")]
    fig.legend(handles=handles, frameon=False, fontsize=7.5, ncol=4, loc="upper left", bbox_to_anchor=(0.01, 0.93))

    axis = axes[2]
    rows = [("Overall", int(internal.loc[0.5, "tp"]), int(internal.loc[0.6, "tp"]),
             int(internal.loc[0.5, "tp"] + internal.loc[0.5, "fn"]))]
    for name in ["Fuzzers", "Analysis"]:
        r = categories.loc[name]
        rows.append((name, int(r.attack_records - r.baseline_missed), int(r.attack_records - r.candidate_missed),
                     int(r.attack_records)))
    for yi, (name, hit50, hit60, n) in enumerate(rows):
        p50, lo50, hi50 = ci_pct(hit50, n)
        p60, lo60, hi60 = ci_pct(hit60, n)
        axis.plot([p60, p50], [yi, yi], color=GRID, lw=3, zorder=1)
        axis.errorbar(p50, yi, xerr=[[lo50], [hi50]], fmt="o", color=INK2, ms=7, capsize=2, zorder=3,
                      label="threshold 0.50" if yi == 0 else None)
        axis.errorbar(p60, yi, xerr=[[lo60], [hi60]], fmt="D", color=AQUA, ms=6, capsize=2, zorder=3,
                      label="threshold 0.60" if yi == 0 else None)
        axis.text(101, yi, f"n={n:,}\n{p50:.1f}% → {p60:.1f}%", va="center", fontsize=7, color=INK2)
    axis.set_yticks(range(len(rows)), [r[0] for r in rows], fontsize=8.5)
    axis.invert_yaxis()
    axis.set_xlim(70, 100)
    axis.set_xlabel("Detection rate (%) — axis starts at 70%", fontsize=8)
    axis.set_title("Internal evaluation partition — experimental RF", fontsize=9.5, loc="left")
    axis.legend(frameon=False, fontsize=7, loc="upper left", bbox_to_anchor=(0.0, 0.92))
    style(axis)
    fig.suptitle("Threshold trade-off: a higher threshold lowers false positives but misses more attacks, "
                 "most for Fuzzers and Analysis (internal data)",
                 fontsize=10, x=0.01, ha="left")
    fig.text(0.01, -0.06,
             "Validation: production model on validation.csv (also used for model selection). Calibration and internal "
             "evaluation: disjoint grouped partitions of train.csv\nscored by an experimental RF fitted on the remaining "
             "60%. Official test data are not used. Error bars: 95% Wilson intervals; 0.50 and 0.60 are paired on the "
             "same records,\nso overlap of separate intervals is not a significance test.", fontsize=7, color=INK2)
    fig.tight_layout(rect=(0, 0, 1, 0.9))
    save(fig, "figB_threshold_tradeoff.png")


# C ---------------------------------------------------------------------------------
def figure_c():
    dttl = pd.read_csv(EVAL / "fp_analysis/multiseed_paired_differences.csv")
    ttl = pd.read_csv(EVAL / "fp_analysis/ttl_free_paired_differences.csv")
    comparisons = [("Remove dttl\n(41 features)", BLUE), ("Remove sttl, dttl,\nct_state_ttl (39)", ORANGE),
                   ("Noise control\n(model seed + 1000)", AQUA)]
    # Panel title and, per comparison, (source frame, column) or None when not measured.
    panels = [
        ("Overall FPR", [(dttl, "fpr__dttl_minus_base"), (ttl, "fpr__ttlfree_minus_base"),
                         (dttl, "fpr__alt_minus_base")]),
        ("FPR, normals with\nsttl 62 or 254", [None, (ttl, "slice_fpr__ttlfree_minus_base"),
                                               (ttl, "slice_fpr__alt_minus_base")]),
        ("Attack recall", [(dttl, "recall__dttl_minus_base"), (ttl, "recall__ttlfree_minus_base"),
                           (dttl, "recall__alt_minus_base")]),
        ("Fuzzers recall", [(dttl, "fuzzers_recall__dttl_minus_base"), (ttl, "recall_fuzzers__ttlfree_minus_base"),
                            (dttl, "fuzzers_recall__alt_minus_base")]),
        ("Analysis recall", [(dttl, "analysis_recall__dttl_minus_base"), (ttl, "recall_analysis__ttlfree_minus_base"),
                             (dttl, "analysis_recall__alt_minus_base")]),
    ]
    fig, axes = plt.subplots(1, len(panels), figsize=(12, 3.2), sharey=True)
    for axis, (title, entries) in zip(axes, panels):
        axis.axvline(0, color=INK2, lw=1)
        all_values = []
        for yi, ((label, color), entry) in enumerate(zip(comparisons, entries)):
            if entry is None:
                axis.text(0, yi, "not measured", ha="center", va="center", fontsize=7, color=MUTED)
                continue
            frame, column = entry
            values = 100 * frame[column].to_numpy()
            all_values.extend(values)
            jitter = np.linspace(-0.12, 0.12, len(values))
            axis.scatter(values, yi + jitter, s=18, color=color, alpha=0.6, linewidths=0)
            axis.plot(values.mean(), yi, "|", color=INK, ms=16, mew=2)
        limit = max(np.abs(all_values).max(), 0.1) * 1.25
        axis.set_xlim(-limit, limit)
        axis.set_title(title, fontsize=9, loc="left")
        axis.set_xlabel("Difference vs baseline (pp)", fontsize=7.5)
        style(axis)
    axes[0].set_yticks(range(len(comparisons)), [c[0] for c in comparisons], fontsize=8)
    axes[0].invert_yaxis()
    fig.suptitle("Paired differences from the 42-feature baseline on five identical grouped splits of train.csv "
                 "(dots = seeds, bar = mean)", fontsize=10, x=0.01, ha="left")
    fig.text(0.01, -0.07, "Positive FPR = more false positives; negative recall = more missed attacks. Each panel has "
             "its own symmetric scale. Splits share data, so seeds are not independent tests.\nThe noise control "
             "differs from the baseline only in its random seed; both experiments used identical baseline and "
             "control runs. Official test data are not used.", fontsize=7, color=INK2)
    fig.tight_layout()
    save(fig, "figC_multiseed_paired_differences.png")


# D ---------------------------------------------------------------------------------
def figure_d():
    stats = pd.read_csv(EVAL / "report_stats/wilson_intervals.csv")
    test = stats[(stats["dataset"] == "Official UNSW-NB15 test") & (stats["scope"] == "all records")
                 & stats["metric"].str.startswith("detection rate")]
    internal = stats[(stats["dataset"].str.startswith("Internal")) & (stats["scope"] == "threshold 0.50")
                     & stats["metric"].str.startswith("detection rate")]
    order = test.sort_values("estimate")["metric"].tolist()
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.9), sharey=True)
    for axis, frame, color, title in [
        (axes[0], test, ORANGE, "Official test — production RF (threshold 0.50)"),
        (axes[1], internal, AQUA, "Internal evaluation partition — experimental RF (0.50)"),
    ]:
        frame = frame.set_index("metric").loc[order]
        y = np.arange(len(order))
        estimate = 100 * frame["estimate"]
        axis.errorbar(estimate, y, xerr=[estimate - 100 * frame["ci95_low"], 100 * frame["ci95_high"] - estimate],
                      fmt="o", color=color, ms=6, capsize=2.5, elinewidth=1.2)
        for yi, (_, row) in zip(y, frame.iterrows()):
            axis.text(100.6, yi, f"{100 * row.estimate:.1f}%  n={int(row.trials):,}", va="center",
                      fontsize=7, color=INK2)
        axis.set_xlim(80, 100)
        axis.set_xlabel("Detection rate (%) with 95% Wilson interval — axis starts at 80%", fontsize=7.5)
        axis.set_title(title, fontsize=9, loc="left")
        style(axis)
    axes[0].set_yticks(range(len(order)), [m.replace("detection rate: ", "") for m in order], fontsize=8.5)
    fig.suptitle("Binary detection rate by attack category on two different evaluation sets",
                 fontsize=10, x=0.01, ha="left")
    fig.text(0.01, -0.06, "Panels use different models and data and must not be read as one comparison. Wilson "
             "intervals assume independent records and ignore correlation and distribution shift.\nThe model "
             "predicts attack vs normal only; a category's rate is the share of its records flagged as attacks.",
             fontsize=7, color=INK2)
    fig.tight_layout(w_pad=6)
    save(fig, "figD_attack_category_detection.png")


# E ---------------------------------------------------------------------------------
def figure_e():
    results = pd.read_csv(EVAL / "test_results.csv")
    cmap = LinearSegmentedColormap.from_list("blue_ramp", BLUE_RAMP)
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.0))
    fig.subplots_adjust(wspace=0.55)
    titles = {"full_test": "All official test records", "without_training_overlap":
              "Excluding records whose features occur in training"}
    for axis, (_, row) in zip(axes, results.iterrows()):
        counts = np.array([[row.true_negative, row.false_positive], [row.false_negative, row.true_positive]])
        rates = counts / counts.sum(axis=1, keepdims=True)
        image = axis.imshow(rates * 100, cmap=cmap, vmin=0, vmax=100)
        names = [["True negative", "False positive"], ["False negative", "True positive"]]
        for i in range(2):
            for j in range(2):
                color = "white" if rates[i, j] > 0.55 else INK
                axis.text(j, i, f"{counts[i, j]:,}\n{100 * rates[i, j]:.2f}% of row\n{names[i][j]}",
                          ha="center", va="center", fontsize=8, color=color)
        axis.set_xticks([0, 1], ["Normal", "Attack"], fontsize=8.5)
        axis.set_yticks([0, 1], [f"Normal\n(n={counts[0].sum():,})", f"Attack\n(n={counts[1].sum():,})"], fontsize=8.5)
        axis.set_xlabel("Predicted class", fontsize=8)
        axis.set_ylabel("True class", fontsize=8)
        axis.set_title(f"{titles[row.subset]}\n({int(row.records):,} records)", fontsize=9, loc="left")
        for spine in axis.spines.values():
            spine.set_visible(False)
        axis.tick_params(colors=INK2, length=0)
    bar = fig.colorbar(image, ax=axes, shrink=0.8, pad=0.02)
    bar.set_label("Row percentage (%)", fontsize=8, color=INK2)
    bar.ax.tick_params(labelsize=7, colors=INK2)
    fig.suptitle("Official-test confusion matrices, production Random Forest (threshold 0.50)",
                 fontsize=10, x=0.01, ha="left")
    fig.text(0.01, -0.02, "Row percentages: normal row = specificity / false-positive rate; attack row = "
             "miss rate / recall. One shared colour scale (0–100%) across both panels.", fontsize=7, color=INK2)
    save(fig, "figE_test_confusion_matrices.png")


def run():
    plt.rcParams.update({"font.family": "DejaVu Sans", "text.color": INK, "axes.labelcolor": INK2})
    for make in [figure_a, figure_b, figure_c, figure_d, figure_e]:
        make()
    print(f"Figures written to {FIGURES}")


if __name__ == "__main__":
    run()
