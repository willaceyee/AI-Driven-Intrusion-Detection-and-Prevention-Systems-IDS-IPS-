# Priority 2 Evidence Audit: Experimental Results

**Project:** SEC3044 AI-Driven IDS/IPS
**Branch:** `feature/evaluation-reporting` (from `main` at `2825649`, after Priority 1 PR #2)
**Scope:** read-only audit of existing results, documentation corrections, report figures and approved derived statistics.

No model was retrained, rescored for selection, or tuned. The production pipeline (`models/artifacts/selected_pipeline.joblib`, SHA-256 `a171cb07…`), preprocessing, API and dashboard were not changed. Derived statistics are arithmetic on committed counts.

---

## 1. Verified results and source files

Each metric was recomputed from its confusion counts. All matched the stored values exactly (tolerance 1e-9).

| Evidence | Source file | Check |
|---|---|---|
| Validation, 3 models (RF: P 95.86%, R 97.41%, F1 96.63%, FPR 8.96%) | `evaluation/validation_results.csv` | Rows sum to 35,069 |
| Official test, all records (Acc 87.17%, P 81.85%, R 98.54%, F1 89.43%, FPR 26.77%) | `evaluation/test_results.csv` | Class totals 37,000 / 45,332 |
| Official test, excluding records also in training (Acc 86.59%, P 80.52%, R 98.38%, F1 88.56%, FPR 26.57%) | `evaluation/test_results.csv` | 75,818 records |
| Test detection rate by category (e.g. Fuzzers 90.04%, Analysis 99.85%) | `evaluation/test_category_results.csv` | Category counts add up to the FN and FP totals |
| Threshold tables (validation, calibration and internal partitions) | `evaluation/fp_analysis/threshold_*.csv` | Recomputed |
| Multi-seed and TTL-free runs (30 runs), paired differences, decisions | `evaluation/fp_analysis/multiseed_*`, `ttl_free_*` | Recomputed; pass/fail results reproduce |
| Shift statistics (largest KS 0.016 validation / 0.27 test; decomposition) | `evaluation/shift_analysis/*` | Match the summary and README |
| Dashboard metrics (8.96%, 26.77%, 9,904 / 37,000) | `frontend/detection_intelligence.py` | Hard-coded copies, currently matching |

The baseline and noise-control runs are identical in both multi-seed experiments. This confirms the runs are deterministic.

## 2. Methodological weaknesses (ranked by severity)

**High**
1. **No untouched test set.** The official test set was inspected for the baseline evaluation and the shift diagnostics. Shift conclusions are drawn after looking at the test data and must stay at the level of association.
2. **Model selection only tested in-distribution performance.** Validation is distributed like training (largest KS 0.016). The ranking of Random Forest over the Decision Tree, which had lower validation FPR, therefore says nothing about generalisation to shifted traffic.
3. **Category evidence mixed datasets.** Fuzzers and Analysis are weak on the internal partition (85.8% and 90.8%). On the official test set, only Fuzzers is weak (90.04%); Analysis is 99.85%. This is now labelled throughout.

**Medium**

4. **Two sources of threshold evidence.** The 0.60 calibration used an experimental model trained on 60% of `train.csv`, not the production model. The validation sweep used the production model, but on model-selection data.
5. **The multi-seed rule is weak.** 5 overlapping splits; with no real effect, "better on at least 4 of 5 seeds" still happens 3/16 (about 19%) of the time by chance. The single-seed noise control produced more false positives than the baseline on 5 of 5 seeds, so its noise estimate is crude.
6. **The FPR-gap decomposition is reference-dependent.** See section 5.
7. **PSI is degenerate for discrete features.** 9 features have one bin (PSI is 0 by construction) and the TTL features have 3. KS is crude for discrete features, and its p-values are omitted.
8. **Permutation importance** (3 repeats, validation data) is unreliable for correlated features. The TTL-free result shows that high importance does not mean a feature is necessary.
9. **Duplicates slightly inflate test recall.** 5,315 test attacks (11.7%) are exact copies of training attack records, all detected. The overlap-excluded recall (98.38% vs 98.54%) shows the effect is small.

**Low**

10. Timing is batch-only on one machine (1.07 s for 82,332 records); no per-request latency is measured.
11. The meaning of the `is_ftp_login` values is unconfirmed.
12. Dashboard metrics are hard-coded rather than read from the result files.

## 3. Documentation corrections made

No numerical results were changed.

| File | Correction |
|---|---|
| `docs/priority1_research_summary.md` | "cause 8,886" → "account for 8,886"; "best explained by" → "most plausibly associated with" |
| | "About half" of the gap → reference-dependent range 53–79% (TTL groupings) |
| | Threshold category losses labelled as internal evidence; test-set Fuzzers/Analysis rates added |
| | Permutation-importance statement made specific, with the correlated-feature caveat |
| | Wilson-interval caveat added to the limitations |
| `README.md` | Three outdated planning-stage statements updated: overlap "still need inspection", test file "is reserved", "proposed decisions… no model created" |
| | Threshold 0.60 bullet labelled internal, with test-set category rates |
| | "produce" → "account for"; decomposition range and Wilson caveat added; reproduce commands added |
| `evaluation/analyze_dataset_shift.py` | Figure 3 title "cause" → "account for". All 10 output CSV/JSON files regenerate byte-identically. |

## 4. Visualisation decisions

**New figures** (`evaluation/report_figures.py`, output in `evaluation/report_figures/`):

| Figure | Source | Shows | Design notes |
|---|---|---|---|
| A — validation model comparison | `validation_results.csv` | P/R/F1 and FPR for the 3 default models | Dot plot (axis stated as starting at 90%) plus FPR bars from 0; Wilson intervals; labelled in-distribution only |
| B — threshold trade-off | `threshold_analysis.csv`, `threshold_calibration.csv`, `threshold_attack_category_analysis.csv`, `threshold_internal_evaluation.csv` | FPR and recall across thresholds; overall, Fuzzers and Analysis recall at 0.50 vs 0.60 | Three datasets named on every panel; no official test data; notes that the 0.50 and 0.60 intervals come from the same records, so their overlap is not a significance test |
| C — paired multi-seed differences | `multiseed_paired_differences.csv`, `ttl_free_paired_differences.csv` | Per-seed and mean differences vs baseline, 5 metrics, both experiments plus the noise control | Symmetric axis around 0 per panel; "not measured" shown where the slice FPR was not recorded |
| D — detection by attack category | `report_stats/wilson_intervals.csv` | Detection rate with 95% Wilson intervals and n | Official test and internal partition in **separate panels**, labelled as different models and data |
| E — official-test confusion matrices | `test_results.csv` | Counts and row percentages | One shared colour scale; replaces the earlier raw-count figure for report use |

**Kept unchanged** (for reproducibility):
- `evaluation/test_confusion_matrices.png`
- shift figures 1, 2, 4 and 5

Figure 3 was regenerated with only its title changed.

**Not used in the report:** the dashboard screenshots in `frontend/screenshots/` are JPEG-compressed and their text is unreadable at report size. Keep them as demo backups only.

## 5. Approved derived statistics and caveats

**Wilson intervals** (`evaluation/report_stats/wilson_intervals.csv`, 58 rows; every row names its source file). Examples:

| Rate | Estimate | 95% Wilson |
|---|---:|---:|
| Official-test FPR | 26.77% | 26.32–27.22% |
| Official-test recall | 98.54% | 98.43–98.65% |
| Official-test Fuzzers detection (n = 6,062) | 90.04% | 89.26–90.77% |
| Official-test Worms detection (n = 44) | 100.0% | 91.97–100.0% |
| Internal Fuzzers detection, threshold 0.50 → 0.60 (n = 2,894) | 85.8% → 76.2% | 84.5–87.1% → 74.6–77.7% |

Caveats:
- Each record is treated as an independent Bernoulli trial with a fixed rate. Network records are correlated (repeated flows, shared hosts, duplicates), so the intervals are likely too narrow.
- They ignore distribution shift. They describe sampling uncertainty within one evaluation set and **do not establish external generalisation**.
- Intervals for paired comparisons (0.50 vs 0.60 on the same records) must not be read as a test of the difference.

**FPR-gap decomposition sensitivity** (`evaluation/report_stats/fpr_gap_decomposition.csv`).

The gap of 17.80 pp is split into a mix part and a within-group part, with s = group share and r = group FPR:
- **Validation reference:** mix = Σ(s_t − s_v)·r_v
- **Test reference:** mix = Σ(s_t − s_v)·r_t
- **Midpoint reference (Shapley):** mix = Σ(s_t − s_v)·(r_v + r_t)/2

Each pair sums exactly to the gap. Groups with fewer than 30 normal records share a pooled rate, as in the original analysis.

| Grouping | Mix, validation ref. | Mix, midpoint | Mix, test ref. | Mix share of gap |
|---|---:|---:|---:|---:|
| protocol/service/state | 2.21 pp | 3.36 pp | 4.50 pp | 12–25% |
| `sttl` value | 10.24 pp | 12.18 pp | 14.11 pp | 58–79% |
| combination × `sttl` | 9.48 pp | 11.56 pp | 13.64 pp | 53–77% |

Caveats:
- The components are **descriptive and reference-dependent, not causal**.
- The robust conclusion is qualitative: the TTL-group mix change accounts for a larger share of the gap than the protocol/service/state mix under every reference.
- The exact share is not identified. The 53–79% range quoted in the README and the summary is the spread of the mix share across the two TTL-based groupings (`sttl` value: 58–79%; combination × `sttl`: 53–77%) and the three references. It is a **descriptive sensitivity range, not a confidence interval**, and it does **not** establish the causal contribution of TTL.
- The original validation-reference values (2.21 / 10.24 / 9.48 pp) and their calculations in `evaluation/shift_analysis/` are unchanged; the alternative references are added alongside them.

## 6. Remaining research limitations

- There is no independent test dataset; generalisation beyond UNSW-NB15 is not established.
- The official-test FPR (26.77%) remains unresolved. Threshold, `dttl`-removal and TTL-free alternatives all failed their pre-declared checks.
- Random Forest scores are uncalibrated vote fractions.
- ROC/PR curves, AUC and per-request API latency have not been measured. They are optional next steps that need approval; on the test set they would be descriptive only.
- Prevention is simulated. From existing counts, 9,904 of 54,575 simulated block actions on the official test set (18.1%) would block normal traffic.
- Literature on UNSW-NB15 TTL artefacts still needs verification (Priority 3).

## Reproduce

```
python -m evaluation.report_statistics
python -m evaluation.report_figures
python -m evaluation.analyze_dataset_shift   # regenerates shift reports and figures 1–5
```
