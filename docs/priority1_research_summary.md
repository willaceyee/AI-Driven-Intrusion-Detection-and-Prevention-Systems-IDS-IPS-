# Priority 1 Research Summary: False Positives and Generalisation

**Project:** SEC3044 AI-Driven IDS/IPS
**Branch:** `feature/fp-analysis`
**Status:** Closed. The original 42-feature Random Forest is kept at threshold 0.50.

All experiments below are research-only. The production pipeline (`models/artifacts/selected_pipeline.joblib`, SHA-256 `a171cb07…`), preprocessing, backend and dashboard were not changed. Every number comes from a generated report in this repository; the source file is named in each section.

---

## 1. Baseline

**Model:** Random Forest (100 trees, `random_state=42`) on 42 UNSW-NB15 features.
- Numeric features are standardised and categorical features are one-hot encoded.
- It was selected by validation attack-class F1 over Logistic Regression and Decision Tree (`evaluation/validation_results.csv`, `evaluation/model_selection.json`).

**Data split:** the official training set is split 80/20 into `train.csv` and `validation.csv` with `StratifiedGroupKFold`. Identical feature records are kept on the same side of the split.

| Dataset | Records | Precision | Recall | F1 | FPR | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| Validation | 35,069 | 95.86% | 97.41% | 96.63% | 8.96% | 1,004 | 618 |
| Official test | 82,332 | 81.85% | 98.54% | 89.43% | **26.77%** | 9,904 | 661 |
| Official test, excluding rows also in training | 75,818 | 80.52% | 98.38% | 88.56% | 26.57% | 9,518 | 646 |

Sources: `evaluation/test_results.csv`, `evaluation/test_category_results.csv`, `evaluation/test_confusion_matrices.png`.

**Problem addressed:** a high false-positive rate, and a three-fold increase in FPR from validation to the official test set.

## 2. False-positive investigations (validation set)

Scripts: `evaluation/analyze_false_positives.py`, `analyze_fp_categories.py`, `analyze_fp_combinations.py`, `analyze_fp_confidence.py`, `analyze_feature_importance.py`. Outputs are in `evaluation/fp_analysis/`.

- **Numeric features.** False positives have much higher `sttl`/`dttl` than true negatives (medians 254/252 vs 31/29). They also have longer durations and larger packet intervals (`numeric_comparison.csv`). These are associations, not proven causes.
- **Traffic combinations.** Four protocol/service/state combinations account for 999 of the 1,004 validation false positives (`combination_analysis.csv`):

  | Combination | FPR |
  |---|---:|
  | `tcp/-/FIN` | 11.9% |
  | `udp/-/INT` | 41.1% |
  | `tcp/http/FIN` | 11.1% |
  | `tcp/ftp/FIN` | 19.7% |

  All four contain both normal and attack records in training, so these categories alone can't separate the classes.
- **Score confidence.** False positives in these groups have median attack scores of 0.63–0.73, clearly above 0.50 (`confidence_analysis.csv`).
- **Permutation importance.** `dttl`, `sttl`, `service` and the connection-count features matter most for both recall and FPR (`feature_importance.csv`).

## 3. Threshold 0.60: rejected for deployment

Raising the threshold lowers FPR on validation, but recall falls with it (`threshold_analysis.csv`):

| Threshold | FPR | Recall | F1 |
|---:|---:|---:|---:|
| 0.50 | 8.96% | 97.41% | 96.63% |
| 0.60 | 5.83% | 95.76% | 96.49% |
| 0.70 | 3.65% | 93.41% | 95.74% |
| 0.80 | 1.96% | 90.54% | 94.58% |
| 0.90 | 0.58% | 85.52% | 92.06% |

**Controlled calibration** (`validate_threshold_policy.py`):
- **Setup:** `train.csv` was split into fitting, calibration and internal-evaluation parts (60/20/20, grouped).
- **Policy:** minimise FPR while keeping recall at or above 95%. It selected 0.60.
- **Internal result:** FPR fell from 10.06% to 6.93%, but recall fell from 97.56% to 95.82%. That is **333 more missed attacks** (`threshold_internal_evaluation.csv`).

**Why it was rejected:** the losses fall on the weakest categories (`threshold_attack_category_analysis.csv`):
- **Fuzzers:** recall fell from 85.83% to 76.16%; 280 of the 333 extra misses are Fuzzers.
- **Analysis:** recall fell from 90.82% to 82.95%.

## 4. `dttl` ablation and multi-seed robustness check: rejected

**Single split** (`experiment_ttl_ablation.py`, `ttl_ablation_*.csv`):
- Removing `dttl` gave 36 fewer false positives and 9 fewer missed attacks than the baseline.
- That partition had already been inspected, so this needed a robustness check.

**Multi-seed check** (`experiment_multiseed.py`, `multiseed_*.csv`):
- **Setup:** 5 split seeds (42, 7, 123, 2024, 31337) with identical grouped 80/20 partitions per seed and threshold 0.50.
- **Noise control:** the baseline retrained with only a different model seed. This shows how much results move by chance.
- **Decision rule, fixed before running:** lower FPR on at least 4 of 5 seeds, and an average gain larger than the noise control's variation.

| Result (41-feature minus baseline) | Value |
|---|---|
| Seeds with lower FPR | 1 of 5 (fails the rule) |
| Average FPR change | **+0.14 pp** (worse) |
| Seed noise (control) | 0.12 pp |
| False positives / false negatives, summed over 5 seeds | 4,168 / 2,494 vs baseline 4,106 / 2,471 |

**Conclusion:** the single-split gain did not replicate and was no larger than random variation from the model seed.

## 5. Dataset-shift diagnostics

Script: `evaluation/analyze_dataset_shift.py`. Reports are in `evaluation/shift_analysis/`, figures in `evaluation/shift_analysis/figures/`.

The production model only scored validation and the official test set here. It reproduced the official test results exactly (9,904 FP, 661 FN). No model was trained and no threshold was tuned.

1. **Validation matches training; the official test set does not.**
   - Normal records, training vs validation: largest KS statistic 0.016, largest PSI 0.0015.
   - Normal records, training vs test: KS 0.27 (`sttl`), PSI 0.28 (`dttl`).
   - So the validation FPR only describes data like the training data (`numeric_shift.csv`, `fig4_numeric_shift_ks.png`).
2. **Splitting the 17.8-point FPR gap** (`fpr_decomposition.csv`, `fig1_fpr_gap_decomposition.png`).

   "Traffic mix" means more test traffic falls into groups that are already hard. "Within group" means the same group is classified worse on the test set.

   | Grouped by | Traffic mix | Within group |
   |---|---:|---:|
   | protocol/service/state | 2.2 pp | 15.6 pp |
   | `sttl` value | **10.2 pp** | 7.6 pp |
   | combination × `sttl` | 9.5 pp | 8.3 pp |

3. **TTL and false positives** (`ttl_analysis.csv`, `fig2_sttl_shift_and_fpr.png`).

   | Normal records with | Share of training normals | Share of test normals | Test FPR |
   |---|---:|---:|---:|
   | `sttl=254` | 20% | 41% | 59% |
   | `sttl=31` | 70% | 45% | 0.04% |

   - 90% of all training records with `sttl=254` are attacks.
   - `sttl=254` normals cause 8,886 of the 9,904 test false positives.
4. **Within the same TTL group, test FPR is higher than validation FPR** (`fig3_top_fp_groups.png`):
   - `tcp/-/FIN` with `sttl=254`: 44% → 61%
   - `udp/-/INT` with `sttl=254`: 44% → 78%

   Among `sttl=254` normals, the largest remaining shift is in the connection-count features (KS 0.11–0.13, `numeric_shift_sttl254.csv`).
5. **Minor factors** (`overlap_analysis.csv`, `unseen_patterns.csv`, `fp_score_distribution.csv`):
   - **Conflicting labels:** 386 test FPs (3.9%) are exact copies of training records labelled attack, so no model could avoid them.
   - **New traffic:** combinations rare or absent in training cover only 0.3% of test normals.
   - **Class balance:** the test set's larger share of normal traffic lowers precision but doesn't affect FPR.
   - **Scores:** test false positives are spread across scores 0.5–1.0 (median 0.71; `fig5_fp_score_distribution.png`), so no threshold can remove them cheaply.

## 6. TTL-free model (`sttl`, `dttl`, `ct_state_ttl` removed): rejected

Script: `evaluation/experiment_ttl_free_multiseed.py`. Outputs: `evaluation/fp_analysis/ttl_free_*.csv` and `ttl_free_decision.json`.

**Setup:** same seeds, partitions, threshold and noise control as section 4. The official test set was not read.

**Criteria, fixed before running.** "Slice" means normal records with `sttl` of 62 or 254.

| Criterion | Seeds passing | Average | Result |
|---|---:|---|---|
| C1: slice FPR falls on at least 4 of 5 seeds, by more than the noise control | 2 of 5 | +0.14 pp (worse); noise 0.49 pp | **Fail** |
| C2: recall drops by no more than 0.5 pp | 5 of 5 | 0.02 pp | Pass |
| C3: Fuzzers and Analysis recall each drop by no more than 2 pp | 5 of 5 | Fuzzers +0.03 pp, Analysis −0.20 pp | Pass |
| C4: overall FPR rises by no more than 0.5 pp | 5 of 5 | +0.06 pp | Pass |

**Worst single seed:**
- recall −0.14 pp
- Fuzzers recall −0.79 pp
- Analysis recall −0.98 pp
- overall FPR +0.18 pp
- slice FPR +0.70 pp

**What it shows:**
- Removing the TTL features changed nothing measurable inside the training distribution. 99.9% of internal false positives stay in the slice, at about 39% FPR.
- TTL **marks** the traffic group that is hard to classify. Removing it doesn't fix the errors, because other features carry the same information.
- Whether a TTL-free model behaves differently on the shifted official test set was not tested. It failed the pre-declared rule, and the test set is not used for selection.

## 7. Limitations

1. `validation.csv` was used for model selection and for investigations in sections 2–3. It is not an untouched held-out set.
2. The internal evaluation partition (seed 42) was inspected repeatedly. The multi-seed checks show stability across splits of one dataset, not independent results. Their confidence intervals are exploratory only.
3. The **official test set has been inspected**: for the baseline evaluation and for the shift diagnostics in section 5. It was never used to select a model or threshold, but it is no longer fully untouched. Any future final evaluation must say so.
4. UNSW-NB15 has no third independent dataset. External generalisation, for example to other networks or datasets, has not been shown.
5. KS and PSI look at one feature at a time. KS p-values are left out because they are always "significant" at these sample sizes. PSI depends on how features are binned, and its 0.1/0.25 cut-offs are rules of thumb from other fields.
6. Shift statistics show association, not cause. The explanations in section 5 are the most plausible ones, not proven mechanisms. Literature on TTL artefacts in UNSW-NB15 still has to be verified for the report.
7. Random Forest scores are vote fractions, not calibrated probabilities of attack.
8. Prevention is **simulated**. No real firewall enforcement takes place.

## 8. Final Priority 1 decision

**Keep the original 42-feature Random Forest at threshold 0.50.** All three candidate changes failed pre-declared checks or were rejected on safety grounds:

| Candidate | Outcome | Reason |
|---|---|---|
| Threshold 0.60 | Rejected | 333 more missed attacks; Fuzzers recall −9.7 pp |
| Remove `dttl` | Rejected | Not robust across 5 seeds; within random variation |
| Remove all TTL features | Rejected | No reduction in slice FPR (C1 failed) |

The 26.77% official-test FPR is best explained by a difference between the training and test traffic. About half comes from more test normals having TTL values that mostly belong to attacks in training. The other half comes from normal traffic in the same groups being classified worse. Validation could not show this, because it matches the training data. This is reported as a known limitation of the model and the dataset.

**Possible follow-up, not started:** separate alerting from simulated blocking. Every flow above 0.50 would still alert, but only flows above a higher cut-off, chosen on internal data, would be blocked. This would need approval because it changes the prevention logic.

## Reproduce

Run from the repository root:

```
python -m evaluation.experiment_multiseed           # about 11 min
python -m evaluation.experiment_ttl_free_multiseed  # about 11 min
python -m evaluation.analyze_dataset_shift          # about 10 s
```

Recorded environment: Python 3.12, scikit-learn 1.9.1. The cloud reruns used pandas 3.0.5; the project pins pandas 3.1.1.
