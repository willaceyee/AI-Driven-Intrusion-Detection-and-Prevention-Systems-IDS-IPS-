# NIDS-WEB-03A backend proposal

This is a proposal only. NIDS-WEB-03A does not change the existing `/predict` endpoint, model artifact, preprocessing, threshold, or prevention behavior.

## Minimum additive response contract

The safest migration is to preserve every existing response field and add response-level `model` and `decision_policy` objects plus an optional `intelligence` object on each result.

```json
{
  "model": {
    "id": "unsw-nb15-random-forest",
    "version": "immutable-artifact-version",
    "positive_class": 1,
    "positive_class_name": "malicious"
  },
  "decision_policy": {
    "id": "review-policy-version",
    "threshold": 0.5,
    "comparator": ">=",
    "threshold_source": "validation",
    "response_mapping": {
      "normal": "allow",
      "malicious": "simulated_block"
    }
  },
  "results": [
    {
      "record_id": "existing-value",
      "row_number": 1,
      "predicted_label": 1,
      "prediction": "malicious",
      "simulated_action": "block",
      "intelligence": {
        "score": {
          "value": 0.83,
          "meaning": "estimated probability of the positive class",
          "scale": [0.0, 1.0],
          "higher_means": "more support for malicious",
          "calibrated": false,
          "calibration_method": null,
          "calibration_split": null
        },
        "explanation": {
          "method": "TreeSHAP",
          "method_version": "reviewed-library-version",
          "output_space": "probability_or_raw_margin_must_be_declared",
          "baseline": 0.0,
          "source_feature_mapping": "one-hot/transformed features aggregated to the 42 source features",
          "attributions": [
            {"feature": "dur", "source_value": 0.1, "contribution": 0.02}
          ],
          "additivity_checked": true
        }
      }
    }
  ]
}
```

The example values above define shape only and must never be returned as defaults or displayed as genuine results. The backend should omit `score` or `explanation` when it cannot provide validated values. It should not send feature rankings without a declared explanation method, output space, baseline and mapping back to the original 42 input fields.

## Required review before enablement

- Assign immutable model and policy versions and return them with every prediction batch.
- Define whether the score is an uncalibrated vote fraction, calibrated probability, decision margin or another quantity.
- Assess calibration on data excluded from model fitting. Report the method, split, reliability metrics and known limitations.
- Validate attribution additivity and the aggregation of one-hot encoded features back to source fields.
- Confirm that reference labels and `attack_cat` remain evaluation metadata and are never model inputs.
- Keep detection (`predicted_label`) distinct from prevention (`simulated_action` or a future policy decision).
- Treat explanations as model-behavior evidence, not causal or root-cause findings.

## Prevention Decision Lab methodology

1. Fit the model on training data only.
2. Fit any calibration mapping on a dedicated calibration subset or through leakage-safe cross-validation within training data.
3. Compare candidate thresholds and response policies using validation data and pre-agreed error costs. Record every candidate and selection rule.
4. Freeze the model, calibration mapping, threshold and response policy together under immutable versions.
5. Evaluate the frozen system once on the reserved test set. Do not use test outcomes to revise the threshold or policy.
6. Report confusion counts, precision, recall, F1, false-positive rate, calibration quality, policy costs and subgroup/attack-category results where the recorded data supports them.
7. Keep enforcement disabled until the backend and project team approve the policy, operational safeguards, rollback and audit requirements.

## Frontend enablement rule

The explanation and policy controls remain disabled until the backend contract is implemented, its semantics are documented, targeted contract tests pass, and the evaluation/model owners approve the evidence. The current binary `/predict` response remains fully supported.
