"""Targeted checks for evaluation and investigation data transformations."""

from io import BytesIO

import pandas as pd

from frontend.detection_intelligence import (
    INPUT_FEATURES,
    TEST_SNAPSHOT,
    VALIDATION_SNAPSHOT,
    build_upload_context,
    filter_evaluation_records,
    make_confusion_matrix_figure,
    make_metric_comparison_figure,
    make_outcome_figure,
    snapshot_from_labeled_records,
)
from preprocessing.prepare import FEATURES


def sample_source():
    rows = []
    for label, category in [(0, "Normal"), (0, "Normal"), (1, "Exploits"), (1, "Fuzzers")]:
        row = {feature: 1 for feature in FEATURES}
        row.update({"proto": "tcp", "service": "-", "state": "FIN", "label": label, "attack_cat": category})
        rows.append(row)
    return pd.DataFrame(rows)


def sample_results():
    predicted = [0, 1, 0, 1]
    return [
        {
            "record_id": f"demo-check-row-{index}",
            "row_number": index,
            "predicted_label": label,
            "prediction": "malicious" if label else "normal",
            "simulated_action": "block" if label else "allow",
        }
        for index, label in enumerate(predicted, start=1)
    ]


def check():
    assert len(INPUT_FEATURES) == 42
    csv_bytes = sample_source().to_csv(index=False).encode("utf-8")
    context, metadata = build_upload_context(csv_bytes, sample_results())
    assert metadata == {"has_ground_truth": True, "label_warning": None, "has_attack_category": True}
    assert context["evaluation_outcome"].tolist() == [
        "true negative", "false positive", "false negative", "true positive"
    ]
    snapshot = snapshot_from_labeled_records(context)
    assert (snapshot.true_negative, snapshot.false_positive, snapshot.false_negative, snapshot.true_positive) == (1, 1, 1, 1)
    assert len(filter_evaluation_records(context, "Errors only")) == 2
    assert filter_evaluation_records(context, "False positive")["row_number"].tolist() == [2]
    assert filter_evaluation_records(context, "All outcomes", ["Exploits"])["row_number"].tolist() == [3]

    unlabeled = sample_source().drop(columns=["label", "attack_cat"]).to_csv(index=False).encode("utf-8")
    unlabeled_context, unlabeled_metadata = build_upload_context(unlabeled, sample_results())
    assert not unlabeled_metadata["has_ground_truth"]
    assert "evaluation_outcome" not in unlabeled_context

    invalid = sample_source()
    invalid.loc[0, "label"] = 3
    invalid_context, invalid_metadata = build_upload_context(
        invalid.to_csv(index=False).encode("utf-8"), sample_results()
    )
    assert not invalid_metadata["has_ground_truth"] and invalid_metadata["label_warning"]
    assert "evaluation_outcome" not in invalid_context

    assert round(VALIDATION_SNAPSHOT.f1, 10) == round(0.9662954035408527, 10)
    assert round(VALIDATION_SNAPSHOT.false_positive_rate, 10) == round(0.08964285714285715, 10)
    assert round(TEST_SNAPSHOT.f1, 10) == round(0.8942516540382556, 10)
    assert round(TEST_SNAPSHOT.false_positive_rate, 10) == round(0.2676756756756757, 10)
    assert make_confusion_matrix_figure(VALIDATION_SNAPSHOT).data[0].type == "heatmap"
    assert len(make_metric_comparison_figure().data) == 2
    assert make_outcome_figure(context).data[0].type == "bar"
    print("Passed labelled-upload isolation, error filtering, evaluation metrics and analysis figures.")


if __name__ == "__main__":
    check()
