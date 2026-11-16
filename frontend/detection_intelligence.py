"""Evaluation-only analysis helpers for the Streamlit SOC.

Ground-truth fields are joined only after the backend has returned predictions. They
are never sent to, or used as inputs by, the model.
"""

from dataclasses import dataclass
from io import BytesIO

import numpy as np
import pandas as pd
import plotly.graph_objects as go

from preprocessing.prepare import CATEGORICAL, FEATURES, NUMERIC, validate_features


@dataclass(frozen=True)
class EvaluationSnapshot:
    name: str
    role: str
    true_negative: int
    false_positive: int
    false_negative: int
    true_positive: int

    @property
    def total(self):
        return self.true_negative + self.false_positive + self.false_negative + self.true_positive

    @property
    def precision(self):
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 0.0

    @property
    def recall(self):
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 0.0

    @property
    def f1(self):
        denominator = self.precision + self.recall
        return 2 * self.precision * self.recall / denominator if denominator else 0.0

    @property
    def false_positive_rate(self):
        denominator = self.false_positive + self.true_negative
        return self.false_positive / denominator if denominator else 0.0


VALIDATION_SNAPSHOT = EvaluationSnapshot(
    name="Validation",
    role="Model-selection split",
    true_negative=10_196,
    false_positive=1_004,
    false_negative=618,
    true_positive=23_251,
)

TEST_SNAPSHOT = EvaluationSnapshot(
    name="Reserved test",
    role="Final held-out evaluation",
    true_negative=27_096,
    false_positive=9_904,
    false_negative=661,
    true_positive=44_671,
)

EVALUATION_SNAPSHOTS = (VALIDATION_SNAPSHOT, TEST_SNAPSHOT)


def build_upload_context(csv_bytes, result_rows):
    """Join genuine source features to results after inference has completed."""
    source = pd.read_csv(BytesIO(csv_bytes), encoding="utf-8-sig", keep_default_na=False)
    results = pd.DataFrame(result_rows)
    if len(source) != len(results):
        raise ValueError("Uploaded rows and prediction results do not align.")

    features = validate_features(source).reset_index(drop=True)
    result_fields = [
        "record_id", "row_number", "predicted_label", "prediction", "simulated_action"
    ]
    if not set(result_fields).issubset(results.columns):
        raise ValueError("Prediction results are missing required record fields.")
    context = pd.concat([results[result_fields].reset_index(drop=True), features], axis=1)
    metadata = {"has_ground_truth": False, "label_warning": None, "has_attack_category": False}

    if "label" not in source.columns:
        return context, metadata
    try:
        labels = pd.to_numeric(source["label"], errors="raise")
        if labels.isna().any() or not labels.isin([0, 1]).all():
            raise ValueError("labels must contain only 0 or 1")
        labels = labels.astype(int).reset_index(drop=True)
    except (TypeError, ValueError):
        metadata["label_warning"] = (
            "The optional label column is not binary, so evaluation analysis is unavailable. "
            "Detection results are unaffected."
        )
        return context, metadata

    context["reference_label"] = labels
    context["reference_class"] = np.where(labels.eq(1), "malicious", "normal")
    context["evaluation_outcome"] = np.select(
        [
            labels.eq(0) & context["predicted_label"].eq(0),
            labels.eq(0) & context["predicted_label"].eq(1),
            labels.eq(1) & context["predicted_label"].eq(0),
            labels.eq(1) & context["predicted_label"].eq(1),
        ],
        ["true negative", "false positive", "false negative", "true positive"],
        default="unknown",
    )
    metadata["has_ground_truth"] = True

    if "attack_cat" in source.columns:
        context["reference_attack_category"] = source["attack_cat"].astype(str).str.strip()
        metadata["has_attack_category"] = True
    return context, metadata


def snapshot_from_labeled_records(records, name="Current labelled upload", role="Post-prediction audit"):
    """Calculate evaluation metrics from records with verified binary reference labels."""
    if "evaluation_outcome" not in records.columns:
        raise ValueError("Ground-truth evaluation outcomes are unavailable.")
    counts = records["evaluation_outcome"].value_counts()
    return EvaluationSnapshot(
        name=name,
        role=role,
        true_negative=int(counts.get("true negative", 0)),
        false_positive=int(counts.get("false positive", 0)),
        false_negative=int(counts.get("false negative", 0)),
        true_positive=int(counts.get("true positive", 0)),
    )


def filter_evaluation_records(records, outcome="Errors only", attack_categories=None):
    """Filter labelled audit records without changing any model decision."""
    visible = records
    if outcome == "Errors only":
        visible = visible[visible["evaluation_outcome"].isin(["false positive", "false negative"])]
    elif outcome != "All outcomes":
        visible = visible[visible["evaluation_outcome"] == outcome.lower()]
    if attack_categories and "reference_attack_category" in visible.columns:
        visible = visible[visible["reference_attack_category"].isin(attack_categories)]
    return visible


def make_confusion_matrix_figure(snapshot):
    matrix = [
        [snapshot.true_negative, snapshot.false_positive],
        [snapshot.false_negative, snapshot.true_positive],
    ]
    labels = [
        [f"TN<br>{snapshot.true_negative:,}", f"FP<br>{snapshot.false_positive:,}"],
        [f"FN<br>{snapshot.false_negative:,}", f"TP<br>{snapshot.true_positive:,}"],
    ]
    figure = go.Figure(go.Heatmap(
        z=matrix,
        x=["Predicted normal", "Predicted malicious"],
        y=["Actual normal", "Actual malicious"],
        text=labels,
        texttemplate="%{text}",
        hovertemplate="%{y}<br>%{x}<br>%{z:,} records<extra></extra>",
        colorscale=[[0, "#102034"], [0.5, "#177f7b"], [1, "#3de0c5"]],
        showscale=False,
    ))
    figure.update_layout(
        height=370,
        margin={"l": 10, "r": 10, "t": 20, "b": 10},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#a7b5c6"},
    )
    figure.update_yaxes(autorange="reversed")
    return figure


def make_metric_comparison_figure():
    metrics = ["Precision", "Recall", "F1", "False-positive rate"]
    figure = go.Figure()
    for snapshot, color in zip(EVALUATION_SNAPSHOTS, ["#3de0c5", "#ffb547"]):
        figure.add_trace(go.Bar(
            name=snapshot.name,
            x=metrics,
            y=[snapshot.precision, snapshot.recall, snapshot.f1, snapshot.false_positive_rate],
            marker_color=color,
            hovertemplate=f"%{{x}}<br>%{{y:.2%}}<extra>{snapshot.name}</extra>",
        ))
    figure.update_layout(
        barmode="group",
        height=370,
        margin={"l": 10, "r": 10, "t": 20, "b": 10},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#a7b5c6"},
        legend={"orientation": "h", "y": 1.08},
        yaxis={"tickformat": ".0%", "range": [0, 1], "gridcolor": "#213044"},
        xaxis={"gridcolor": "#213044"},
    )
    return figure


def make_outcome_figure(records):
    order = ["true negative", "false positive", "false negative", "true positive"]
    counts = records["evaluation_outcome"].value_counts().reindex(order, fill_value=0)
    colors = ["#3de0c5", "#ffb547", "#ff4d6d", "#42a5f5"]
    figure = go.Figure(go.Bar(
        x=[label.title() for label in order],
        y=counts.values,
        marker_color=colors,
        text=[f"{value:,}" for value in counts.values],
        textposition="outside",
        hovertemplate="%{x}<br>%{y:,} records<extra></extra>",
    ))
    figure.update_layout(
        height=300,
        margin={"l": 10, "r": 10, "t": 20, "b": 10},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#a7b5c6"},
        yaxis={"title": "Records", "gridcolor": "#213044"},
    )
    return figure


INPUT_FEATURES = tuple(FEATURES)
NUMERIC_FEATURES = tuple(NUMERIC)
CATEGORICAL_FEATURES = tuple(CATEGORICAL)
