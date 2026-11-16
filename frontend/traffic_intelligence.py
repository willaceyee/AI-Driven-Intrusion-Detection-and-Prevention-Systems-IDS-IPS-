"""Deterministic traffic projection and synthetic scenario data for the SOC UI."""

from dataclasses import dataclass
from io import BytesIO

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from sklearn.decomposition import PCA

from preprocessing.prepare import CATEGORICAL, NUMERIC, make_preprocessor, validate_features


MAX_PROJECTION_POINTS = 1_200
PROJECTION_SEED = 42


@dataclass(frozen=True)
class ThreatScenario:
    scenario_id: str
    name: str
    attack_type: str
    origin_name: str
    origin_lat: float
    origin_lon: float
    destination_name: str
    destination_lat: float
    destination_lon: float
    steps: tuple[str, ...]
    outcome: str


THREAT_SCENARIOS = (
    ThreatScenario(
        "credential-spray",
        "Credential spray exercise",
        "Simulated credential access",
        "Reykjavík scenario node",
        64.1466,
        -21.9426,
        "Kuala Lumpur scenario node",
        3.1390,
        101.6869,
        ("Authentication burst", "Rule match", "Account challenge", "Analyst review"),
        "Simulated account challenge issued",
    ),
    ThreatScenario(
        "service-probe",
        "Exposed-service probe",
        "Simulated reconnaissance",
        "São Paulo scenario node",
        -23.5505,
        -46.6333,
        "Singapore scenario node",
        1.3521,
        103.8198,
        ("Port sequence observed", "Rate threshold crossed", "Session isolated", "Case retained"),
        "Simulated session isolation",
    ),
    ThreatScenario(
        "data-egress",
        "Data-egress tabletop",
        "Simulated abnormal transfer",
        "Tokyo scenario node",
        35.6762,
        139.6503,
        "Sydney scenario node",
        -33.8688,
        151.2093,
        ("Transfer volume rises", "Policy alert", "Connection paused", "Evidence exported"),
        "Simulated connection pause",
    ),
)


def deterministic_stratified_indices(labels, max_points=MAX_PROJECTION_POINTS, seed=PROJECTION_SEED):
    """Return a reproducible, class-aware bounded sample of row positions."""
    labels = np.asarray(labels)
    if labels.ndim != 1:
        raise ValueError("Labels must be one-dimensional.")
    if max_points < 2:
        raise ValueError("max_points must be at least 2.")
    if len(labels) <= max_points:
        return np.arange(len(labels), dtype=int)

    classes, counts = np.unique(labels, return_counts=True)
    quotas = np.floor(counts / len(labels) * max_points).astype(int)
    quotas = np.maximum(quotas, 1)
    quotas = np.minimum(quotas, counts)
    while quotas.sum() < max_points:
        remaining = counts - quotas
        candidate = int(np.argmax(remaining))
        if remaining[candidate] == 0:
            break
        quotas[candidate] += 1
    while quotas.sum() > max_points:
        removable = np.where(quotas > 1, quotas, 0)
        candidate = int(np.argmax(removable))
        quotas[candidate] -= 1

    generator = np.random.default_rng(seed)
    selected = []
    for label, quota in zip(classes, quotas):
        positions = np.flatnonzero(labels == label)
        selected.extend(generator.choice(positions, size=int(quota), replace=False).tolist())
    return np.asarray(sorted(selected), dtype=int)


def build_traffic_projection(csv_bytes, result_rows, max_points=MAX_PROJECTION_POINTS):
    """Build a bounded PCA projection from actual uploaded feature values."""
    source = pd.read_csv(BytesIO(csv_bytes), encoding="utf-8-sig", keep_default_na=False)
    results = pd.DataFrame(result_rows)
    required_result_fields = {
        "record_id", "row_number", "predicted_label", "prediction", "simulated_action"
    }
    if not required_result_fields.issubset(results.columns):
        raise ValueError("Prediction results are missing required record fields.")
    if len(source) != len(results):
        raise ValueError("Uploaded rows and prediction results do not align.")

    indices = deterministic_stratified_indices(results["predicted_label"], max_points=max_points)
    source_sample = source.iloc[indices].reset_index(drop=True)
    result_sample = results.iloc[indices].reset_index(drop=True)
    features = validate_features(source_sample)

    transformer = make_preprocessor()
    transformed = transformer.fit_transform(features)
    dense = transformed.toarray() if hasattr(transformed, "toarray") else np.asarray(transformed)
    component_count = min(3, dense.shape[0], dense.shape[1])
    if component_count < 2:
        raise ValueError("At least two records and transformed features are required for projection.")
    reducer = PCA(n_components=component_count, svd_solver="randomized", random_state=PROJECTION_SEED)
    coordinates = reducer.fit_transform(dense)

    projection = pd.concat([result_sample, features.reset_index(drop=True)], axis=1)
    projection["pc1"] = coordinates[:, 0]
    projection["pc2"] = coordinates[:, 1]
    projection["pc3"] = coordinates[:, 2] if component_count >= 3 else 0.0
    metadata = {
        "source_rows": len(source),
        "sample_rows": len(projection),
        "source_class_counts": {
            str(label): int(count)
            for label, count in results["prediction"].value_counts().sort_index().items()
        },
        "sample_class_counts": {
            str(label): int(count)
            for label, count in projection["prediction"].value_counts().sort_index().items()
        },
        "max_points": max_points,
        "seed": PROJECTION_SEED,
        "method": "PCA after sample-fitted numeric scaling and categorical one-hot encoding",
        "explained_variance_ratio": tuple(float(value) for value in reducer.explained_variance_ratio_),
    }
    return projection, metadata


def filter_projection(
    projection,
    prediction="All",
    categorical_feature=None,
    categorical_values=None,
    numeric_feature=None,
    numeric_range=None,
):
    """Apply explainable UI filters without changing projection coordinates."""
    visible = projection
    if prediction != "All":
        visible = visible[visible["prediction"] == prediction.lower()]
    if categorical_feature in CATEGORICAL and categorical_values:
        visible = visible[visible[categorical_feature].isin(categorical_values)]
    if numeric_feature in NUMERIC and numeric_range is not None:
        lower, upper = numeric_range
        visible = visible[visible[numeric_feature].between(lower, upper, inclusive="both")]
    return visible


def get_scenario(scenario_id):
    for scenario in THREAT_SCENARIOS:
        if scenario.scenario_id == scenario_id:
            return scenario
    raise KeyError(f"Unknown threat scenario: {scenario_id}")


def make_projection_figure(projection, dimensions=3, height=560):
    """Create either the primary 3D view or its 2D accessibility fallback."""
    if dimensions not in {2, 3}:
        raise ValueError("Projection dimensions must be 2 or 3.")
    common = {
        "data_frame": projection,
        "x": "pc1",
        "y": "pc2",
        "color": "prediction",
        "symbol": "prediction",
        "color_discrete_map": {"malicious": "#ff4d6d", "normal": "#3de0c5"},
        "symbol_map": {"malicious": "diamond", "normal": "circle"},
        "hover_name": "record_id",
        "hover_data": {
            "row_number": True,
            "prediction": True,
            "simulated_action": True,
            "proto": True,
            "service": True,
            "state": True,
            "pc1": ":.3f",
            "pc2": ":.3f",
            "pc3": ":.3f",
        },
        "labels": {"pc1": "PC1", "pc2": "PC2", "pc3": "PC3", "prediction": "Prediction"},
    }
    if dimensions == 3:
        figure = px.scatter_3d(z="pc3", **common)
        figure.update_traces(marker={"size": 4, "opacity": 0.74})
        figure.update_layout(scene={
            "xaxis_title": "PC1 · feature variation",
            "yaxis_title": "PC2 · feature variation",
            "zaxis_title": "PC3 · feature variation",
            "bgcolor": "rgba(0,0,0,0)",
        })
    else:
        figure = px.scatter(**common)
        figure.update_traces(marker={"size": 7, "opacity": 0.7})
        figure.update_xaxes(title="PC1 · feature variation", gridcolor="#213044", zerolinecolor="#33465e")
        figure.update_yaxes(title="PC2 · feature variation", gridcolor="#213044", zerolinecolor="#33465e")
    figure.update_layout(
        height=height,
        margin={"l": 10, "r": 10, "t": 25, "b": 10},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#a7b5c6"},
        legend={"orientation": "h", "y": 1.02, "x": 0},
        uirevision="traffic-projection",
    )
    return figure


def make_scenario_globe(scenario, height=560):
    """Create a globe for one explicitly synthetic, deterministic exercise."""
    figure = go.Figure()
    figure.add_trace(go.Scattergeo(
        lat=[scenario.origin_lat, scenario.destination_lat],
        lon=[scenario.origin_lon, scenario.destination_lon],
        mode="lines",
        line={"width": 3, "color": "#ff4d6d"},
        hoverinfo="skip",
        name="Simulated route",
    ))
    figure.add_trace(go.Scattergeo(
        lat=[scenario.origin_lat, scenario.destination_lat],
        lon=[scenario.origin_lon, scenario.destination_lon],
        mode="markers+text",
        marker={"size": [10, 13], "color": ["#ff4d6d", "#3de0c5"], "line": {"width": 1, "color": "#071018"}},
        text=["SIMULATED ORIGIN", "SIMULATED DESTINATION"],
        textposition=["top center", "bottom center"],
        customdata=[scenario.origin_name, scenario.destination_name],
        hovertemplate="%{text}<br>%{customdata}<extra></extra>",
        name="Scenario nodes",
    ))
    figure.update_geos(
        projection_type="orthographic",
        projection_rotation={"lat": 12, "lon": 70, "roll": 0},
        showland=True,
        landcolor="#132238",
        showocean=True,
        oceancolor="#07111e",
        showcountries=True,
        countrycolor="#34465c",
        showcoastlines=True,
        coastlinecolor="#476078",
        bgcolor="rgba(0,0,0,0)",
    )
    figure.update_layout(
        height=height,
        margin={"l": 0, "r": 0, "t": 10, "b": 0},
        paper_bgcolor="rgba(0,0,0,0)",
        font={"color": "#a7b5c6"},
        showlegend=False,
        uirevision=f"scenario-{scenario.scenario_id}",
    )
    return figure
