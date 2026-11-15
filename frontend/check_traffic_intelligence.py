"""Targeted checks for traffic projection, filtering and synthetic scenarios."""

from pathlib import Path

import numpy as np
import pandas as pd

from frontend.traffic_intelligence import (
    THREAT_SCENARIOS,
    build_traffic_projection,
    deterministic_stratified_indices,
    filter_projection,
    get_scenario,
    make_projection_figure,
    make_scenario_globe,
)


ROOT = Path(__file__).resolve().parents[1]


def check():
    labels = np.array([0] * 4_000 + [1] * 6_000)
    first = deterministic_stratified_indices(labels, max_points=1_200)
    second = deterministic_stratified_indices(labels, max_points=1_200)
    assert np.array_equal(first, second)
    assert len(first) == 1_200 and set(labels[first]) == {0, 1}

    full_source = pd.read_csv(ROOT / "data/processed/validation.csv")
    source = full_source.groupby("label", group_keys=False).head(1_000).reset_index(drop=True)
    result_rows = []
    for number, label in enumerate(source["label"].astype(int), start=1):
        malicious = bool(label)
        result_rows.append({
            "record_id": f"projection-test-row-{number}",
            "row_number": number,
            "predicted_label": int(label),
            "prediction": "malicious" if malicious else "normal",
            "simulated_action": "block" if malicious else "allow",
        })
    csv_bytes = source.to_csv(index=False).encode("utf-8")
    projection, metadata = build_traffic_projection(csv_bytes, result_rows, max_points=600)
    repeat, repeat_metadata = build_traffic_projection(csv_bytes, result_rows, max_points=600)
    assert len(projection) == 600 == metadata["sample_rows"]
    assert metadata == repeat_metadata and metadata["source_rows"] == 2_000
    assert np.allclose(projection[["pc1", "pc2", "pc3"]], repeat[["pc1", "pc2", "pc3"]])
    assert set(projection.prediction) == {"normal", "malicious"}

    malicious = filter_projection(projection, prediction="Malicious")
    assert not malicious.empty and malicious.prediction.eq("malicious").all()
    proto = projection.proto.iloc[0]
    one_proto = filter_projection(projection, categorical_feature="proto", categorical_values=[proto])
    assert not one_proto.empty and one_proto.proto.eq(proto).all()
    lower, upper = projection.dur.quantile([0.25, 0.75])
    duration = filter_projection(projection, numeric_feature="dur", numeric_range=(lower, upper))
    assert duration.dur.between(lower, upper, inclusive="both").all()

    assert len(THREAT_SCENARIOS) == 3
    assert get_scenario("credential-spray") == THREAT_SCENARIOS[0]
    assert all(-90 <= item.origin_lat <= 90 and -180 <= item.origin_lon <= 180 for item in THREAT_SCENARIOS)
    assert all(-90 <= item.destination_lat <= 90 and -180 <= item.destination_lon <= 180 for item in THREAT_SCENARIOS)
    assert all(item.steps and item.outcome for item in THREAT_SCENARIOS)
    assert {trace.type for trace in make_projection_figure(projection, dimensions=3).data} == {"scatter3d"}
    assert {trace.type for trace in make_projection_figure(projection, dimensions=2).data} == {"scatter"}
    assert {trace.type for trace in make_scenario_globe(THREAT_SCENARIOS[0]).data} == {"scattergeo"}
    print("Passed deterministic sampling, PCA bounds, repeatability, filters, 2D fallback and scenarios.")


if __name__ == "__main__":
    check()
