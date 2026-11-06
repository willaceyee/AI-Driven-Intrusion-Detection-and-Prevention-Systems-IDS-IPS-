"""Validate UNSW-NB15 training data and prepare a reproducible grouped split."""

import csv
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import OneHotEncoder, StandardScaler


ROOT = Path(__file__).resolve().parents[1]
CATEGORICAL = ["proto", "service", "state"]
FEATURES = """dur proto service state spkts dpkts sbytes dbytes rate sttl dttl
sload dload sloss dloss sinpkt dinpkt sjit djit swin stcpb dtcpb dwin tcprtt
synack ackdat smean dmean trans_depth response_body_len ct_srv_src ct_state_ttl
ct_dst_ltm ct_src_dport_ltm ct_dst_sport_ltm ct_dst_src_ltm is_ftp_login
ct_ftp_cmd ct_flw_http_mthd ct_src_ltm ct_srv_dst is_sm_ips_ports""".split()
NUMERIC = [name for name in FEATURES if name not in CATEGORICAL]
OPTIONAL = {"id", "label", "attack_cat"}


def read_csv(path):
    """Check headers before pandas can rename duplicates automatically."""
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        header = next(csv.reader(handle), [])
    if not header or len(header) != len(set(header)):
        raise ValueError("CSV must have a nonempty header with unique column names.")
    return pd.read_csv(path, encoding="utf-8-sig", keep_default_na=False)


def validate_features(frame):
    """Return ordered model inputs; optional labels never enter this result."""
    missing = sorted(set(FEATURES) - set(frame.columns))
    unexpected = sorted(set(frame.columns) - set(FEATURES) - OPTIONAL)
    if frame.empty or not frame.columns.is_unique or missing or unexpected:
        raise ValueError(
            f"Invalid input schema or empty data. Missing: {missing}; unexpected: {unexpected}"
        )
    features = frame.loc[:, FEATURES].copy()
    for name in CATEGORICAL:
        if features[name].isna().any():
            raise ValueError(f"Missing category in {name}.")
        features[name] = features[name].astype(str).str.strip()
        if features[name].eq("").any():
            raise ValueError(f"Empty category in {name}.")
    for name in NUMERIC:
        features[name] = pd.to_numeric(features[name], errors="raise").astype(float)
        if not np.isfinite(features[name]).all():
            raise ValueError(f"Non-finite numeric value in {name}.")
    return features


def make_preprocessor():
    """Fit only on training inputs. Unknown categories become all-zero indicators."""
    return ColumnTransformer(
        [
            ("numeric", StandardScaler(), NUMERIC),
            ("categorical", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL),
        ],
        sparse_threshold=1.0,
    )


def prepare():
    source = ROOT / "data/raw/UNSW_NB15_training-set.csv"
    frame = read_csv(source)
    features = validate_features(frame)
    if "label" not in frame:
        raise ValueError("Training CSV requires label.")
    labels = pd.to_numeric(frame["label"], errors="raise")
    if not labels.isin([0, 1]).all() or labels.nunique() != 2:
        raise ValueError("Training labels must contain both binary classes 0 and 1.")
    labels = labels.astype(int)

    # Factorize complete feature tuples so grouping excludes labels and identifiers.
    groups, unique_groups = pd.factorize(pd.MultiIndex.from_frame(features), sort=False)
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    train_indices, validation_indices = next(splitter.split(features, labels, groups))
    overlap = set(groups[train_indices]) & set(groups[validation_indices])
    if overlap:
        raise RuntimeError("Identical feature groups crossed the split.")

    transformer = make_preprocessor()
    transformer.fit(features.iloc[train_indices])
    # Verify validation transformation without fitting any validation statistics.
    validation_matrix = transformer.transform(features.iloc[validation_indices])
    group_labels = pd.DataFrame({"group": groups, "label": labels})
    report = {
        "source": source.name,
        "seed": 42,
        "split_method": "First fold of five-fold StratifiedGroupKFold",
        "source_rows": len(frame),
        "input_features": FEATURES,
        "unique_feature_groups": len(unique_groups),
        "binary_conflict_groups": int((group_labels.groupby("group").label.nunique() > 1).sum()),
        "shared_train_validation_groups": len(overlap),
        "transformed_columns": validation_matrix.shape[1],
    }
    for name, indices in [("train", train_indices), ("validation", validation_indices)]:
        report[name] = {
            "rows": len(indices),
            "fraction": len(indices) / len(frame),
            "label_counts": labels.iloc[indices].value_counts().sort_index().to_dict(),
        }

    output = ROOT / "data/processed"
    output.mkdir(parents=True, exist_ok=True)
    frame.iloc[train_indices].to_csv(output / "train.csv", index=False)
    frame.iloc[validation_indices].to_csv(output / "validation.csv", index=False)
    joblib.dump(transformer, output / "preprocessor.joblib")
    (output / "split_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    prepare()
