
import joblib
import numpy as np
import pandas as pd

from preprocessing.prepare import ROOT, read_csv, validate_features


GROUPS = [
    ("tcp", "-", "FIN"),
    ("udp", "-", "INT"),
    ("tcp", "http", "FIN"),
    ("tcp", "ftp", "FIN"),
]


def analyze():
    train = read_csv(ROOT / "data/processed/train.csv")
    validation = read_csv(ROOT / "data/processed/validation.csv")

    model = joblib.load(
        ROOT / "models/artifacts/selected_pipeline.joblib"
    )

    features = validate_features(validation)
    labels = validation["label"].astype(int).to_numpy()

    predictions = model.predict(features)
    probabilities = model.predict_proba(features)

    # Find the correct column for the malicious class.
    class_index = list(model.classes_).index(1)
    scores = probabilities[:, class_index]

    records = features.copy()
    records["actual"] = labels
    records["predicted"] = predictions
    records["attack_score"] = scores

    rows = []

    for proto, service, state in GROUPS:
        group_name = f"{proto}/{service}/{state}"

        train_group = train[
            (train["proto"] == proto)
            & (train["service"] == service)
            & (train["state"] == state)
        ]

        val_group = records[
            (records["proto"] == proto)
            & (records["service"] == service)
            & (records["state"] == state)
        ]

        fp = val_group[
            (val_group["actual"] == 0)
            & (val_group["predicted"] == 1)
        ]

        tn = val_group[
            (val_group["actual"] == 0)
            & (val_group["predicted"] == 0)
        ]

        attacks = val_group[val_group["actual"] == 1]

        print(f"\n=== {group_name} ===")
        print("Training normal:",
              int((train_group["label"] == 0).sum()))
        print("Training malicious:",
              int((train_group["label"] == 1).sum()))
        print("Validation false positives:", len(fp))
        print("Validation true negatives:", len(tn))

        for name, subset in [("FP", fp), ("TN", tn)]:
            if len(subset):
                print(
                    f"{name} attack-score median: "
                    f"{subset['attack_score'].median():.4f}"
                )

        attack_recall = (
            (attacks["predicted"] == 1).mean()
            if len(attacks) else np.nan
        )

        rows.append({
            "group": group_name,
            "train_normal": int(
                (train_group["label"] == 0).sum()
            ),
            "train_attack": int(
                (train_group["label"] == 1).sum()
            ),
            "val_fp": len(fp),
            "val_tn": len(tn),
            "val_attacks": len(attacks),
            "val_attack_recall": attack_recall,
            "fp_score_median": (
                fp["attack_score"].median()
                if len(fp) else np.nan
            ),
            "tn_score_median": (
                tn["attack_score"].median()
                if len(tn) else np.nan
            ),
        })

    output = ROOT / "evaluation/fp_analysis"
    output.mkdir(parents=True, exist_ok=True)

    pd.DataFrame(rows).to_csv(
        output / "confidence_analysis.csv",
        index=False,
    )

    print("\nSaved confidence_analysis.csv")


if __name__ == "__main__":
    analyze()
