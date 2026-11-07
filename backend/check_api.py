"""Check a running local backend: python -m backend.check_api [base_url]."""

import sys

import joblib
import pandas as pd
import requests

from preprocessing.prepare import ROOT, validate_features


def check():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    response = requests.get(f"{url}/health", timeout=10)
    response.raise_for_status()
    assert response.json()["status"] == "ready"
    frame = pd.read_csv(ROOT / "data/processed/validation.csv", nrows=100)
    pipeline = joblib.load(ROOT / "models/artifacts/selected_pipeline.joblib")
    expected = pipeline.predict(validate_features(frame)).tolist()

    def upload(content, status=200):
        response = requests.post(
            f"{url}/predict", files={"file": ("sample.csv", content, "text/csv")}, timeout=60
        )
        assert response.status_code == status, response.text
        return response.json()

    result = upload(frame.to_csv(index=False))
    assert [row["predicted_label"] for row in result["results"]] == expected
    assert [row["row_number"] for row in result["results"]] == list(range(1, 101))
    assert result["summary"] == {"total": 100, "normal": expected.count(0), "malicious": expected.count(1)}
    blocked = [row["record_id"] for row in result["results"] if row["predicted_label"] == 1]
    assert result["simulated_block_list"] == blocked
    assert all(row["simulated_action"] == ("block" if row["predicted_label"] else "allow") for row in result["results"])
    changed = frame.assign(label=99, attack_cat="ignored")
    changed = changed[changed.columns[::-1]]
    again = upload(changed.to_csv(index=False))
    assert [row["predicted_label"] for row in again["results"]] == expected
    assert result["upload_id"] != again["upload_id"]
    upload(frame.assign(state="unseen-category").to_csv(index=False))
    for content in [
        "", "dur,dur\n1,2\n", b"\xff\xfe", "dur,proto\n1,tcp,extra\n",
        frame.head(0).to_csv(index=False),
        frame.drop(columns="dur").to_csv(index=False),
        frame.assign(dur="invalid").to_csv(index=False),
        frame.assign(dur=float("inf")).to_csv(index=False),
        frame.assign(proto="").to_csv(index=False),
        frame.assign(unexpected=1).to_csv(index=False),
    ]:
        error = upload(content, 422)
        assert "detail" in error and "results" not in error
    print("Passed prediction parity, summaries, simulated actions, column ordering, label exclusion,")
    print("unique upload IDs, unseen categories, and 10 invalid-upload cases.")


if __name__ == "__main__":
    check()
