"""Local CSV prediction API. Run with python -m uvicorn backend.app:app."""

import csv
import io
from contextlib import asynccontextmanager
from uuid import uuid4

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, UploadFile

from preprocessing.prepare import ROOT, validate_features


@asynccontextmanager
async def lifespan(app):
    model_path = ROOT / "models/artifacts/selected_pipeline.joblib"
    if not model_path.is_file():
        raise RuntimeError("Run python -m models.train before starting the backend.")
    app.state.pipeline = joblib.load(model_path)
    yield


app = FastAPI(
    title="UNSW-NB15 Detection Demo",
    lifespan=lifespan,
    swagger_ui_parameters={"syntaxHighlight": False},
)


@app.get("/health")
def health():
    return {"status": "ready", "simulation": True}


@app.post("/predict")
def predict(file: UploadFile):
    """Validate the entire CSV before producing any prediction or simulated action."""
    try:
        text = file.file.read().decode("utf-8-sig")
        rows = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(rows, [])
        if not header or len(header) != len(set(header)):
            raise ValueError("CSV requires unique, nonempty column headers.")
        records = []
        for number, row in enumerate(rows, start=1):
            if len(row) != len(header):
                raise ValueError(f"Data row {number} has an incorrect number of fields.")
            records.append(row)
        features = validate_features(pd.DataFrame(records, columns=header))
    except (UnicodeError, csv.Error, ValueError, OverflowError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    predictions = app.state.pipeline.predict(features)
    upload_id = uuid4().hex
    results = []
    block_list = []
    for number, label in enumerate(predictions, start=1):
        record_id = f"demo-{upload_id}-row-{number}"
        malicious = int(label) == 1
        results.append({
            "record_id": record_id,
            "row_number": number,
            "predicted_label": int(label),
            "prediction": "malicious" if malicious else "normal",
            "simulated_action": "block" if malicious else "allow",
        })
        if malicious:
            block_list.append(record_id)
    return {
        "upload_id": upload_id,
        "simulation": True,
        "summary": {
            "total": len(results),
            "normal": len(results) - len(block_list),
            "malicious": len(block_list),
        },
        "results": results,
        "simulated_block_list": block_list,
    }
