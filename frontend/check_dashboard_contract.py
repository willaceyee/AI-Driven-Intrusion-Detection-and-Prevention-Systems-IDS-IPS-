"""Check the SOC presentation against the established backend response contract."""

from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch

import pandas as pd
import requests
from streamlit.testing.v1 import AppTest


ROOT = Path(__file__).resolve().parents[1]


def check():
    upload = BytesIO(b"dur\n1\n")
    upload.name = "soc_sample.csv"
    result = {
        "upload_id": "a" * 32,
        "simulation": True,
        "summary": {"total": 3, "normal": 1, "malicious": 2},
        "results": [
            {
                "record_id": "demo-a-row-1", "row_number": 1, "predicted_label": 1,
                "prediction": "malicious", "simulated_action": "block",
            },
            {
                "record_id": "demo-a-row-2", "row_number": 2, "predicted_label": 0,
                "prediction": "normal", "simulated_action": "allow",
            },
            {
                "record_id": "demo-a-row-3", "row_number": 3, "predicted_label": 1,
                "prediction": "malicious", "simulated_action": "block",
            },
        ],
        "simulated_block_list": ["demo-a-row-1", "demo-a-row-3"],
    }
    response = Mock(status_code=200)
    response.json.return_value = result

    with (
        patch("streamlit.file_uploader", return_value=upload),
        patch("requests.post", return_value=response) as post,
        patch("streamlit.download_button") as download,
    ):
        app = AppTest.from_file(str(ROOT / "frontend/app.py")).run(timeout=15)
        app.button[0].click().run(timeout=15)
        assert not app.exception and not app.error
        assert len(app.tabs) == 4 and len(app.slider) == 1
        assert len(app.dataframe[0].value) == 3
        assert len(app.dataframe[1].value) == 2

        app.selectbox[0].select("Malicious").run(timeout=15)
        assert app.dataframe[0].value.prediction.eq("malicious").all()
        app.selectbox[1].select("Block").run(timeout=15)
        assert app.dataframe[0].value.simulated_action.eq("block").all()

        csv_call = next(call for call in download.call_args_list if call.kwargs["file_name"] == "detection_results.csv")
        exported = pd.read_csv(BytesIO(csv_call.args[1]))
        pd.testing.assert_frame_equal(exported, pd.DataFrame(result["results"]))
        assert post.call_args.args[0].endswith("/predict")

        for error, message in [
            (requests.exceptions.ConnectionError(), "Cannot reach"),
            (requests.exceptions.Timeout(), "timed out"),
        ]:
            post.side_effect = error
            app.button[0].click().run(timeout=15)
            assert not app.exception and message in app.error[0].value
            assert "prediction_result" not in app.session_state

        invalid = Mock(status_code=422)
        invalid.json.return_value = {
            "detail": "Invalid input schema. Missing: ['dur', 'proto']; unexpected: ['bad_column']"
        }
        post.side_effect = None
        post.return_value = invalid
        app.button[0].click().run(timeout=15)
        assert not app.exception and "2 required column(s) missing" in app.error[0].value
        assert "['dur'" not in app.error[0].value
        assert "prediction_result" not in app.session_state
    print("SOC contract, filters, replay, exports and error-state clearing passed.")


if __name__ == "__main__":
    check()
