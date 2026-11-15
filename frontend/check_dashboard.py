"""Run dashboard integration checks with the backend running on port 8000."""

from io import BytesIO
from pathlib import Path
from unittest.mock import patch
import time

import pandas as pd
import requests
from streamlit.testing.v1 import AppTest


ROOT = Path(__file__).resolve().parents[1]


def detection_button(app):
    return next(button for button in app.button if button.label == "Run detection")


def check():
    app_path = str(ROOT / "frontend/app.py")
    app = AppTest.from_file(app_path).run(timeout=15)
    assert not app.exception and detection_button(app).disabled
    upload = BytesIO((ROOT / "data/processed/validation.csv").read_bytes())
    upload.name = "validation.csv"
    started = time.perf_counter()
    with patch("streamlit.file_uploader", return_value=upload), patch("streamlit.download_button") as download:
        app = AppTest.from_file(app_path).run()
        detection_button(app).click().run(timeout=120)
        assert not app.exception and not app.error
        result = app.session_state["prediction_result"]
        assert result["summary"]["total"] == 35069
        csv_call = next(call for call in download.call_args_list if call.kwargs["file_name"] == "detection_results.csv")
        exported = pd.read_csv(BytesIO(csv_call.args[1]))
        pd.testing.assert_frame_equal(exported, pd.DataFrame(result["results"]))
        assert len(app.dataframe[0].value) == 100
        assert len(app.dataframe[1].value) <= 100
        for choice in ["Malicious", "Normal"]:
            app.selectbox[0].select(choice).run()
            assert not app.exception
            assert app.dataframe[0].value.prediction.eq(choice.lower()).all()
            assert len(app.dataframe[0].value) <= 100
        app.selectbox[0].select("All").run()
        linked_record = result["results"][89]["record_id"]
        app.text_input[0].input(linked_record).run()
        assert not app.exception
        assert app.dataframe[0].value["record_id"].tolist() == [linked_record]
        print(f"Full validation upload, preview, filters and complete export passed in {time.perf_counter()-started:.2f}s.")

        for error, message in [
            (requests.exceptions.ConnectionError(), "Cannot reach"),
            (requests.exceptions.Timeout(), "timed out"),
        ]:
            with patch("requests.post", side_effect=error):
                detection_button(app).click().run()
            assert not app.exception
            assert message in app.error[0].value
            assert "prediction_result" not in app.session_state
            assert len(app.metric) == 0

        invalid = BytesIO(b"dur,dur\n1,2\n")
        invalid.name = "invalid.csv"
        with patch("streamlit.file_uploader", return_value=invalid):
            detection_button(app).click().run()
        assert not app.exception and "Please check your CSV" in app.error[0].value
        assert "prediction_result" not in app.session_state
    print("Invalid-upload, unavailable-service, timeout and stale-results checks passed.")


if __name__ == "__main__":
    check()
