"""Verify the PCA workspace is connected to genuine backend prediction results."""

from io import BytesIO
from pathlib import Path

from streamlit.testing.v1 import AppTest


ROOT = Path(__file__).resolve().parents[1]


def detection_button(app):
    return next(button for button in app.button if button.label == "Run detection")


def radio_with_option(app, option):
    return next(control for control in app.radio if option in control.options)


def select_control(app, label):
    return next(control for control in app.selectbox if control.label == label)


def check():
    app_path = str(ROOT / "frontend/app.py")
    upload = BytesIO((ROOT / "data/processed/validation.csv").read_bytes())
    upload.name = "validation.csv"

    from unittest.mock import patch

    with patch("streamlit.file_uploader", return_value=upload):
        app = AppTest.from_file(app_path).run(timeout=15)
        detection_button(app).click().run(timeout=120)

        assert not app.exception and not app.error
        result = app.session_state["prediction_result"]
        projection = app.session_state["traffic_projection"]
        metadata = app.session_state["projection_metadata"]
        assert metadata["source_rows"] == result["summary"]["total"] == 35069
        assert metadata["sample_rows"] == len(projection) <= metadata["max_points"]

        predictions_by_row = {
            int(record["row_number"]): (record["record_id"], record["prediction"], record["simulated_action"])
            for record in result["results"]
        }
        for sampled in projection[["row_number", "record_id", "prediction", "simulated_action"]].itertuples():
            assert predictions_by_row[int(sampled.row_number)] == (
                sampled.record_id,
                sampled.prediction,
                sampled.simulated_action,
            )

        navigation = radio_with_option(app, "Traffic Intelligence")
        assert "Traffic Intelligence" in navigation.options
        navigation.set_value("Traffic Intelligence").run(timeout=30)
        assert not app.exception and not app.error
        projection_view = radio_with_option(app, "3D feature space")
        assert projection_view.value == "3D feature space"
        assert len(app.get("plotly_chart")) == 1

        prediction_filter = select_control(app, "Projection prediction")
        prediction_filter.select("Malicious").run(timeout=30)
        assert not app.exception and select_control(app, "Projection prediction").value == "Malicious"
        radio_with_option(app, "3D feature space").set_value("2D accessible view").run(timeout=30)
        assert not app.exception and radio_with_option(app, "3D feature space").value == "2D accessible view"
        assert len(app.get("plotly_chart")) == 1

        selected_row = int(select_control(app, "Inspect sampled record").value)
        selected = projection.loc[projection["row_number"].eq(selected_row)].iloc[0]
        handoff = next(button for button in app.button if button.label == "Use this record in investigation and replay")
        handoff.click().run(timeout=30)
        assert app.session_state["investigation_query"] == selected["record_id"]
        assert app.session_state["replay_position"] == selected_row

    print("Real 35,069-row upload, PCA workspace, filters, 3D/2D views and handoff passed.")


if __name__ == "__main__":
    check()
