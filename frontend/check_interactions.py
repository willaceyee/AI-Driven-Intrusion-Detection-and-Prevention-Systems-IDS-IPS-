"""Regression checks for navigation, record identity, replay boundaries and scenario controls."""

from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch

from streamlit.testing.v1 import AppTest

from frontend.scenario_interaction import scenario_card_html
from frontend.traffic_intelligence import THREAT_SCENARIOS, make_scenario_globe


ROOT = Path(__file__).resolve().parents[1]


def button(app, label):
    return next(item for item in app.button if item.label == label)


def radio_with_option(app, option):
    return next(item for item in app.radio if option in item.options)


def select_control(app, label):
    return next(item for item in app.selectbox if item.label == label)


def check():
    upload = BytesIO(b"dur\n1\n")
    upload.name = "interaction_sample.csv"
    records = [
        {
            "record_id": f"demo-interaction-row-{row}",
            "row_number": row,
            "predicted_label": int(row in {1, 3}),
            "prediction": "malicious" if row in {1, 3} else "normal",
            "simulated_action": "block" if row in {1, 3} else "allow",
        }
        for row in range(1, 5)
    ]
    result = {
        "upload_id": "b" * 32,
        "simulation": True,
        "summary": {"total": 4, "normal": 2, "malicious": 2},
        "results": records,
        "simulated_block_list": [records[0]["record_id"], records[2]["record_id"]],
    }
    response = Mock(status_code=200)
    response.json.return_value = result

    with patch("streamlit.file_uploader", return_value=upload), patch("requests.post", return_value=response):
        app = AppTest.from_file(str(ROOT / "frontend/app.py")).run(timeout=15)
        button(app, "Run detection").click().run(timeout=15)
        assert not app.exception and not app.error

        select_control(app, "Flagged record to investigate").select(3).run(timeout=15)
        button(app, "Investigate selected record").click().run(timeout=15)
        assert app.session_state["active_workspace"] == "Incident Investigation"
        assert app.session_state["investigation_query"] == records[2]["record_id"]
        assert app.session_state["replay_position"] == 3
        assert len(app.dataframe[0].value) == 1

        button(app, "← Back to Command Overview").click().run(timeout=15)
        assert app.session_state["active_workspace"] == "Command Overview"

        radio_with_option(app, "Prevention & Replay").set_value("Prevention & Replay").run(timeout=15)
        assert app.slider[0].value == 3
        button(app, "Previous").click().run(timeout=15)
        assert app.session_state["replay_position"] == 2
        button(app, "Next flagged").click().run(timeout=15)
        assert app.session_state["replay_position"] == 3
        jump = next(item for item in app.number_input if item.label == "Jump to CSV row")
        jump.set_value(1).run(timeout=15)
        button(app, "Jump to record").click().run(timeout=15)
        assert app.session_state["replay_position"] == 1
        assert button(app, "Previous").disabled

        radio_with_option(app, "Scenario Globe").set_value("Scenario Globe").run(timeout=15)
        assert select_control(app, "Highlighted tabletop route").value == "credential-spray"
        next(item for item in app.radio if item.label == "Educational stage").set_value(4).run(timeout=15)
        assert len(app.get("plotly_chart")) == 1

    figure = make_scenario_globe(THREAT_SCENARIOS[0], stage_index=3)
    assert len(figure.frames) == 0 and len(figure.data) == 4
    card = scenario_card_html(THREAT_SCENARIOS[0], 0, THREAT_SCENARIOS)
    assert "pointerdown" in card and "pointerup" in card and "cubic-bezier" in card
    assert "prefers-reduced-motion" in card and "ArrowLeft" in card and "Escape" in card
    assert "https://" not in card and card.count("http://") == 1  # Local SVG namespace only.
    assert "startGlobeMotion" in card and "sentinelMotionStarted" in card
    assert "circle[data-sentinel-signal]" in card
    assert "requestAnimationFrame" in card and "getPointAtLength" in card
    assert "plotly_afterplot" in card and "signal.isConnected" in card
    assert "restoreAfterResize" in card and "removeEventListener" in card
    assert "document.contains(globe)" in card and "setInterval" not in card
    assert "(() =>" in card
    assert "length > 0" in card and "__sentinelRedraw" in card  # Hidden-route and reduced-motion redraw guards.
    print("Navigation, exact record handoff, replay boundaries and synthetic scenario controls passed.")


if __name__ == "__main__":
    check()
