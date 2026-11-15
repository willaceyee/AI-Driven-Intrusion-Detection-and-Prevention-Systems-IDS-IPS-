"""Streamlit Security Operations Center for the local IDS/IPS demonstration."""

from ast import literal_eval
import json
from html import escape
from pathlib import Path

import altair as alt
import pandas as pd
import requests
import streamlit as st

from frontend.soc_theme import apply_soc_theme, render_brand, render_empty_state, render_section_header


BACKEND = "http://127.0.0.1:8000"
PREVIEW_ROWS = 100
SEQUENCE_SEGMENTS = 48
ROOT = Path(__file__).resolve().parents[1]


def clear_results():
    """Remove results whenever the selected upload changes or a request fails."""
    st.session_state.pop("prediction_result", None)
    st.session_state.pop("result_filename", None)


def summarise_validation_error(detail):
    """Turn a long backend schema report into a readable operator message."""
    if "Missing:" not in detail or "unexpected:" not in detail:
        return detail
    try:
        missing_text = detail.split("Missing:", 1)[1].split(";", 1)[0].strip()
        unexpected_text = detail.split("unexpected:", 1)[1].strip()
        missing = literal_eval(missing_text)
        unexpected = literal_eval(unexpected_text)
    except (SyntaxError, ValueError):
        return "Schema mismatch: the CSV does not contain the required 42-feature input."
    return (
        f"Schema mismatch: {len(missing)} required column(s) missing; "
        f"{len(unexpected)} unexpected column(s)."
    )


def run_detection(upload):
    """Submit the selected CSV without changing the backend contract."""
    clear_results()
    try:
        with st.spinner("Analysing uploaded traffic with the selected model…"):
            response = requests.post(
                f"{BACKEND}/predict",
                files={"file": (upload.name, upload.getvalue(), "text/csv")},
                timeout=(10, 120),
            )
        if response.status_code == 422:
            detail = response.json().get("detail", "Invalid upload.")
            st.error(f"Please check your CSV. {summarise_validation_error(detail)}")
            with st.expander("Technical validation details"):
                st.code(detail, language=None, wrap_lines=True)
            return
        response.raise_for_status()
        st.session_state.prediction_result = response.json()
        st.session_state.result_filename = upload.name
    except requests.exceptions.Timeout:
        st.error("The request timed out. Try a smaller CSV and check the backend terminal.")
    except requests.exceptions.ConnectionError:
        st.error("Cannot reach the detection service. Start the backend on port 8000, then try again.")
    except (requests.exceptions.HTTPError, ValueError):
        st.error("The detection service returned an unexpected response. Check the backend terminal.")


def metric_card(label, value, detail, tone="neutral"):
    st.markdown(
        f"""<div class="metric-card metric-{tone}"><div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div><div class="metric-detail">{detail}</div></div>""",
        unsafe_allow_html=True,
    )


def make_distribution_chart(summary):
    source = pd.DataFrame({
        "classification": ["Malicious", "Normal"],
        "records": [summary["malicious"], summary["normal"]],
    })
    return (
        alt.Chart(source)
        .mark_arc(innerRadius=64, outerRadius=94, cornerRadius=6, padAngle=0.025)
        .encode(
            theta=alt.Theta("records:Q"),
            color=alt.Color(
                "classification:N",
                scale=alt.Scale(domain=["Malicious", "Normal"], range=["#ff4d6d", "#3de0c5"]),
                legend=alt.Legend(title=None, orient="bottom", labelColor="#a7b5c6"),
            ),
            tooltip=["classification:N", alt.Tooltip("records:Q", format=",")],
        )
        .properties(height=260)
        .configure(background="transparent")
        .configure_view(strokeOpacity=0)
    )


def make_sequence_chart(rows):
    """Aggregate genuine decisions into ordered CSV row segments."""
    chart_rows = rows[["row_number", "predicted_label"]].copy()
    segment_count = min(SEQUENCE_SEGMENTS, len(chart_rows))
    chart_rows["segment"] = ((chart_rows["row_number"] - 1) * segment_count // len(chart_rows)) + 1
    chart_rows = chart_rows.groupby("segment", as_index=False).agg(
        start_row=("row_number", "min"),
        end_row=("row_number", "max"),
        records=("row_number", "size"),
        flagged=("predicted_label", "sum"),
    )
    chart_rows["flagged_share"] = chart_rows["flagged"] / chart_rows["records"]
    return (
        alt.Chart(chart_rows)
        .mark_area(line={"color": "#ff4d6d", "strokeWidth": 2}, color="#ff4d6d", opacity=0.22)
        .encode(
            x=alt.X("start_row:Q", title="CSV row order (not time)"),
            y=alt.Y(
                "flagged_share:Q",
                title="Flagged share",
                axis=alt.Axis(format=".0%"),
                scale=alt.Scale(domain=[0, 1]),
            ),
            tooltip=[
                alt.Tooltip("start_row:Q", title="First row", format=","),
                alt.Tooltip("end_row:Q", title="Last row", format=","),
                alt.Tooltip("records:Q", title="Records", format=","),
                alt.Tooltip("flagged:Q", title="Flagged", format=","),
                alt.Tooltip("flagged_share:Q", title="Flagged share", format=".1%"),
            ],
        )
        .properties(height=220)
        .configure(background="transparent")
        .configure_axis(gridColor="#213044", domainColor="#33465e", labelColor="#91a2b8", titleColor="#91a2b8")
        .configure_view(strokeOpacity=0)
    )


@st.cache_data(show_spinner=False)
def load_model_assurance():
    """Read existing validation evidence without changing evaluation artifacts."""
    results = pd.read_csv(ROOT / "evaluation/validation_results.csv")
    selected = results.loc[results["model"] == "Random Forest"]
    return selected.iloc[0].to_dict() if not selected.empty else None


def render_overview(rows, summary):
    total = summary["total"]
    threat_rate = (summary["malicious"] / total * 100) if total else 0
    columns = st.columns(4)
    with columns[0]:
        metric_card("Records analysed", f"{total:,}", "Current uploaded dataset")
    with columns[1]:
        metric_card("Flagged malicious", f"{summary['malicious']:,}", "Requires analyst review", "danger")
    with columns[2]:
        metric_card("Normal", f"{summary['normal']:,}", "Model predictions", "safe")
    with columns[3]:
        metric_card("Review workload", f"{threat_rate:.1f}%", "Share flagged by model", "warning")
    st.caption(
        "Counts describe model predictions for this upload—not measured accuracy or live network activity. "
        "Prevention actions are simulated."
    )
    chart_left, chart_right = st.columns([0.85, 1.65], gap="large")
    with chart_left:
        st.markdown("#### Classification split")
        st.altair_chart(make_distribution_chart(summary), width="stretch")
    with chart_right:
        st.markdown("#### Flagged share by file order")
        st.caption("Aggregated across 48 ordered CSV row segments. Position shows file order—not an event timestamp.")
        st.altair_chart(make_sequence_chart(rows), width="stretch")
    st.markdown(
        """<div class="analyst-callout"><div class="callout-label">MODEL LIMITATION</div>
        <div><strong>A flagged record is a review signal, not proof of intrusion.</strong>
        The selected model produced an 8.96% false-positive rate on held-out validation data.
        Corroborate decisions with packet, session, host, or identity evidence before escalation.</div></div>""",
        unsafe_allow_html=True,
    )


def render_investigation(rows, result):
    render_section_header(
        "Incident investigation",
        "Filter model decisions, inspect record-level actions, and review simulated containment identifiers.",
        "INVESTIGATE",
    )
    controls = st.columns([1, 1, 1.4])
    with controls[0]:
        selection = st.selectbox("Show predictions", ["All", "Malicious", "Normal"])
    with controls[1]:
        action = st.selectbox("Simulated action", ["All actions", "Block", "Allow"])
    with controls[2]:
        query = st.text_input("Find record", placeholder="Record ID or row number")
    visible = rows
    if selection != "All":
        visible = visible[visible["prediction"] == selection.lower()]
    if action != "All actions":
        visible = visible[visible["simulated_action"] == action.lower()]
    if query.strip():
        needle = query.strip().lower()
        visible = visible[
            visible["record_id"].str.lower().str.contains(needle, regex=False)
            | visible["row_number"].astype(str).eq(needle)
        ]
    st.caption(f"Showing up to {PREVIEW_ROWS} of {len(visible):,} matching records.")
    st.dataframe(
        visible.head(PREVIEW_ROWS),
        hide_index=True,
        width="stretch",
        column_config={
            "record_id": st.column_config.TextColumn("Demonstration record"),
            "row_number": st.column_config.NumberColumn("Row", format="%d"),
            "predicted_label": st.column_config.NumberColumn("Label", format="%d"),
            "prediction": st.column_config.TextColumn("Prediction"),
            "simulated_action": st.column_config.TextColumn("Simulated action"),
        },
    )
    st.markdown("#### Simulated containment queue")
    if result["summary"]["malicious"]:
        st.warning(
            f"{result['summary']['malicious']:,} malicious predictions triggered simulated block actions. "
            "Review the source row before escalation; no firewall or network control was changed."
        )
        st.dataframe(
            pd.DataFrame({"demonstration_identifier": result["simulated_block_list"][:PREVIEW_ROWS]}),
            hide_index=True,
            width="stretch",
        )
        st.caption("Preview limited to 100 identifiers. The full prediction export contains every simulated action.")
        st.markdown(
            """<div class="analyst-callout compact"><div class="callout-label">ANALYST NEXT STEP</div>
            <div>Use the CSV row number to find the original record, then validate it against network or host evidence.
            This dataset contains no source IP, packet payload, geolocation, or relationship edges, so the dashboard
            cannot attribute the prediction to a real host.</div></div>""",
            unsafe_allow_html=True,
        )
    else:
        st.success("No malicious predictions were returned for this upload.")


def render_replay(rows):
    render_section_header(
        "Attack replay",
        "Step through model output in upload order. This is a deterministic review—not live packet playback.",
        "REPLAY",
    )
    if rows.empty:
        return
    position = st.slider("Record position", 1, len(rows), 1)
    event = rows.iloc[position - 1]
    malicious = event["prediction"] == "malicious"
    status = "THREAT DETECTED" if malicious else "TRAFFIC ALLOWED"
    tone = "replay-danger" if malicious else "replay-safe"
    st.markdown(
        f"""<div class="replay-card {tone}"><div class="replay-index">EVENT {position:04d} / {len(rows):04d}</div>
        <div class="replay-status">{status}</div><div class="replay-grid">
        <span>Record</span><strong>{escape(str(event['record_id']))}</strong><span>Model label</span><strong>{int(event['predicted_label'])}</strong>
        <span>Simulated response</span><strong>{event['simulated_action'].upper()}</strong></div></div>""",
        unsafe_allow_html=True,
    )


def render_exports(rows, result):
    render_section_header(
        "Model assurance and exports",
        "Separate established validation evidence from the current upload, then export the complete result set.",
        "ASSURE",
    )
    assurance = load_model_assurance()
    if assurance:
        assurance_columns = st.columns(4)
        assurance_values = [
            ("Validation precision", assurance["precision"]),
            ("Validation recall", assurance["recall"]),
            ("Validation F1", assurance["f1"]),
            ("False-positive rate", assurance["false_positive_rate"]),
        ]
        for column, (label, value) in zip(assurance_columns, assurance_values):
            with column:
                metric_card(label, f"{value:.2%}", "Held-out validation only")
        st.caption(
            "These are stored Random Forest validation results, not metrics for the current upload. "
            "Official test-set evaluation and live-network performance remain unverified."
        )
    st.markdown("#### Current case exports")
    csv_col, json_col = st.columns(2)
    with csv_col:
        st.download_button(
            "Download all predictions (CSV)", rows.to_csv(index=False).encode("utf-8"),
            file_name="detection_results.csv", mime="text/csv", width="stretch",
        )
    with json_col:
        st.download_button(
            "Download complete response (JSON)", json.dumps(result, indent=2).encode("utf-8"),
            file_name="detection_response.json", mime="application/json", width="stretch",
        )


st.set_page_config(
    page_title="Sentinel SOC | IDS/IPS", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded"
)
apply_soc_theme()

with st.sidebar:
    render_brand()
    st.markdown('<div class="sidebar-label">DETECTION INPUT</div>', unsafe_allow_html=True)
    upload = st.file_uploader(
        "Upload traffic CSV", type=["csv"], on_change=clear_results,
        help="Use the agreed UNSW-NB15 format with all 42 prediction features.",
    )
    st.caption("Optional dataset label columns are excluded from prediction by the backend.")
    if st.button("Run detection", disabled=upload is None, type="primary", width="stretch"):
        run_detection(upload)
    st.markdown('<div class="sidebar-rule"></div>', unsafe_allow_html=True)
    st.markdown("**Environment**")
    st.markdown('<div class="status-row"><span class="status-dot"></span> Local demonstration</div>', unsafe_allow_html=True)
    st.caption("UNSW-NB15 · Random Forest · Simulated prevention")
    st.info("Block-list entries are generated demonstration identifiers. No real host is blocked.")

st.markdown(
    """<div class="topbar"><div><div class="eyebrow">SECURITY OPERATIONS / DETECTION CONSOLE</div>
    <h1>Sentinel Command</h1><p>Upload-based intrusion detection and transparent simulated response.</p></div>
    <div class="mode-badge"><span></span> DEMO MODE</div></div>""",
    unsafe_allow_html=True,
)

if "prediction_result" not in st.session_state:
    render_empty_state()
else:
    result = st.session_state.prediction_result
    rows = pd.DataFrame(result["results"])
    st.markdown(
        f'<div class="result-context"><span>ACTIVE CASE</span> {escape(st.session_state.result_filename)} · '
        f'{result["upload_id"][:12]}…</div>', unsafe_allow_html=True,
    )
    st.markdown(
        """<div class="case-flow"><div class="flow-active"><b>01 DETECT</b><span>Model decisions ready</span></div>
        <div><b>02 INVESTIGATE</b><span>Validate flagged rows</span></div>
        <div><b>03 RESPOND</b><span>Review simulated actions</span></div></div>""",
        unsafe_allow_html=True,
    )
    overview_tab, investigate_tab, replay_tab, export_tab = st.tabs(
        ["Command overview", "Incident investigation", "Attack replay", "Model & exports"]
    )
    with overview_tab:
        render_overview(rows, result["summary"])
    with investigate_tab:
        render_investigation(rows, result)
    with replay_tab:
        render_replay(rows)
    with export_tab:
        render_exports(rows, result)
