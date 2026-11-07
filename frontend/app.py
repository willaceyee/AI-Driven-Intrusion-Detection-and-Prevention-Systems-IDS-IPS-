"""Streamlit interface for the local intrusion detection demonstration."""

import pandas as pd
import requests
import streamlit as st


BACKEND = "http://127.0.0.1:8000"
PREVIEW_ROWS = 100


def clear_results():
    st.session_state.pop("prediction_result", None)
    st.session_state.pop("result_filename", None)


st.set_page_config(page_title="Network Detection Demo", page_icon="🛡️", layout="wide")
st.title("Network Detection Demo")
st.caption("UNSW-NB15 • Random Forest • Simulated prevention")
st.info("Block-list entries are demonstration identifiers. Actions are simulated.")
upload = st.file_uploader(
    "Upload network traffic records", type=["csv"], on_change=clear_results,
    help="Use the UNSW-NB15 CSV format. Start with data/processed/demo_sample.csv.",
)
st.caption("CSV uploads require the agreed 42 features. Dataset label columns are excluded from prediction.")

if st.button("Run detection", disabled=upload is None, type="primary"):
    clear_results()
    try:
        with st.spinner("Analysing traffic records…"):
            response = requests.post(
                f"{BACKEND}/predict",
                files={"file": (upload.name, upload.getvalue(), "text/csv")},
                timeout=(10, 120),
            )
        if response.status_code == 422:
            st.error(f"Please check your CSV. {response.json().get('detail', 'Invalid upload.')}")
        else:
            response.raise_for_status()
            st.session_state.prediction_result = response.json()
            st.session_state.result_filename = upload.name
    except requests.exceptions.Timeout:
        st.error("The request timed out. Try a smaller CSV and check the backend terminal.")
    except requests.exceptions.ConnectionError:
        st.error("Cannot reach the detection service. Start the backend on port 8000, then try again.")
    except (requests.exceptions.HTTPError, ValueError):
        st.error("The detection service returned an unexpected response. Check the backend terminal.")

if "prediction_result" in st.session_state:
    result = st.session_state.prediction_result
    summary = result["summary"]
    st.subheader(f"Results for {st.session_state.result_filename}")
    total, normal, malicious = st.columns(3)
    total.metric("Records analysed", f"{summary['total']:,}")
    normal.metric("Normal predictions", f"{summary['normal']:,}")
    malicious.metric("Malicious predictions", f"{summary['malicious']:,}")
    st.caption("Counts show model predictions. Detection accuracy is assessed separately using labelled evaluation data.")
    rows = pd.DataFrame(result["results"])
    selection = st.selectbox("Show predictions", ["All", "Malicious", "Normal"])
    visible = rows
    if selection != "All":
        visible = rows[rows["prediction"] == selection.lower()]
    st.caption(f"Showing up to {PREVIEW_ROWS} of {len(visible):,} matching records.")
    st.dataframe(visible.head(PREVIEW_ROWS), hide_index=True, width="stretch")
    st.download_button(
        "Download all predictions (CSV)", rows.to_csv(index=False).encode("utf-8"),
        file_name="detection_results.csv", mime="text/csv",
    )
    st.subheader("Alerts and simulated block list")
    if summary["malicious"]:
        st.warning(f"{summary['malicious']:,} records triggered a simulated block action.")
        st.dataframe(
            pd.DataFrame({"demonstration_identifier": result["simulated_block_list"][:PREVIEW_ROWS]}),
            hide_index=True, width="stretch",
        )
        st.caption("The preview shows up to 100 entries. The downloaded predictions include every simulated action.")
    else:
        st.success("No malicious predictions in this upload.")
