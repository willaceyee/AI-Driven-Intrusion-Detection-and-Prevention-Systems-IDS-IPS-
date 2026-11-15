"""Streamlit Security Operations Center for the local IDS/IPS demonstration."""

from ast import literal_eval
import json
from html import escape

import altair as alt
import pandas as pd
import requests
import streamlit as st

from frontend.detection_intelligence import (
    INPUT_FEATURES,
    TEST_SNAPSHOT,
    VALIDATION_SNAPSHOT,
    build_upload_context,
    filter_evaluation_records,
    make_confusion_matrix_figure,
    make_metric_comparison_figure,
    make_outcome_figure,
    snapshot_from_labeled_records,
)
from frontend.soc_theme import apply_soc_theme, render_brand, render_empty_state, render_section_header
from frontend.traffic_intelligence import (
    CATEGORICAL,
    NUMERIC,
    THREAT_SCENARIOS,
    build_traffic_projection,
    filter_projection,
    get_scenario,
    make_projection_figure,
    make_scenario_globe,
)


BACKEND = "http://127.0.0.1:8000"
PREVIEW_ROWS = 100
SEQUENCE_SEGMENTS = 48


def clear_results():
    """Remove results whenever the selected upload changes or a request fails."""
    st.session_state.pop("prediction_result", None)
    st.session_state.pop("result_filename", None)
    st.session_state.pop("traffic_projection", None)
    st.session_state.pop("projection_metadata", None)
    st.session_state.pop("projection_error", None)
    st.session_state.pop("investigation_query", None)
    st.session_state.pop("replay_position", None)
    st.session_state.pop("record_linked_notice", None)
    st.session_state.pop("upload_context", None)
    st.session_state.pop("upload_context_metadata", None)
    st.session_state.pop("upload_context_error", None)


def link_record_to_workflow(record_id, row_number):
    """Prepare a sampled record for the existing investigation and replay widgets."""
    st.session_state.investigation_query = record_id
    st.session_state.replay_position = int(row_number)
    st.session_state.record_linked_notice = int(row_number)


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
        result = response.json()
        st.session_state.prediction_result = result
        st.session_state.result_filename = upload.name
        try:
            context, context_metadata = build_upload_context(upload.getvalue(), result["results"])
            st.session_state.upload_context = context
            st.session_state.upload_context_metadata = context_metadata
        except Exception as error:  # Optional analysis must not invalidate genuine backend results.
            st.session_state.upload_context_error = str(error)
        try:
            with st.spinner("Preparing a bounded feature-similarity projection…"):
                projection, metadata = build_traffic_projection(upload.getvalue(), result["results"])
            st.session_state.traffic_projection = projection
            st.session_state.projection_metadata = metadata
        except Exception as error:  # Detection remains usable if optional visualization preparation fails.
            st.session_state.projection_error = str(error)
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


def render_explanation_panel():
    st.markdown("#### Explainable AI readiness")
    st.markdown(
        """<div class="explanation-locked"><div><span>BACKEND SUPPORT REQUIRED</span>
        <strong>Record-level explanation unavailable</strong></div>
        <p>The current API returns a class label, not a probability, calibrated score, decision threshold,
        or validated feature attribution. Input values below are evidence for investigation—not proof that a
        feature caused this decision.</p></div>""",
        unsafe_allow_html=True,
    )
    st.button("Request validated explanation", disabled=True, key="explanation_disabled")
    st.caption(
        "Enable only after the backend supplies model/version identity, score semantics and calibration status, "
        "explanation method, source-feature mapping, attribution values, and decision-policy metadata."
    )


def render_record_inspector(visible):
    context = st.session_state.get("upload_context")
    if context is None or visible.empty:
        if st.session_state.get("upload_context_error"):
            st.warning("Source feature inspection is unavailable; detection results remain valid.")
        return

    candidate_rows = visible.head(PREVIEW_ROWS)["row_number"].astype(int).tolist()
    selected_row = st.selectbox(
        "Inspect matching record",
        candidate_rows,
        format_func=lambda value: f"CSV row {value:,}",
        key="investigation_record",
    )
    record = context.loc[context["row_number"].eq(selected_row)].iloc[0]
    st.markdown("#### Selected record evidence")
    detail_columns = st.columns(3)
    detail_values = [
        ("Prediction", record["prediction"].upper(), "Model output"),
        ("Simulated action", record["simulated_action"].upper(), "Demonstration policy"),
        ("CSV sequence", f"Row {selected_row:,}", "Not an event timestamp"),
    ]
    for column, (label, value, detail) in zip(detail_columns, detail_values):
        with column:
            metric_card(label, value, detail, "danger" if value in {"MALICIOUS", "BLOCK"} else "neutral")

    reference_text = "No ground-truth label is available for this uploaded record."
    if "reference_class" in record.index:
        outcome = str(record["evaluation_outcome"]).upper()
        category = ""
        if "reference_attack_category" in record.index:
            category = f" · recorded category: {escape(str(record['reference_attack_category']))}"
        reference_text = (
            f"Evaluation reference: <strong>{escape(str(record['reference_class']).upper())}</strong> · "
            f"{escape(outcome)}{category}. These fields were joined after inference and were not model inputs."
        )
    st.markdown(f'<div class="evidence-note">{reference_text}</div>', unsafe_allow_html=True)

    projection = st.session_state.get("traffic_projection")
    represented = projection is not None and projection["row_number"].eq(selected_row).any()
    if represented:
        projected = projection.loc[projection["row_number"].eq(selected_row)].iloc[0]
        st.caption(
            f"Visualization context: represented in the bounded PCA sample at "
            f"PC1 {projected['pc1']:.3f}, PC2 {projected['pc2']:.3f}, PC3 {projected['pc3']:.3f}. "
            "Coordinates express transformed-feature similarity only."
        )
    else:
        st.caption(
            "Visualization context: this record is not in the bounded PCA sample. It remains available for "
            "investigation and replay; no topology or communication relationship is implied."
        )

    with st.expander("View all 42 model input features"):
        feature_table = pd.DataFrame({
            "feature": INPUT_FEATURES,
            "uploaded_value": [str(record[feature]) for feature in INPUT_FEATURES],
        })
        st.dataframe(feature_table, hide_index=True, width="stretch")
        st.caption(
            "These are the genuine uploaded inputs used by the existing pipeline. Display order is descriptive; "
            "it is not a feature-importance ranking."
        )
    st.button(
        "Prepare this record for replay",
        key="investigation_replay_handoff",
        on_click=link_record_to_workflow,
        args=(record["record_id"], selected_row),
    )
    render_explanation_panel()


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
        query = st.text_input(
            "Find record", placeholder="Record ID or row number", key="investigation_query"
        )
    visible = rows
    if selection != "All":
        visible = visible[visible["prediction"] == selection.lower()]
    if action != "All actions":
        visible = visible[visible["simulated_action"] == action.lower()]
    if query.strip():
        needle = query.strip().lower()
        record_ids = visible["record_id"].str.lower()
        exact_record_id = record_ids.eq(needle)
        record_match = exact_record_id if exact_record_id.any() else record_ids.str.contains(needle, regex=False)
        visible = visible[
            record_match | visible["row_number"].astype(str).eq(needle)
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
    render_record_inspector(visible)
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


def render_traffic_intelligence():
    render_section_header(
        "Traffic intelligence explorer",
        "Explore similarity among actual uploaded feature records using a bounded, deterministic projection.",
        "FEATURE SPACE",
    )
    projection = st.session_state.get("traffic_projection")
    metadata = st.session_state.get("projection_metadata")
    if projection is None or metadata is None:
        st.warning(
            "The detection results remain available, but the feature projection could not be prepared. "
            f"{st.session_state.get('projection_error', 'No projection data is available.')}"
        )
        return

    variance = metadata["explained_variance_ratio"]
    explained = sum(variance[:3])
    st.markdown(
        f"""<div class="analyst-callout compact"><div class="callout-label">HOW TO READ THIS</div>
        <div><strong>Nearby points have similar transformed UNSW-NB15 feature values.</strong>
        Position is PCA feature space—not geography, network topology, communication, or time.
        The three displayed components explain {explained:.1%} of variance in the bounded sample.</div></div>""",
        unsafe_allow_html=True,
    )
    st.caption(
        f"Showing a deterministic, class-aware sample of {metadata['sample_rows']:,} from "
        f"{metadata['source_rows']:,} uploaded records · seed {metadata['seed']} · maximum {metadata['max_points']:,}."
    )
    ratios = list(variance[:3]) + [0.0] * (3 - len(variance[:3]))
    representation_columns = st.columns(4)
    representation_values = [
        ("Records represented", f"{metadata['sample_rows']:,}", f"of {metadata['source_rows']:,} uploaded"),
        ("PC1 variance", f"{ratios[0]:.1%}", "Sample-fitted PCA"),
        ("PC2 variance", f"{ratios[1]:.1%}", "Sample-fitted PCA"),
        ("PC3 variance", f"{ratios[2]:.1%}", "Sample-fitted PCA"),
    ]
    for column, (label, value, detail) in zip(representation_columns, representation_values):
        with column:
            metric_card(label, value, detail)
    source_classes = metadata["source_class_counts"]
    sample_classes = metadata["sample_class_counts"]
    st.info(
        "Sampling disclosure: the deterministic sample is allocated across predicted classes so both model "
        f"outcomes remain visible (source normal {source_classes.get('normal', 0):,}, malicious "
        f"{source_classes.get('malicious', 0):,}; sample normal {sample_classes.get('normal', 0):,}, malicious "
        f"{sample_classes.get('malicious', 0):,}). Sampling and PCA can compress rare patterns and distort visual "
        "density; use the complete exports and investigation table for record counts."
    )

    control_columns = st.columns(3)
    with control_columns[0]:
        prediction = st.selectbox(
            "Projection prediction", ["All", "Malicious", "Normal"], key="projection_prediction"
        )
    with control_columns[1]:
        categorical_feature = st.selectbox(
            "Categorical feature", ["None", *CATEGORICAL], key="projection_category"
        )
    with control_columns[2]:
        numeric_feature = st.selectbox(
            "Numeric feature", ["None", *NUMERIC], key="projection_numeric"
        )

    categorical_values = None
    if categorical_feature != "None":
        options = sorted(projection[categorical_feature].astype(str).unique())
        categorical_values = st.multiselect(
            f"Filter {categorical_feature}", options, key=f"projection_values_{categorical_feature}"
        )
    numeric_range = None
    if numeric_feature != "None":
        minimum = float(projection[numeric_feature].min())
        maximum = float(projection[numeric_feature].max())
        if minimum < maximum:
            numeric_range = st.slider(
                f"Filter {numeric_feature}",
                min_value=minimum,
                max_value=maximum,
                value=(minimum, maximum),
                key=f"projection_range_{numeric_feature}",
            )
        else:
            st.caption(f"All sampled records have {numeric_feature} = {minimum:g}.")

    visible = filter_projection(
        projection,
        prediction=prediction,
        categorical_feature=None if categorical_feature == "None" else categorical_feature,
        categorical_values=categorical_values,
        numeric_feature=None if numeric_feature == "None" else numeric_feature,
        numeric_range=numeric_range,
    )
    st.caption(f"{len(visible):,} sampled records match the active projection filters.")
    if visible.empty:
        st.info("No sampled records match this filter combination. Adjust a filter to restore the view.")
        return

    view_mode = st.radio(
        "Projection view",
        ["3D feature space", "2D accessible view"],
        horizontal=True,
        key="projection_view_mode",
    )
    dimensions = 3 if view_mode.startswith("3D") else 2
    st.plotly_chart(
        make_projection_figure(visible, dimensions=dimensions),
        width="stretch",
        config={"displaylogo": False, "scrollZoom": True},
        key=f"traffic_projection_{dimensions}",
    )

    row_options = visible["row_number"].astype(int).tolist()
    selected_row = st.selectbox(
        "Inspect sampled record",
        row_options,
        format_func=lambda value: (
            f"Row {value:,} · "
            f"{visible.loc[visible['row_number'] == value, 'prediction'].iloc[0].upper()}"
        ),
        key="projection_record",
    )
    record = visible.loc[visible["row_number"] == selected_row].iloc[0]
    tone = "replay-danger" if record["prediction"] == "malicious" else "replay-safe"
    st.markdown(
        f"""<div class="replay-card {tone}"><div class="replay-index">SAMPLED RECORD · CSV ROW {int(record['row_number']):,}</div>
        <div class="replay-status">{record['prediction'].upper()} · {record['simulated_action'].upper()}</div>
        <div class="replay-grid"><span>Record</span><strong>{escape(str(record['record_id']))}</strong>
        <span>Protocol / service / state</span><strong>{escape(str(record['proto']))} / {escape(str(record['service']))} / {escape(str(record['state']))}</strong>
        <span>PCA coordinates</span><strong>{record['pc1']:.3f}, {record['pc2']:.3f}, {record['pc3']:.3f}</strong></div></div>""",
        unsafe_allow_html=True,
    )
    st.button(
        "Use this record in investigation and replay",
        key="projection_handoff",
        on_click=link_record_to_workflow,
        args=(record["record_id"], int(record["row_number"])),
    )
    if st.session_state.get("record_linked_notice") == int(record["row_number"]):
        st.success("Record linked. Open Incident investigation or Attack replay to continue.")


def render_scenario_globe():
    render_section_header(
        "Scenario threat globe",
        "Explore a deterministic tabletop scenario that is deliberately separate from model detections.",
        "SYNTHETIC",
    )
    st.warning(
        "Scenario only: every location, route, activity step, and response below is synthetic. "
        "The Random Forest model did not detect or infer geography."
    )
    scenario_id = st.selectbox(
        "Tabletop scenario",
        [item.scenario_id for item in THREAT_SCENARIOS],
        format_func=lambda value: get_scenario(value).name,
        key="scenario_id",
    )
    scenario = get_scenario(scenario_id)
    st.plotly_chart(
        make_scenario_globe(scenario),
        width="stretch",
        config={"displaylogo": False, "scrollZoom": True},
        key="scenario_globe",
    )
    scenario_columns = st.columns(3)
    scenario_facts = [
        ("Synthetic origin", scenario.origin_name, scenario.attack_type),
        ("Synthetic destination", scenario.destination_name, "Tabletop destination"),
        ("Response outcome", scenario.outcome, "Simulated control only"),
    ]
    for column, (label, value, detail) in zip(scenario_columns, scenario_facts):
        with column:
            st.markdown(
                f"""<div class="scenario-fact"><span>{escape(label)}</span><strong>{escape(value)}</strong>
                <small>{escape(detail)}</small></div>""",
                unsafe_allow_html=True,
            )
    st.markdown("#### Scenario activity sequence")
    steps = "".join(
        f'<div><b>{number:02d}</b><span>{escape(step)}</span></div>'
        for number, step in enumerate(scenario.steps, start=1)
    )
    st.markdown(f'<div class="scenario-steps">{steps}</div>', unsafe_allow_html=True)


def render_detection_analysis():
    render_section_header(
        "Detection intelligence",
        "Examine held-out model errors and, when labels exist, audit the current upload after prediction.",
        "EVALUATE",
    )
    st.markdown(
        """<div class="analyst-callout compact"><div class="callout-label">EVALUATION BOUNDARY</div>
        <div><strong>Evaluation outcomes require known reference labels.</strong> Validation and reserved-test
        results below are historical held-out evaluations. They are not accuracy measurements for a new,
        unlabelled upload and do not establish effectiveness on live network traffic.</div></div>""",
        unsafe_allow_html=True,
    )
    split_name = st.radio(
        "Evidence split", ["Validation", "Reserved test"], horizontal=True, key="analysis_split"
    )
    snapshot = VALIDATION_SNAPSHOT if split_name == "Validation" else TEST_SNAPSHOT
    metric_columns = st.columns(4)
    metric_values = [
        ("Precision", snapshot.precision, "Flagged attacks that were attacks"),
        ("Recall", snapshot.recall, "Recorded attacks detected"),
        ("Attack F1", snapshot.f1, "Precision/recall balance"),
        ("False-positive rate", snapshot.false_positive_rate, "Normal records flagged"),
    ]
    for column, (label, value, detail) in zip(metric_columns, metric_values):
        with column:
            metric_card(label, f"{value:.2%}", detail, "warning" if label == "False-positive rate" else "neutral")

    chart_columns = st.columns(2, gap="large")
    with chart_columns[0]:
        st.markdown(f"#### {snapshot.name} confusion matrix")
        st.caption(f"{snapshot.total:,} records · {snapshot.role}")
        st.plotly_chart(
            make_confusion_matrix_figure(snapshot), width="stretch", config={"displaylogo": False}
        )
    with chart_columns[1]:
        st.markdown("#### Validation versus reserved test")
        st.caption("Separate splits shown side by side; the reserved test was not used for model selection.")
        st.plotly_chart(
            make_metric_comparison_figure(), width="stretch", config={"displaylogo": False}
        )

    st.warning(
        f"False-blocking consequence: {snapshot.false_positive:,} genuinely normal records were classified as "
        f"malicious on the {snapshot.name.lower()} split. In this prototype that produces only a simulated block. "
        "In a real system, an equivalent prevention policy could interrupt legitimate users or services, so a "
        "detection label must not automatically become an enforcement decision without reviewed policy evidence."
    )
    st.caption(
        f"False negatives: {snapshot.false_negative:,} recorded attacks were predicted normal on this split. "
        "Reducing one error type can increase the other; policy choices require validated scores and explicit costs."
    )

    st.markdown("### Current upload label audit")
    context = st.session_state.get("upload_context")
    context_metadata = st.session_state.get("upload_context_metadata") or {}
    if context is None:
        st.info("Source-record context is unavailable. Historical evaluation evidence above remains available.")
    elif not context_metadata.get("has_ground_truth"):
        if context_metadata.get("label_warning"):
            st.warning(context_metadata["label_warning"])
        else:
            st.info(
                "This upload has no verified binary label column. Predictions can be investigated and exported, "
                "but accuracy, false positives and false negatives cannot be calculated for it."
            )
    else:
        current = snapshot_from_labeled_records(context)
        st.success(
            "A verified binary label column is available. It was joined only after the backend returned predictions; "
            "the backend's existing feature validation excluded label and attack_cat from model inputs."
        )
        current_columns = st.columns(4)
        for column, (label, value) in zip(
            current_columns,
            [
                ("Current precision", current.precision),
                ("Current recall", current.recall),
                ("Current attack F1", current.f1),
                ("Current FPR", current.false_positive_rate),
            ],
        ):
            with column:
                metric_card(label, f"{value:.2%}", "Labelled upload audit")
        st.plotly_chart(make_outcome_figure(context), width="stretch", config={"displaylogo": False})

        filter_columns = st.columns(2)
        with filter_columns[0]:
            outcome_filter = st.selectbox(
                "Evaluation outcome",
                ["Errors only", "False positive", "False negative", "True positive", "True negative", "All outcomes"],
                key="evaluation_outcome_filter",
            )
        selected_categories = None
        with filter_columns[1]:
            if context_metadata.get("has_attack_category"):
                categories = sorted(context["reference_attack_category"].astype(str).unique())
                selected_categories = st.multiselect(
                    "Recorded attack category", categories, key="evaluation_category_filter"
                )
            else:
                st.caption("No recorded attack-category field is available for filtering.")
        mistakes = filter_evaluation_records(context, outcome_filter, selected_categories)
        st.caption(f"{len(mistakes):,} records match this post-prediction audit filter; preview limited to {PREVIEW_ROWS}.")
        display_columns = [
            "record_id", "row_number", "reference_class", "prediction", "evaluation_outcome", "simulated_action"
        ]
        if "reference_attack_category" in mistakes.columns:
            display_columns.append("reference_attack_category")
        st.dataframe(mistakes[display_columns].head(PREVIEW_ROWS), hide_index=True, width="stretch")
        if not mistakes.empty:
            audit_row = st.selectbox(
                "Send audit record to investigation and replay",
                mistakes.head(PREVIEW_ROWS)["row_number"].astype(int).tolist(),
                format_func=lambda value: f"CSV row {value:,}",
                key="audit_record_handoff",
            )
            audit_record = context.loc[context["row_number"].eq(audit_row)].iloc[0]
            st.button(
                "Prepare selected audit record",
                key="audit_handoff_button",
                on_click=link_record_to_workflow,
                args=(audit_record["record_id"], audit_row),
            )

    st.markdown("### Prevention Decision Lab readiness")
    st.markdown(
        """<div class="decision-lab"><div><span>DETECTION</span><strong>Current capability</strong>
        <p>Binary class labels from the unchanged Random Forest API.</p></div>
        <div class="decision-arrow">→</div><div><span>PREVENTION</span><strong>Not yet enabled</strong>
        <p>Requires genuine score semantics, calibration evidence, threshold metadata and an approved cost policy.</p>
        </div></div>""",
        unsafe_allow_html=True,
    )
    st.button("Compare response policies", disabled=True, key="policy_lab_disabled")
    st.caption(
        "No threshold control is presented as operational. Candidate policies must be selected using training/validation "
        "or a dedicated calibration split, then evaluated once on untouched held-out data—not tuned against the reserved test set."
    )


def render_replay(rows):
    render_section_header(
        "Attack replay",
        "Step through model output in upload order. This is a deterministic review—not live packet playback.",
        "REPLAY",
    )
    if rows.empty:
        return
    position = st.slider("Record position", 1, len(rows), key="replay_position")
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
    assurance = VALIDATION_SNAPSHOT
    if assurance:
        assurance_columns = st.columns(4)
        assurance_values = [
            ("Validation attack F1", assurance.f1, "Model selection split"),
            ("Validation FPR", assurance.false_positive_rate, "1,004 / 11,200 normal"),
            ("Test attack F1", TEST_SNAPSHOT.f1, "Reserved test set"),
            ("Test FPR", TEST_SNAPSHOT.false_positive_rate, "9,904 / 37,000 normal"),
        ]
        for column, (label, value, detail) in zip(assurance_columns, assurance_values):
            with column:
                metric_card(label, f"{value:.2%}", detail)
        st.caption(
            "Validation selected the model; the reserved test set estimates later generalisation. "
            "They are separate evaluations—not metrics for the current upload or evidence of live-network effectiveness."
        )
        st.warning(
            "Generalisation warning: false-positive rate increased from 8.96% on validation to 26.77% "
            "on the reserved test set. Operational deployment would require threshold and error-cost analysis."
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
        <div><b>03 VISUALIZE</b><span>Explore feature similarity</span></div>
        <div><b>04 RESPOND</b><span>Review simulated actions</span></div></div>""",
        unsafe_allow_html=True,
    )
    overview_tab, investigate_tab, analysis_tab, traffic_tab, globe_tab, replay_tab, export_tab = st.tabs(
        [
            "Command overview",
            "Incident investigation",
            "Detection analysis",
            "Traffic intelligence",
            "Scenario globe",
            "Attack replay",
            "Model & exports",
        ]
    )
    with overview_tab:
        render_overview(rows, result["summary"])
    with investigate_tab:
        render_investigation(rows, result)
    with analysis_tab:
        render_detection_analysis()
    with traffic_tab:
        render_traffic_intelligence()
    with globe_tab:
        render_scenario_globe()
    with replay_tab:
        render_replay(rows)
    with export_tab:
        render_exports(rows, result)
