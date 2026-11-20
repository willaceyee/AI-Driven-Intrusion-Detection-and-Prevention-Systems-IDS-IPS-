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
    THREAT_SCENARIOS,
    get_scenario,
    make_scenario_globe,
)


BACKEND = "http://127.0.0.1:8000"
PREVIEW_ROWS = 100
SEQUENCE_SEGMENTS = 48
NAV_ITEMS = (
    "Command Overview",
    "Incident Investigation",
    "Detection Intelligence",
    "Prevention & Replay",
    "Scenario Globe",
    "Model & Reports",
)


def clear_results():
    """Remove results whenever the selected upload changes or a request fails."""
    st.session_state.pop("prediction_result", None)
    st.session_state.pop("result_filename", None)
    st.session_state.pop("investigation_query", None)
    st.session_state.pop("replay_position", None)
    st.session_state.pop("record_linked_notice", None)
    st.session_state.pop("upload_context", None)
    st.session_state.pop("upload_context_metadata", None)
    st.session_state.pop("upload_context_error", None)
    st.session_state.pop("active_workspace", None)


def link_record_to_workflow(record_id, row_number):
    """Prepare a sampled record for the existing investigation and replay widgets."""
    st.session_state.investigation_query = record_id
    st.session_state.replay_position = int(row_number)
    st.session_state.record_linked_notice = int(row_number)


def navigate_to(workspace):
    """Move between SOC workspaces without duplicating horizontal navigation."""
    st.session_state.active_workspace = workspace


def short_record_id(record_id):
    """Create a compact display reference while retaining the full identifier elsewhere."""
    prefix, separator, row = str(record_id).rpartition("-row-")
    if not separator:
        return str(record_id)[-18:]
    return f"…{prefix[-6:]} · row {row}"


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
    except requests.exceptions.Timeout:
        st.error("The request timed out. Try a smaller CSV and check the backend terminal.")
    except requests.exceptions.ConnectionError:
        st.error("Cannot reach the detection service. Start the backend on port 8000, then try again.")
    except (requests.exceptions.HTTPError, ValueError):
        st.error("The detection service returned an unexpected response. Check the backend terminal.")


def metric_card(label, value, detail, tone="neutral"):
    st.markdown(metric_card_markup(label, value, detail, tone), unsafe_allow_html=True)


def metric_card_markup(label, value, detail, tone="neutral"):
    return (
        f'<div class="metric-card metric-{tone}"><div class="metric-label">{escape(str(label))}</div>'
        f'<div class="metric-value">{escape(str(value))}</div>'
        f'<div class="metric-detail">{escape(str(detail))}</div></div>'
    )


def make_distribution_chart(summary):
    source = pd.DataFrame({
        "classification": ["Malicious", "Normal"],
        "records": [summary["malicious"], summary["normal"]],
    })
    return (
        alt.Chart(source)
        .mark_arc(innerRadius=45, outerRadius=68, cornerRadius=5, padAngle=0.025)
        .encode(
            theta=alt.Theta("records:Q"),
            color=alt.Color(
                "classification:N",
                scale=alt.Scale(domain=["Malicious", "Normal"], range=["#ff4d6d", "#3de0c5"]),
                legend=alt.Legend(title=None, orient="bottom", labelColor="#a7b5c6"),
            ),
            tooltip=["classification:N", alt.Tooltip("records:Q", format=",")],
        )
        .properties(height=185)
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
        .properties(height=175)
        .configure(background="transparent")
        .configure_axis(gridColor="#213044", domainColor="#33465e", labelColor="#91a2b8", titleColor="#91a2b8")
        .configure_view(strokeOpacity=0)
    )


def render_overview(rows, summary, result):
    """Render the dense command surface using only current results and verified evidence."""
    total = summary["total"]
    threat_rate = (summary["malicious"] / total * 100) if total else 0
    kpis = [
        ("Records analysed", f"{total:,}", "Current upload · prediction count", "safe"),
        ("Flagged malicious", f"{summary['malicious']:,}", "Current upload · predicted malicious", "danger"),
        ("Normal", f"{summary['normal']:,}", "Current upload · predicted normal", "info"),
        ("Review workload", f"{threat_rate:.1f}%", f"{summary['malicious']:,} of {total:,} records", "warning"),
        ("Validation FPR", f"{VALIDATION_SNAPSHOT.false_positive_rate:.2%}", "Historical validation evidence", "evidence"),
    ]
    st.markdown(
        '<div class="overview-kpis">' + "".join(metric_card_markup(*item) for item in kpis) + "</div>",
        unsafe_allow_html=True,
    )

    chart_column, distribution_column, status_column = st.columns([1.75, 0.72, 0.82], gap="small")
    with chart_column:
        with st.container(border=True):
            st.markdown("#### Threat activity by ordered record")
            st.caption("Model decisions across the uploaded file sequence · row order, not event time.")
            st.altair_chart(make_sequence_chart(rows), width="stretch")
    with distribution_column:
        with st.container(border=True):
            st.markdown("#### Detection distribution")
            st.altair_chart(make_distribution_chart(summary), width="stretch")
    with status_column:
        with st.container(border=True):
            st.markdown("#### Operational status")
            label_available = bool((st.session_state.get("upload_context_metadata") or {}).get("has_ground_truth"))
            statuses = [
                ("Backend ready", "Detection service returned this case", "ok"),
                ("Model loaded", "Random Forest pipeline", "ok"),
                ("Prevention simulated", "No real controls changed", "caution"),
                ("Label audit", "Available" if label_available else "Not supplied", "ok" if label_available else "muted"),
            ]
            status_markup = "".join(
                f'<div class="ops-status ops-{tone}"><span></span><div><strong>{escape(label)}</strong>'
                f'<small>{escape(detail)}</small></div></div>'
                for label, detail, tone in statuses
            )
            st.markdown(f'<div class="ops-stack">{status_markup}</div>', unsafe_allow_html=True)

    queue_column, prevention_column = st.columns([1.7, 0.9], gap="small")
    queue = rows.loc[rows["prediction"].eq("malicious")].head(5).copy()
    queue["record_ref"] = queue["record_id"].map(short_record_id)
    queue["action"] = "Simulated block"
    context = st.session_state.get("upload_context")
    if context is not None and "evaluation_outcome" in context.columns:
        outcome_lookup = context.set_index("row_number")["evaluation_outcome"]
        queue["evaluation"] = queue["row_number"].map(outcome_lookup).str.title()
    else:
        queue["evaluation"] = "No reference label"
    with queue_column:
        with st.container(border=True):
            heading, action = st.columns([1.5, 0.7], vertical_alignment="center")
            with heading:
                st.markdown("#### Investigation queue")
                st.caption("First five flagged records in CSV order · not a severity ranking.")
            with action:
                st.button(
                    "Open investigation",
                    key="overview_investigation",
                    on_click=navigate_to,
                    args=("Incident Investigation",),
                    width="stretch",
                )
            st.dataframe(
                queue[["record_ref", "row_number", "prediction", "action", "evaluation"]],
                hide_index=True,
                width="stretch",
                column_config={
                    "record_ref": st.column_config.TextColumn("Record reference", help="Full identifiers remain available in Incident Investigation and exports."),
                    "row_number": st.column_config.NumberColumn("Row", format="%d"),
                    "prediction": st.column_config.TextColumn("Prediction"),
                    "action": st.column_config.TextColumn("Response"),
                    "evaluation": st.column_config.TextColumn("Evaluation outcome"),
                },
            )
            with st.expander("Full demonstration identifiers"):
                st.code("\n".join(queue["record_id"].astype(str)), language=None, wrap_lines=True)
    with prevention_column:
        with st.container(border=True):
            st.markdown("#### Simulated prevention")
            st.markdown(
                f"""<div class="prevention-summary"><div><strong>{summary['malicious']:,}</strong>
                <span>queued simulated blocks</span></div><div><strong>0</strong>
                <span>real controls changed</span></div></div>""",
                unsafe_allow_html=True,
            )
            st.info("Simulation only—no firewall, host, or network control was changed.")
            st.button(
                "Open prevention & replay",
                key="overview_prevention",
                on_click=navigate_to,
                args=("Prevention & Replay",),
                width="stretch",
            )

    with st.container(border=True):
        globe_copy, globe_visual = st.columns([0.75, 1.25], gap="medium", vertical_alignment="center")
        with globe_copy:
            st.markdown("#### Scenario Globe · synthetic")
            st.write(
                "Use the tabletop scenario to demonstrate response sequencing. Its locations are deterministic "
                "simulation data—not detected geography or global telemetry."
            )
            st.button(
                "Open Scenario Globe",
                key="overview_globe_button",
                on_click=navigate_to,
                args=("Scenario Globe",),
                width="stretch",
            )
        with globe_visual:
            st.plotly_chart(
                make_scenario_globe(THREAT_SCENARIOS[0], height=230),
                width="stretch",
                config={"displaylogo": False, "scrollZoom": False},
                key="overview_globe",
            )

    st.markdown(
        """<div class="analyst-callout compact"><div class="callout-label">ANALYST LIMIT</div>
        <div><strong>A model flag is a review signal, not proof of intrusion.</strong> Corroborate decisions with
        packet, session, host, or identity evidence before escalation.</div></div>""",
        unsafe_allow_html=True,
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


def render_investigation(rows, result):
    render_section_header(
        "Incident investigation",
        "Filter model decisions, inspect uploaded features, and connect evidence to replay.",
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
    preview = visible.head(PREVIEW_ROWS).copy()
    preview.insert(0, "record_reference", preview["record_id"].map(short_record_id))
    st.dataframe(
        preview,
        hide_index=True,
        width="stretch",
        column_order=["record_reference", "row_number", "prediction", "simulated_action"],
        column_config={
            "record_reference": st.column_config.TextColumn(
                "Record reference",
                help="A shortened display reference. The full demonstration identifier remains available in record inspection and exports.",
            ),
            "row_number": st.column_config.NumberColumn("Row", format="%d"),
            "prediction": st.column_config.TextColumn("Prediction"),
            "simulated_action": st.column_config.TextColumn("Simulated action"),
        },
    )
    render_record_inspector(visible)
    st.markdown(
        """<div class="analyst-callout compact"><div class="callout-label">ANALYST NEXT STEP</div>
        <div>Use the CSV row number to find the original record, then validate it against network or host evidence.
        This dataset contains no source IP, packet payload, geolocation, or relationship edges, so the dashboard
        cannot attribute the prediction to a real host.</div></div>""",
        unsafe_allow_html=True,
    )


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
        display_columns = ["record_reference", "row_number", "reference_class", "prediction", "evaluation_outcome"]
        if "reference_attack_category" in mistakes.columns:
            display_columns.append("reference_attack_category")
        mistake_preview = mistakes.head(PREVIEW_ROWS).copy()
        mistake_preview.insert(0, "record_reference", mistake_preview["record_id"].map(short_record_id))
        st.dataframe(
            mistake_preview,
            hide_index=True,
            width="stretch",
            column_order=display_columns,
            column_config={
                "record_reference": st.column_config.TextColumn(
                    "Record reference",
                    help="Use the row number or full exported identifier for exact traceability.",
                ),
                "row_number": st.column_config.NumberColumn("Row", format="%d"),
                "reference_class": st.column_config.TextColumn("Reference"),
                "evaluation_outcome": st.column_config.TextColumn("Outcome"),
                "reference_attack_category": st.column_config.TextColumn("Recorded category"),
            },
        )
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


def render_replay(rows, include_header=True):
    if include_header:
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


def render_prevention_replay(rows, result):
    render_section_header(
        "Prevention and replay",
        "Review ordered model decisions and the simulated containment queue without changing real controls.",
        "RESPOND",
    )
    replay_column, summary_column = st.columns([1.45, 0.75], gap="large")
    with replay_column:
        render_replay(rows, include_header=False)
    with summary_column:
        with st.container(border=True):
            st.markdown("#### Response boundary")
            metric_card(
                "Queued simulated blocks",
                f"{result['summary']['malicious']:,}",
                "Model-labelled malicious records",
                "danger",
            )
            metric_card("Real controls changed", "0", "Demonstration environment", "safe")
            st.warning("No firewall, endpoint, account, or network policy was modified.")
    st.markdown("#### Simulated containment queue")
    if result["summary"]["malicious"]:
        block_preview = pd.DataFrame({
            "record_reference": [short_record_id(value) for value in result["simulated_block_list"][:PREVIEW_ROWS]],
            "full_demonstration_identifier": result["simulated_block_list"][:PREVIEW_ROWS],
            "response": "simulated block",
        })
        st.dataframe(
            block_preview,
            hide_index=True,
            width="stretch",
            column_order=["record_reference", "response"],
            column_config={
                "record_reference": st.column_config.TextColumn(
                    "Record reference",
                    help="Full demonstration identifiers remain available in Model & Reports exports.",
                ),
                "response": st.column_config.TextColumn("Simulated response"),
            },
        )
        st.caption("Preview limited to 100 identifiers. Complete prediction exports remain available in Model & Reports.")
    else:
        st.success("No malicious predictions were returned for this upload.")


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

workspace = st.session_state.get("active_workspace", NAV_ITEMS[0])
with st.sidebar:
    render_brand()
    st.markdown('<div class="sidebar-label">DETECTION INPUT</div>', unsafe_allow_html=True)
    upload = st.file_uploader(
        "Upload traffic CSV", type=["csv"], on_change=clear_results,
        help="Use the agreed UNSW-NB15 format with all 42 prediction features.",
    )
    st.markdown(
        """<div class="upload-guidance"><strong>CSV requirements</strong>
        <span>Include all 42 UNSW-NB15 prediction features. Optional reference labels are excluded from model input.</span></div>""",
        unsafe_allow_html=True,
    )
    if st.button("Run detection", disabled=upload is None, type="primary", width="stretch"):
        run_detection(upload)
    st.markdown('<div class="sidebar-rule"></div>', unsafe_allow_html=True)
    if "prediction_result" in st.session_state:
        st.markdown('<div class="sidebar-label">BACKEND / MODEL READINESS</div>', unsafe_allow_html=True)
        st.markdown(
            """<div class="sidebar-readiness"><div><span></span>Backend ready</div>
            <div><span></span>Model loaded · Random Forest</div><div><span></span>Prediction case ready</div>
            <div class="readiness-caution"><span></span>Prevention simulated</div></div>""",
            unsafe_allow_html=True,
        )
        st.markdown('<div class="sidebar-rule"></div>', unsafe_allow_html=True)
        st.markdown('<div class="sidebar-label">SOC WORKSPACES</div>', unsafe_allow_html=True)
        workspace = st.radio(
            "SOC workspace",
            NAV_ITEMS,
            key="active_workspace",
            label_visibility="collapsed",
        )
    else:
        st.markdown("**Environment**")
        st.markdown('<div class="status-row"><span class="status-dot"></span> Local demonstration</div>', unsafe_allow_html=True)
        st.caption("UNSW-NB15 · Random Forest · Simulated prevention")
        st.info("Upload a valid dataset to activate the SOC workspaces. No real host will be blocked.")

if "prediction_result" not in st.session_state:
    st.markdown(
        """<div class="topbar compact"><div><h1>Sentinel Command</h1>
        <p>Upload-based intrusion detection and transparent simulated response.</p></div>
        <div class="mode-badge"><span></span> LOCAL DEMO</div></div>""",
        unsafe_allow_html=True,
    )
    render_empty_state()
else:
    result = st.session_state.prediction_result
    rows = pd.DataFrame(result["results"])
    st.markdown(
        f"""<div class="topbar compact"><div><h1>Sentinel Command</h1>
        <p>{escape(st.session_state.result_filename)} · {result['summary']['total']:,} records · Random Forest</p></div>
        <div class="header-status"><span class="ready">Backend ready</span><span>Simulation only</span></div></div>""",
        unsafe_allow_html=True,
    )
    if workspace == "Command Overview":
        render_overview(rows, result["summary"], result)
    elif workspace == "Incident Investigation":
        render_investigation(rows, result)
    elif workspace == "Detection Intelligence":
        render_detection_analysis()
    elif workspace == "Prevention & Replay":
        render_prevention_replay(rows, result)
    elif workspace == "Scenario Globe":
        render_scenario_globe()
    elif workspace == "Model & Reports":
        render_exports(rows, result)
