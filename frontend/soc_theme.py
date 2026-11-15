"""Visual system and reusable presentation fragments for the Streamlit SOC."""

import streamlit as st


def apply_soc_theme():
    st.markdown(
        """
        <style>
        :root { --ink:#e8f0f8; --muted:#91a2b8; --line:rgba(123,159,194,.16); --cyan:#3de0c5; --red:#ff4d6d; --amber:#ffbd59; }
        .stApp { background:radial-gradient(circle at 85% 5%,rgba(22,105,119,.16),transparent 30rem),linear-gradient(rgba(7,14,24,.96),rgba(7,14,24,.98)),repeating-linear-gradient(0deg,transparent 0,transparent 31px,rgba(61,224,197,.025) 32px),repeating-linear-gradient(90deg,transparent 0,transparent 31px,rgba(61,224,197,.025) 32px); color:var(--ink); }
        [data-testid="stSidebar"] { background:#0a1320; border-right:1px solid var(--line); }
        [data-testid="stSidebar"]>div { padding-top:1.2rem; }
        [data-testid="stHeader"] { background:transparent; }
        .block-container { max-width:1500px; padding-top:2rem; padding-bottom:4rem; }
        h1,h2,h3,h4 { letter-spacing:-.025em; color:var(--ink); }
        p,label,[data-testid="stCaptionContainer"] { color:var(--muted); }
        .soc-brand { display:flex; align-items:center; gap:.8rem; margin:.2rem 0 2rem; }
        .soc-mark { width:40px; height:40px; display:grid; place-items:center; border:1px solid rgba(61,224,197,.5); border-radius:10px; color:var(--cyan); background:rgba(61,224,197,.08); box-shadow:0 0 24px rgba(61,224,197,.08); font-size:1.2rem; }
        .soc-name { font-weight:800; letter-spacing:.08em; color:#f4f8fc; }
        .soc-sub { color:#70839a; font-size:.7rem; letter-spacing:.16em; }
        .sidebar-label,.eyebrow { color:#688096; font-size:.68rem; letter-spacing:.18em; font-weight:700; margin-bottom:.6rem; }
        .sidebar-rule { height:1px; background:var(--line); margin:1.5rem 0; }
        .status-row { color:#bdcbd9; font-size:.82rem; margin:.6rem 0; }
        .status-dot,.mode-badge span { display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--cyan); box-shadow:0 0 10px var(--cyan); margin-right:.45rem; }
        .topbar { display:flex; justify-content:space-between; align-items:flex-start; gap:2rem; margin-bottom:1.4rem; }
        .topbar h1 { font-size:clamp(2rem,4vw,3.4rem); line-height:1; margin:.2rem 0 .7rem; }
        .topbar p { margin:0; font-size:1rem; }
        .mode-badge { border:1px solid rgba(61,224,197,.25); border-radius:999px; padding:.55rem .8rem; color:#9fc8c1; font-size:.68rem; letter-spacing:.13em; white-space:nowrap; background:rgba(61,224,197,.05); }
        .result-context { border-left:2px solid var(--cyan); background:rgba(61,224,197,.04); padding:.65rem .85rem; margin:1.2rem 0; color:#a8b7c7; font-size:.78rem; }
        .result-context span { color:var(--cyan); font-weight:800; letter-spacing:.12em; margin-right:.6rem; }
        .case-flow { display:grid; grid-template-columns:repeat(4,1fr); gap:1px; margin:0 0 1rem; border:1px solid var(--line); border-radius:10px; overflow:hidden; background:var(--line); }
        .case-flow>div { display:flex; flex-direction:column; gap:.15rem; padding:.75rem 1rem; background:#0b1624; }
        .case-flow b { color:#8da0b5; font-size:.65rem; letter-spacing:.12em; }
        .case-flow span { color:#60758c; font-size:.72rem; }
        .case-flow .flow-active b { color:var(--cyan); }
        .metric-card { min-height:132px; border:1px solid var(--line); border-radius:14px; padding:1.15rem; background:linear-gradient(145deg,rgba(16,29,45,.96),rgba(10,19,31,.92)); position:relative; overflow:hidden; }
        .metric-card:after { content:''; position:absolute; top:0; right:0; width:45px; height:2px; background:#5d7893; }
        .metric-danger:after { background:var(--red); box-shadow:0 0 12px var(--red); }
        .metric-safe:after { background:var(--cyan); box-shadow:0 0 12px var(--cyan); }
        .metric-warning:after { background:var(--amber); }
        .metric-label { color:#8194aa; text-transform:uppercase; letter-spacing:.12em; font-size:.66rem; font-weight:700; }
        .metric-value { color:#f4f8fc; font-size:2rem; font-weight:750; margin:.4rem 0 .1rem; }
        .metric-detail { color:#657a91; font-size:.76rem; }
        .section-head { display:flex; align-items:flex-start; gap:1rem; margin:.5rem 0 1.2rem; }
        .section-code { color:var(--cyan); border:1px solid rgba(61,224,197,.25); border-radius:5px; padding:.3rem .4rem; font-size:.6rem; letter-spacing:.1em; margin-top:.35rem; }
        .section-head h2 { margin:0 0 .2rem; font-size:1.45rem; }
        .section-head p { margin:0; font-size:.85rem; }
        .empty-shell { border:1px solid var(--line); border-radius:18px; padding:clamp(1.5rem,4vw,3.5rem); margin-top:1.2rem; background:linear-gradient(135deg,rgba(15,29,44,.88),rgba(8,17,29,.7)); position:relative; overflow:hidden; }
        .empty-shell:before { content:''; position:absolute; width:260px; height:260px; border:1px solid rgba(61,224,197,.1); border-radius:50%; right:-90px; top:-90px; box-shadow:0 0 0 35px rgba(61,224,197,.02),0 0 0 70px rgba(61,224,197,.015); }
        .empty-kicker { color:var(--cyan); font-size:.7rem; letter-spacing:.16em; font-weight:800; }
        .empty-shell h2 { max-width:700px; font-size:clamp(1.6rem,3vw,2.5rem); margin:.7rem 0; }
        .empty-shell>p { max-width:680px; }
        .workflow { display:grid; grid-template-columns:repeat(3,1fr); gap:.8rem; margin-top:2rem; }
        .workflow div { padding:1rem; border-top:1px solid var(--line); color:#8799ad; font-size:.8rem; }
        .workflow b { display:block; color:#dbe6ef; margin-bottom:.3rem; }
        .workflow span { color:var(--cyan); font-family:monospace; margin-right:.4rem; }
        .replay-card { border:1px solid var(--line); border-radius:15px; padding:1.5rem; background:rgba(11,21,34,.86); }
        .replay-danger { border-left:3px solid var(--red); } .replay-safe { border-left:3px solid var(--cyan); }
        .replay-index { color:#6e8299; font-size:.67rem; letter-spacing:.16em; }
        .replay-status { color:#f2f7fb; font-size:1.55rem; font-weight:800; margin:.45rem 0 1.2rem; }
        .replay-grid { display:grid; grid-template-columns:minmax(130px,.4fr) 1fr; gap:.55rem 1rem; font-size:.82rem; }
        .replay-grid span { color:#6f849c; } .replay-grid strong { color:#cbd7e2; overflow-wrap:anywhere; }
        .analyst-callout { display:grid; grid-template-columns:145px 1fr; gap:1.1rem; align-items:start; margin:1rem 0; padding:1rem 1.1rem; border:1px solid rgba(255,189,89,.2); border-left:3px solid var(--amber); border-radius:9px; background:rgba(255,189,89,.045); color:#9baabd; font-size:.8rem; line-height:1.55; }
        .analyst-callout strong { color:#dce5ed; }
        .analyst-callout.compact { margin-top:.8rem; }
        .callout-label { color:var(--amber); font-size:.64rem; font-weight:800; letter-spacing:.13em; }
        .scenario-fact { min-height:118px; display:flex; flex-direction:column; gap:.4rem; padding:1rem; border:1px solid var(--line); border-radius:12px; background:#0b1624; }
        .scenario-fact span { color:#8194aa; text-transform:uppercase; letter-spacing:.12em; font-size:.66rem; font-weight:700; }
        .scenario-fact strong { color:#e8f0f8; font-size:1rem; line-height:1.35; }
        .scenario-fact small { color:#657a91; font-size:.76rem; }
        .scenario-steps { display:grid; grid-template-columns:repeat(4,1fr); gap:1px; border:1px solid var(--line); border-radius:10px; overflow:hidden; background:var(--line); }
        .scenario-steps>div { display:flex; gap:.7rem; align-items:center; padding:.9rem; background:#0b1624; }
        .scenario-steps b { color:var(--cyan); font-family:monospace; font-size:.72rem; }
        .scenario-steps span { color:#9aacbf; font-size:.78rem; }
        .evidence-note { margin:.8rem 0; padding:.85rem 1rem; border-left:2px solid var(--cyan); background:rgba(61,224,197,.04); color:#9fb0c2; font-size:.8rem; }
        .evidence-note strong { color:#e8f0f8; }
        .explanation-locked { display:grid; grid-template-columns:minmax(210px,.7fr) 1.5fr; gap:1.2rem; align-items:center; padding:1rem; border:1px dashed #3b4d64; border-radius:12px; background:rgba(11,22,36,.65); }
        .explanation-locked div { display:flex; flex-direction:column; gap:.25rem; }
        .explanation-locked span,.decision-lab span { color:var(--amber); font-size:.62rem; font-weight:800; letter-spacing:.13em; }
        .explanation-locked strong,.decision-lab strong { color:#dce5ed; font-size:.95rem; }
        .explanation-locked p,.decision-lab p { color:#8497ac; font-size:.78rem; line-height:1.55; margin:0; }
        .decision-lab { display:grid; grid-template-columns:1fr auto 1fr; gap:1rem; align-items:stretch; margin:.8rem 0; }
        .decision-lab>div:not(.decision-arrow) { display:flex; flex-direction:column; gap:.35rem; padding:1rem; border:1px solid var(--line); border-radius:12px; background:#0b1624; }
        .decision-lab .decision-arrow { display:flex; align-items:center; color:var(--cyan); font-size:1.4rem; }
        [data-baseweb="tab-list"] { gap:.25rem; border-bottom:1px solid var(--line); overflow-x:auto; scrollbar-width:thin; }
        [data-baseweb="tab"] { color:#8497ac; } [aria-selected="true"] { color:var(--cyan)!important; }
        [data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:10px; overflow:hidden; }
        .stButton>button[kind="primary"],.stDownloadButton>button { border-radius:8px; font-weight:700; }
        .stButton>button[kind="primary"] { background:linear-gradient(90deg,#18a993,#3de0c5); color:#04120f; border:0; }
        [data-testid="stVegaLiteChart"],[data-testid="stPlotlyChart"] { background:transparent; border-radius:10px; overflow:hidden; }
        @media (max-width:800px) { .topbar{flex-direction:column}.workflow,.case-flow,.scenario-steps,.explanation-locked,.decision-lab{grid-template-columns:1fr}.decision-lab .decision-arrow{justify-content:center;transform:rotate(90deg)}.metric-card{min-height:110px}.analyst-callout{grid-template-columns:1fr;gap:.45rem} }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_brand():
    st.markdown(
        """<div class="soc-brand"><div class="soc-mark">⬡</div><div><div class="soc-name">SENTINEL</div>
        <div class="soc-sub">IDS / IPS LAB</div></div></div>""",
        unsafe_allow_html=True,
    )


def render_empty_state():
    st.markdown(
        """<div class="empty-shell"><div class="empty-kicker">READY FOR ANALYSIS</div>
        <h2>Turn an uploaded traffic dataset into an explainable detection case.</h2>
        <p>Select a valid UNSW-NB15 CSV in the sidebar. Sentinel will validate every row, run the saved
        classifier, and present the returned decisions without altering network controls.</p>
        <div class="workflow"><div><b><span>01</span> Validate</b>42 agreed input features</div>
        <div><b><span>02</span> Detect</b>Saved Random Forest pipeline</div>
        <div><b><span>03</span> Investigate</b>Predictions and simulated actions</div></div></div>""",
        unsafe_allow_html=True,
    )


def render_section_header(title, description, code):
    st.markdown(
        f"""<div class="section-head"><div class="section-code">{code}</div>
        <div><h2>{title}</h2><p>{description}</p></div></div>""",
        unsafe_allow_html=True,
    )
