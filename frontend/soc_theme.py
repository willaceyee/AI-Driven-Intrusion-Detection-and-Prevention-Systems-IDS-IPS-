"""Visual system and reusable presentation fragments for the Streamlit SOC."""

import streamlit as st


def apply_soc_theme():
    st.markdown(
        """
        <style>
        :root { --ink:#edf4fa; --muted:#a6b6c5; --line:#24384c; --surface:#0d1a29; --surface-2:#101f30; --teal:#35d7c1; --blue:#55a9ef; --red:#ff5b73; --amber:#f6bd55; }
        html,body,[class*="css"] { font-family:Inter,"Segoe UI",system-ui,sans-serif; }
        .stApp { background:#07111d; color:var(--ink); }
        [data-testid="stSidebar"] { background:#091522; border-right:1px solid var(--line); min-width:260px; }
        [data-testid="stSidebar"]>div { padding-top:1rem; }
        [data-testid="stHeader"] { background:rgba(7,17,29,.92); border-bottom:1px solid rgba(36,56,76,.45); }
        .block-container { max-width:1680px; padding:1rem 1.35rem 3rem; }
        h1,h2,h3,h4 { letter-spacing:-.025em; color:var(--ink); }
        h4 { font-size:1rem; }
        p,label,[data-testid="stCaptionContainer"] { color:var(--muted); }
        .soc-brand { display:flex; align-items:center; gap:.75rem; margin:.1rem 0 1.35rem; }
        .soc-mark { width:42px; height:42px; display:grid; place-items:center; border:1px solid rgba(53,215,193,.6); border-radius:10px; color:var(--teal); background:#0d2230; font-size:1.15rem; }
        .soc-name { font-weight:800; letter-spacing:.07em; color:#f5f8fb; }
        .soc-sub { color:#91a4b6; font-size:.67rem; letter-spacing:.15em; }
        .sidebar-label { color:#91a4b6; font-size:.62rem; letter-spacing:.17em; font-weight:750; margin-bottom:.55rem; }
        .upload-guidance { display:grid; gap:.22rem; margin:.55rem 0 .15rem; padding:.65rem .7rem; border:1px solid #294057; border-radius:8px; background:#0d1d2b; }
        .upload-guidance strong { color:#edf4fa; font-size:.78rem; font-weight:700; }
        .upload-guidance span { color:#c3d0da; font-size:.76rem; line-height:1.5; }
        .sidebar-rule { height:1px; background:var(--line); margin:1rem 0; }
        .status-row { color:#c2cfda; font-size:.8rem; margin:.55rem 0; }
        .status-dot,.mode-badge span { display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--teal); margin-right:.45rem; }
        .sidebar-readiness { display:grid; gap:.45rem; color:#b8c7d4; font-size:.75rem; }
        .sidebar-readiness>div { display:flex; align-items:center; }
        .sidebar-readiness span { width:7px; height:7px; flex:0 0 7px; border-radius:50%; background:#38d68f; margin-right:.55rem; }
        .sidebar-readiness .readiness-caution span { background:var(--amber); }
        [data-testid="stSidebar"] [role="radiogroup"] { gap:.22rem; }
        [data-testid="stSidebar"] [role="radiogroup"] label { min-height:42px; padding:.48rem .6rem; border:1px solid transparent; border-radius:8px; transition:background .16s ease,border-color .16s ease,transform .16s ease; }
        [data-testid="stSidebar"] [role="radiogroup"] label:hover { background:#102437; border-color:#294157; transform:translateX(2px); }
        [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) { background:#123c42; border-color:#216461; }
        [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) p { color:#f2fbf8; font-weight:700; }
        [data-testid="stSidebar"] [role="radiogroup"] p { font-size:.78rem; }
        .topbar { display:flex; justify-content:space-between; align-items:center; gap:1.5rem; padding-bottom:.8rem; margin-bottom:.75rem; border-bottom:1px solid var(--line); }
        .topbar h1 { font-size:clamp(1.85rem,3vw,2.55rem); line-height:1.05; margin:0 0 .28rem; }
        .topbar p { margin:0; font-size:.86rem; color:#b2c1ce; }
        .mode-badge { border:1px solid rgba(53,215,193,.35); border-radius:8px; padding:.5rem .7rem; color:#a8d8d1; font-size:.66rem; letter-spacing:.11em; white-space:nowrap; background:#0d202d; }
        .header-status { display:flex; gap:.55rem; white-space:nowrap; }
        .header-status span { display:inline-flex; align-items:center; min-height:32px; padding:.35rem .65rem; border:1px solid #31485e; border-radius:8px; background:#101e2c; color:#b9c8d4; font-size:.72rem; font-weight:700; }
        .header-status .ready { border-color:#19735f; color:#7be7c9; }
        .header-status .ready:before { content:''; width:7px; height:7px; border-radius:50%; background:#3cdd9b; margin-right:.45rem; }
        .overview-kpis { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:.65rem; margin:.15rem 0 .75rem; }
        .metric-card { min-height:104px; border:1px solid var(--line); border-radius:10px; padding:.82rem .85rem .75rem 1rem; background:linear-gradient(145deg,#112233,#0d1a29); position:relative; overflow:hidden; transition:transform .16s ease,border-color .16s ease; }
        .metric-card:hover { transform:translateY(-2px); border-color:#3b566f; }
        .metric-card:after { content:''; position:absolute; left:0; top:0; bottom:0; width:4px; background:#607b93; }
        .metric-danger:after { background:var(--red); } .metric-safe:after { background:var(--teal); }
        .metric-info:after { background:var(--blue); } .metric-warning:after { background:var(--amber); }
        .metric-evidence:after { background:#93abc0; }
        .metric-label { color:#94a8bc; text-transform:uppercase; letter-spacing:.11em; font-size:.61rem; font-weight:750; }
        .metric-value { color:#f5f8fb; font-size:1.65rem; line-height:1; font-weight:760; margin:.55rem 0 .25rem; }
        .metric-detail { color:#91a4b6; font-size:.67rem; line-height:1.35; }
        [data-testid="stVerticalBlockBorderWrapper"] { border-color:var(--line)!important; border-radius:10px!important; background:#0b1725; box-shadow:none; }
        [data-testid="stVerticalBlockBorderWrapper"]:hover { border-color:#324b63!important; }
        [data-testid="stVerticalBlockBorderWrapper"] h4 { margin-top:0!important; margin-bottom:.1rem; }
        .ops-stack { display:grid; gap:.42rem; }
        .ops-status { display:flex; align-items:flex-start; gap:.58rem; padding:.55rem .58rem; border:1px solid #24384c; border-radius:7px; background:#101e2d; }
        .ops-status>span { width:9px; height:9px; margin-top:.2rem; flex:0 0 9px; border-radius:50%; background:#38d68f; }
        .ops-status.ops-caution>span { background:var(--amber); } .ops-status.ops-muted>span { background:#64798d; }
        .ops-status div { display:flex; flex-direction:column; gap:.08rem; }
        .ops-status strong { color:#dce6ee; font-size:.72rem; }
        .ops-status small { color:#91a4b6; font-size:.61rem; line-height:1.3; }
        .prevention-summary { display:grid; grid-template-columns:1fr 1fr; gap:.5rem; margin:.7rem 0; }
        .prevention-summary>div { min-height:88px; padding:.75rem; border:1px solid var(--line); border-radius:8px; background:#101e2d; }
        .prevention-summary strong { display:block; color:var(--red); font-size:1.65rem; line-height:1.1; }
        .prevention-summary>div:last-child strong { color:#edf4fa; }
        .prevention-summary span { display:block; margin-top:.25rem; color:#879aad; font-size:.69rem; line-height:1.3; }
        .section-head { display:flex; align-items:flex-start; gap:.8rem; margin:.25rem 0 .9rem; }
        .section-code { color:var(--teal); border:1px solid rgba(53,215,193,.3); border-radius:5px; padding:.25rem .38rem; font-size:.57rem; letter-spacing:.09em; margin-top:.25rem; }
        .section-head h2 { margin:0 0 .16rem; font-size:1.35rem; }
        .section-head p { margin:0; font-size:.78rem; }
        .empty-shell { border:1px solid var(--line); border-radius:12px; padding:clamp(1.5rem,4vw,3rem); margin-top:1rem; background:#0c1928; position:relative; overflow:hidden; }
        .empty-kicker { color:var(--teal); font-size:.65rem; letter-spacing:.14em; font-weight:800; }
        .empty-shell h2 { max-width:700px; font-size:clamp(1.5rem,3vw,2.2rem); margin:.65rem 0; }
        .empty-shell>p { max-width:680px; }
        .workflow { display:grid; grid-template-columns:repeat(3,1fr); gap:.7rem; margin-top:1.5rem; }
        .workflow div { padding:.85rem; border-top:1px solid var(--line); color:#8799ad; font-size:.76rem; }
        .workflow b { display:block; color:#dbe6ef; margin-bottom:.25rem; }
        .workflow span { color:var(--teal); font-family:monospace; margin-right:.35rem; }
        .replay-card { border:1px solid var(--line); border-radius:10px; padding:1.15rem; background:#0d1a29; }
        .replay-danger { border-left:3px solid var(--red); } .replay-safe { border-left:3px solid var(--teal); }
        .replay-index { color:#74889c; font-size:.62rem; letter-spacing:.14em; }
        .replay-status { color:#f2f7fb; font-size:1.35rem; font-weight:800; margin:.4rem 0 .9rem; }
        .replay-grid { display:grid; grid-template-columns:minmax(120px,.4fr) 1fr; gap:.48rem .85rem; font-size:.77rem; }
        .replay-grid span { color:#758ba1; } .replay-grid strong { color:#cbd7e2; overflow-wrap:anywhere; }
        .analyst-callout { display:grid; grid-template-columns:130px 1fr; gap:.9rem; align-items:start; margin:.8rem 0; padding:.82rem 1rem; border:1px solid rgba(246,189,85,.25); border-left:3px solid var(--amber); border-radius:8px; background:#171a1b; color:#9baabd; font-size:.75rem; line-height:1.5; }
        .analyst-callout strong { color:#dce5ed; } .analyst-callout.compact { margin-top:.65rem; }
        .callout-label { color:var(--amber); font-size:.59rem; font-weight:800; letter-spacing:.12em; }
        .scenario-fact { min-height:105px; display:flex; flex-direction:column; gap:.35rem; padding:.85rem; border:1px solid var(--line); border-radius:9px; background:#0d1a29; }
        .scenario-fact span { color:#8194aa; text-transform:uppercase; letter-spacing:.11em; font-size:.61rem; font-weight:700; }
        .scenario-fact strong { color:#e8f0f8; font-size:.9rem; line-height:1.35; }
        .scenario-fact small { color:#657a91; font-size:.7rem; }
        .scenario-steps { display:grid; grid-template-columns:repeat(4,1fr); gap:1px; border:1px solid var(--line); border-radius:9px; overflow:hidden; background:var(--line); }
        .scenario-steps>div { display:flex; gap:.6rem; align-items:center; padding:.75rem; background:#0d1a29; }
        .scenario-steps b { color:var(--teal); font-family:monospace; font-size:.68rem; }
        .scenario-steps span { color:#9aacbf; font-size:.73rem; }
        .evidence-note { margin:.7rem 0; padding:.75rem .9rem; border-left:2px solid var(--teal); background:#0d202c; color:#9fb0c2; font-size:.75rem; }
        .evidence-note strong { color:#e8f0f8; }
        .decision-lab span { color:var(--amber); font-size:.58rem; font-weight:800; letter-spacing:.12em; }
        .decision-lab strong { color:#dce5ed; font-size:.88rem; }
        .decision-lab p { color:#8497ac; font-size:.73rem; line-height:1.48; margin:0; }
        .decision-lab { display:grid; grid-template-columns:1fr auto 1fr; gap:.8rem; align-items:stretch; margin:.7rem 0; }
        .decision-lab>div:not(.decision-arrow) { display:flex; flex-direction:column; gap:.3rem; padding:.85rem; border:1px solid var(--line); border-radius:9px; background:#0d1a29; }
        .decision-lab .decision-arrow { display:flex; align-items:center; color:var(--teal); font-size:1.2rem; }
        [data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:8px; overflow:hidden; }
        [data-testid="stDataFrame"] * { font-size:.73rem; }
        .stButton>button,.stDownloadButton>button { min-height:38px; border-radius:7px; font-size:.75rem; font-weight:700; border-color:#38536c; transition:transform .15s ease,border-color .15s ease,background .15s ease; }
        .stButton>button:hover,.stDownloadButton>button:hover { transform:translateY(-1px); border-color:var(--teal); color:#dffbf4; }
        .stButton>button:focus-visible,.stDownloadButton>button:focus-visible,a:focus-visible,[role="radiogroup"] label:has(input:focus-visible) { outline:2px solid var(--teal)!important; outline-offset:2px!important; box-shadow:none!important; }
        .stButton>button[kind="primary"] { background:linear-gradient(90deg,#20b7a4,#3adbc5); color:#04120f; border:0; }
        .stButton>button[kind="primary"] p,.stButton>button[kind="primary"]:hover p { color:#04120f!important; font-weight:800; }
        .stButton>button:disabled { opacity:.58; transform:none; }
        .stButton>button[kind="primary"]:disabled { opacity:1; background:#163f43; border:1px solid #28575b; }
        .stButton>button[kind="primary"]:disabled p { color:#a9c5c7!important; }
        [data-testid="stVegaLiteChart"],[data-testid="stPlotlyChart"] { background:transparent; border-radius:8px; overflow:hidden; }
        [data-testid="stFileUploader"] { border-radius:8px; }
        [data-testid="stAlert"] { border-radius:8px; }
        @media (prefers-reduced-motion:reduce) { * { scroll-behavior:auto!important; transition:none!important; animation:none!important; } }
        @media (max-width:800px) {
          body:has([data-testid="stExpandSidebarButton"][aria-expanded="false"]) [data-testid="stSidebar"] { transform:translateX(-100%)!important; }
          [data-testid="stExpandSidebarButton"] { position:fixed; top:.5rem; left:.65rem; z-index:1002; width:44px; height:44px; border:1px solid #3d5871; border-radius:8px; background:#101e2c; box-shadow:0 4px 16px rgba(0,0,0,.3); }
          .block-container { padding:3.15rem .85rem 2rem; }
          .topbar { flex-direction:column; align-items:flex-start; gap:.65rem; padding-left:2.75rem; }
          .topbar h1 { font-size:1.7rem; }
          .topbar p { font-size:.8rem; }
          .header-status { flex-direction:column; gap:.3rem; }
          .header-status span { min-height:28px; padding:.28rem .5rem; font-size:.64rem; }
          .overview-kpis { grid-template-columns:repeat(2,minmax(0,1fr)); gap:.5rem; }
          .overview-kpis .metric-card:last-child { grid-column:1/-1; min-height:74px; }
          .metric-card { min-height:96px; padding:.75rem .72rem .65rem .88rem; }
          .metric-value { font-size:1.42rem; }
          .metric-detail { font-size:.62rem; }
          .section-head { flex-direction:column; gap:.35rem; margin-bottom:1rem; }
          .section-code { margin-top:0; }
          .section-head h2 { font-size:1.45rem; }
          .section-head p { font-size:.82rem; line-height:1.5; }
          [data-testid="stSidebar"] [role="radiogroup"] label,.stButton>button,.stDownloadButton>button { min-height:44px; }
          .workflow,.scenario-steps,.decision-lab { grid-template-columns:1fr; }
          .decision-lab .decision-arrow { justify-content:center; transform:rotate(90deg); }
          .analyst-callout { grid-template-columns:1fr; gap:.35rem; }
          .prevention-summary { grid-template-columns:1fr 1fr; }
          .replay-grid { grid-template-columns:1fr; }
        }
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
        <h2>Turn an uploaded traffic dataset into a reviewable detection case.</h2>
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
