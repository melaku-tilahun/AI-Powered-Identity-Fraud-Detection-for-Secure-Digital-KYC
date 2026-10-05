import uuid

import streamlit as st
import pandas as pd
import networkx as nx

from src.data import DemoEvent, get_demo_scenario
from src.onboarding import process_onboarding
from src.rules import evaluate_rules
from src.graph_engine import build_onboarding_graph, analyze_graph, graph_summary
from src.models import get_model_predictions, get_model_metrics
from src.risk import calculate_hybrid_risk
from src.explainability import generate_explanations


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="AI-Powered Identity Fraud Detection for Secure Digital KYC: A Zero Trust Approach",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# STYLING
# ============================================================

st.markdown(
    """
    <style>
    .main-title {
        font-size: 2.4rem;
        font-weight: 700;
        margin-bottom: 0;
    }

    .subtitle {
        font-size: 1.05rem;
        color: #6b7280;
        margin-bottom: 1.5rem;
    }

    /* ---- Fayda ID Card ---- */
    .fayda-card {
        border-radius: 10px;
        overflow: hidden;
        border: 1px solid #cbd5e1;
        box-shadow: 0 2px 10px rgba(0,0,0,0.07);
        margin-bottom: 1.2rem;
        max-width: 540px;
        font-family: 'Segoe UI', Arial, sans-serif;
        background: #ffffff;
    }

    .fayda-card-header {
        background: #ffffff;
        border-bottom: 1px solid #e2e8f0;
        padding: 0.65rem 1.1rem;
        display: flex;
        align-items: center;
        gap: 0.7rem;
    }

    .fayda-card-header .brand {
        color: #1e293b;
        font-size: 1.0rem;
        font-weight: 700;
        letter-spacing: 0.12em;
    }

    .fayda-card-header .brand-sub {
        color: #64748b;
        font-size: 0.68rem;
        letter-spacing: 0.02em;
        margin-top: 1px;
    }

    .fayda-card-header .verified-badge {
        margin-left: auto;
        background: #f1f5f9;
        color: #64748b;
        border: 1px solid #cbd5e1;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        padding: 0.2rem 0.55rem;
        border-radius: 20px;
    }

    .fayda-card-body {
        background: #ffffff;
        padding: 0.9rem 1.1rem;
        display: flex;
        gap: 1rem;
        align-items: flex-start;
    }

    .fayda-photo {
        width: 64px;
        height: 80px;
        background: #f1f5f9;
        border-radius: 4px;
        border: 1px solid #e2e8f0;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
        color: #94a3b8;
        font-size: 0.62rem;
        text-align: center;
        line-height: 1.4;
    }

    .fayda-fields {
        flex: 1;
    }

    .fayda-row {
        margin-bottom: 0.45rem;
    }

    .fayda-label {
        font-size: 0.6rem;
        font-weight: 700;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.07em;
    }

    .fayda-value {
        font-size: 0.88rem;
        font-weight: 600;
        color: #1e293b;
    }

    .fayda-value.mono {
        font-family: 'Courier New', monospace;
        font-size: 0.82rem;
        color: #334155;
        font-weight: 400;
    }

    .fayda-card-footer {
        background: #ffffff;
        border-top: 1px solid #e2e8f0;
        padding: 0.35rem 1.1rem;
        font-size: 0.6rem;
        color: #94a3b8;
        letter-spacing: 0.03em;
    }

    .signal-box {
        padding: 1.1rem 1.3rem;
        border-radius: 12px;
        border: 1px solid #e5e7eb;
        background: #f9fafb;
        margin-bottom: 1rem;
    }

    .signal-header {
        font-size: 0.78rem;
        font-weight: 700;
        color: #6b7280;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 0.5rem;
    }

    .risk-card {
        padding: 1.5rem;
        border-radius: 12px;
        border: 1px solid #d1d5db;
        text-align: center;
        margin-bottom: 1rem;
    }

    .risk-score {
        font-size: 3.2rem;
        font-weight: 800;
    }

    .risk-label {
        font-size: 1.2rem;
        font-weight: 700;
    }

    .signal-card {
        padding: 1rem;
        border: 1px solid #e5e7eb;
        border-radius: 10px;
        background: #fafafa;
        min-height: 110px;
    }

    .small-label {
        font-size: 0.8rem;
        color: #6b7280;
        text-transform: uppercase;
    }

    .big-value {
        font-size: 1.5rem;
        font-weight: 700;
    }

    .verified {
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid #86efac;
        background: #f0fdf4;
    }

    .warning {
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid #facc15;
        background: #fefce8;
    }

    .danger {
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid #fca5a5;
        background: #fef2f2;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SESSION STATE
# ============================================================

if "scenario_result" not in st.session_state:
    st.session_state.scenario_result = None

if "live_result" not in st.session_state:
    st.session_state.live_result = None

# Stable live identity ID — regenerated only when user clicks Assess
if "live_identity_id" not in st.session_state:
    st.session_state.live_identity_id = f"LIVE-{uuid.uuid4().hex[:8].upper()}"


# ============================================================
# SHARED PIPELINE RUNNER
# ============================================================

def run_pipeline(event: DemoEvent) -> dict:
    """
    Run the full fraud-risk pipeline on a DemoEvent and return
    a result dict identical in structure to scenario_result.
    """
    onboarding = process_onboarding(event)
    rule_result = evaluate_rules(onboarding)
    model_result = get_model_predictions(onboarding)
    graph = build_onboarding_graph(onboarding)
    graph_result = analyze_graph(
        graph,
        onboarding.identity_id,
        onboarding.device_id,
        onboarding.network_id,
    )
    risk_result = calculate_hybrid_risk(
        rule_result=rule_result,
        model_result=model_result,
        graph_result=graph_result,
        onboarding=onboarding,
    )
    explanations = generate_explanations(
        onboarding=onboarding,
        rule_result=rule_result,
        model_result=model_result,
        graph_result=graph_result,
        risk_result=risk_result,
    )
    return {
        "event": event,
        "onboarding": onboarding,
        "rules": rule_result,
        "models": model_result,
        "graph": graph,
        "graph_result": graph_result,
        "risk": risk_result,
        "explanations": explanations,
    }


# ============================================================
# SHARED RESULTS RENDERER
# ============================================================

def render_results(result: dict, show_coordination_box: bool = False) -> None:
    """
    Render the full results panel for either Live or Scenario mode.
    Called identically from both tabs.
    """
    onboarding   = result["onboarding"]
    rule_result  = result["rules"]
    model_result = result["models"]
    graph        = result["graph"]
    graph_result = result["graph_result"]
    risk_result  = result["risk"]
    explanations = result["explanations"]

    # ----------------------------------------------------------
    # TOP STATUS METRICS
    # ----------------------------------------------------------

    st.markdown("---")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Identity Verification",
            "VERIFIED" if onboarding.identity_verified else "FAILED",
        )

    with col2:
        st.metric(
            "Rule Risk",
            f"{rule_result['score']:.0f}/100",
        )

    with col3:
        st.metric(
            "Graph Risk",
            f"{graph_result['score']:.0f}/100",
        )

    with col4:
        st.metric(
            "Final Risk",
            f"{risk_result['score']:.0f}/100",
        )

    # ----------------------------------------------------------
    # RISK DECISION
    # ----------------------------------------------------------

    st.markdown("## Risk Decision")

    risk_score = risk_result["score"]
    risk_level = risk_result["level"]
    decision   = risk_result["decision"]

    if risk_level == "Trusted":
        st.success(
            f"### {risk_score:.0f}/100 — TRUSTED\n\n"
            f"**Decision:** {decision}"
        )
    elif risk_level == "Low":
        st.info(
            f"### {risk_score:.0f}/100 — LOW RISK\n\n"
            f"**Decision:** {decision}"
        )
    elif risk_level == "Elevated":
        st.warning(
            f"### {risk_score:.0f}/100 — ELEVATED RISK\n\n"
            f"**Decision:** {decision}"
        )
    else:
        st.error(
            f"### {risk_score:.0f}/100 — HIGH RISK\n\n"
            f"**Decision:** {decision}"
        )

    # ----------------------------------------------------------
    # 1. IDENTITY VERIFICATION
    # ----------------------------------------------------------

    st.markdown("## 1. Identity Verification")

    identity_col1, identity_col2 = st.columns(2)

    with identity_col1:
        if onboarding.identity_verified:
            st.markdown(
                """
                <div class="verified">
                <strong>✓ Identity Verified</strong><br>
                Synthetic Fayda/eSignet verification successful.
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.error("Identity verification failed.")

    with identity_col2:
        st.metric(
            "Pseudonymous Identity",
            onboarding.identity_id,
        )

    # ----------------------------------------------------------
    # 2. ONBOARDING RISK SIGNALS
    # ----------------------------------------------------------

    st.markdown("## 2. Onboarding Risk Signals")

    signals = [
        ("Device Reuse",          onboarding.device_reuse_count),
        ("Identity Reuse",        onboarding.identity_reuse_count),
        ("Registrations / 24h",   onboarding.registrations_24h),
        ("Network Identities",    onboarding.network_identity_count),
        ("Automation Score",      f"{onboarding.automation_score:.2f}"),
        ("Behavior Score",        f"{onboarding.behavior_score:.2f}"),
    ]

    cols = st.columns(3)

    for index, (label, value) in enumerate(signals):
        with cols[index % 3]:
            st.markdown(
                f"""
                <div class="signal-card">
                    <div class="small-label">{label}</div>
                    <div class="big-value">{value}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # ----------------------------------------------------------
    # 3. RISK ENGINE
    # ----------------------------------------------------------

    st.markdown("## 3. Risk Engine")

    engine_col1, engine_col2, engine_col3 = st.columns(3)

    with engine_col1:
        st.markdown("### Rule Engine")
        st.metric("Rule Score", f"{rule_result['score']:.0f}/100")
        for rule in rule_result.get("triggered_rules", []):
            st.write(f"• {rule}")

    with engine_col2:
        st.markdown("### Machine Learning")

        ml_probability = model_result.get("fraud_probability", 0)
        st.metric("Fraud Probability", f"{ml_probability * 100:.1f}%")
        st.write(
            f"Selected model: "
            f"**{model_result.get('selected_model', 'N/A')}**"
        )

        all_preds = model_result.get("predictions", {})
        if all_preds:
            pred_df = pd.DataFrame(
                [
                    {"Model": k, "Fraud Probability": f"{v*100:.1f}%"}
                    for k, v in all_preds.items()
                ]
            )
            st.dataframe(pred_df, use_container_width=True, hide_index=True)

    with engine_col3:
        st.markdown("### Graph Analytics")
        st.metric("Graph Risk", f"{graph_result['score']:.0f}/100")
        st.write(
            f"Suspicious relationships: "
            f"**{graph_result.get('suspicious_relationships', 0)}**"
        )

        g_sum = graph_summary(graph)
        st.caption(
            f"Graph: {g_sum['nodes']} nodes · "
            f"{g_sum['edges']} edges · "
            f"{g_sum['identities']} identities"
        )

        for sig in graph_result.get("signals", []):
            st.write(f"— {sig}")

    # ----------------------------------------------------------
    # 4. EXPLAINABILITY
    # ----------------------------------------------------------

    st.markdown("## 4. Why Was This Risk Score Generated?")

    if explanations:
        for explanation in explanations:
            st.write(f"• {explanation}")
    else:
        st.write("No elevated-risk explanations were generated.")

    # ----------------------------------------------------------
    # 5. ONBOARDING RELATIONSHIP GRAPH
    # ----------------------------------------------------------

    st.markdown("## 5. Onboarding Relationship Graph")

    st.caption(
        "The graph shows relationships between identities, devices, "
        "accounts, sessions and networks."
    )

    graph_data = [
        {
            "Source": source,
            "Relationship": data.get("relationship", "connected"),
            "Target": target,
        }
        for source, target, data in graph.edges(data=True)
    ]

    if graph_data:
        st.dataframe(
            pd.DataFrame(graph_data),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No graph relationships detected.")

    # ----------------------------------------------------------
    # COORDINATED FRAUD PATTERN (scenario tab only)
    # ----------------------------------------------------------

    if show_coordination_box:
        st.markdown("---")
        st.markdown("## Coordinated Fraud Pattern")
        st.error(
            """
            **Multiple identities are individually valid, but their
            relationships create a suspicious pattern.**

            The graph engine detects shared infrastructure and
            abnormal registration behavior that would be difficult
            to identify by evaluating each identity independently.
            """
        )
        st.code(
            """
Identity A ─────┐
Identity B ─────┤
Identity C ─────┼──── Device X
Identity D ─────┤        |
Identity E ─────┘        |
                          |
                       Network N
            """,
            language="text",
        )

    # ----------------------------------------------------------
    # EXPANDERS
    # ----------------------------------------------------------

    with st.expander("Risk Score Breakdown (Fusion Weights)"):
        st.markdown(
            """
            | Component | Weight | Raw Score | Contribution |
            |-----------|--------|-----------|-------------|
            | Rule Engine | 25% | {rule}/100 | {rule_c:.1f} |
            | Machine Learning | 40% | {ml}/100 | {ml_c:.1f} |
            | Graph Analytics | 25% | {graph}/100 | {graph_c:.1f} |
            | Behavioral | 10% | {beh}/100 | {beh_c:.1f} |
            | **Coordination bonus** | — | — | **+{cb}** |
            | **Final** | 100% | — | **{final}/100** |
            """.format(
                rule=risk_result["rule_score"],
                ml=risk_result["ml_score"],
                graph=risk_result["graph_score"],
                beh=risk_result["behavioral_score"],
                rule_c=risk_result["rule_score"] * 0.25,
                ml_c=risk_result["ml_score"] * 0.40,
                graph_c=risk_result["graph_score"] * 0.25,
                beh_c=risk_result["behavioral_score"] * 0.10,
                cb=risk_result["coordination_bonus"],
                final=risk_result["score"],
            )
        )

    with st.expander("Research Model Evaluation"):
        st.markdown(
            """
            These results are generated from the synthetic benchmark
            dataset used by the prototype. They are not production
            fraud-detection performance claims.
            """
        )
        try:
            metrics = get_model_metrics()
            if metrics:
                st.dataframe(
                    pd.DataFrame(metrics),
                    use_container_width=True,
                    hide_index=True,
                )
        except Exception as exc:
            st.warning(f"Model evaluation unavailable: {exc}")

    with st.expander("Privacy & Zero Trust Architecture"):
        st.markdown(
            """
            ### Privacy-by-Design

            - Synthetic/pseudonymous identifiers
            - Data minimization
            - No raw biometric data required
            - Separation of identity and fraud-risk data
            - Retention controls
            - Audit logging

            ### Zero Trust Principles

            - Explicit verification
            - Least-privilege access
            - RBAC
            - Encryption in transit
            - Encryption at rest
            - Secrets management
            - Continuous auditability

            The prototype does not connect to CBE production systems
            or real Fayda infrastructure.
            """
        )

    with st.expander("System Architecture"):
        st.code(
            """
                    DIGITAL ONBOARDING
                            |
                            v
                +----------------------+
                | Fayda/eSignet        |
                | Verification         |
                | Simulator            |
                +----------+-----------+
                           |
                    Identity Verified
                           |
                           v
                +----------------------+
                | Signal Collection    |
                |----------------------|
                | Identity             |
                | Device               |
                | Session              |
                | Network              |
                | Behavior             |
                | Velocity             |
                +----------+-----------+
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
      Rule Engine      ML Engine       Graph Engine
                      LR / RF / XGB       NetworkX
          |                |                |
          +----------------+----------------+
                           |
                           v
                  +----------------+
                  | Risk Fusion    |
                  +-------+--------+
                          |
                          v
                  +----------------+
                  | Explainability |
                  +-------+--------+
                          |
                          v
                    RISK DECISION
                          |
          +---------------+---------------+
          |               |               |
       APPROVE         VERIFY           HOLD
            """
        )


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">AI-Powered Identity Fraud Detection for Secure Digital KYC: A Zero Trust Approach</div>',
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="subtitle">
    Research prototype — 3rd Annual Cybersecurity Awareness Month Conference 2026 &nbsp;|&nbsp; Commercial Bank of Ethiopia
    </div>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SIDEBAR (shared)
# ============================================================

st.sidebar.title("Demo Control")

st.sidebar.markdown(
    """
    **Architecture**

    Identity Verification  
    ↓  
    Signal Collection  
    ↓  
    Rules + ML + Graph  
    ↓  
    Risk Fusion  
    ↓  
    Explainability  
    ↓  
    Decision
    """
)

st.sidebar.markdown("---")
st.sidebar.caption(
    "Synthetic data only."
)


# ============================================================
# TABS
# ============================================================

tab_live, tab_scenario = st.tabs(
    ["Live Onboarding", "Scenario Player"]
)


# ============================================================
# TAB 1 — LIVE ONBOARDING
# ============================================================

with tab_live:

    st.markdown("### Live Onboarding Demo")
    st.markdown(
        "Simulate a customer onboarding event as if you are the customer. "
        "**Step 1** shows what CBE's system receives automatically from "
        "Fayda/eSignet after identity verification. "
        "**Step 2** shows the signals the onboarding system automatically "
        "collects from the session — adjust them to explore how the risk "
        "engine responds."
    )

    # ----------------------------------------------------------
    # PHASE 1 — SIMULATED FAYDA RESPONSE
    # Displayed read-only; auto-generated, not typed by the user.
    # ----------------------------------------------------------

    st.markdown("---")
    st.markdown("#### Step 1 — Fayda/eSignet Identity Verification")
    st.caption(
        "In production, this response arrives automatically from the "
        "national ID system after the customer completes biometric "
        "authentication. No identity attributes are entered manually."
    )

    live_id = st.session_state.live_identity_id

    st.markdown(
        f"""
        <div class="fayda-card">
            <div class="fayda-card-header">
                <div>
                    <div class="brand">FAYDA</div>
                    <div class="brand-sub">Federal Democratic Republic of Ethiopia &nbsp;|&nbsp; eSignet</div>
                </div>
                <div class="verified-badge">VERIFIED</div>
            </div>
            <div class="fayda-card-body">
                <div class="fayda-photo">Photo<br>verified<br>biometric</div>
                <div class="fayda-fields">
                    <div class="fayda-row">
                        <div class="fayda-label">Full Name</div>
                        <div class="fayda-value">Abebe Kebede</div>
                    </div>
                    <div class="fayda-row">
                        <div class="fayda-label">National ID</div>
                        <div class="fayda-value mono">123456789</div>
                    </div>
                    <div class="fayda-row">
                        <div class="fayda-label">Identity attributes</div>
                        <div class="fayda-value" style="font-size:0.75rem;font-weight:400;color:#94a3b8;">Received by CBE &mdash; not passed to fraud-risk layer</div>
                    </div>
                </div>
            </div>
            <div class="fayda-card-footer">Simulated response &nbsp;&middot;&nbsp; No real Fayda infrastructure accessed</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ----------------------------------------------------------
    # PHASE 2 — AUTOMATICALLY COLLECTED SIGNALS
    # In production these are captured by the onboarding platform,
    # not entered by the customer. Here the presenter adjusts them
    # to demonstrate different risk scenarios.
    # ----------------------------------------------------------

    st.markdown("---")
    st.markdown("#### Step 2 — Automatically Collected Onboarding Signals")
    st.caption(
        "These signals are collected automatically by CBE's onboarding "
        "platform — from device fingerprinting, session tracking, velocity "
        "counters, and behavioural analytics. Adjust them to explore how "
        "the risk engine responds to different onboarding contexts."
    )

    st.markdown(
        """
        <div class="signal-box">
            <div class="signal-header">Device &amp; Network Signals</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    dev_col1, dev_col2 = st.columns(2)

    with dev_col1:
        live_device_reuse = st.slider(
            "Device reuse count",
            min_value=0,
            max_value=10,
            value=0,
            help=(
                "How many other identities have used this device fingerprint "
                "to register in the past. Collected by the device fingerprinting service."
            ),
        )
        live_network_ids = st.slider(
            "Identities on same network",
            min_value=1,
            max_value=15,
            value=1,
            help=(
                "How many other identities have registered from the same "
                "IP/network range in the past 24 h. Collected by network correlation."
            ),
        )

    with dev_col2:
        live_registrations = st.slider(
            "Registrations from this network in last 24 h",
            min_value=1,
            max_value=20,
            value=1,
            help=(
                "Total registration events seen from this network block in "
                "the last 24 hours. Collected by the velocity counter."
            ),
        )
        live_session_secs = st.slider(
            "Session duration (seconds)",
            min_value=10,
            max_value=900,
            value=480,
            help=(
                "How long the onboarding session took. A real human typically "
                "takes 3–10 minutes. Bots can complete it in < 30 seconds."
            ),
        )

    st.markdown(
        """
        <div class="signal-box">
            <div class="signal-header">Behavioural Signals</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    beh_col1, beh_col2 = st.columns(2)

    with beh_col1:
        live_automation = st.slider(
            "Automation score (0 = human, 1 = bot)",
            min_value=0.0,
            max_value=1.0,
            value=0.05,
            step=0.01,
            help=(
                "Derived from mouse movement, keystroke timing, and interaction "
                "patterns. Collected by the behavioural analytics layer."
            ),
        )

    with beh_col2:
        live_behavior = st.slider(
            "Behaviour anomaly score (0 = normal, 1 = highly anomalous)",
            min_value=0.0,
            max_value=1.0,
            value=0.05,
            step=0.01,
            help=(
                "Derived from deviations from normal onboarding interaction "
                "patterns. Collected by the session anomaly detector."
            ),
        )

    st.markdown("---")

    run_live = st.button(
        "Assess Risk",
        type="primary",
        use_container_width=True,
        key="run_live_btn",
    )

    if run_live:

        # Regenerate a fresh pseudonymous identity ID each assessment.
        st.session_state.live_identity_id = (
            f"LIVE-{uuid.uuid4().hex[:8].upper()}"
        )
        live_id = st.session_state.live_identity_id

        live_event = DemoEvent(
            scenario="Live Registration",

            identity_id=live_id,
            device_id="LIVE-DEV-001",
            account_id=f"LIVE-ACC-{uuid.uuid4().hex[:6].upper()}",
            session_id=f"LIVE-SES-{uuid.uuid4().hex[:6].upper()}",
            network_id="LIVE-NET-001",

            identity_verified=True,   # Fayda verification always succeeds in live mode

            device_reuse_count=live_device_reuse,
            identity_reuse_count=0,
            registrations_24h=live_registrations,
            network_identity_count=live_network_ids,

            automation_score=live_automation,
            behavior_score=live_behavior,

            session_duration_seconds=live_session_secs,

            ip_address="10.0.0.1",

            metadata={
                "description": "Live onboarding event — presenter-configured signals",
                "expected_outcome": "unknown",
                "source": "live_demo",
            },
        )

        with st.spinner("Running fraud-risk pipeline..."):
            st.session_state.live_result = run_pipeline(live_event)

    if st.session_state.live_result is not None:
        render_results(st.session_state.live_result, show_coordination_box=False)

    else:
        st.info(
            "Adjust the signal sliders above to configure the onboarding "
            "context, then click **Assess Risk** to run the pipeline."
        )

        st.markdown("### Research Question")
        st.markdown(
            """
            #### Can an onboarding event be suspicious even when the identity is valid?

            **Yes.**

            Fayda/eSignet answers:

            > **Is this identity valid?**

            The fraud-risk layer answers:

            > **Is this onboarding *activity* consistent with a legitimate customer?**

            A fraudster who passes identity verification can still exhibit
            suspicious device reuse, bot-like behaviour, or coordinated
            network patterns that the risk engine will detect.
            """
        )


# ============================================================
# TAB 2 — SCENARIO PLAYER
# ============================================================

with tab_scenario:

    SCENARIO_DESCRIPTIONS = {
        "Legitimate Onboarding": "Normal first-time customer — unique device, low velocity, human session behaviour.",
        "Account Farming": "One device used for 5+ registrations — shared infrastructure, elevated velocity.",
        "Automated Onboarding": "Bot-speed registration — session 18 s, automation score 0.91, 12 registrations / 24 h.",
        "Coordinated Fraud": "Five individually valid identities sharing the same device and network.",
    }

    scenario = st.selectbox(
        "Select onboarding scenario",
        list(SCENARIO_DESCRIPTIONS.keys()),
        key="scenario_selector",
    )

    st.info(SCENARIO_DESCRIPTIONS[scenario])

    run_scenario = st.button(
        "Run Risk Assessment",
        use_container_width=True,
        type="primary",
        key="run_scenario_btn",
    )

    if run_scenario:
        with st.spinner("Processing onboarding event..."):
            event = get_demo_scenario(scenario)
            st.session_state.scenario_result = run_pipeline(event)

    if st.session_state.scenario_result is not None:
        show_coord = (
            st.session_state.scenario_result["event"].scenario
            == "Coordinated Fraud"
        )
        render_results(
            st.session_state.scenario_result,
            show_coordination_box=show_coord,
        )

    else:
        st.info(
            "Select a scenario above and click "
            "**Run Risk Assessment** to start the demonstration."
        )

        st.markdown("## Prototype Architecture")

        st.code(
            """
Digital Onboarding
        |
        v
Fayda/eSignet Verification
        |
        v
Signal Collection
        |
        +----------------+
        |                |
        v                v
     Rules             ML Models
                        LR / RF / XGBoost
        |                |
        +--------+-------+
                 |
                 v
          Graph Analytics
             NetworkX
                 |
                 v
            Risk Fusion
                 |
                 v
          Explainability
                 |
                 v
        Risk-Based Decision
            """,
            language="text",
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.caption(
    "AI-Powered Identity Fraud Detection for Secure Digital KYC: A Zero Trust Approach "
    "— Synthetic Research Prototype | CBE Cybersecurity Conference 2026"
)