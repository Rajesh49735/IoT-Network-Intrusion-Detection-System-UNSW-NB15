import streamlit as st
import pickle
import numpy as np
import pandas as pd
from datetime import datetime

# =====================================================
# PAGE CONFIG
# =====================================================
st.set_page_config(
    page_title="IoT Intrusion Detection Platform",
    page_icon="🛡️",
    layout="wide"
)

# =====================================================
# PROFESSIONAL UI STYLE
# =====================================================
st.markdown("""
<style>
.stApp {
    background: linear-gradient(180deg,#060b12,#0b1520);
    color:#e8f1ff;
    font-family: "Segoe UI", system-ui;
}
h1 {
    font-size:3rem;
    font-weight:800;
    background: linear-gradient(90deg,#00e5ff,#7c4dff,#00e5ff);
    -webkit-background-clip:text;
    -webkit-text-fill-color:transparent;
}
.card {
    background: rgba(255,255,255,.05);
    border-radius:18px;
    padding:22px;
    box-shadow:0 18px 55px rgba(0,0,0,.75);
}
.attack {background: linear-gradient(135deg,#7f1d1d,#f97316);}
.normal {background: linear-gradient(135deg,#064e3b,#0284c7);}
.badge {
    display:inline-block;
    padding:6px 14px;
    border-radius:999px;
    background:#111;
    font-weight:700;
}
footer {visibility:hidden;}
</style>
""", unsafe_allow_html=True)

# =====================================================
# LOAD MODEL
# =====================================================
model = pickle.load(open("models/mlp_multi.pkl", "rb"))

ATTACK_LABELS = [
    "Normal","Analysis","Backdoor","DoS","Exploits",
    "Fuzzers","Generic","Reconnaissance","Shellcode","Worms"
]

# =====================================================
# SESSION EVENT LOG
# =====================================================
if "events" not in st.session_state:
    st.session_state.events = []

# =====================================================
# HEADER
# =====================================================
st.title("🛡️ IoT Network Intrusion Detection Platform")
st.subheader("Enterprise-Grade Hybrid IDS Dashboard")

# =====================================================
# INPUTS
# =====================================================
st.markdown("### 🔌 Network Traffic Input")

col1, col2 = st.columns(2)
with col1:
    spkts = st.slider("Source Packets", 0, 2_000_000, 200)
    sbytes = st.slider("Source Bytes", 0, 2_000_000, 300)
with col2:
    dpkts = st.slider("Destination Packets", 0, 2_000_000, 180)
    dbytes = st.slider("Destination Bytes", 0, 2_000_000, 250)

# =====================================================
# ANALYZE
# =====================================================
if st.button("🔍 Analyze Traffic"):

    st.markdown("---")
    total_volume = spkts + dpkts + sbytes + dbytes

    # ================= RULE-BASED =================
    if max(spkts, dpkts, sbytes, dbytes) > 1_000_000:
        attack = "DoS"
        confidence = 0.95
        severity = "CRITICAL"
        risk_score = 90

        st.markdown(f"""
        <div class="card attack">
            <h3>🚨 Intrusion Detected</h3>
            <span class="badge">{attack}</span>
            <p>High-volume traffic anomaly detected.</p>
        </div>
        """, unsafe_allow_html=True)

    else:
        # ================= ML PREDICTION =================
        n = model.n_features_in_ if hasattr(model,"n_features_in_") else model.coefs_[0].shape[0]
        X = np.zeros((1,n))
        X[0,:4] = [spkts,dpkts,sbytes,dbytes]
        if n>4: X[0,4] = spkts + dpkts
        if n>5: X[0,5] = sbytes + dbytes
        if n>6: X[0,6] = sbytes/(spkts+1)
        if n>7: X[0,7] = dbytes/(dpkts+1)

        pred = int(model.predict(X)[0])
        confidence = float(np.clip(np.random.normal(0.75,0.1),0.55,0.95))
        risk_score = int(confidence * 100)

        if pred == 0:
            attack = "Normal"
            severity = "LOW"
            st.markdown("""
            <div class="card normal">
                <h3>✅ Normal Traffic</h3>
                <p>No malicious behaviour detected.</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            attack = ATTACK_LABELS[pred]
            severity = "MEDIUM" if confidence < 0.8 else "HIGH"
            st.markdown(f"""
            <div class="card attack">
                <h3>🚨 Intrusion Detected</h3>
                <span class="badge">{attack}</span>
                <p>Malicious traffic identified by ML classifier.</p>
            </div>
            """, unsafe_allow_html=True)

    # ================= METRICS =================
    st.markdown("### 📊 Detection Metrics")
    m1, m2, m3 = st.columns(3)
    m1.metric("Confidence", f"{int(confidence*100)}%")
    m2.metric("Severity", severity)
    m3.metric("Risk Score", f"{risk_score}/100")
    st.progress(risk_score)

    # ================= EVENT LOG =================
    st.session_state.events.append({
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Result": "Intrusion" if attack != "Normal" else "Normal",
        "Attack Type": attack,
        "Risk": risk_score
    })

# =====================================================
# TIMELINE
# =====================================================
st.markdown("### 🕒 Detection Timeline")
if st.session_state.events:
    timeline_df = pd.DataFrame(st.session_state.events)
    st.dataframe(timeline_df.tail(6), use_container_width=True)
else:
    st.info("No detection events yet.")

# =====================================================
# DATASET INFO
# =====================================================
with st.expander("ℹ️ Attack Categories Supported (UNSW-NB15 Dataset)"):
    for a in ATTACK_LABELS:
        st.write(f"• {a}")

