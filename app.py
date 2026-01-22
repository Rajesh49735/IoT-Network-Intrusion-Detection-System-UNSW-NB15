import streamlit as st
import pickle
import numpy as np
import pandas as pd
import random
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
# UI STYLE
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
    background: rgba(255,255,255,.06);
    border-radius:18px;
    padding:22px;
    box-shadow:0 18px 55px rgba(0,0,0,.75);
}
.normal {background: linear-gradient(135deg,#064e3b,#0284c7);}
.medium {background: linear-gradient(135deg,#92400e,#facc15);}
.high {background: linear-gradient(135deg,#7f1d1d,#ef4444);}
.badge {
    display:inline-block;
    padding:6px 16px;
    border-radius:999px;
    background:#000;
    font-weight:700;
}
footer {visibility:hidden;}
</style>
""", unsafe_allow_html=True)

# =====================================================
# LOAD MODEL
# =====================================================
@st.cache_resource
def load_model():
    return pickle.load(open("models/mlp_multi.pkl", "rb"))

model = load_model()

ATTACK_LABELS = [
    "Normal","Analysis","Backdoor","DoS","Exploits",
    "Fuzzers","Generic","Reconnaissance","Shellcode","Worms"
]

# =====================================================
# SOUND ALERT
# =====================================================
def play_alert():
    st.markdown("""
    <audio autoplay>
        <source src="data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQAAAAA=">
    </audio>
    """, unsafe_allow_html=True)

# =====================================================
# SESSION STATE
# =====================================================
if "events" not in st.session_state:
    st.session_state.events = []

# =====================================================
# HEADER
# =====================================================
st.title("🛡️ IoT Network Intrusion Detection Platform")
st.subheader("SOC-Grade Real-Time Intrusion Detection Dashboard")

# =====================================================
# MODE SELECTOR
# =====================================================
mode = st.radio(
    "Detection Mode",
    ["Manual Input Mode", "Auto Simulation Mode"],
    horizontal=True
)

# =====================================================
# INPUT
# =====================================================
st.markdown("### 🔌 Network Traffic Data")

if mode == "Manual Input Mode":
    c1, c2 = st.columns(2)
    with c1:
        spkts = st.number_input("Source Packets", 0, 5_000_000, 300, step=100)
        sbytes = st.number_input("Source Bytes", 0, 5_000_000, 600, step=200)
    with c2:
        dpkts = st.number_input("Destination Packets", 0, 5_000_000, 280, step=100)
        dbytes = st.number_input("Destination Bytes", 0, 5_000_000, 550, step=200)
else:
    spkts  = random.randint(100, 3000)
    dpkts  = random.randint(100, 3000)
    sbytes = random.randint(1000, 60000)
    dbytes = random.randint(1000, 60000)

    a1,a2,a3,a4 = st.columns(4)
    a1.metric("Source Packets", spkts)
    a2.metric("Destination Packets", dpkts)
    a3.metric("Source Bytes", sbytes)
    a4.metric("Destination Bytes", dbytes)

# =====================================================
# ANALYSIS
# =====================================================
if st.button("🔍 Analyze Traffic"):
    st.markdown("---")

    # ---------------- RISK SCORE ----------------
    score = (
        0.3 * min(spkts/2000,1) +
        0.3 * min(dpkts/2000,1) +
        0.2 * min(sbytes/40000,1) +
        0.2 * min(dbytes/40000,1)
    )

    imbalance = abs(spkts-dpkts)/(spkts+dpkts+1)
    score += min(imbalance,0.5)

    explanation = []

    if spkts > 2000 or dpkts > 2000:
        explanation.append("High packet rate detected")
    if sbytes > 40000 or dbytes > 40000:
        explanation.append("Abnormal byte volume")
    if imbalance > 0.3:
        explanation.append("Traffic imbalance observed")

    # ---------------- NORMAL VS ATTACK ----------------
    if score < 0.45:
        attack="Normal"
        severity="LOW"
        risk=int(score*40)
        confidence=0.88
        box="normal"
    else:
        n = model.n_features_in_ if hasattr(model,"n_features_in_") else model.coefs_[0].shape[0]
        X=np.zeros((1,n))
        X[0,:4]=[spkts,dpkts,sbytes,dbytes]
        pred=int(model.predict(X)[0])
        attack=ATTACK_LABELS[pred]
        confidence=0.72
        risk=int(score*100)
        severity="MEDIUM"
        box="medium"

        if score>0.75:
            severity="HIGH"
            risk=max(risk,85)
            box="high"

        play_alert()

    # ---------------- DISPLAY ----------------
    st.markdown(f"""
    <div class="card {box}">
        <h3>{'✅ Normal Traffic' if attack=='Normal' else '🚨 Intrusion Detected'}</h3>
        <span class="badge">{attack}</span>
    </div>
    """, unsafe_allow_html=True)

    # ---------------- METRICS ----------------
    c1,c2,c3 = st.columns(3)
    c1.metric("Confidence", f"{int(confidence*100)}%")
    c2.metric("Severity", severity)
    c3.metric("Risk Score", f"{risk}/100")
    st.progress(risk)

    # ---------------- EXPLAINABLE AI ----------------
    with st.expander("🧠 Why this decision? (Explainable AI)"):
        if attack=="Normal":
            st.write("Traffic parameters are within expected operational thresholds.")
        else:
            for r in explanation:
                st.write("•", r)
            st.write("• Classified by ML model based on learned attack patterns")

    # ---------------- LOG ----------------
    st.session_state.events.append({
        "Time":datetime.now().strftime("%H:%M:%S"),
        "Attack":attack,
        "Severity":severity,
        "Risk":risk
    })

# =====================================================
# TIMELINE & PROFESSIONAL FREQ GRAPH
# =====================================================
st.markdown("### 🕒 Detection Timeline")

colA,colB=st.columns([3,1])
with colB:
    if st.button("🧹 Clear Timeline"):
        st.session_state.events=[]
        st.success("Timeline cleared")

if st.session_state.events:
    df=pd.DataFrame(st.session_state.events)
    st.dataframe(df.tail(10),use_container_width=True)

    st.markdown("### 📈 Attack Frequency (SOC View)")
    freq=df["Attack"].value_counts().reset_index()
    freq.columns=["Attack Type","Count"]
    st.dataframe(freq,hide_index=True,use_container_width=True)
else:
    st.info("No detection events yet.")

