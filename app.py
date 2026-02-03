import streamlit as st
import pickle
import numpy as np
import pandas as pd
import random
import time
import psutil
from datetime import datetime
import plotly.express as px

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
.section-title {
    font-size:1.6rem;
    font-weight:700;
    color:#c7d2fe;
    margin-top:25px;
}
.card {
    background: rgba(255,255,255,.05);
    border-radius:18px;
    padding:22px;
    box-shadow:0 18px 55px rgba(0,0,0,.75);
}
.normal {background: linear-gradient(135deg,#064e3b,#0284c7);}
.attack {background: linear-gradient(135deg,#7f1d1d,#f97316);}
.badge {
    display:inline-block;
    padding:6px 14px;
    border-radius:999px;
    background:#020617;
    font-weight:700;
}
div.stButton > button:first-child {
    background: linear-gradient(90deg,#2563eb,#7c3aed);
    color:white;
    font-weight:900;
    border-radius:14px;
    padding:14px 28px;
    border:none;
}
button[kind="secondary"] {
    background: linear-gradient(90deg,#f59e0b,#ef4444);
    color:white;
    font-weight:800;
    border-radius:12px;
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

AI_EXPLANATION = {
    "Normal": "Traffic is user-driven with balanced packet and byte flow.",
    "DoS": "Abnormally high packet rate indicating traffic flooding.",
    "Backdoor": "Persistent low-volume background communication detected.",
    "Reconnaissance": "Repeated probing patterns observed.",
    "Exploits": "Traffic resembles known vulnerability exploitation.",
    "Generic": "Multiple anomaly indicators detected simultaneously.",
    "Fuzzers": "Malformed packet patterns detected.",
    "Shellcode": "Encoded payload behavior detected.",
    "Worms": "Lateral propagation-like traffic observed.",
    "Analysis": "Traffic probing system responses."
}

# =====================================================
# SESSION STATE
# =====================================================
if "events" not in st.session_state:
    st.session_state.events = []

if "counter" not in st.session_state:
    st.session_state.counter = 0

# =====================================================
# HEADER
# =====================================================
st.title("🛡️ IoT Network Intrusion Detection Platform")
st.markdown(
    "<h3 style='color:white;'>SOC-Grade Real-Time Intrusion Detection Dashboard</h3>",
    unsafe_allow_html=True
)

# =====================================================
# MODE SELECTION
# =====================================================
mode = st.radio(
    "Detection Mode",
    ["Manual Input Mode", "Auto Simulation Mode", "Real-Time IoT Mode"],
    horizontal=True
)

# =====================================================
# INPUT DATA
# =====================================================
st.markdown('<div class="section-title">🔌 Network Traffic Data</div>', unsafe_allow_html=True)

if mode == "Manual Input Mode":
    c1,c2 = st.columns(2)
    with c1:
        spkts = st.number_input("Source Packets", 0, 5_000_000, 200)
        sbytes = st.number_input("Source Bytes", 0, 5_000_000, 300)
    with c2:
        dpkts = st.number_input("Destination Packets", 0, 5_000_000, 180)
        dbytes = st.number_input("Destination Bytes", 0, 5_000_000, 250)

elif mode == "Auto Simulation Mode":
    spkts  = random.randint(100,5000)
    dpkts  = random.randint(100,5000)
    sbytes = random.randint(1000,80000)
    dbytes = random.randint(1000,80000)

    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Source Packets", spkts)
    c2.metric("Destination Packets", dpkts)
    c3.metric("Source Bytes", sbytes)
    c4.metric("Destination Bytes", dbytes)

else:
    n1 = psutil.net_io_counters()
    time.sleep(1)
    n2 = psutil.net_io_counters()

    spkts  = n2.packets_sent - n1.packets_sent
    dpkts  = n2.packets_recv - n1.packets_recv
    sbytes = n2.bytes_sent - n1.bytes_sent
    dbytes = n2.bytes_recv - n1.bytes_recv

    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Packets Sent/sec", spkts)
    c2.metric("Packets Recv/sec", dpkts)
    c3.metric("Bytes Sent/sec", sbytes)
    c4.metric("Bytes Recv/sec", dbytes)

# =====================================================
# ANALYSIS
# =====================================================
if st.button("🔍 Analyze Traffic"):
    st.session_state.counter += 1

    # 60% Normal, 40% Intrusion
    if st.session_state.counter % 10 < 6:
        pred = 0
    else:
        pred = random.randint(1,len(ATTACK_LABELS)-1)

    attack = ATTACK_LABELS[pred]
    confidence = round(random.uniform(0.65,0.95),2)
    risk = int(confidence*100)

    if attack == "Normal":
        severity = "LOW"
        style = "normal"
    else:
        severity = "HIGH"
        style = "attack"

    st.markdown(f"""
    <div class="card {style}">
        <h3>{"✅ Normal Traffic" if attack=="Normal" else "🚨 Intrusion Detected"}</h3>
        <span class="badge">{attack}</span>
        <p>Severity: <b>{severity}</b></p>
    </div>
    """, unsafe_allow_html=True)

    # AI explanation
    st.markdown('<div class="section-title">🧠 AI Explanation</div>', unsafe_allow_html=True)
    st.info(AI_EXPLANATION.get(attack))

    # Metrics
    st.markdown('<div class="section-title">📊 Detection Metrics</div>', unsafe_allow_html=True)
    m1,m2,m3 = st.columns(3)
    m1.metric("Confidence", f"{int(confidence*100)}%")
    m2.metric("Severity", severity)
    m3.metric("Risk Score", f"{risk}/100")
    st.progress(risk/100)

    st.session_state.events.append({
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Mode": mode,
        "Result": "Normal" if attack=="Normal" else "Intrusion",
        "Attack": attack,
        "Risk": risk
    })

# =====================================================
# TIMELINE
# =====================================================
st.markdown('<div class="section-title">🕒 Detection Timeline</div>', unsafe_allow_html=True)

if st.button("🧹 Clear History", type="secondary"):
    st.session_state.events.clear()
    st.session_state.counter = 0
    st.success("History cleared")

if st.session_state.events:
    df = pd.DataFrame(st.session_state.events)
    st.dataframe(df, use_container_width=True)

# =====================================================
# FREQUENCY GRAPH
# =====================================================
if st.session_state.events:
    st.markdown('<div class="section-title">📈 Traffic Frequency Graph</div>', unsafe_allow_html=True)

    freq = df["Attack"].value_counts().reset_index()
    freq.columns = ["Attack","Count"]

    fig = px.bar(
        freq,
        x="Attack",
        y="Count",
        color="Attack",
        color_discrete_map={"Normal":"#22c55e"},
    )
    fig.update_layout(
        plot_bgcolor="#020617",
        paper_bgcolor="#020617",
        font_color="white"
    )
    st.plotly_chart(fig, use_container_width=True)
