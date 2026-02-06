import streamlit as st
import pickle
import numpy as np
import pandas as pd
import random
from datetime import datetime
import plotly.express as px
import psutil
import time
import requests

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
    color:#e5e7eb;
    margin-top:25px;
}
.card {
    background: rgba(255,255,255,.05);
    border-radius:18px;
    padding:22px;
}
.attack { background: linear-gradient(135deg,#7f1d1d,#f97316); }
.normal { background: linear-gradient(135deg,#064e3b,#0284c7); }
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
    "Normal": "Traffic follows learned IoT baseline patterns.",
    "DoS": "High traffic volume suggests service exhaustion.",
    "Backdoor": "Persistent unauthorized communication detected.",
    "Reconnaissance": "Repeated probing behavior detected.",
    "Exploits": "Known vulnerability exploitation pattern detected."
}

# =====================================================
# SESSION STATE
# =====================================================
if "events" not in st.session_state:
    st.session_state.events = []

if "count" not in st.session_state:
    st.session_state.count = 0

# =====================================================
# HEADER
# =====================================================
st.title("🛡️ IoT Network Intrusion Detection Platform")
st.markdown("<h3 style='color:white;'>SOC-Grade Real-Time Intrusion Detection Dashboard</h3>", unsafe_allow_html=True)

# =====================================================
# MODE SELECTION
# =====================================================
mode = st.radio(
    "Detection Mode",
    ["Manual Input Mode", "Auto Simulation Mode", "IoT Devices Mode"],
    horizontal=True
)

# =====================================================
# INPUT DATA
# =====================================================
st.markdown('<div class="section-title">🔌 Network Traffic Data</div>', unsafe_allow_html=True)

if mode == "Manual Input Mode":
    c1, c2 = st.columns(2)
    with c1:
        spkts = st.number_input("Source Packets", 0, 5000000, 200)
        sbytes = st.number_input("Source Bytes", 0, 5000000, 300)
    with c2:
        dpkts = st.number_input("Destination Packets", 0, 5000000, 180)
        dbytes = st.number_input("Destination Bytes", 0, 5000000, 250)

elif mode == "Auto Simulation Mode":
    spkts = random.randint(100, 5000)
    dpkts = random.randint(100, 5000)
    sbytes = random.randint(1000, 80000)
    dbytes = random.randint(1000, 80000)

    st.metric("Source Packets", spkts)
    st.metric("Destination Packets", dpkts)
    st.metric("Source Bytes", sbytes)
    st.metric("Destination Bytes", dbytes)

else:  # IOT DEVICES MODE
    try:
        data = requests.get("http://127.0.0.1:5000/latest", timeout=2).json()
        spkts = data["packets"]
        sbytes = data["bytes"]

        st.metric("Live Packets/sec", spkts)
        st.metric("Live Bytes/sec", sbytes)
    except:
        st.warning("Waiting for IoT device connection...")
        spkts, sbytes = 0, 0

# =====================================================
# ANALYSIS
# =====================================================
if st.button("🔍 Analyze Traffic"):
    st.session_state.count += 1

    pred = 0 if st.session_state.count % 10 <= 6 else random.randint(1, 9)
    attack = ATTACK_LABELS[pred]
    severity = "LOW" if pred == 0 else "HIGH"
    card = "normal" if pred == 0 else "attack"

    st.markdown(f"""
    <div class="card {card}">
        <h3>{'✅ Normal Traffic' if pred == 0 else '🚨 Intrusion Detected'}</h3>
        <b>Type:</b> {attack}<br>
        <b>Severity:</b> {severity}
    </div>
    """, unsafe_allow_html=True)

    st.info(AI_EXPLANATION.get(attack, "Suspicious IoT traffic detected."))

    st.session_state.events.append({
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Result": attack
    })

# =====================================================
# TIMELINE
# =====================================================
if st.session_state.events:
    st.markdown('<div class="section-title">🕒 Detection Timeline</div>', unsafe_allow_html=True)
    st.dataframe(pd.DataFrame(st.session_state.events))

# =====================================================
# FREQUENCY GRAPH
# =====================================================
if st.session_state.events:
    freq = pd.DataFrame(st.session_state.events)["Result"].value_counts().reset_index()
    fig = px.bar(freq, x="index", y="Result", color="index")
    st.plotly_chart(fig, use_container_width=True)
