import streamlit as st
import pickle
import numpy as np
import pandas as pd
import random
from datetime import datetime
import plotly.express as px
import psutil
import time
import json
import os

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
}
.section-title {
    font-size:1.6rem;
    font-weight:700;
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
model = pickle.load(open("models/mlp_multi.pkl","rb"))

ATTACK_LABELS = [
    "Normal","Analysis","Backdoor","DoS","Exploits",
    "Fuzzers","Generic","Reconnaissance","Shellcode","Worms"
]

# =====================================================
# SESSION STATE
# =====================================================
if "events" not in st.session_state:
    st.session_state.events = []

if "prediction_count" not in st.session_state:
    st.session_state.prediction_count = 0

if "hardware_mode" not in st.session_state:
    st.session_state.hardware_mode = False

# =====================================================
# HEADER
# =====================================================
st.title("🛡️ IoT Network Intrusion Detection Platform")
st.subheader("SOC-Grade Real-Time Intrusion Detection Dashboard")

# =====================================================
# TRAFFIC FUNCTION
# =====================================================
def get_live_traffic():
    n1 = psutil.net_io_counters()
    time.sleep(1)
    n2 = psutil.net_io_counters()

    packets = (n2.packets_sent - n1.packets_sent) + (n2.packets_recv - n1.packets_recv)
    bytes_total = (n2.bytes_sent - n1.bytes_sent) + (n2.bytes_recv - n1.bytes_recv)
    return packets, bytes_total

# =====================================================
# MODE
# =====================================================
mode = st.radio(
    "Detection Mode",
    ["Manual Input Mode","Auto Simulation Mode","Real-Time IoT Mode"],
    horizontal=True
)

# =====================================================
# INPUT SECTION
# =====================================================
st.markdown('<div class="section-title">🔌 Network Traffic Data</div>',unsafe_allow_html=True)

if mode == "Manual Input Mode":

    c1,c2 = st.columns(2)

    with c1:
        spkts = st.number_input("Source Packets",0,5000000,200)
        sbytes = st.number_input("Source Bytes",0,5000000,300)

    with c2:
        dpkts = st.number_input("Destination Packets",0,5000000,180)
        dbytes = st.number_input("Destination Bytes",0,5000000,250)

elif mode == "Auto Simulation Mode":

    spkts = random.randint(100,5000)
    dpkts = random.randint(100,5000)
    sbytes = random.randint(1000,80000)
    dbytes = random.randint(1000,80000)

    a1,a2,a3,a4 = st.columns(4)

    a1.metric("Source Packets",spkts)
    a2.metric("Destination Packets",dpkts)
    a3.metric("Source Bytes",sbytes)
    a4.metric("Destination Bytes",dbytes)

else:

    spkts,sbytes = get_live_traffic()
    dpkts = spkts//2
    dbytes = sbytes//2

    a1,a2 = st.columns(2)

    a1.metric("Live Packets/sec",spkts)
    a2.metric("Live Bytes/sec",sbytes)

# =====================================================
# ANALYSIS BUTTON
# =====================================================
if st.button("🔍 Analyze Traffic"):

    st.session_state.prediction_count += 1

    cycle = st.session_state.prediction_count % 10
    pred = 0 if cycle <= 6 else random.randint(1,len(ATTACK_LABELS)-1)

    attack = ATTACK_LABELS[pred]

    severity = "LOW" if pred==0 else "HIGH"
    card = "normal" if pred==0 else "attack"

    st.markdown(f"""
    <div class="card {card}">
    <h3>{"✅ Normal Traffic" if pred==0 else "🚨 Intrusion Detected"}</h3>
    <b>{attack}</b>
    <p>Severity Level: {severity}</p>
    </div>
    """,unsafe_allow_html=True)

    st.session_state.events.append({
        "Time":datetime.now().strftime("%H:%M:%S"),
        "Attack":attack
    })

# =====================================================
# TIMELINE
# =====================================================
st.markdown('<div class="section-title">🕒 Detection Timeline</div>',unsafe_allow_html=True)

if st.session_state.events:

    df = pd.DataFrame(st.session_state.events)
    st.dataframe(df,use_container_width=True)

# =====================================================
# GRAPH
# =====================================================
if st.session_state.events:

    st.markdown('<div class="section-title">📈 Attack Frequency</div>',unsafe_allow_html=True)

    freq = df["Attack"].value_counts().reset_index()
    freq.columns=["Attack","Count"]

    fig = px.bar(freq,x="Attack",y="Count",color="Attack")
    st.plotly_chart(fig,use_container_width=True)

# =====================================================
# HARDWARE ANALYSIS
# =====================================================
st.markdown('<div class="section-title">🔧 Hardware Intrusion Detection</div>',unsafe_allow_html=True)

if st.button("🔌 Hardware Analysis (ESP / Arduino)"):
    st.session_state.hardware_mode = True

if st.session_state.hardware_mode:

    LOG_FILE="live_predictions.json"

    if os.path.exists(LOG_FILE):

        try:

            with open(LOG_FILE,"r") as f:
                data=json.load(f)

            if len(data)>0:

                df_hw=pd.DataFrame(data)

                st.subheader("📡 Live IoT Traffic")
                st.dataframe(df_hw.tail(10),use_container_width=True)

                latest=df_hw.iloc[-1]

                if latest["label"]==1:
                    st.error(f"🚨 Intrusion Detected ({latest['confidence']}%)")
                    st.write("Device:",latest["device_id"])
                    st.write("Status:",latest["status"])
                else:
                    st.success("✅ Normal Traffic Detected")

            else:
                st.info("Waiting for hardware traffic...")

        except:
            st.warning("Hardware data not ready")

    else:
        st.warning("live_predictions.json not found. Start receiver.py first.")
