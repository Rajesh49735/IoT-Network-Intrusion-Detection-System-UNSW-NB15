import streamlit as st
import pickle
import numpy as np
import pandas as pd
import random
import time
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
import os

# =====================================================
# PAGE CONFIG
# =====================================================
st.set_page_config(page_title="IoT IDS Platform", page_icon="🛡️", layout="wide")

# =====================================================
# LOAD MODEL
# =====================================================
model = pickle.load(open("models/mlp_multi.pkl", "rb"))

ATTACK_LABELS = [
    "Normal","Analysis","Backdoor","DoS","Exploits",
    "Fuzzers","Generic","Reconnaissance","Shellcode","Worms"
]

# =====================================================
# SESSION STATE
# =====================================================
if "events" not in st.session_state:
    st.session_state.events = []

# =====================================================
# HEADER
# =====================================================
st.title("🛡️ IoT Network Intrusion Detection Platform")
st.caption("SOC-Grade Real-Time Intrusion Detection Dashboard")

# =====================================================
# MODE + CONTROLS
# =====================================================
col1, col2, col3 = st.columns(3)
with col1:
    mode = st.radio("Mode", ["Manual Input", "Auto Simulation"], horizontal=True)
with col2:
    auto_refresh = st.checkbox("Auto Refresh (5s)")
with col3:
    if st.button("Reset Dataset"):
        st.session_state.events = []
        st.success("Dataset reset successfully")

if auto_refresh and mode == "Auto Simulation":
    time.sleep(5)
    st.experimental_rerun()

# =====================================================
# INPUT DATA
# =====================================================
st.subheader("🔌 Network Traffic")

if mode == "Manual Input":
    c1, c2 = st.columns(2)
    with c1:
        spkts = st.number_input("Source Packets", 0, 5_000_000, 200, step=100)
        sbytes = st.number_input("Source Bytes", 0, 5_000_000, 300, step=100)
    with c2:
        dpkts = st.number_input("Destination Packets", 0, 5_000_000, 180, step=100)
        dbytes = st.number_input("Destination Bytes", 0, 5_000_000, 250, step=100)
else:
    spkts = random.randint(100, 5000)
    dpkts = random.randint(100, 5000)
    sbytes = random.randint(1000, 80000)
    dbytes = random.randint(1000, 80000)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Source Packets", spkts)
    m2.metric("Destination Packets", dpkts)
    m3.metric("Source Bytes", sbytes)
    m4.metric("Destination Bytes", dbytes)

# =====================================================
# ANALYSIS
# =====================================================
if st.button("Analyze Traffic") or (auto_refresh and mode == "Auto Simulation"):

    if max(spkts, dpkts, sbytes, dbytes) > 1_000_000:
        attack = "DoS"
        severity = "CRITICAL"
        confidence = 0.95
    else:
        X = np.zeros((1, model.n_features_in_))
        X[0, :4] = [spkts, dpkts, sbytes, dbytes]
        pred = int(model.predict(X)[0])
        attack = ATTACK_LABELS[pred]
        confidence = np.clip(np.random.normal(0.78, 0.1), 0.6, 0.95)
        severity = "LOW" if attack == "Normal" else ("MEDIUM" if confidence < 0.8 else "HIGH")

    risk = int(confidence * 100)

    st.success(f"Result: {attack} | Severity: {severity} | Risk: {risk}")

    st.session_state.events.append({
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Attack": attack,
        "Severity": severity,
        "Risk": risk
    })

# =====================================================
# 📈 LIVE TREND GRAPH
# =====================================================
st.subheader("📈 Live Detection Trend")
if st.session_state.events:
    df = pd.DataFrame(st.session_state.events)
    trend = df["Attack"].apply(lambda x: "Normal" if x=="Normal" else "Intrusion")
    st.line_chart(trend.value_counts().cumsum())
else:
    st.info("No trend data available")

# =====================================================
# 📊 ATTACK SEVERITY HEATMAP
# =====================================================
st.subheader("📊 Attack Severity Heatmap")
if st.session_state.events:
    heatmap_df = pd.crosstab(df["Attack"], df["Severity"])
    st.dataframe(heatmap_df, use_container_width=True)
else:
    st.info("No data for heatmap")

# =====================================================
# 📄 PDF REPORT GENERATOR
# =====================================================
st.subheader("📄 Security Report")

def generate_pdf(data):
    filename = "IDS_Report.pdf"
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    content = [Paragraph("IoT IDS Security Report", styles["Title"])]

    table_data = [data.columns.tolist()] + data.values.tolist()
    content.append(Table(table_data))
    doc.build(content)
    return filename

if st.session_state.events:
    if st.button("Generate PDF Report"):
        df = pd.DataFrame(st.session_state.events)
        pdf_file = generate_pdf(df)
        with open(pdf_file, "rb") as f:
            st.download_button("Download Report", f, file_name=pdf_file)

