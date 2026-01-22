import streamlit as st
import numpy as np
import pickle
import random
import time

# ------------------ PAGE CONFIG ------------------
st.set_page_config(
    page_title="IoT Network Intrusion Detection Platform",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ------------------ LOAD MODEL ------------------
@st.cache_resource
def load_model():
    return pickle.load(open("models/mlp_multi.pkl", "rb"))

model = load_model()

# Attack labels (UNSW-NB15)
ATTACK_LABELS = [
    "Normal",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Reconnaissance",
    "Backdoor",
    "Shellcode",
    "Worms",
    "Analysis",
    "Generic"
]

# ------------------ HEADER ------------------
st.markdown("""
<style>
body { background-color: #0b0f1a; }
.big-title {
    font-size: 48px;
    font-weight: 800;
    background: linear-gradient(90deg, #00f5ff, #00ff87);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
.sub-title {
    color: #9aa4bf;
    font-size: 18px;
}
.glass {
    background: rgba(255,255,255,0.05);
    border-radius: 16px;
    padding: 20px;
    box-shadow: 0 0 25px rgba(0,255,255,0.15);
}
.alert-normal {
    background: linear-gradient(90deg, #00ff87, #00c853);
    padding: 20px;
    border-radius: 14px;
    font-size: 22px;
    font-weight: bold;
}
.alert-attack {
    background: linear-gradient(90deg, #ff1744, #ff9100);
    padding: 20px;
    border-radius: 14px;
    font-size: 22px;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="big-title">🛡️ IoT Network Intrusion Detection Platform</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">SOC-Grade Real-Time Intrusion Detection Dashboard</div>', unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

# ------------------ MODE SELECTION ------------------
col1, col2, col3 = st.columns([3,2,2])

with col1:
    mode = st.radio("Mode", ["Manual Input", "Auto Simulation"], horizontal=True)

with col2:
    auto_refresh = st.checkbox("Auto Refresh (5s)", value=False)

with col3:
    if st.button("🔄 Reset Dataset"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.success("Dataset reset successfully")
        st.stop()

st.markdown("<hr>", unsafe_allow_html=True)

# ------------------ INPUT SECTION ------------------
st.markdown('<div class="glass">', unsafe_allow_html=True)

if mode == "Auto Simulation":
    spkts  = random.randint(50, 5000)
    dpkts  = random.randint(50, 5000)
    sbytes = random.randint(500, 90000)
    dbytes = random.randint(500, 90000)

    st.markdown("### 🔄 Live Simulated Traffic")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Source Packets", spkts)
    c2.metric("Destination Packets", dpkts)
    c3.metric("Source Bytes", sbytes)
    c4.metric("Destination Bytes", dbytes)

else:
    st.markdown("### ✍️ Manual Traffic Input")
    spkts  = st.number_input("Source Packets", min_value=0, step=10)
    dpkts  = st.number_input("Destination Packets", min_value=0, step=10)
    sbytes = st.number_input("Source Bytes", min_value=0, step=100)
    dbytes = st.number_input("Destination Bytes", min_value=0, step=100)

st.markdown("</div>", unsafe_allow_html=True)
st.markdown("<br>", unsafe_allow_html=True)

# ------------------ DETECTION ------------------
if st.button("🚨 Detect Intrusion"):
    # Expand basic inputs to match trained feature space
    feature_count = model.coefs_[0].shape[0]
    base = np.array([spkts, dpkts, sbytes, dbytes])
    expanded = np.pad(base, (0, feature_count - 4), mode="wrap")
    expanded = expanded.reshape(1, -1)

    prediction = model.predict(expanded)[0]

    st.markdown("<br>", unsafe_allow_html=True)

    if prediction == 0:
        st.markdown('<div class="alert-normal">✅ NORMAL TRAFFIC DETECTED</div>', unsafe_allow_html=True)
    else:
        attack_name = ATTACK_LABELS[prediction] if prediction < len(ATTACK_LABELS) else "Unknown Attack"
        st.markdown(f'<div class="alert-attack">🚨 INTRUSION DETECTED: {attack_name.upper()}</div>', unsafe_allow_html=True)

# ------------------ AUTO REFRESH ------------------
if auto_refresh and mode == "Auto Simulation":
    time.sleep(5)
    st.stop()

