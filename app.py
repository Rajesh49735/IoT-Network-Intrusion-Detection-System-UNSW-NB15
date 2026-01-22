import streamlit as st
import pickle
import numpy as np

# =====================================================
# Page Config
# =====================================================
st.set_page_config(
    page_title="IoT Network Intrusion Detection",
    page_icon="🛡️",
    layout="centered"
)

# =====================================================
# Custom Styling (Keep your existing CSS if you want)
# =====================================================
st.markdown("""
<style>
.stApp {
    background: radial-gradient(circle at top, #0b1f2a, #09161f, #050b10);
    color: #e6f1ff;
}
footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# =====================================================
# Load Multi-Class Model
# =====================================================
model = pickle.load(open("models/mlp_multi.pkl", "rb"))

# =====================================================
# ATTACK LABELS (FROM UNSW-NB15 DATASET)
# =====================================================
ATTACK_LABELS = [
    "Normal",
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms"
]

# =====================================================
# UI
# =====================================================
st.title("🛡️ IoT Network Intrusion Detection System")
st.subheader("Real-Time Intrusion Detection & Attack Classification")

st.write("Enter network traffic values:")

# Inputs
spkts = st.number_input("Source Packets", min_value=0, value=200)
dpkts = st.number_input("Destination Packets", min_value=0, value=180)
sbytes = st.number_input("Source Bytes", min_value=0, value=300)
dbytes = st.number_input("Destination Bytes", min_value=0, value=250)

# =====================================================
# Detection Logic
# =====================================================
if st.button("Detect Traffic"):

    # ---------------------------
    # RULE-BASED SPIKE DETECTION
    # ---------------------------
    if spkts > 1_000_000 or dpkts > 1_000_000 or sbytes > 1_000_000 or dbytes > 1_000_000:
        st.error("🚨 Intrusion Detected")
        st.warning("Attack Type: DoS (Traffic Flooding)")
        st.caption("Detected using rule-based anomaly detection.")

    else:
        # ---------------------------
        # Feature Count
        # ---------------------------
        n_features = model.n_features_in_ if hasattr(model, "n_features_in_") else model.coefs_[0].shape[0]

        # ---------------------------
        # Feature Vector
        # ---------------------------
        X = np.zeros((1, n_features))
        X[0, :4] = [spkts, dpkts, sbytes, dbytes]

        if n_features > 4:
            X[0, 4] = spkts + dpkts
        if n_features > 5:
            X[0, 5] = sbytes + dbytes
        if n_features > 6:
            X[0, 6] = sbytes / (spkts + 1)
        if n_features > 7:
            X[0, 7] = dbytes / (dpkts + 1)
        if n_features > 8:
            X[0, 8:] = np.random.normal(0, 0.01, n_features - 8)

        # ---------------------------
        # ML Prediction
        # ---------------------------
        pred = model.predict(X)[0]

        # ---------------------------
        # Output Mapping
        # ---------------------------
        if pred == 0:
            st.success("✅ Normal Traffic")
        else:
            attack_name = ATTACK_LABELS[pred] if pred < len(ATTACK_LABELS) else "Unknown Attack"
            st.error("🚨 Intrusion Detected")
            st.warning(f"Attack Type: {attack_name}")

        st.caption("Attack classification based on UNSW-NB15 dataset categories.")

# =====================================================
# Info Panel (Optional but professional)
# =====================================================
with st.expander("ℹ️ Possible Attack Types in Dataset"):
    for atk in ATTACK_LABELS:
        st.write(f"- {atk}")

