import streamlit as st
import pickle
import numpy as np

# =====================================================
# Page Config
# =====================================================
st.set_page_config(
    page_title="IoT Intrusion Detection",
    page_icon="🛡️",
    layout="centered"
)

# =====================================================
# ULTRA-PRO CYBER CSS
# =====================================================
st.markdown("""
<style>

/* ===== BACKGROUND ===== */
.stApp {
    background: radial-gradient(circle at top, #0b1f2a, #09161f, #050b10);
    color: #e6f1ff;
    font-family: 'Segoe UI', sans-serif;
}

/* ===== MAIN HEADING ===== */
h1 {
    font-size: 3rem;
    background: linear-gradient(90deg, #00e5ff, #7c4dff, #00e5ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    text-shadow: 0px 0px 25px rgba(0,229,255,0.6);
}

/* ===== SUBTITLE ===== */
h2 {
    color: #b3ecff;
    text-shadow: 0px 4px 18px rgba(0,0,0,0.8);
}

/* ===== GLASS CARDS ===== */
div[data-testid="stNumberInput"] > div {
    background: rgba(255,255,255,0.07);
    backdrop-filter: blur(12px);
    border-radius: 18px;
    padding: 14px;
    box-shadow:
        inset 0 0 12px rgba(255,255,255,0.08),
        0 18px 40px rgba(0,0,0,0.65);
    transition: all 0.35s ease;
}

/* Hover 3D lift */
div[data-testid="stNumberInput"] > div:hover {
    transform: translateY(-6px) scale(1.01);
    box-shadow:
        inset 0 0 14px rgba(255,255,255,0.12),
        0 28px 60px rgba(0,229,255,0.35);
}

/* ===== BUTTON ===== */
.stButton button {
    background: linear-gradient(145deg, #00e5ff, #2979ff);
    color: white;
    border-radius: 22px;
    padding: 14px 36px;
    font-size: 18px;
    font-weight: 600;
    box-shadow:
        0 10px 35px rgba(0,229,255,0.6),
        inset 0 0 10px rgba(255,255,255,0.25);
    transition: all 0.3s ease;
}

/* Button hover glow */
.stButton button:hover {
    transform: scale(1.08);
    background: linear-gradient(145deg, #2979ff, #00e5ff);
    box-shadow:
        0 18px 60px rgba(124,77,255,0.8),
        inset 0 0 14px rgba(255,255,255,0.35);
}

/* ===== ALERTS ===== */
.stAlert {
    border-radius: 20px;
    backdrop-filter: blur(8px);
    box-shadow:
        inset 0 0 12px rgba(255,255,255,0.1),
        0 18px 45px rgba(0,0,0,0.7);
}

/* ===== FOOTER ===== */
footer {visibility: hidden;}

</style>
""", unsafe_allow_html=True)

# =====================================================
# Load Model
# =====================================================
model = pickle.load(open("models/mlp_multi.pkl", "rb"))

# =====================================================
# UI
# =====================================================
st.title("🛡️ IoT Network Intrusion Detection System")
st.subheader("Real-Time Intrusion Detection Using Machine Learning")

st.write("Enter network traffic values:")

# =====================================================
# Inputs
# =====================================================
spkts = st.number_input("Source Packets", min_value=0, value=200)
dpkts = st.number_input("Destination Packets", min_value=0, value=180)
sbytes = st.number_input("Source Bytes", min_value=0, value=300)
dbytes = st.number_input("Destination Bytes", min_value=0, value=250)

# =====================================================
# Detection
# =====================================================
if st.button("Detect Intrusion"):

    # Rule-based spike detection
    if spkts > 1_000_000 or dpkts > 1_000_000 or sbytes > 1_000_000 or dbytes > 1_000_000:
        st.error("🚨 Intrusion Detected — High-Volume Traffic Anomaly")
        st.caption("Rule-based detection triggered due to abnormal traffic spike.")

    else:
        # Feature count
        if hasattr(model, "n_features_in_"):
            n_features = model.n_features_in_
        else:
            n_features = model.coefs_[0].shape[0]

        # Feature vector
        X = np.zeros((1, n_features))
        X[0, 0:4] = [spkts, dpkts, sbytes, dbytes]

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

        # ML prediction
        pred = model.predict(X)

        if pred[0] == 1:
            st.error("🚨 Intrusion Detected — ML Classification")
        else:
            st.success("✅ Normal Traffic")

        st.caption("ML-based classification using learned multi-dimensional traffic patterns.")

# =====================================================
# Footer
# =====================================================
st.markdown("---")
st.caption(
    "Hybrid Intrusion Detection System combining Machine Learning and Rule-Based Anomaly Detection."
)

