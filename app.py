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
# ULTRA CSS (OUTPUT + +/- ENHANCEMENTS)
# =====================================================
st.markdown("""
<style>

/* ===== BACKGROUND ===== */
.stApp {
    background: radial-gradient(circle at top, #0b1f2a, #09161f, #050b10);
    color: #e6f1ff;
    font-family: 'Segoe UI', sans-serif;
}

/* ===== TITLES ===== */
h1 {
    font-size: 3rem;
    background: linear-gradient(90deg, #00e5ff, #7c4dff, #00e5ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    text-shadow: 0 0 28px rgba(0,229,255,.65);
}
h2 {
    color: #b3ecff;
    text-shadow: 0 6px 22px rgba(0,0,0,.9);
}

/* ===== INPUT GLASS CARDS ===== */
div[data-testid="stNumberInput"] > div {
    background: rgba(255,255,255,.08);
    backdrop-filter: blur(14px);
    border-radius: 18px;
    padding: 14px;
    box-shadow:
        inset 0 0 14px rgba(255,255,255,.1),
        0 18px 44px rgba(0,0,0,.7);
    transition: all .35s ease;
}
div[data-testid="stNumberInput"] > div:hover {
    transform: translateY(-6px) scale(1.01);
    box-shadow:
        inset 0 0 16px rgba(255,255,255,.14),
        0 28px 64px rgba(0,229,255,.35);
}

/* ===== ENHANCED +/- BUTTONS ===== */
button[kind="secondary"] {
    background: linear-gradient(145deg, #1e3c72, #2a5298) !important;
    color: #e6f1ff !important;
    border-radius: 10px !important;
    box-shadow:
        inset 0 0 10px rgba(255,255,255,.18),
        0 6px 18px rgba(0,0,0,.6) !important;
    transition: all .25s ease !important;
}
button[kind="secondary"]:hover {
    transform: scale(1.12);
    box-shadow:
        0 10px 28px rgba(0,229,255,.6),
        inset 0 0 12px rgba(255,255,255,.25);
}
button[kind="secondary"]:active {
    transform: scale(.95);
}

/* ===== MAIN BUTTON ===== */
.stButton button {
    background: linear-gradient(145deg, #00e5ff, #2979ff);
    color: white;
    border-radius: 22px;
    padding: 14px 36px;
    font-size: 18px;
    font-weight: 600;
    box-shadow:
        0 12px 38px rgba(0,229,255,.65),
        inset 0 0 14px rgba(255,255,255,.28);
    transition: all .3s ease;
}
.stButton button:hover {
    transform: scale(1.08);
    background: linear-gradient(145deg, #2979ff, #00e5ff);
    box-shadow:
        0 20px 66px rgba(124,77,255,.85),
        inset 0 0 18px rgba(255,255,255,.38);
}

/* ===== OUTPUT PANELS ===== */
.output-normal {
    background: linear-gradient(135deg, rgba(0,255,170,.2), rgba(0,140,255,.2));
    border-radius: 22px;
    padding: 22px;
    box-shadow:
        inset 0 0 18px rgba(0,255,170,.45),
        0 22px 60px rgba(0,255,170,.45);
    animation: shimmer 2.2s infinite alternate;
}
.output-attack {
    background: linear-gradient(135deg, rgba(255,60,60,.22), rgba(255,140,0,.22));
    border-radius: 22px;
    padding: 22px;
    box-shadow:
        inset 0 0 22px rgba(255,80,80,.65),
        0 26px 74px rgba(255,60,60,.7);
    animation: pulse 1.4s infinite;
}

/* Animations */
@keyframes shimmer {
    from { box-shadow: 0 18px 48px rgba(0,255,170,.35); }
    to   { box-shadow: 0 28px 70px rgba(0,255,170,.75); }
}
@keyframes pulse {
    0% { box-shadow: 0 0 0 rgba(255,60,60,.6); }
    70% { box-shadow: 0 0 40px rgba(255,60,60,.85); }
    100% { box-shadow: 0 0 0 rgba(255,60,60,.6); }
}

/* Hide footer */
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

# Inputs
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
        st.markdown(
            "<div class='output-attack'>"
            "<h3>🚨 Intrusion Detected</h3>"
            "<p>High-volume traffic anomaly identified using rule-based detection.</p>"
            "</div>",
            unsafe_allow_html=True
        )

    else:
        # Feature size
        n_features = model.n_features_in_ if hasattr(model, "n_features_in_") else model.coefs_[0].shape[0]

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

        pred = model.predict(X)

        if pred[0] == 1:
            st.markdown(
                "<div class='output-attack'>"
                "<h3>🚨 Intrusion Detected</h3>"
                "<p>Machine-learning classifier identified malicious traffic behavior.</p>"
                "</div>",
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                "<div class='output-normal'>"
                "<h3>✅ Normal Traffic</h3>"
                "<p>No anomalous or malicious patterns detected.</p>"
                "</div>",
                unsafe_allow_html=True
            )

st.markdown("---")
st.caption("Hybrid IDS with enhanced UI, animated outputs, and cyber-grade visual depth.")

