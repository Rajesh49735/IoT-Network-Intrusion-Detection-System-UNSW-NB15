import streamlit as st
import pickle
import numpy as np

# =====================================================
# Page Configuration
# =====================================================
st.set_page_config(
    page_title="IoT Network Intrusion Detection",
    page_icon="🛡️",
    layout="centered"
)

# =====================================================
# Custom CSS (Colors + 3D Effects)
# =====================================================
st.markdown("""
<style>
/* Background */
.stApp {
    background: radial-gradient(circle at top, #0f2027, #203a43, #2c5364);
    color: white;
}

/* Titles */
h1, h2, h3 {
    text-shadow: 0px 6px 18px rgba(0,0,0,0.6);
}

/* Input Cards */
div[data-testid="stNumberInput"] > div {
    background: rgba(255,255,255,0.06);
    border-radius: 16px;
    padding: 12px;
    box-shadow: 0px 10px 28px rgba(0,0,0,0.35);
    transition: transform 0.3s ease;
}

div[data-testid="stNumberInput"] > div:hover {
    transform: translateY(-4px);
}

/* Button */
.stButton button {
    background: linear-gradient(145deg, #00c6ff, #0072ff);
    color: white;
    border-radius: 16px;
    padding: 12px 30px;
    font-size: 16px;
    box-shadow: 0px 10px 25px rgba(0,0,0,0.45);
    transition: all 0.3s ease;
}

.stButton button:hover {
    transform: scale(1.05);
    background: linear-gradient(145deg, #0072ff, #00c6ff);
}

/* Alerts */
.stAlert {
    border-radius: 18px;
    box-shadow: 0px 14px 32px rgba(0,0,0,0.5);
}

/* Footer hide */
footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# =====================================================
# Load Model
# =====================================================
model = pickle.load(open("models/mlp_multi.pkl", "rb"))

# =====================================================
# UI Content
# =====================================================
st.title("🛡️ IoT Network Intrusion Detection System")
st.subheader("Real-Time Intrusion Detection Using Machine Learning")

st.write("Enter network traffic values:")

# =====================================================
# User Inputs
# =====================================================
spkts = st.number_input("Source Packets", min_value=0, value=200)
dpkts = st.number_input("Destination Packets", min_value=0, value=180)
sbytes = st.number_input("Source Bytes", min_value=0, value=300)
dbytes = st.number_input("Destination Bytes", min_value=0, value=250)

# =====================================================
# Detection Logic
# =====================================================
if st.button("Detect Intrusion"):

    # -------------------------------
    # Rule-Based Detection
    # -------------------------------
    if (
        spkts > 1_000_000
        or dpkts > 1_000_000
        or sbytes > 1_000_000
        or dbytes > 1_000_000
    ):
        st.error("🚨 Intrusion Detected (Traffic Spike Anomaly)")
        st.caption("Rule-based anomaly detection triggered due to abnormal traffic volume.")

    else:
        # -------------------------------
        # Feature Size Handling
        # -------------------------------
        if hasattr(model, "n_features_in_"):
            n_features = model.n_features_in_
        else:
            n_features = model.coefs_[0].shape[0]

        # -------------------------------
        # Feature Vector Creation
        # -------------------------------
        input_data = np.zeros((1, n_features), dtype=float)

        # Base features
        input_data[0, 0] = spkts
        input_data[0, 1] = dpkts
        input_data[0, 2] = sbytes
        input_data[0, 3] = dbytes

        # Derived features
        if n_features > 4:
            input_data[0, 4] = spkts + dpkts
        if n_features > 5:
            input_data[0, 5] = sbytes + dbytes
        if n_features > 6:
            input_data[0, 6] = sbytes / (spkts + 1)
        if n_features > 7:
            input_data[0, 7] = dbytes / (dpkts + 1)
        if n_features > 8:
            input_data[0, 8] = abs(spkts - dpkts)
        if n_features > 9:
            input_data[0, 9] = abs(sbytes - dbytes)

        # Remaining features
        if n_features > 10:
            input_data[0, 10:] = np.random.normal(
                loc=0.0, scale=0.01, size=(n_features - 10)
            )

        # -------------------------------
        # ML Prediction
        # -------------------------------
        prediction = model.predict(input_data)

        if prediction[0] == 1:
            st.error("🚨 Intrusion Detected (ML Classification)")
        else:
            st.success("✅ Normal Traffic")

        st.caption("Machine-learning classification based on learned traffic patterns.")

# =====================================================
# Footer Note
# =====================================================
st.markdown("---")
st.caption(
    "This system uses a hybrid intrusion detection approach combining "
    "rule-based anomaly detection and machine-learning classification."
)

