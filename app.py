import streamlit as st
import pickle
import numpy as np

# ------------------------------------------------
# Load trained ML model
# ------------------------------------------------
model = pickle.load(open("models/mlp_multi.pkl", "rb"))

# ------------------------------------------------
# UI
# ------------------------------------------------
st.title("IoT Network Intrusion Detection System")
st.subheader("Real-Time Intrusion Detection Using Machine Learning")

st.write("Enter network traffic values:")

# ------------------------------------------------
# User Inputs
# ------------------------------------------------
spkts = st.number_input("Source Packets", min_value=0, value=10)
dpkts = st.number_input("Destination Packets", min_value=0, value=10)
sbytes = st.number_input("Source Bytes", min_value=0, value=100)
dbytes = st.number_input("Destination Bytes", min_value=0, value=100)

# ------------------------------------------------
# Detect Button
# ------------------------------------------------
if st.button("Detect Intrusion"):

    # ------------------------------------------------
    # RULE-BASED ANOMALY DETECTION (Industry Standard)
    # ------------------------------------------------
    if (
        spkts > 1_000_000
        or dpkts > 1_000_000
        or sbytes > 1_000_000
        or dbytes > 1_000_000
    ):
        st.error("🚨 Intrusion Detected (Traffic Spike Anomaly)")
        st.caption(
            "Rule-based detection triggered due to abnormal traffic volume."
        )

    else:
        # ------------------------------------------------
        # Determine feature size safely
        # ------------------------------------------------
        if hasattr(model, "n_features_in_"):
            n_features = model.n_features_in_
        else:
            n_features = model.coefs_[0].shape[0]

        # ------------------------------------------------
        # Create full feature vector
        # ------------------------------------------------
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

        # Fill remaining features with small noise
        if n_features > 10:
            input_data[0, 10:] = np.random.normal(
                loc=0.0, scale=0.01, size=(n_features - 10)
            )

        # ------------------------------------------------
        # ML Prediction
        # ------------------------------------------------
        prediction = model.predict(input_data)

        if prediction[0] == 1:
            st.error("🚨 Intrusion Detected (ML Model)")
        else:
            st.success("✅ Normal Traffic")

        st.caption(
            "Machine-learning classification based on learned traffic patterns."
        )

# ------------------------------------------------
# Footer
# ------------------------------------------------
st.markdown("---")
st.caption(
    "This system uses a hybrid intrusion detection approach combining "
    "rule-based anomaly detection and machine-learning classification."
)

