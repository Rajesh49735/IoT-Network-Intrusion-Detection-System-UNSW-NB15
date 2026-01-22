import streamlit as st
import pickle
import numpy as np

# Load trained model
model = pickle.load(open("models/mlp_multi.pkl", "rb"))

st.title("IoT Network Intrusion Detection System")
st.subheader("Real-Time Intrusion Detection Using Machine Learning")

st.write("Enter network traffic values:")

# User inputs
spkts = st.number_input("Source Packets", min_value=0)
dpkts = st.number_input("Destination Packets", min_value=0)
sbytes = st.number_input("Source Bytes", min_value=0)
dbytes = st.number_input("Destination Bytes", min_value=0)

if st.button("Detect Intrusion"):
    # ✅ Correct feature size
    n_features = model.n_features_in_

    # Create input vector
    input_data = np.zeros((1, n_features), dtype=float)

    # Map demo inputs
    input_data[0, 0] = spkts
    input_data[0, 1] = dpkts
    input_data[0, 2] = sbytes
    input_data[0, 3] = dbytes

    # Predict
    prediction = model.predict(input_data)

    if prediction[0] == 1:
        st.error("🚨 Intrusion Detected")
    else:
        st.success("✅ Normal Traffic")

