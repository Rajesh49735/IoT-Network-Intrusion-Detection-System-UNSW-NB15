import streamlit as st
import pickle
import numpy as np

# Load trained model
model = pickle.load(open('models/mlp_multi.pkl', 'rb'))


st.title("IoT Network Intrusion Detection System")
st.subheader("Real-Time Intrusion Detection Using Machine Learning")

st.write("Enter network traffic values:")

# Inputs (demo-level, enough for viva)
spkts = st.number_input("Source Packets", min_value=0)
dpkts = st.number_input("Destination Packets", min_value=0)
sbytes = st.number_input("Source Bytes", min_value=0)
dbytes = st.number_input("Destination Bytes", min_value=0)

if st.button("Detect Intrusion"):
    input_data = np.array([[spkts, dpkts, sbytes, dbytes]])
    prediction = model.predict(input_data)

    if prediction[0] == 1:
        st.error("🚨 Intrusion Detected")
    else:
        st.success("✅ Normal Traffic")
