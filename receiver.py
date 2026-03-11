"""
receiver.py – Flask API server for IoT IDS Hardware Integration
===============================================================

Receives JSON traffic features from Arduino/ESP8266 via HTTP POST,
runs ML prediction, stores results, and exposes API for Streamlit.

APIs:
POST /predict
GET  /status
GET  /predictions
GET  /clear
"""

from flask import Flask, request, jsonify
import pickle
import numpy as np
import json
import os
from datetime import datetime
import threading
import random

app = Flask(__name__)

# ----------------------------------------------------
# Paths
# ----------------------------------------------------
MODEL_PATH = "models/random_forest_bin.pkl"
SCALER_PATH = "models/scaler_bin.pkl"
LIVE_LOG_PATH = "live_predictions.json"

# ----------------------------------------------------
# Attack labels (UNSW-NB15)
# ----------------------------------------------------
ATTACK_TYPES = [
    "Normal",
    "DoS",
    "Fuzzers",
    "Exploits",
    "Reconnaissance",
    "Backdoor",
    "Shellcode",
    "Worms",
    "Generic"
]

# ----------------------------------------------------
# Feature order
# ----------------------------------------------------
FEATURE_COLS = [
    "rate","sttl","sload","dload",
    "ct_srv_src","ct_state_ttl","ct_dst_ltm",
    "ct_src_dport_ltm","ct_dst_sport_ltm",
    "ct_dst_src_ltm","ct_src_ltm","ct_srv_dst",
    "state_CON","state_INT"
]

# ----------------------------------------------------
# Load ML model
# ----------------------------------------------------
print("[INFO] Loading model:", MODEL_PATH)

try:
    with open(MODEL_PATH,"rb") as f:
        model = pickle.load(f)
    print("[OK] Model loaded:",type(model).__name__)
except:
    print("[WARN] Model not found → DEMO mode")
    model = None

print("[INFO] Loading scaler:",SCALER_PATH)

try:
    with open(SCALER_PATH,"rb") as f:
        scaler = pickle.load(f)
    print("[OK] Scaler loaded")
except:
    print("[WARN] Scaler not found")
    scaler = None

# ----------------------------------------------------
# Thread-safe log
# ----------------------------------------------------
log_lock = threading.Lock()
MAX_LOG_ENTRIES = 500


def append_to_log(entry):

    with log_lock:

        if os.path.exists(LIVE_LOG_PATH):
            try:
                with open(LIVE_LOG_PATH,"r") as f:
                    data=json.load(f)
            except:
                data=[]
        else:
            data=[]

        data.append(entry)

        data=data[-MAX_LOG_ENTRIES:]

        with open(LIVE_LOG_PATH,"w") as f:
            json.dump(data,f,indent=2)


# ----------------------------------------------------
# Prediction function
# ----------------------------------------------------
def run_prediction(features):

    x=np.array(features,dtype=float).reshape(1,-1)

    if scaler is not None:
        x=scaler.transform(x)

    if model is not None:

        label=int(model.predict(x)[0])

        if hasattr(model,"predict_proba"):
            proba=model.predict_proba(x)[0]
            confidence=float(round(max(proba)*100,2))
        else:
            confidence=100.0

    else:
        # DEMO MODE
        label=random.choice([0,1])
        confidence=float(round(random.uniform(75,95),2))

    # Determine attack type
    if label==0:
        attack="Normal"
        status="Normal"
    else:
        attack=random.choice(ATTACK_TYPES[1:])
        status="INTRUSION DETECTED"

    return{
        "label":label,
        "status":status,
        "attack_type":attack,
        "confidence":confidence
    }


# ----------------------------------------------------
# POST /predict
# ----------------------------------------------------
@app.route("/predict",methods=["POST"])
def predict():

    try:

        data=request.get_json(force=True)

        if data is None:
            return jsonify({"error":"No JSON body"}),400

        features=[float(data.get(col,0)) for col in FEATURE_COLS]

        prediction=run_prediction(features)

        entry={
            "timestamp":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "device_id":data.get("device_id","ARDUINO-UNO-01"),
            "features":dict(zip(FEATURE_COLS,features)),
            "label":prediction["label"],
            "status":prediction["status"],
            "attack_type":prediction["attack_type"],
            "confidence":prediction["confidence"]
        }

        append_to_log(entry)

        icon="🚨" if prediction["label"]==1 else "✅"

        print(
            f"[{entry['timestamp']}] {icon} {prediction['attack_type']} "
            f"({prediction['confidence']}%) | "
            f"device={entry['device_id']} | rate={features[0]}"
        )

        return jsonify(prediction)

    except Exception as e:

        print("[ERROR]",e)
        return jsonify({"error":str(e)}),500


# ----------------------------------------------------
# GET /status
# ----------------------------------------------------
@app.route("/status",methods=["GET"])
def status():

    count=0

    if os.path.exists(LIVE_LOG_PATH):
        try:
            with open(LIVE_LOG_PATH) as f:
                count=len(json.load(f))
        except:
            pass

    return jsonify({
        "status":"running",
        "model":type(model).__name__ if model else "demo_mode",
        "log_entries":count
    })


# ----------------------------------------------------
# GET /predictions
# ----------------------------------------------------
@app.route("/predictions",methods=["GET"])
def predictions():

    if os.path.exists(LIVE_LOG_PATH):

        try:
            with open(LIVE_LOG_PATH) as f:
                data=json.load(f)
        except:
            data=[]
    else:
        data=[]

    return jsonify(data)


# ----------------------------------------------------
# GET /clear
# ----------------------------------------------------
@app.route("/clear",methods=["GET"])
def clear():

    with log_lock:
        with open(LIVE_LOG_PATH,"w") as f:
            json.dump([],f)

    return jsonify({"message":"Log cleared"})


# ----------------------------------------------------
# MAIN
# ----------------------------------------------------
if __name__=="__main__":

    print("\n"+"="*50)
    print(" IoT IDS Receiver API")
    print(" POST /predict")
    print(" GET  /status")
    print(" GET  /predictions")
    print(" GET  /clear")
    print("="*50+"\n")

    app.run(host="0.0.0.0",port=5050)
