"""
receiver.py  –  Flask API server for IoT IDS Hardware Integration
=================================================================
Receives JSON traffic features from Arduino/ESP8266 via HTTP POST,
runs the trained ML model (binary classification), and appends the
result to a shared JSON log file that Streamlit reads in real-time.

Usage:
    pip install flask numpy pandas scikit-learn pickle5
    python receiver.py

Runs on: http://0.0.0.0:5050
Endpoint: POST /predict  { JSON traffic features }
"""

from flask import Flask, request, jsonify
import pickle
import numpy as np
import json
import os
from datetime import datetime
import threading

app = Flask(__name__)

# ── Paths ──────────────────────────────────────────────────────
MODEL_PATH    = "models/random_forest_bin.pkl"   # best binary model
SCALER_PATH   = "models/scaler_bin.pkl"          # MinMaxScaler saved during training
LIVE_LOG_PATH = "live_predictions.json"          # Shared file Streamlit reads

# ── Binary classification feature order (must match training) ──
FEATURE_COLS = [
    "rate", "sttl", "sload", "dload",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "ct_src_ltm", "ct_srv_dst",
    "state_CON", "state_INT"
]

# ── Load model & scaler ────────────────────────────────────────
print("[INFO] Loading model from:", MODEL_PATH)
try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    print("[OK]  Model loaded:", type(model).__name__)
except FileNotFoundError:
    print("[WARN] Model file not found at", MODEL_PATH)
    print("       Using DEMO mode (random predictions)")
    model = None

print("[INFO] Loading scaler from:", SCALER_PATH)
try:
    with open(SCALER_PATH, "rb") as f:
        scaler = pickle.load(f)
    print("[OK]  Scaler loaded")
except FileNotFoundError:
    print("[WARN] Scaler not found — feature values will NOT be scaled")
    scaler = None

# ── Thread-safe log writer ─────────────────────────────────────
log_lock = threading.Lock()
MAX_LOG_ENTRIES = 200  # Keep last 200 entries in the live log

def append_to_log(entry: dict):
    """Append one prediction entry to the shared JSON log."""
    with log_lock:
        if os.path.exists(LIVE_LOG_PATH):
            with open(LIVE_LOG_PATH, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = []
        else:
            data = []

        data.append(entry)
        # Keep only last N entries so file stays small
        data = data[-MAX_LOG_ENTRIES:]

        with open(LIVE_LOG_PATH, "w") as f:
            json.dump(data, f, indent=2)


def run_prediction(features: list) -> dict:
    """Run model prediction on a 1×14 feature vector."""
    x = np.array(features, dtype=float).reshape(1, -1)

    if scaler is not None:
        x = scaler.transform(x)

    if model is not None:
        label = int(model.predict(x)[0])
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(x)[0]
            confidence = float(round(max(proba) * 100, 2))
        else:
            confidence = 100.0
    else:
        # Demo mode: simple threshold on 'rate' (index 0)
        label = 1 if features[0] > 200 else 0
        confidence = 85.0 + np.random.uniform(-5, 5)

    return {
        "label": label,
        "status": "INTRUSION DETECTED" if label == 1 else "Normal",
        "confidence": confidence
    }


# ── POST /predict ──────────────────────────────────────────────
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(force=True)
        if data is None:
            return jsonify({"error": "No JSON body"}), 400

        # Extract features in correct order, default 0 if missing
        features = [float(data.get(col, 0)) for col in FEATURE_COLS]

        prediction = run_prediction(features)

        # Build log entry
        entry = {
            "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "device_id":  data.get("device_id", "unknown"),
            "features":   dict(zip(FEATURE_COLS, features)),
            "label":      prediction["label"],
            "status":     prediction["status"],
            "confidence": prediction["confidence"]
        }

        append_to_log(entry)

        # Console log
        icon = "🚨" if prediction["label"] == 1 else "✅"
        print(f"[{entry['timestamp']}] {icon} {entry['status']} "
              f"({prediction['confidence']:.1f}%) | "
              f"device={entry['device_id']} | rate={features[0]:.1f}")

        return jsonify({
            "status":     prediction["status"],
            "label":      prediction["label"],
            "confidence": prediction["confidence"],
            "timestamp":  entry["timestamp"]
        }), 200

    except Exception as e:
        print(f"[ERROR] {e}")
        return jsonify({"error": str(e)}), 500


# ── GET /status ─ health check ─────────────────────────────────
@app.route("/status", methods=["GET"])
def status():
    log_count = 0
    if os.path.exists(LIVE_LOG_PATH):
        with log_lock:
            with open(LIVE_LOG_PATH, "r") as f:
                try:
                    log_count = len(json.load(f))
                except:
                    pass
    return jsonify({
        "status":      "running",
        "model":       type(model).__name__ if model else "demo_mode",
        "log_entries": log_count
    })


# ── GET /clear ─ reset the live log ───────────────────────────
@app.route("/clear", methods=["GET"])
def clear_log():
    with log_lock:
        with open(LIVE_LOG_PATH, "w") as f:
            json.dump([], f)
    return jsonify({"message": "Log cleared"})


if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  IoT IDS Receiver  |  http://0.0.0.0:5050")
    print("  POST /predict     → run ML prediction")
    print("  GET  /status      → health check")
    print("  GET  /clear       → clear live log")
    print("=" * 50 + "\n")
    app.run(host="0.0.0.0", port=5050, debug=False)
