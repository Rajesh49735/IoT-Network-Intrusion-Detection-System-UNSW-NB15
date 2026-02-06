from flask import Flask, request, jsonify, render_template_string
from datetime import datetime

app = Flask(__name__)

# =====================================================
# GLOBAL STATE (LATEST ESP DATA)
# =====================================================
latest_data = {
    "packets": 0,
    "bytes": 0,
    "last_seen": "Never",
    "status": "Waiting for ESP8266..."
}

# =====================================================
# SIMPLE DASHBOARD (FOR EXAMINER)
# =====================================================
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>IoT Device Traffic Monitor</title>
    <meta http-equiv="refresh" content="2">
    <style>
        body {
            background:#020617;
            color:#e5e7eb;
            font-family:Segoe UI, Arial;
            text-align:center;
        }
        h1 { color:#38bdf8; }
        .card {
            background:#020617;
            border:1px solid #334155;
            padding:25px;
            border-radius:16px;
            width:320px;
            margin:auto;
            box-shadow:0 0 20px rgba(0,0,0,.6);
        }
        .ok { color:#22c55e; font-weight:bold; }
        .wait { color:#facc15; font-weight:bold; }
    </style>
</head>
<body>
    <h1>📡 ESP8266 Real-Time Traffic Monitor</h1>
    <div class="card">
        <p>Status: 
            {% if status == "ESP8266 Connected" %}
                <span class="ok">{{status}}</span>
            {% else %}
                <span class="wait">{{status}}</span>
            {% endif %}
        </p>
        <p><b>Packets/sec:</b> {{packets}}</p>
        <p><b>Bytes/sec:</b> {{bytes}}</p>
        <p><b>Last Update:</b> {{last_seen}}</p>
    </div>
</body>
</html>
"""

# =====================================================
# WEB DASHBOARD
# =====================================================
@app.route("/", methods=["GET"])
def dashboard():
    return render_template_string(
        HTML_PAGE,
        packets=latest_data["packets"],
        bytes=latest_data["bytes"],
        last_seen=latest_data["last_seen"],
        status=latest_data["status"]
    )

# =====================================================
# ESP8266 → SERVER DATA ENDPOINT
# =====================================================
@app.route("/iot", methods=["POST"])
def receive_iot_data():
    global latest_data

    data = request.get_json(force=True)

    latest_data["packets"] = int(data.get("packets", 0))
    latest_data["bytes"] = int(data.get("bytes", 0))
    latest_data["last_seen"] = datetime.now().strftime("%H:%M:%S")
    latest_data["status"] = "ESP8266 Connected"

    return jsonify({"message": "Data received successfully"})

# =====================================================
# API FOR STREAMLIT
# =====================================================
@app.route("/latest", methods=["GET"])
def latest():
    return jsonify(latest_data)

# =====================================================
# START SERVER
# =====================================================
if __name__ == "__main__":
    print("🚀 IoT Receiver Running...")
    print("📡 Waiting for ESP8266 data...")
    app.run(host="0.0.0.0", port=5000)
