from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# Store latest ESP traffic
latest_data = {
    "packets": 0,
    "bytes": 0,
    "status": "Waiting for ESP8266..."
}

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>IoT Traffic Monitor</title>
    <meta http-equiv="refresh" content="2">
    <style>
        body { background:#0f172a; color:white; font-family:Arial; text-align:center; }
        h1 { color:#38bdf8; }
        .card { background:#020617; padding:20px; border-radius:12px; width:300px; margin:auto; }
    </style>
</head>
<body>
    <h1>📡 IoT Traffic Monitor</h1>
    <div class="card">
        <p><b>Status:</b> {{status}}</p>
        <p><b>Packets/sec:</b> {{packets}}</p>
        <p><b>Bytes/sec:</b> {{bytes}}</p>
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def dashboard():
    return render_template_string(
        HTML_PAGE,
        packets=latest_data["packets"],
        bytes=latest_data["bytes"],
        status=latest_data["status"]
    )

@app.route("/iot", methods=["POST"])
def receive_iot_data():
    global latest_data
    data = request.json

    latest_data["packets"] = data.get("packets", 0)
    latest_data["bytes"] = data.get("bytes", 0)
    latest_data["status"] = "ESP8266 Connected ✅"

    return jsonify({"message": "Data received"})

@app.route("/latest", methods=["GET"])
def latest():
    return jsonify(latest_data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
