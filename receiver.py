from flask import Flask, request

app = Flask(__name__)

# This handles the "GET /" request that was causing your 404
@app.route('/')
def home():
    sensor_val = request.args.get('sensor')
    if sensor_val:
        print(f" [!] Data received at Root: {sensor_val}")
        return f"Logged {sensor_val}", 200
    return "Server is Running. Use /iot?sensor=XX to send data."

# This handles the "GET /iot" request
@app.route('/iot')
def receive_iot_data():
    sensor_val = request.args.get('sensor')
    if sensor_val:
        print(f" [>] Data received at /iot: {sensor_val}")
        return f"Logged {sensor_val}", 200
    return "No sensor data", 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
