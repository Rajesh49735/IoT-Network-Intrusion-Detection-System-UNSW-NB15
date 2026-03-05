from flask import Flask, request

app = Flask(__name__)

# This handles "GET /?sensor=XX" (The 404 fix)
@app.route('/')
@app.route('/iot')
def receive_data():
    sensor_val = request.args.get('sensor')
    if sensor_val:
        print(f" [!] SUCCESS! Received Value: {sensor_val}")
        return f"Logged {sensor_val}", 200
    else:
        print(" [?] Connection established, but no sensor data found in the URL.")
        return "Connected, but send ?sensor=XX", 200

if __name__ == "__main__":
    # Ensure this IP matches what you see in the terminal (192.168.0.234)
    app.run(host="0.0.0.0", port=5000, debug=True)
