from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def home():
    return "IoT Intrusion Detection Server: ONLINE"

# This route matches the '/iot' path in your ESP8266 code
@app.route('/iot', methods=['GET'])
def receive_iot_data():
    # Looks for ?sensor=XX in the URL
    sensor_val = request.args.get('sensor')
    
    if sensor_val:
        print(f" [!] Alert: Incoming Traffic detected.")
        print(f" [>] Sensor Value: {sensor_val}")
        return f"Data {sensor_val} logged successfully", 200
    else:
        print(" [?] Received request at /iot but no 'sensor' parameter found.")
        return "Missing data", 400

if __name__ == "__main__":
    # host='0.0.0.0' allows devices on your network to connect to your laptop
    app.run(host="0.0.0.0", port=5000, debug=True)
