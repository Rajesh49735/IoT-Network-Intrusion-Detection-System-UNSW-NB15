from flask import Flask, request

app = Flask(__name__)

# Homepage route
@app.route('/')
def home():
    return "IoT Intrusion Detection Server Running"

# ESP8266 will send data here
@app.route('/data', methods=['POST', 'GET'])
def receive():
    data = request.data.decode()
    print("Traffic received:", data)
    return "Data received successfully"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
