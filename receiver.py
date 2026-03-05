from flask import Flask, request

app = Flask(__name__)

# Test page
@app.route('/')
def home():
    return "IoT IDS Receiver Running"

# ESP8266 will send data here
@app.route('/data', methods=['POST','GET'])
def receive():
    data = request.data.decode()
    print("Traffic received:", data)
    return "OK"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
