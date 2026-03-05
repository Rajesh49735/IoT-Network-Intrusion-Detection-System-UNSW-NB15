from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def home():
    return "IoT IDS Server Running"

@app.route('/data', methods=['POST','GET'])
def receive():
    data = request.data.decode()
    print("Received:", data)
    return "OK"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
