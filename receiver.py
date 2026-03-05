from flask import Flask, request
from datetime import datetime
import json

app = Flask(__name__)
DATA_FILE = "esp_data.json"

@app.route('/iot', methods=['GET'])
def handle_iot():
    sensor_val = request.args.get('sensor')
    
    if sensor_val:
        try:
            val = int(sensor_val)
            # We map the single hardware value to multiple features your model expects
            # Adjust these multipliers based on how your model was trained
            data = {
                "spkts": val,
                "sbytes": val * 64,
                "dpkts": int(val * 0.8),
                "dbytes": int(val * 55),
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }
            
            with open(DATA_FILE, "w") as f:
                json.dump(data, f)
            
            print(f" [!] Hardware Data Received: {val} packets")
            return "OK", 200
        except Exception as e:
            print(f" [X] Error processing data: {e}")
            return "Error", 500
            
    return "No Data", 400

if __name__ == "__main__":
    # Listen on your local IP so ESP8266 can find it
    app.run(host="0.0.0.0", port=5000)
