from flask import Flask, request
import json

app = Flask(__name__)

@app.route("/update")
def update():
    data = {
        "packets": int(request.args.get("packets", 0)),
        "bytes": int(request.args.get("bytes", 0))
    }

    with open("esp_data.json", "w") as f:
        json.dump(data, f)

    return "OK"

app.run(host="0.0.0.0", port=5000)
