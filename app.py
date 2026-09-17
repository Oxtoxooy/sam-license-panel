
from flask import Flask, request, jsonify, render_template
from pathlib import Path
from datetime import datetime, timezone, timedelta
import json, secrets, string

app = Flask(__name__)
DB = Path("database.json")

def load_db():
    if not DB.exists():
        DB.write_text(json.dumps({"keys": []}, indent=2))
    return json.loads(DB.read_text())

def save_db(data):
    DB.write_text(json.dumps(data, indent=2))

def now():
    return datetime.now(timezone.utc)

def parse_iso(s):
    return datetime.fromisoformat(s.replace("Z","+00:00"))

def status(k):
    if k["status"] == "revoked":
        return "revoked"
    if parse_iso(k["expires_at"]) <= now():
        return "expired"
    return "active"

def make_key():
    alphabet = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4)]
    return "SAM-" + "-".join(parts)

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/api/keys")
def list_keys():
    data = load_db()
    for k in data["keys"]:
        k["status"] = status(k)
    save_db(data)
    return jsonify(data["keys"])

@app.post("/api/keys")
def generate_keys():
    body = request.get_json(silent=True) or {}
    try:
        duration = int(body.get("duration_hours", 24))
        quantity = max(1, min(int(body.get("quantity", 1)), 100))
    except Exception:
        return jsonify({"error":"duration_hours and quantity must be integers"}), 400
    if duration <= 0 or duration > 24*365:
        return jsonify({"error":"duration_hours must be between 1 and 8760"}), 400

    data = load_db()
    created = now()
    result = []
    existing = {k["key"] for k in data["keys"]}
    for _ in range(quantity):
        key = make_key()
        while key in existing:
            key = make_key()
        existing.add(key)
        item = {
            "id": secrets.token_hex(8),
            "key": key,
            "status": "active",
            "created_at": created.isoformat(),
            "expires_at": (created + timedelta(hours=duration)).isoformat(),
            "device_id": None,
            "last_used": None
        }
        data["keys"].append(item)
        result.append(item)
    save_db(data)
    return jsonify(result), 201

@app.post("/api/keys/<key>/revoke")
def revoke(key):
    data = load_db()
    for k in data["keys"]:
        if k["key"] == key:
            k["status"] = "revoked"
            save_db(data)
            return jsonify(k)
    return jsonify({"error":"key not found"}), 404

@app.post("/api/keys/<key>/reset-device")
def reset_device(key):
    data = load_db()
    for k in data["keys"]:
        if k["key"] == key:
            k["device_id"] = None
            save_db(data)
            return jsonify(k)
    return jsonify({"error":"key not found"}), 404

@app.post("/api/keys/validate")
def validate():
    body = request.get_json(silent=True) or {}
    key = body.get("key","").strip()
    device_id = body.get("device_id")
    data = load_db()
    for k in data["keys"]:
        if k["key"] == key:
            st = status(k)
            if st != "active":
                return jsonify({"valid":False,"status":st})
            if k["device_id"] and device_id and k["device_id"] != device_id:
                return jsonify({"valid":False,"status":"device_mismatch"})
            if device_id and not k["device_id"]:
                k["device_id"] = device_id
            k["last_used"] = now().isoformat()
            save_db(data)
            return jsonify({"valid":True,"status":"active","expires_at":k["expires_at"]})
    return jsonify({"valid":False,"status":"not_found"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
