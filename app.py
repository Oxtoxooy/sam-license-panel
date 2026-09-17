from flask import Flask, request, jsonify, render_template
from datetime import datetime, timezone, timedelta
import os
import secrets
import string

from supabase import create_client

app = Flask(__name__)

# Supabase connection
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]

supabase = create_client(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY
)


def now():
    return datetime.now(timezone.utc)


def parse_iso(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def get_status(key_data):
    if key_data["status"] == "revoked":
        return "revoked"

    if parse_iso(key_data["expires_at"]) <= now():
        return "expired"

    return "active"


def make_key():
    alphabet = string.ascii_uppercase + string.digits
    parts = [
        "".join(secrets.choice(alphabet) for _ in range(5))
        for _ in range(4)
    ]
    return "SAM-" + "-".join(parts)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/keys")
def list_keys():
    response = (
        supabase
        .table("license_keys")
        .select("*")
        .order("created_at", desc=True)
        .execute()
    )

    keys = response.data or []

    for key in keys:
        key["status"] = get_status(key)

    return jsonify(keys)


@app.post("/api/keys")
def generate_keys():
    body = request.get_json(silent=True) or {}

    try:
        duration = int(body.get("duration_hours", 24))
        quantity = max(1, min(int(body.get("quantity", 1)), 100))
    except Exception:
        return jsonify({
            "error": "duration_hours and quantity must be integers"
        }), 400

    if duration <= 0 or duration > 24 * 365:
        return jsonify({
            "error": "duration_hours must be between 1 and 8760"
        }), 400

    created = now()
    result = []

    for _ in range(quantity):
        key = make_key()

        item = {
            "id": secrets.token_hex(8),
            "key": key,
            "status": "active",
            "created_at": created.isoformat(),
            "expires_at": (
                created + timedelta(hours=duration)
            ).isoformat(),
            "device_id": None,
            "last_used": None
        }

        supabase.table("license_keys").insert(item).execute()
        result.append(item)

    return jsonify(result), 201


@app.post("/api/keys/<key>/revoke")
def revoke(key):
    response = (
        supabase
        .table("license_keys")
        .update({"status": "revoked"})
        .eq("key", key)
        .execute()
    )

    if not response.data:
        return jsonify({"error": "key not found"}), 404

    return jsonify(response.data[0])


@app.post("/api/keys/<key>/reset-device")
def reset_device(key):
    response = (
        supabase
        .table("license_keys")
        .update({"device_id": None})
        .eq("key", key)
        .execute()
    )

    if not response.data:
        return jsonify({"error": "key not found"}), 404

    return jsonify(response.data[0])


@app.post("/api/keys/validate")
def validate():
    body = request.get_json(silent=True) or {}

    key = body.get("key", "").strip()
    device_id = body.get("device_id")

    response = (
        supabase
        .table("license_keys")
        .select("*")
        .eq("key", key)
        .limit(1)
        .execute()
    )

    keys = response.data or []

    if not keys:
        return jsonify({
            "valid": False,
            "status": "not_found"
        })

    key_data = keys[0]
    status = get_status(key_data)

    if status != "active":
        return jsonify({
            "valid": False,
            "status": status
        })

    if (
        key_data["device_id"]
        and device_id
        and key_data["device_id"] != device_id
    ):
        return jsonify({
            "valid": False,
            "status": "device_mismatch"
        })

    update_data = {
        "last_used": now().isoformat()
    }

    if device_id and not key_data["device_id"]:
        update_data["device_id"] = device_id

    supabase \
        .table("license_keys") \
        .update(update_data) \
        .eq("key", key) \
        .execute()

    return jsonify({
        "valid": True,
        "status": "active",
        "expires_at": key_data["expires_at"]
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
