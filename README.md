
# SAM License Panel — Local Demo

## Requirements
- Python 3.10+
- Flask

## Run
1. Open a terminal in this folder.
2. Install Flask:
   python -m pip install flask
3. Start:
   python app.py
4. Open:
   http://127.0.0.1:5000

The JSON file `database.json` is the mock database and is created automatically.

## REST API

Generate:
POST /api/keys
JSON: {"duration_hours":24,"quantity":5}

List:
GET /api/keys

Revoke:
POST /api/keys/<KEY>/revoke

Reset device:
POST /api/keys/<KEY>/reset-device

Validate:
POST /api/keys/validate
JSON: {"key":"SAM-XXXXX-XXXXX-XXXXX-XXXXX","device_id":"demo-device-1"}

This is a local demo, not production authentication/security. For production use HTTPS, authenticated admin accounts, hashed license secrets, rate limiting, audit logs, and a real database.
