#!/usr/bin/env python3
"""
Challenge 8 — Multi-Step Chain Challenge
Vulnerability chain: JWT None-Algorithm Bypass -> SSRF via Internal Report Endpoint

Step 1: The /auth endpoint issues a JWT. Players must forge a JWT with role=admin
        using the "none" algorithm attack.

Step 2: With admin JWT, /api/report?source=<url> is accessible.
        The source parameter fetches content from a URL — SSRF.
        The internal flag endpoint is http://127.0.0.1:5001/internal/secret
        (served on a second internal Flask thread on port 5001)
"""

import base64, json, hashlib, hmac, threading
from flask import Flask, request, jsonify
import urllib.request
import urllib.error

app = Flask(__name__)
internal_app = Flask("internal")

FLAG = open("flag.txt").read().strip()

# ---- JWT Helpers ----
SECRET = "nullgrids_jwt_s3cr3t_2026"

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s: str) -> bytes:
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def make_jwt(payload: dict, algorithm: str = "HS256") -> str:
    header = {"alg": algorithm, "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(',',':')).encode())
    p = b64url_encode(json.dumps(payload, separators=(',',':')).encode())
    sig_input = f"{h}.{p}".encode()
    if algorithm == "HS256":
        sig = hmac.new(SECRET.encode(), sig_input, hashlib.sha256).digest()
    else:
        sig = b""
    return f"{h}.{p}.{b64url_encode(sig)}"

def verify_jwt(token: str):
    """Returns (payload, error). VULNERABLE: accepts 'none' algorithm."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None, "Malformed token"
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        alg = header.get("alg", "")
        
        if alg == "none" or alg == "None" or alg == "NONE":
            # VULNERABILITY: skip signature verification for 'none' algorithm
            return payload, None
        elif alg == "HS256":
            sig_input = f"{parts[0]}.{parts[1]}".encode()
            expected = hmac.new(SECRET.encode(), sig_input, hashlib.sha256).digest()
            provided = b64url_decode(parts[2])
            if hmac.compare_digest(expected, provided):
                return payload, None
            else:
                return None, "Invalid signature"
        else:
            return None, f"Unsupported algorithm: {alg}"
    except Exception as e:
        return None, str(e)

# ---- Main App Routes ----

@app.route("/")
def index():
    return """
    <html><head><title>NullGrids Chain Challenge</title></head>
    <body style='font-family:monospace;background:#000;color:#ff0044;padding:40px'>
    <h1>NullGrids Internal Report Portal</h1>
    <p style='color:#aaa'>Authentication: JWT-based | Authorization: role-based</p>
    <br>
    <p>Endpoints:</p>
    <ul>
      <li>POST /auth — get JWT token: {"username":"employee","password":"ng2026"}</li>
      <li>GET /api/report?source=URL — admin only: fetch a report from URL</li>
      <li>GET /api/me — show your decoded JWT claims</li>
    </ul>
    <p style='color:#444;font-size:12px'>NullGrids v2026.3 | Internal Use Only</p>
    </body></html>
    """

VALID_CREDS = {
    "employee": "ng2026",
    "analyst":  "nullgrids_analyst_2026"
}

@app.route("/auth", methods=["POST"])
def auth():
    data = request.get_json(force=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if VALID_CREDS.get(username) == password:
        payload = {"sub": username, "role": "employee", "iat": 1710000000}
        token = make_jwt(payload, "HS256")
        return jsonify({
            "token": token,
            "msg": "Authenticated. Use token in Authorization: Bearer <token>",
            "note": "Admin role required for /api/report"
        })
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/me")
def me():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "No token provided"}), 401
    token = auth_header[7:]
    payload, err = verify_jwt(token)
    if err:
        return jsonify({"error": err}), 401
    return jsonify({"claims": payload})

BLOCKED_NETWORKS = ["0.0.0.0", "169.254.", "10.0.", "172.16.", "192.168."]
# NOTE: 127.0.0.1 is NOT blocked — that's the SSRF target

@app.route("/api/report")
def report():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "No token provided"}), 401
    token = auth_header[7:]
    payload, err = verify_jwt(token)
    if err:
        return jsonify({"error": err}), 401

    if payload.get("role") != "admin":
        return jsonify({"error": "Admin role required for report access"}), 403

    source = request.args.get("source", "")
    if not source:
        return jsonify({"error": "?source=URL parameter required"}), 400

    # Block some ranges but NOT localhost
    for blocked in BLOCKED_NETWORKS:
        if blocked in source:
            return jsonify({"error": "Network range blocked"}), 403

    try:
        req = urllib.request.Request(source, headers={"User-Agent": "NullGrids-Reporter/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            content = resp.read(4096).decode("utf-8", errors="replace")
        return jsonify({"source": source, "content": content})
    except urllib.error.URLError as e:
        return jsonify({"error": f"Failed to fetch: {e}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---- Internal App (port 5001, simulates internal service) ----

@internal_app.route("/internal/secret")
def internal_secret():
    return jsonify({
        "classification": "TOP SECRET",
        "flag": FLAG,
        "note": "NullGrids Q1 2026 Breach Report — RESTRICTED"
    })

@internal_app.route("/")
def internal_index():
    return "NullGrids Internal Service — restricted access", 200

def run_internal():
    internal_app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False)

if __name__ == "__main__":
    t = threading.Thread(target=run_internal, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
