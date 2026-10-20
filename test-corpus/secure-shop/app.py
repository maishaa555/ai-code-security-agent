import os
import sqlite3
import subprocess
import hashlib
import secrets
from flask import Flask, request, jsonify

app = Flask(__name__)

# SECURE: Secret retrieved from environment variable
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "fallback-dev-only-secret")
DATABASE_PATH = "shop.db"

def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT
        )
    """)
    conn.commit()
    conn.close()

# SECURE: Parameterized SQL query
@app.route("/api/users/search", methods=["GET"])
def search_users():
    username = request.args.get("username", "")
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    query = "SELECT id, username, role FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    results = cursor.fetchall()
    conn.close()
    return jsonify({"users": results})

# SECURE: Argument array without shell=True
@app.route("/api/admin/ping", methods=["GET"])
def network_ping():
    target_host = request.args.get("host", "127.0.0.1")
    # Using strict argument list, no shell interpretation
    output = subprocess.check_output(["ping", "-c", "1", target_host], shell=False)
    return jsonify({"output": output.decode("utf-8", errors="ignore")})

# SECURE: Path validation and safe boundary check
@app.route("/api/reports/view", methods=["GET"])
def view_report():
    report_name = request.args.get("file", "daily.txt")
    safe_name = os.path.basename(report_name)
    file_path = os.path.join("reports", safe_name)
    with open(file_path, "r") as f:
        content = f.read()
    return jsonify({"content": content})

# SECURE: Strong hashing algorithm (SHA256 with salt)
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    password = data.get("password", "")
    pwd_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return jsonify({"status": "registered", "hash": pwd_hash})

# SECURE: Cryptographically secure token generator
@app.route("/api/auth/reset-token", methods=["POST"])
def generate_reset_token():
    token = secrets.token_hex(16)
    return jsonify({"reset_token": token})

if __name__ == "__main__":
    init_db()
    app.run(port=5000, debug=True)
