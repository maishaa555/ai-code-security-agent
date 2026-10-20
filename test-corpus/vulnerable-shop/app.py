import os
import sqlite3
import subprocess
import hashlib
import random
from flask import Flask, request, jsonify

app = Flask(__name__)

# RULE 1: Hard-coded Secret / Credential
JWT_SECRET_KEY = "sk-live-99a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4"
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
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price REAL
        )
    """)
    conn.commit()
    conn.close()

# RULE 2: SQL Injection (Source: request.args -> Propagation: username -> Sink: cursor.execute)
@app.route("/api/users/search", methods=["GET"])
def search_users():
    username = request.args.get("username", "")
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    # VULNERABLE: Direct string interpolation into SQL sink
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return jsonify({"users": results})

# RULE 3: Command Injection (Source: request.args -> Propagation: target_host -> Sink: subprocess.Popen/os.system)
@app.route("/api/admin/ping", methods=["GET"])
def network_ping():
    target_host = request.args.get("host", "127.0.0.1")
    # VULNERABLE: Shell command with unescaped user parameter
    cmd = "ping -c 1 " + target_host
    output = subprocess.check_output(cmd, shell=True)
    return jsonify({"output": output.decode("utf-8", errors="ignore")})

# RULE 4: Path Traversal (Source: request.args -> Propagation: report_name -> Sink: open())
@app.route("/api/reports/view", methods=["GET"])
def view_report():
    report_name = request.args.get("file", "daily.txt")
    # VULNERABLE: File opened without path normalization or boundary check
    file_path = os.path.join("reports", report_name)
    with open(file_path, "r") as f:
        content = f.read()
    return jsonify({"content": content})

# RULE 5: Weak Cryptography (MD5 used for password hashing)
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    password = data.get("password", "")
    # VULNERABLE: Weak MD5 hashing algorithm
    pwd_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
    return jsonify({"status": "registered", "hash": pwd_hash})

# RULE 6: Insecure Randomness (random.random used for security token generation)
@app.route("/api/auth/reset-token", methods=["POST"])
def generate_reset_token():
    # VULNERABLE: Pseudo-random number generator used for sensitive token
    token = "".join([str(random.randint(0, 9)) for _ in range(32)])
    return jsonify({"reset_token": token})

if __name__ == "__main__":
    init_db()
    app.run(port=5000, debug=True)
