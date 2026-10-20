import pytest
import sqlite3
import os
import sys

# Ensure app can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app import app, init_db, DATABASE_PATH

@pytest.fixture
def client():
    app.config["TESTING"] = True
    if os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)
    init_db()
    with app.test_client() as client:
        yield client
    if os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)

def test_search_users_basic(client):
    # Pre-populate a user
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password_hash, role) VALUES ('alice', 'hash123', 'admin')")
    conn.commit()
    conn.close()

    response = client.get("/api/users/search?username=alice")
    assert response.status_code == 200
    data = response.get_json()
    assert len(data["users"]) == 1
    assert data["users"][0][1] == "alice"

def test_reset_token_endpoint(client):
    response = client.post("/api/auth/reset-token")
    assert response.status_code == 200
    data = response.get_json()
    assert "reset_token" in data
    assert len(data["reset_token"]) == 32
