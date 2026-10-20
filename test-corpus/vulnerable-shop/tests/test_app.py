import unittest
import sqlite3
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app import app, init_db, DATABASE_PATH

class ShopTestCase(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        if os.path.exists(DATABASE_PATH):
            try:
                os.remove(DATABASE_PATH)
            except Exception:
                pass
        init_db()

    def tearDown(self):
        if os.path.exists(DATABASE_PATH):
            try:
                os.remove(DATABASE_PATH)
            except Exception:
                pass

    def test_search_users_basic(self):
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password_hash, role) VALUES ('alice', 'hash123', 'admin')")
        conn.commit()
        conn.close()

        response = self.client.get("/api/users/search?username=alice")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(len(data["users"]), 1)
        self.assertEqual(data["users"][0][1], "alice")

    def test_reset_token_endpoint(self):
        response = self.client.post("/api/auth/reset-token")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("reset_token", data)
        self.assertEqual(len(data["reset_token"]), 32)

if __name__ == "__main__":
    unittest.main()
