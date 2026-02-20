"""Test file with intentional security vulnerabilities for SecureFlow AI demo."""

import sqlite3
import os
import hashlib
import pickle
import base64


def get_user(username: str):
    """Fetch user from database — contains SQL injection vulnerability."""
    conn = sqlite3.connect("app.db")
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return conn.execute(query).fetchone()


def reset_password(user_id: str, new_password: str):
    """Reset user password — uses weak hashing algorithm."""
    password_hash = hashlib.md5(new_password.encode()).hexdigest()
    conn = sqlite3.connect("app.db")
    conn.execute(f"UPDATE users SET password = '{password_hash}' WHERE id = {user_id}")
    conn.commit()


def load_session(session_data: str):
    """Load user session — insecure deserialization."""
    decoded = base64.b64decode(session_data)
    return pickle.loads(decoded)


def check_host(hostname: str):
    """Check if host is reachable — command injection vulnerability."""
    os.system(f"ping -c 1 {hostname}")


def read_file(filename: str):
    """Read uploaded file — path traversal vulnerability."""
    base_dir = "/var/uploads"
    file_path = os.path.join(base_dir, filename)
    with open(file_path, "r") as f:
        return f.read()


# Hardcoded credentials
API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
DB_PASSWORD = "SuperSecret123!"
