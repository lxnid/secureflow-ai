"""ShopFast — User management endpoint (INTENTIONALLY VULNERABLE for demo).

Contains security vulnerabilities:
1. Path Traversal (CWE-22) — unsanitized file path from user input
2. Weak password hashing (CWE-916) — MD5 instead of bcrypt/argon2
3. XSS (CWE-79) — user input reflected without escaping
"""

import hashlib
import os

from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

UPLOAD_DIR = "/var/uploads/avatars"


@app.route("/api/users/<int:user_id>/avatar", methods=["GET"])
def get_avatar(user_id):
    """Serve user avatar image."""
    filename = request.args.get("file", "default.png")

    # VULNERABILITY: Path Traversal (CWE-22)
    # User-controlled filename with no sanitization
    file_path = os.path.join(UPLOAD_DIR, filename)

    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            return f.read(), 200, {"Content-Type": "image/png"}

    return jsonify({"error": "Avatar not found"}), 404


@app.route("/api/users/register", methods=["POST"])
def register_user():
    """Register a new user."""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")

    # VULNERABILITY: Weak password hashing (CWE-916)
    # MD5 is cryptographically broken — should use bcrypt or argon2
    password_hash = hashlib.md5(password.encode()).hexdigest()

    # Store user (simplified)
    user = {
        "username": username,
        "email": email,
        "password_hash": password_hash,
    }

    return jsonify({"status": "created", "user": username})


@app.route("/api/users/profile", methods=["GET"])
def user_profile():
    """Render user profile page."""
    username = request.args.get("name", "Guest")

    # VULNERABILITY: Reflected XSS (CWE-79)
    # User input directly injected into HTML without escaping
    html = f"""
    <html>
    <head><title>Profile — {username}</title></head>
    <body>
        <h1>Welcome, {username}!</h1>
        <p>Your profile page</p>
    </body>
    </html>
    """
    return html
