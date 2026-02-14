"""ShopFast — Payment endpoint (INTENTIONALLY VULNERABLE for demo).

Contains multiple security vulnerabilities that SecureFlow AI should detect:
1. SQL Injection (CWE-89) — string concatenation in query
2. Hardcoded secret (CWE-798) — API key in source code
3. Missing input validation — no amount bounds checking
"""

import sqlite3
import logging

from flask import Flask, request, jsonify

app = Flask(__name__)
logger = logging.getLogger(__name__)

# VULNERABILITY: Hardcoded API key (CWE-798)
STRIPE_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
DATABASE_URL = "sqlite:///shopfast.db"


def get_db():
    return sqlite3.connect("shopfast.db")


@app.route("/api/payments", methods=["POST"])
def process_payment():
    """Process a payment for an order."""
    data = request.get_json()
    user_id = data.get("user_id")
    amount = data.get("amount")
    card_token = data.get("card_token")

    db = get_db()
    cursor = db.cursor()

    # VULNERABILITY: SQL Injection (CWE-89)
    # User input directly concatenated into query
    query = f"SELECT * FROM users WHERE id = {user_id} AND status = 'active'"
    cursor.execute(query)
    user = cursor.fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    # VULNERABILITY: No input validation on amount
    # Could be negative, zero, or astronomically large
    order_query = f"INSERT INTO orders (user_id, amount, status) VALUES ({user_id}, {amount}, 'pending')"
    cursor.execute(order_query)
    db.commit()

    # Log payment details including sensitive data
    logger.info(f"Payment processed: user={user_id}, amount={amount}, card={card_token}")

    return jsonify({
        "status": "success",
        "order_id": cursor.lastrowid,
        "amount": amount,
    })


@app.route("/api/payments/search", methods=["GET"])
def search_payments():
    """Search payment history."""
    search_term = request.args.get("q", "")
    db = get_db()
    cursor = db.cursor()

    # VULNERABILITY: SQL Injection (CWE-89)
    query = "SELECT * FROM orders WHERE description LIKE '%" + search_term + "%'"
    cursor.execute(query)
    results = cursor.fetchall()

    return jsonify({"results": results})
